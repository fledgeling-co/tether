//! Optional TLS passthrough ingress. Routing reads bounded ClientHello metadata, never plaintext.
//! The origin application must authenticate TLS and its peer; routing does not grant authorization.

use futures_util::{SinkExt, StreamExt};
use std::{collections::HashSet, future::Future, sync::Arc, time::Duration};
use tether::carrier::{self, Carrier, Result};
use tether_relay::Relay;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_tungstenite::tungstenite::Message;

const MAX_HELLO: usize = 32_768;
const MAX_RECORDS: usize = 256;
const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(60);
const WRITE_WAIT: Duration = Duration::from_secs(15);

/// A DNS suffix, excluding the public per-host label. This is owner configuration, never a URL.
pub fn valid_suffix(suffix: &str) -> bool {
    let suffix = suffix.strip_suffix('.').unwrap_or(suffix);
    !suffix.is_empty()
        && suffix.len() <= 200
        && suffix.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// A relay host ID is a public route selector, never a pairing password.
pub fn route_host(server_name: &str, suffix: &str) -> Option<String> {
    if !valid_suffix(suffix) {
        return None;
    }
    let lower = server_name.to_ascii_lowercase();
    let suffix = format!(".{}", suffix.trim_end_matches('.').to_ascii_lowercase());
    let id = lower.strip_suffix(&suffix)?;
    (id.len() == 52
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)))
    .then(|| id.to_owned())
}

/// Parses a TLS 1.3-capable ClientHello body. Duplicate extensions and ambiguous SNI are refused.
pub fn server_name(body: &[u8]) -> Option<String> {
    if body.len() > MAX_HELLO - 4 {
        return None;
    }
    let mut input = Cursor::new(body);
    if input.take(2)? != [3, 3] {
        return None;
    }
    input.take(32)?;
    if input.vector8()?.len() > 32 {
        return None;
    }
    let ciphers = input.vector16()?;
    if ciphers.is_empty() || ciphers.len() % 2 != 0 || input.vector8()? != [0] {
        return None;
    }
    let mut extensions = Cursor::new(input.vector16()?);
    if !input.done() {
        return None;
    }
    let mut name = None;
    let mut tls13 = false;
    let mut seen = HashSet::new();
    while !extensions.done() {
        let kind = extensions.u16()?;
        if !seen.insert(kind) {
            return None;
        }
        let bytes = extensions.vector16()?;
        if kind == 0 {
            let mut value = Cursor::new(bytes);
            let mut names = Cursor::new(value.vector16()?);
            if !value.done() {
                return None;
            }
            while !names.done() {
                let kind = names.u8()?;
                let value = names.vector16()?;
                if kind != 0 || name.is_some() || value.is_empty() || value.len() > 253 {
                    return None;
                }
                if !value
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-')
                {
                    return None;
                }
                name = Some(std::str::from_utf8(value).ok()?.to_owned());
            }
        } else if kind == 43 {
            let mut value = Cursor::new(bytes);
            let versions = value.vector8()?;
            if !value.done() || versions.is_empty() || versions.len() % 2 != 0 {
                return None;
            }
            tls13 = versions.as_chunks::<2>().0.contains(&[3, 4]);
        }
    }
    if tls13 {
        name
    } else {
        None
    }
}
struct Cursor<'a> {
    bytes: &'a [u8],
    index: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }
    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.index.checked_add(length)?;
        let value = self.bytes.get(self.index..end)?;
        self.index = end;
        Some(value)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn vector8(&mut self) -> Option<&'a [u8]> {
        let length = self.u8()? as usize;
        self.take(length)
    }
    fn vector16(&mut self) -> Option<&'a [u8]> {
        let length = self.u16()?;
        self.take(length)
    }
    fn done(&self) -> bool {
        self.index == self.bytes.len()
    }
}
async fn hello(socket: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut original = Vec::new();
    let mut handshake = Vec::new();
    for _ in 0..MAX_RECORDS {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != 22
            || header[1] != 3
            || ![1, 3].contains(&header[2])
            || length == 0
            || length > 16_384
            || original.len() + length + 5 > MAX_HELLO + MAX_RECORDS * 5
            || handshake.len() + length > MAX_HELLO
        {
            return Err("invalid TLS hello".into());
        }
        let start = handshake.len();
        handshake.resize(start + length, 0);
        socket.read_exact(&mut handshake[start..]).await?;
        original.extend_from_slice(&header);
        original.extend_from_slice(&handshake[start..]);
        if handshake.len() < 4 {
            continue;
        }
        let body_length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | handshake[3] as usize;
        if handshake[0] != 1 || body_length > MAX_HELLO - 4 {
            return Err("invalid TLS hello".into());
        }
        if handshake.len() >= body_length + 4 {
            let name = server_name(&handshake[4..body_length + 4]).ok_or("TLS1.3 SNI required")?;
            return Ok((name, original));
        }
    }
    Err("TLS hello has too many fragments".into())
}

fn check_internal_url(value: &str) -> Result<()> {
    let url = url::Url::parse(value)?;
    let loopback = url
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|address| address.is_loopback());
    if url.scheme() != "ws"
        || !loopback
        || url.path() != "/v1/relay"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("ingress must use this process's loopback relay URL".into());
    }
    carrier::check_relay_url(value, true)
}

pub async fn serve(
    listener: TcpListener,
    relay: Relay,
    relay_url: String,
    suffix: String,
) -> Result<()> {
    serve_with_shutdown(listener, relay, relay_url, suffix, std::future::pending()).await
}

/// Stops accepting and closes active forwarding paths when shutdown resolves.
pub async fn serve_with_shutdown(
    listener: TcpListener,
    relay: Relay,
    relay_url: String,
    suffix: String,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    if !valid_suffix(&suffix) {
        return Err("invalid ingress suffix".into());
    }
    check_internal_url(&relay_url)?;
    let slots = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = listener.accept() => {
                let (socket, _) = incoming?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { drop(socket); continue; };
                let relay = relay.clone(); let relay_url = relay_url.clone(); let suffix = suffix.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = connection(socket, relay, &relay_url, &suffix).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn connection(
    mut socket: TcpStream,
    relay: Relay,
    relay_url: &str,
    suffix: &str,
) -> Result<()> {
    let (name, original) = timeout(HANDSHAKE_WAIT, hello(&mut socket)).await??;
    let id = route_host(&name, suffix).ok_or("unknown route")?;
    let app = relay.host_app(&id).ok_or("host unavailable")?;
    let Carrier::Relay(mut relay_socket) = timeout(
        WRITE_WAIT,
        carrier::relay_client(relay_url, &app, &id, true),
    )
    .await??
    else {
        return Err("invalid carrier".into());
    };
    timeout(
        WRITE_WAIT,
        relay_socket.send(Message::Binary(original.into())),
    )
    .await??;
    let (mut reader, mut writer) = socket.into_split();
    let (mut relay_writer, mut relay_reader) = (*relay_socket).split();
    let (activity, mut observed) = watch::channel(tokio::time::Instant::now());
    let received = activity.clone();
    let to_relay = async move {
        let mut bytes = [0; 16_384];
        loop {
            let count = reader.read(&mut bytes).await?;
            // An empty carrier record is an explicit write-half EOF, not a closed WebSocket.
            timeout(
                WRITE_WAIT,
                relay_writer.send(Message::Binary(bytes[..count].to_vec().into())),
            )
            .await??;
            received.send_replace(tokio::time::Instant::now());
            if count == 0 {
                break;
            }
        }
        Ok::<(), carrier::Error>(())
    };
    let from_relay = async move {
        while let Some(frame) = relay_reader.next().await {
            match frame? {
                Message::Binary(data) if data.len() <= carrier::MAX_FRAME => {
                    if data.is_empty() {
                        timeout(WRITE_WAIT, writer.shutdown()).await??;
                        return Ok(());
                    }
                    timeout(WRITE_WAIT, writer.write_all(&data)).await??;
                    activity.send_replace(tokio::time::Instant::now());
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => return Err("relay closed".into()),
            }
        }
        Err::<(), carrier::Error>("relay closed".into())
    };
    let idle = async {
        loop {
            let deadline = *observed.borrow() + IDLE;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                changed = observed.changed() => if changed.is_err() { break; },
            }
        }
    };
    tokio::pin!(to_relay, from_relay, idle);
    let lifetime = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(lifetime);
    let mut outgoing_done = false;
    let mut incoming_done = false;
    while !outgoing_done || !incoming_done {
        tokio::select! {
            result = &mut to_relay, if !outgoing_done => { result?; outgoing_done = true; },
            result = &mut from_relay, if !incoming_done => { result?; incoming_done = true; },
            _ = &mut idle => break,
            _ = &mut lifetime => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod parser_tests {
    use super::*;

    fn vector(bytes: &[u8]) -> Vec<u8> {
        let mut output = (bytes.len() as u16).to_be_bytes().to_vec();
        output.extend_from_slice(bytes);
        output
    }
    fn extension(kind: u16, bytes: &[u8]) -> Vec<u8> {
        let mut output = kind.to_be_bytes().to_vec();
        output.extend(vector(bytes));
        output
    }
    fn body(name: &[u8], versions: &[u8]) -> Vec<u8> {
        let mut server_name = vec![0];
        server_name.extend(vector(name));
        let mut extensions = extension(0, &vector(&server_name));
        extensions.extend(extension(43, versions));
        base(&[], &[0x13, 1], &[0], &extensions)
    }
    fn base(session: &[u8], ciphers: &[u8], compression: &[u8], extensions: &[u8]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(session.len() as u8);
        body.extend(session);
        body.extend(vector(ciphers));
        body.push(compression.len() as u8);
        body.extend(compression);
        body.extend(vector(extensions));
        body
    }
    fn handshake(body: &[u8]) -> Vec<u8> {
        let length = body.len() as u32;
        let mut bytes = vec![1, (length >> 16) as u8, (length >> 8) as u8, length as u8];
        bytes.extend(body);
        bytes
    }
    fn record(bytes: &[u8]) -> Vec<u8> {
        let mut output = vec![22, 3, 1];
        output.extend((bytes.len() as u16).to_be_bytes());
        output.extend(bytes);
        output
    }

    #[test]
    fn truncations_and_invalid_extension_shapes_fail_without_panics() {
        let valid = body(b"example.test", &[4, 3, 4, 3, 3]);
        assert_eq!(server_name(&valid).as_deref(), Some("example.test"));
        for length in 0..valid.len() {
            assert_eq!(server_name(&valid[..length]), None, "truncation {length}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(server_name(&trailing), None);
        for versions in [
            &[][..],
            &[1][..],
            &[1, 3][..],
            &[2, 3, 3][..],
            &[3, 3, 4, 3][..],
        ] {
            assert_eq!(server_name(&body(b"example.test", versions)), None);
        }
        for name in [
            &[][..],
            b"bad name",
            b"bad/name",
            b"bad@name",
            b"bad\0name",
            &[255][..],
        ] {
            assert_eq!(server_name(&body(name, &[2, 3, 4])), None);
        }
        assert_eq!(server_name(&vec![0; MAX_HELLO + 1]), None);
    }
    #[test]
    fn duplicate_sni_or_versions_and_invalid_legacy_fields_are_rejected() {
        let mut names = vec![0];
        names.extend(vector(b"example.test"));
        let sni = extension(0, &vector(&names));
        let versions = extension(43, &[2, 3, 4]);
        for extensions in [
            [sni.clone(), sni.clone(), versions.clone()].concat(),
            [sni.clone(), versions.clone(), versions.clone()].concat(),
        ] {
            assert_eq!(server_name(&base(&[], &[0x13, 1], &[0], &extensions)), None);
        }
        let extensions = [sni, versions].concat();
        for (session, ciphers, compression) in [
            (vec![0; 33], vec![0x13, 1], vec![0]),
            (vec![], vec![], vec![0]),
            (vec![], vec![0x13], vec![0]),
            (vec![], vec![0x13, 1], vec![1]),
        ] {
            assert_eq!(
                server_name(&base(&session, &ciphers, &compression, &extensions)),
                None
            );
        }
        let mut invalid = body(b"example.test", &[2, 3, 4]);
        invalid[1] = 2;
        assert_eq!(server_name(&invalid), None);
        let mut duplicate = names.clone();
        duplicate.extend(names);
        let extensions = [extension(0, &vector(&duplicate)), extension(43, &[2, 3, 4])].concat();
        assert_eq!(server_name(&base(&[], &[0x13, 1], &[0], &extensions)), None);
    }
    #[test]
    fn routing_accepts_only_one_valid_host_label_in_a_valid_suffix() {
        let id = "a".repeat(52);
        assert_eq!(
            route_host(&format!("{id}.example.test"), "example.test"),
            Some(id.clone())
        );
        assert_eq!(
            route_host(
                &format!("{}.EXAMPLE.TEST", id.to_uppercase()),
                "example.test."
            ),
            Some(id.clone())
        );
        for suffix in [
            "",
            ".",
            "example..test",
            "https://example.test",
            "-bad.test",
            "bad-.test",
            "bad test",
            "example.test..",
        ] {
            assert!(!valid_suffix(suffix));
            assert_eq!(route_host(&format!("{id}.{suffix}"), suffix), None);
        }
        for name in [
            format!("{id}.other.test"),
            format!("{id}.extra.example.test"),
            format!("{}.example.test", "a".repeat(53)),
            format!("{}0.example.test", "a".repeat(51)),
        ] {
            assert_eq!(route_host(&name, "example.test"), None);
        }
        for url in [
            "wss://example.test/v1/relay",
            "ws://example.test/v1/relay",
            "ws://127.0.0.1:8787/other",
            "ws://user@127.0.0.1/v1/relay",
            "ws://127.0.0.1/v1/relay?x=1",
        ] {
            assert!(check_internal_url(url).is_err());
        }
        assert!(check_internal_url("ws://127.0.0.1:8787/v1/relay").is_ok());
    }
    #[test]
    fn bounded_random_inputs_never_panic() {
        let mut state = 0x21ac_43da_u64;
        for length in 0..2048 {
            let bytes = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect::<Vec<_>>();
            let _ = server_name(&bytes);
        }
    }
    #[tokio::test]
    async fn record_reassembly_preserves_original_bytes_and_rejects_oversize_early() {
        let hello_bytes = handshake(&body(b"example.test", &[2, 3, 4]));
        let wire = hello_bytes.chunks(9).flat_map(record).collect::<Vec<_>>();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            hello(&mut socket).await.unwrap()
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&wire).await.unwrap();
        let (name, original) = peer.await.unwrap();
        assert_eq!(name, "example.test");
        assert_eq!(original, wire);
        for header in [
            vec![22, 3, 1, 255, 255],
            vec![23, 3, 3, 0, 1],
            vec![22, 3, 2, 0, 1],
            vec![22, 3, 1, 0, 0],
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                timeout(Duration::from_millis(200), hello(&mut socket))
                    .await
                    .unwrap()
                    .is_err()
            });
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(&header).await.unwrap();
            assert!(peer.await.unwrap());
        }
    }
}
