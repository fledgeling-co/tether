use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
pub const MAX_FRAME: usize = 65_536;
pub const WAIT: Duration = Duration::from_secs(15);

/// Caller-owned I/O. A carrier conveys ciphertext; it grants no service authorization.
pub enum Carrier {
    Direct(TcpStream),
    Relay(Box<Socket>),
}
pub enum Reader {
    Direct(OwnedReadHalf),
    Relay(SplitStream<Socket>),
}
pub enum Writer {
    Direct(OwnedWriteHalf),
    Relay(SplitSink<Socket, Message>),
}
impl Carrier {
    pub fn split(self) -> (Reader, Writer) {
        match self {
            Self::Direct(socket) => {
                let (reader, writer) = socket.into_split();
                (Reader::Direct(reader), Writer::Direct(writer))
            }
            Self::Relay(socket) => {
                let (writer, reader) = (*socket).split();
                (Reader::Relay(reader), Writer::Relay(writer))
            }
        }
    }
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FRAME {
            return Err("frame exceeds limit".into());
        }
        timeout(WAIT, async {
            match self {
                Self::Direct(socket) => {
                    socket.write_u32(bytes.len() as u32).await?;
                    socket.write_all(bytes).await?;
                }
                Self::Relay(socket) => socket.send(Message::Binary(bytes.to_vec().into())).await?,
            }
            Ok::<(), Error>(())
        })
        .await??;
        Ok(())
    }
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        timeout(Duration::from_secs(60), async {
            match self {
                Self::Direct(socket) => {
                    let length = socket.read_u32().await? as usize;
                    if length > MAX_FRAME {
                        return Err("frame exceeds limit".into());
                    }
                    let mut bytes = vec![0; length];
                    socket.read_exact(&mut bytes).await?;
                    Ok(bytes)
                }
                Self::Relay(socket) => loop {
                    match socket.next().await.ok_or("carrier closed")?? {
                        Message::Binary(bytes) if bytes.len() <= MAX_FRAME => {
                            return Ok(bytes.to_vec())
                        }
                        Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
                        _ => return Err("unexpected carrier frame".into()),
                    }
                },
            }
        })
        .await?
    }
}
impl Reader {
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        // The stream pump owns a bidirectional idle deadline. A one-direction read timeout would
        // incorrectly terminate a healthy sustained upload whose peer has nothing to send yet.
        match self {
            Self::Direct(socket) => {
                let length = socket.read_u32().await? as usize;
                if length > MAX_FRAME {
                    return Err("frame exceeds limit".into());
                }
                let mut bytes = vec![0; length];
                socket.read_exact(&mut bytes).await?;
                Ok(bytes)
            }
            Self::Relay(socket) => loop {
                match socket.next().await.ok_or("carrier closed")?? {
                    Message::Binary(bytes) if bytes.len() <= MAX_FRAME => return Ok(bytes.to_vec()),
                    Message::Ping(_) | Message::Pong(_) => continue,
                    _ => return Err("unexpected carrier frame".into()),
                }
            },
        }
    }
}
impl Writer {
    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FRAME {
            return Err("frame exceeds limit".into());
        }
        timeout(WAIT, async {
            match self {
                Self::Direct(socket) => {
                    socket.write_u32(bytes.len() as u32).await?;
                    socket.write_all(bytes).await?;
                }
                Self::Relay(socket) => socket.send(Message::Binary(bytes.to_vec().into())).await?,
            }
            Ok::<(), Error>(())
        })
        .await??;
        Ok(())
    }
    pub async fn close(&mut self) {
        let _ = timeout(Duration::from_secs(1), async {
            match self {
                Self::Direct(socket) => socket.shutdown().await.map_err(Into::into),
                Self::Relay(socket) => socket.close().await.map_err(|e| -> Error { e.into() }),
            }
        })
        .await;
    }
}

pub fn check_relay_url(url: &str, allow_loopback: bool) -> Result<()> {
    let parsed = url::Url::parse(url)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.query().is_some()
    {
        return Err("relay URL must not carry credentials or fragments".into());
    }
    if parsed.scheme() == "wss" && parsed.host_str().is_some() {
        return Ok(());
    }
    let loopback = parsed
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    if allow_loopback && parsed.scheme() == "ws" && loopback {
        return Ok(());
    }
    Err("relay requires wss://; plaintext is restricted to explicit loopback development".into())
}

pub async fn open(url: &str, hello: Value, allow_loopback: bool) -> Result<Socket> {
    check_relay_url(url, allow_loopback)?;
    let configuration = WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME))
        .max_frame_size(Some(MAX_FRAME));
    let (mut socket, _) = timeout(
        WAIT,
        connect_async_with_config(url, Some(configuration), false),
    )
    .await??;
    send_json(&mut socket, hello).await?;
    Ok(socket)
}
pub async fn send_json(socket: &mut Socket, value: Value) -> Result<()> {
    let bytes = value.to_string();
    if bytes.len() > 2048 {
        return Err("metadata exceeds limit".into());
    }
    timeout(WAIT, socket.send(Message::Text(bytes.into()))).await??;
    Ok(())
}
pub async fn receive_json(socket: &mut Socket) -> Result<Value> {
    timeout(WAIT, async {
        loop {
            match socket.next().await.ok_or("relay closed")?? {
                Message::Text(bytes) if bytes.len() <= 2048 => {
                    return Ok(serde_json::from_str(&bytes)?)
                }
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
                Message::Pong(_) => continue,
                _ => return Err("unexpected relay metadata".into()),
            }
        }
    })
    .await?
}
pub async fn receive_control(socket: &mut Socket) -> Result<Value> {
    loop {
        match timeout(Duration::from_secs(60), socket.next())
            .await?
            .ok_or("relay closed")??
        {
            Message::Text(bytes) if bytes.len() <= 2048 => {
                return Ok(serde_json::from_str(&bytes)?)
            }
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await?,
            Message::Pong(_) => continue,
            _ => return Err("unexpected relay metadata".into()),
        }
    }
}
pub async fn relay_client(url: &str, app: &str, host_id: &str, dev: bool) -> Result<Carrier> {
    crate::storage::app_id(app)?;
    if host_id.len() != 52
        || !host_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
    {
        return Err("invalid public route".into());
    }
    let mut socket = open(
        url,
        json!({"type":"client","app_id":app,"host_id":host_id}),
        dev,
    )
    .await?;
    if receive_json(&mut socket).await?["type"] != "ready" {
        return Err("host unavailable".into());
    }
    Ok(Carrier::Relay(Box::new(socket)))
}
pub async fn relay_attach(url: &str, ticket: &str, dev: bool) -> Result<Carrier> {
    let mut socket = open(url, json!({"type":"attach","ticket":ticket}), dev).await?;
    if receive_json(&mut socket).await?["type"] != "ready" {
        return Err("stream unavailable".into());
    }
    Ok(Carrier::Relay(Box::new(socket)))
}
pub async fn register(
    url: &str,
    app: &str,
    signing_key: &SigningKey,
    dev: bool,
) -> Result<(Socket, String)> {
    let public = signing_key.verifying_key().to_bytes();
    let mut socket = open(
        url,
        json!({"type":"host","app_id":app,"public_key":STANDARD.encode(public)}),
        dev,
    )
    .await?;
    let challenge = receive_json(&mut socket).await?;
    let nonce = STANDARD.decode(challenge["nonce"].as_str().ok_or("missing challenge")?)?;
    if challenge["type"] != "challenge" || nonce.len() != 32 {
        return Err("invalid challenge".into());
    }
    let id = host_id(app, &public);
    let mut signed = b"tether-relay-v1\0".to_vec();
    signed.extend_from_slice(app.as_bytes());
    signed.push(0);
    signed.extend_from_slice(id.as_bytes());
    signed.push(0);
    signed.extend_from_slice(&nonce);
    send_json(&mut socket, json!({"type":"authenticate","signature":STANDARD.encode(signing_key.sign(&signed).to_bytes())})).await?;
    let reply = receive_json(&mut socket).await?;
    if reply["type"] != "registered" || reply["host_id"] != id {
        return Err("registration refused".into());
    }
    Ok((socket, id))
}

pub fn host_id(app: &str, public: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update((app.len() as u32).to_be_bytes());
    hash.update(app.as_bytes());
    hash.update(public);
    let bytes = hash.finalize();
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::new();
    let mut bits: u32 = 0;
    let mut count: u32 = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        count += 8;
        while count >= 5 {
            count -= 5;
            output.push(ALPHABET[((bits >> count) & 31) as usize] as char);
        }
    }
    if count > 0 {
        output.push(ALPHABET[((bits << (5 - count)) & 31) as usize] as char);
    }
    output
}
