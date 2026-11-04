use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::{rngs::OsRng, RngCore};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tether::carrier::{self, Carrier};
use tether_relay::{host_id, Limits, Relay};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;

type Capture = Arc<Mutex<Vec<Vec<u8>>>>;
struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}
async fn forward(carrier: carrier::Socket, target: std::net::SocketAddr, captured: Capture) {
    let Ok(tcp) = TcpStream::connect(target).await else {
        return;
    };
    let (mut target_in, mut target_out) = tcp.into_split();
    let (mut sink, mut source) = carrier.split();
    let inbound = async {
        while let Some(Ok(message)) = source.next().await {
            match message {
                Message::Binary(bytes) => {
                    captured.lock().unwrap().push(bytes.to_vec());
                    if bytes.is_empty() {
                        target_out.shutdown().await?;
                        return Ok::<(), carrier::Error>(());
                    }
                    target_out.write_all(&bytes).await?;
                }
                Message::Ping(_) | Message::Pong(_) => {}
                _ => return Err("carrier closed".into()),
            }
        }
        Err::<(), carrier::Error>("carrier closed".into())
    };
    let outbound = async {
        let mut bytes = [0; 16384];
        loop {
            let count = target_in.read(&mut bytes).await?;
            sink.send(Message::Binary(bytes[..count].to_vec().into()))
                .await?;
            if count == 0 {
                break;
            }
        }
        Ok::<(), carrier::Error>(())
    };
    tokio::pin!(inbound, outbound);
    let (mut input_done, mut output_done) = (false, false);
    while !input_done || !output_done {
        tokio::select! {
            result=&mut inbound,if !input_done=>{if result.is_err(){break};input_done=true;},
            result=&mut outbound,if !output_done=>{if result.is_err(){break};output_done=true;},
        }
    }
}

#[tokio::test]
async fn tls13_identity_ciphertext_and_delayed_response_survive_client_tcp_half_close() {
    let app = "example.tls";
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let id = host_id(app, signing.verifying_key().as_bytes());
    let name = format!("{id}.example.test");
    let certified = rcgen::generate_simple_self_signed(vec![name.clone()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let observed = accepts.clone();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut tasks = Tasks(Vec::new());
    tasks.0.push(tokio::spawn(async move {
        loop {
            let (socket, _) = origin.accept().await.unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(socket).await {
                    assert_eq!(
                        tls.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_3)
                    );
                    let mut bytes = [0; 1024];
                    if let Ok(count) = tls.read(&mut bytes).await {
                        sleep(Duration::from_millis(100)).await;
                        let _ = tls.write_all(&bytes[..count]).await;
                    }
                }
            });
        }
    }));
    let limits = Limits {
        allowed_hosts: Some(HashSet::from([id.clone()])),
        ..Limits::default()
    };
    let relay = Relay::new(limits);
    let web = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/v1/relay", web.local_addr().unwrap());
    let running = relay.clone();
    tasks.0.push(tokio::spawn(async move {
        tether_relay::serve(web, running).await.unwrap();
    }));
    let (mut control, registered) = carrier::register(&relay_url, app, &signing, true)
        .await
        .unwrap();
    assert_eq!(registered, id);
    let captures: Capture = Arc::new(Mutex::new(Vec::new()));
    let captured = captures.clone();
    let host_url = relay_url.clone();
    tasks.0.push(tokio::spawn(async move {
        while let Ok(open) = carrier::receive_json(&mut control).await {
            if open["type"] != "open" {
                break;
            };
            let ticket = open["ticket"].as_str().unwrap().to_string();
            let url = host_url.clone();
            let captured = captured.clone();
            tokio::spawn(async move {
                if let Ok(Carrier::Relay(socket)) = carrier::relay_attach(&url, &ticket, true).await
                {
                    forward(*socket, origin_address, captured).await;
                }
            });
        }
    }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_address = listener.local_addr().unwrap();
    let (shutdown, done) = oneshot::channel();
    let running = relay.clone();
    tasks.0.push(tokio::spawn(async move {
        tether_ingress::serve_with_shutdown(
            listener,
            running,
            relay_url,
            "example.test".into(),
            async {
                let _ = done.await;
            },
        )
        .await
        .unwrap();
    }));
    let mut roots = RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(ingress_address).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from(name).unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(tls.get_ref().1.peer_certificates().unwrap()[0], certificate);
    let secret = b"TETHER_APPLICATION_PLAINTEXT_MUST_NEVER_REACH_THE_RELAY_7fc2dc".repeat(8);
    tls.write_all(&secret).await.unwrap();
    // Close only the raw TCP write half. The origin deliberately responds later.
    tls.get_mut().0.shutdown().await.unwrap();
    let mut echoed = vec![0; secret.len()];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, secret);
    let wire = captures.lock().unwrap().concat();
    assert!(!wire.windows(secret.len()).any(|bytes| bytes == secret));
    assert!(wire.starts_with(&[22, 3]));
    drop(tls);
    let before = accepts.load(Ordering::SeqCst);
    let mut plain = TcpStream::connect(ingress_address).await.unwrap();
    plain
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0];
    assert!(matches!(
        timeout(Duration::from_secs(1), plain.read(&mut byte))
            .await
            .unwrap(),
        Ok(0) | Err(_)
    ));
    let tcp = TcpStream::connect(ingress_address).await.unwrap();
    let unknown = format!("{}.example.test", "a".repeat(52));
    assert!(connector
        .connect(ServerName::try_from(unknown).unwrap(), tcp)
        .await
        .is_err());
    let old = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let old_connector = TlsConnector::from(Arc::new(old));
    let tcp = TcpStream::connect(ingress_address).await.unwrap();
    assert!(old_connector
        .connect(
            ServerName::try_from(format!("{id}.example.test")).unwrap(),
            tcp
        )
        .await
        .is_err());
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        before,
        "invalid ingress requests must not reach the origin"
    );
    shutdown.send(()).unwrap();
    sleep(Duration::from_millis(20)).await;
    assert!(TcpStream::connect(ingress_address).await.is_err());
}
