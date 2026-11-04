use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use std::time::Duration;
use tether_relay::{host_id, registration_message, serve, Limits, Relay};
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
struct Harness {
    relay: Relay,
    url: String,
    server: JoinHandle<()>,
}
impl Harness {
    async fn new(mut limits: Limits) -> Self {
        // Tests exercise anonymous development mode explicitly; production defaults deny unknown hosts.
        limits.allowed_hosts = None;
        Self::with_policy(limits).await
    }
    async fn with_policy(limits: Limits) -> Self {
        let relay = Relay::new(limits);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/relay", listener.local_addr().unwrap());
        let running = relay.clone();
        let server = tokio::spawn(async move {
            serve(listener, running).await.unwrap();
        });
        Self { relay, url, server }
    }
    async fn socket(&self) -> Socket {
        connect_async(&self.url).await.unwrap().0
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}
fn key() -> SigningKey {
    let mut seed = [0; 32];
    OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}
async fn send(socket: &mut Socket, value: Value) {
    socket
        .send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}
async fn receive(socket: &mut Socket) -> Value {
    let frame = timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(frame.to_text().unwrap()).unwrap()
}
async fn register(h: &Harness, app: &str, key: &SigningKey) -> Socket {
    let mut socket = h.socket().await;
    send(&mut socket, json!({"type":"host","app_id":app,"public_key":STANDARD.encode(key.verifying_key().as_bytes())})).await;
    let challenge = receive(&mut socket).await;
    let nonce: [u8; 32] = STANDARD
        .decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let id = host_id(app, key.verifying_key().as_bytes());
    let signature = key.sign(&registration_message(app, &id, &nonce));
    send(
        &mut socket,
        json!({"type":"authenticate","signature":STANDARD.encode(signature.to_bytes())}),
    )
    .await;
    socket
}
async fn registered(h: &Harness, app: &str, key: &SigningKey) -> Socket {
    let mut socket = register(h, app, key).await;
    let value = receive(&mut socket).await;
    assert_eq!(value["type"], "registered");
    assert_eq!(
        value["host_id"],
        host_id(app, key.verifying_key().as_bytes())
    );
    socket
}
async fn open(h: &Harness, host: &mut Socket, app: &str, id: &str) -> (Socket, Socket, String) {
    let mut client = h.socket().await;
    send(
        &mut client,
        json!({"type":"client","app_id":app,"host_id":id}),
    )
    .await;
    let value = receive(host).await;
    assert_eq!(value["type"], "open");
    let ticket = value["ticket"].as_str().unwrap().to_string();
    let mut attachment = h.socket().await;
    send(&mut attachment, json!({"type":"attach","ticket":ticket})).await;
    assert_eq!(receive(&mut attachment).await["type"], "ready");
    assert_eq!(receive(&mut client).await["type"], "ready");
    (client, attachment, ticket)
}
async fn closed(socket: &mut Socket) {
    assert!(matches!(
        timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap(),
        None | Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
}
async fn eventually(h: &Harness, expected: (usize, usize, usize)) {
    for _ in 0..50 {
        let count = h.relay.stats();
        if (count.hosts, count.pending_streams, count.active_streams) == expected {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("relay resources retained: {:?}", h.relay.stats());
}

#[tokio::test]
async fn authenticated_registration_and_opaque_bidirectional_bridge() {
    let h = Harness::new(Limits::default()).await;
    let signing = key();
    let id = host_id("example.app", signing.verifying_key().as_bytes());
    assert_eq!(id.len(), 52);
    assert!(id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
    let mut host = registered(&h, "example.app", &signing).await;
    assert_eq!(h.relay.host_app(&id).as_deref(), Some("example.app"));
    let (mut client, mut attachment, ticket) = open(&h, &mut host, "example.app", &id).await;
    let bytes: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    client
        .send(Message::Binary(bytes.clone().into()))
        .await
        .unwrap();
    assert_eq!(attachment.next().await.unwrap().unwrap().into_data(), bytes);
    attachment
        .send(Message::Binary(vec![99, 0, 255].into()))
        .await
        .unwrap();
    assert_eq!(
        client.next().await.unwrap().unwrap().into_data().as_ref(),
        [99, 0, 255]
    );
    let mut replay = h.socket().await;
    send(&mut replay, json!({"type":"attach","ticket":ticket})).await;
    closed(&mut replay).await;
    client.close(None).await.unwrap();
    closed(&mut attachment).await;
    eventually(&h, (1, 0, 0)).await;
    host.close(None).await.unwrap();
    eventually(&h, (0, 0, 0)).await;
}

#[tokio::test]
async fn invalid_signature_and_replayed_registration_proof_are_refused() {
    let h = Harness::new(Limits::default()).await;
    let signing = key();
    let app = "example.app";
    let id = host_id(app, signing.verifying_key().as_bytes());
    let mut first = h.socket().await;
    send(&mut first,json!({"type":"host","app_id":app,"public_key":STANDARD.encode(signing.verifying_key().as_bytes())})).await;
    let challenge = receive(&mut first).await;
    let nonce: [u8; 32] = STANDARD
        .decode(challenge["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let proof = signing.sign(&registration_message(app, &id, &nonce));
    send(
        &mut first,
        json!({"type":"authenticate","signature":STANDARD.encode([0u8;64])}),
    )
    .await;
    closed(&mut first).await;
    let mut replay = h.socket().await;
    send(&mut replay,json!({"type":"host","app_id":app,"public_key":STANDARD.encode(signing.verifying_key().as_bytes())})).await;
    let _ = receive(&mut replay).await;
    send(
        &mut replay,
        json!({"type":"authenticate","signature":STANDARD.encode(proof.to_bytes())}),
    )
    .await;
    closed(&mut replay).await;
    eventually(&h, (0, 0, 0)).await;
}

#[tokio::test]
async fn duplicate_host_cannot_replace_active_registration() {
    let h = Harness::new(Limits::default()).await;
    let signing = key();
    let app = "example.app";
    let mut host = registered(&h, app, &signing).await;
    let mut duplicate = register(&h, app, &signing).await;
    closed(&mut duplicate).await;
    let id = host_id(app, signing.verifying_key().as_bytes());
    let (mut client, mut attached, _) = open(&h, &mut host, app, &id).await;
    client.send(Message::Binary(vec![1].into())).await.unwrap();
    assert_eq!(
        attached.next().await.unwrap().unwrap().into_data().as_ref(),
        [1]
    );
    host.close(None).await.unwrap();
    closed(&mut client).await;
    closed(&mut attached).await;
    eventually(&h, (0, 0, 0)).await;
}

#[tokio::test]
async fn client_app_scope_cannot_reach_another_application() {
    let h = Harness::new(Limits::default()).await;
    let signing = key();
    let _host = registered(&h, "app.a", &signing).await;
    let mut client = h.socket().await;
    send(&mut client,json!({"type":"client","app_id":"app.b","host_id":host_id("app.a",signing.verifying_key().as_bytes())})).await;
    closed(&mut client).await;
    eventually(&h, (1, 0, 0)).await;
}

#[tokio::test]
async fn pending_and_active_stream_limits_release_after_timeouts() {
    let limits = Limits {
        max_streams_per_host: 1,
        attach_timeout: Duration::from_millis(80),
        stream_idle_timeout: Duration::from_millis(80),
        ..Limits::default()
    };
    let h = Harness::new(limits).await;
    let signing = key();
    let app = "example.app";
    let id = host_id(app, signing.verifying_key().as_bytes());
    let mut host = registered(&h, app, &signing).await;
    let mut pending = h.socket().await;
    send(
        &mut pending,
        json!({"type":"client","app_id":app,"host_id":id}),
    )
    .await;
    let abandoned = receive(&mut host).await;
    let mut refused = h.socket().await;
    send(
        &mut refused,
        json!({"type":"client","app_id":app,"host_id":id}),
    )
    .await;
    closed(&mut refused).await;
    closed(&mut pending).await;
    eventually(&h, (1, 0, 0)).await;
    let mut stale = h.socket().await;
    send(
        &mut stale,
        json!({"type":"attach","ticket":abandoned["ticket"]}),
    )
    .await;
    closed(&mut stale).await;
    let (mut client, mut attached, _) = open(&h, &mut host, app, &id).await;
    for _ in 0..3 {
        sleep(Duration::from_millis(15)).await;
        client.send(Message::Ping(vec![1].into())).await.unwrap();
    }
    // Pings are protocol liveness, not application traffic, and do not extend the stream idle budget.
    loop {
        match timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap()
        {
            Some(Ok(Message::Pong(_))) => {}
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
            _ => panic!("unexpected frame"),
        }
    }
    closed(&mut attached).await;
    eventually(&h, (1, 0, 0)).await;
}

#[tokio::test]
async fn connection_and_per_ip_admission_limits_are_enforced_before_upgrade() {
    let limits = Limits {
        max_connections: 1,
        handshake_timeout: Duration::from_millis(80),
        ..Limits::default()
    };
    let h = Harness::new(limits).await;
    let mut held = h.socket().await;
    assert!(connect_async(&h.url).await.is_err());
    closed(&mut held).await;
    sleep(Duration::from_millis(20)).await;
    assert!(connect_async(&h.url).await.is_ok());
    let limits = Limits {
        attempts_per_minute: 1,
        ..Limits::default()
    };
    let h = Harness::new(limits).await;
    let mut first = h.socket().await;
    first.close(None).await.unwrap();
    assert!(connect_async(&h.url).await.is_err());
}

#[tokio::test]
async fn oversized_metadata_and_non_binary_streams_close_without_forwarding() {
    let h = Harness::new(Limits::default()).await;
    let mut socket = h.socket().await;
    send(
        &mut socket,
        json!({"type":"attach","ticket":"a".repeat(3000)}),
    )
    .await;
    closed(&mut socket).await;
    let signing = key();
    let mut host = registered(&h, "example.app", &signing).await;
    let id = host_id("example.app", signing.verifying_key().as_bytes());
    let (mut client, mut attached, _) = open(&h, &mut host, "example.app", &id).await;
    client
        .send(Message::Text("do not forward plaintext".into()))
        .await
        .unwrap();
    closed(&mut attached).await;
    closed(&mut client).await;
    eventually(&h, (1, 0, 0)).await;
}

#[tokio::test]
async fn default_policy_denies_unknown_hosts_and_allowlist_accepts_only_selected_routes() {
    let denied = Harness::with_policy(Limits::default()).await;
    let signing = key();
    let mut socket = denied.socket().await;
    send(&mut socket, json!({"type":"host", "app_id":"example.app", "public_key":STANDARD.encode(signing.verifying_key().as_bytes())})).await;
    closed(&mut socket).await;
    eventually(&denied, (0, 0, 0)).await;
    let id = host_id("example.app", signing.verifying_key().as_bytes());
    let limits = Limits {
        allowed_hosts: Some(std::collections::HashSet::from([id])),
        ..Limits::default()
    };
    let allowed = Harness::with_policy(limits).await;
    let _host = registered(&allowed, "example.app", &signing).await;
    let mut scoped = allowed.socket().await;
    send(&mut scoped, json!({"type":"host", "app_id":"another.app", "public_key":STANDARD.encode(signing.verifying_key().as_bytes())})).await;
    closed(&mut scoped).await;
    eventually(&allowed, (1, 0, 0)).await;
}

#[tokio::test]
async fn host_liveness_and_global_host_limit_recover_without_replacing_identity() {
    let limits = Limits {
        max_hosts: 1,
        host_ping_interval: Duration::from_millis(20),
        host_idle_timeout: Duration::from_millis(60),
        ..Limits::default()
    };
    let h = Harness::new(limits).await;
    let first_key = key();
    let _first = registered(&h, "app.a", &first_key).await;
    let mut second = register(&h, "app.b", &key()).await;
    closed(&mut second).await;
    // A disconnected/non-reading host cannot retain its registration indefinitely.
    sleep(Duration::from_millis(100)).await;
    eventually(&h, (0, 0, 0)).await;
    let _replacement = registered(&h, "app.a", &first_key).await;
    eventually(&h, (1, 0, 0)).await;
}

#[tokio::test]
async fn established_bridges_retain_both_connection_permits_until_closed() {
    let limits = Limits {
        max_connections: 3,
        ..Limits::default()
    };
    let h = Harness::new(limits).await;
    let signing = key();
    let app = "example.app";
    let mut host = registered(&h, app, &signing).await;
    let id = host_id(app, signing.verifying_key().as_bytes());
    let (mut client, mut attachment, _) = open(&h, &mut host, app, &id).await;
    assert_eq!(h.relay.stats().connections, 3);
    assert!(
        connect_async(&h.url).await.is_err(),
        "an active bridge must not refund its connection permits"
    );
    client
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(
        attachment
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .as_ref(),
        [1, 2, 3]
    );
    client.close(None).await.unwrap();
    closed(&mut attachment).await;
    eventually(&h, (1, 0, 0)).await;
    assert_eq!(h.relay.stats().connections, 1);
    let mut accepted = h.socket().await;
    accepted.close(None).await.unwrap();
}
