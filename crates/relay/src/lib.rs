//! An opaque, bounded relay. It authorizes ownership of public host routes, never application access.
//! Peer authentication and service authorization belong to the encrypted endpoint protocol.

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{hash_map::RandomState, HashMap, HashSet},
    hash::BuildHasher,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
use tokio::time::{sleep, timeout};

const METADATA_LIMIT: usize = 2048;
const WIRE_LIMIT: usize = 65536;

#[derive(Clone, Debug)]
pub struct Limits {
    /// None is explicit open registration; the default empty allowlist denies every host.
    pub allowed_hosts: Option<HashSet<String>>,
    pub max_hosts: usize,
    pub max_streams: usize,
    pub max_streams_per_host: usize,
    pub max_connections: usize,
    pub attempts_per_minute: usize,
    pub max_rate_buckets: usize,
    pub handshake_timeout: Duration,
    pub host_ping_interval: Duration,
    pub host_idle_timeout: Duration,
    pub attach_timeout: Duration,
    pub write_timeout: Duration,
    pub stream_idle_timeout: Duration,
    pub stream_lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            allowed_hosts: Some(HashSet::new()),
            max_hosts: 64,
            max_streams: 64,
            // Opaque carriers include control exchanges; the host separately caps data at eight.
            max_streams_per_host: 24,
            max_connections: 128,
            attempts_per_minute: 256,
            max_rate_buckets: 1024,
            handshake_timeout: Duration::from_secs(5),
            host_ping_interval: Duration::from_secs(15),
            host_idle_timeout: Duration::from_secs(45),
            attach_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(5),
            stream_idle_timeout: Duration::from_secs(60),
            stream_lifetime: Duration::from_secs(3600),
        }
    }
}

#[derive(Clone)]
pub struct Relay(Arc<Shared>);
struct Shared {
    limits: Limits,
    inner: Mutex<Inner>,
    connections: Arc<Semaphore>,
    streams: Arc<Semaphore>,
}
struct Inner {
    hosts: HashMap<(String, String), Host>,
    pending: HashMap<String, Pending>,
    rates: AdmissionFilter,
}
#[derive(Clone)]
struct Host {
    generation: [u8; 16],
    commands: mpsc::Sender<String>,
    cancelled: watch::Sender<bool>,
    streams: Arc<Semaphore>,
}
struct Pending {
    host: (String, String),
    generation: [u8; 16],
    attachment: oneshot::Sender<Connected>,
}
#[derive(Clone, Copy)]
struct Bucket {
    started: Instant,
    count: usize,
}
/// A fixed-memory Count-Min filter: collisions can only make admission stricter.
/// Four independently keyed hash rows avoid a registry of caller IP addresses and a full-table cliff.
struct AdmissionFilter {
    rows: [Vec<Bucket>; 4],
    hashes: [RandomState; 4],
}
impl AdmissionFilter {
    fn new(width: usize) -> Self {
        let width = width.min(16_384);
        let empty = Bucket {
            started: Instant::now(),
            count: 0,
        };
        Self {
            rows: std::array::from_fn(|_| vec![empty; width]),
            hashes: std::array::from_fn(|_| RandomState::new()),
        }
    }
    fn admit(&mut self, address: IpAddr, now: Instant, limit: usize) -> bool {
        if self.rows[0].is_empty() || limit == 0 {
            return false;
        }
        let mut selected = [0; 4];
        let mut minimum = usize::MAX;
        for (row, index) in selected.iter_mut().enumerate() {
            *index = self.hashes[row].hash_one(address) as usize % self.rows[row].len();
            let bucket = &mut self.rows[row][*index];
            if now.duration_since(bucket.started) >= Duration::from_secs(60) {
                bucket.started = now;
                bucket.count = 0;
            }
            minimum = minimum.min(bucket.count);
        }
        if minimum >= limit {
            return false;
        }
        for (row, index) in selected.into_iter().enumerate() {
            self.rows[row][index].count = self.rows[row][index].count.saturating_add(1);
        }
        true
    }
}
struct Connected {
    socket: WebSocket,
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    pub hosts: usize,
    pub pending_streams: usize,
    pub active_streams: usize,
    pub connections: usize,
}

impl Relay {
    pub fn new(limits: Limits) -> Self {
        let rate_width = limits.max_rate_buckets;
        Self(Arc::new(Shared {
            connections: Arc::new(Semaphore::new(limits.max_connections)),
            streams: Arc::new(Semaphore::new(limits.max_streams)),
            limits,
            inner: Mutex::new(Inner {
                hosts: HashMap::new(),
                pending: HashMap::new(),
                rates: AdmissionFilter::new(rate_width),
            }),
        }))
    }
    pub fn router(&self) -> Router {
        Router::new()
            .route("/healthz", get(|| async { "ok\n" }))
            .route("/v1/relay", get(upgrade))
            .with_state(self.clone())
    }
    pub fn host_app(&self, id: &str) -> Option<String> {
        self.lock()
            .hosts
            .keys()
            .find(|(_, host)| host == id)
            .map(|(app, _)| app.clone())
    }
    pub fn stats(&self) -> RelayStats {
        let inner = self.lock();
        RelayStats {
            hosts: inner.hosts.len(),
            pending_streams: inner.pending.len(),
            active_streams: self.0.limits.max_streams - self.0.streams.available_permits(),
            connections: self.0.limits.max_connections - self.0.connections.available_permits(),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn admit(&self, address: IpAddr) -> bool {
        self.lock()
            .rates
            .admit(address, Instant::now(), self.0.limits.attempts_per_minute)
    }
}

pub async fn serve(listener: tokio::net::TcpListener, relay: Relay) -> std::io::Result<()> {
    axum::serve(
        listener,
        relay
            .router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// The application ID is length-prefixed with its UTF-8 byte length as an unsigned u32, big-endian.
/// Host IDs identify public routes and are not pairing secrets.
pub fn host_id(app_id: &str, public_key: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update((app_id.len() as u32).to_be_bytes());
    hash.update(app_id.as_bytes());
    hash.update(public_key);
    data_encoding::BASE32_NOPAD
        .encode(&hash.finalize())
        .to_ascii_lowercase()
}

pub fn registration_message(app_id: &str, id: &str, nonce: &[u8; 32]) -> Vec<u8> {
    let mut bytes = b"tether-relay-v1\0".to_vec();
    bytes.extend_from_slice(app_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(nonce);
    bytes
}

async fn upgrade(
    State(relay): State<Relay>,
    ConnectInfo(address): ConnectInfo<SocketAddr>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    if !relay.admit(address.ip()) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let Ok(permit) = relay.0.connections.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(WIRE_LIMIT)
        .max_frame_size(WIRE_LIMIT)
        .on_upgrade(move |socket| {
            handle(
                Connected {
                    socket,
                    _permit: permit,
                },
                relay,
            )
        })
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Hello {
    #[serde(rename = "host")]
    Host { app_id: String, public_key: String },
    #[serde(rename = "client")]
    Client { app_id: String, host_id: String },
    #[serde(rename = "attach")]
    Attach { ticket: String },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authentication {
    #[serde(rename = "type")]
    kind: String,
    signature: String,
}

async fn handle(mut connected: Connected, relay: Relay) {
    let Some(hello) =
        metadata::<Hello>(&mut connected.socket, relay.0.limits.handshake_timeout).await
    else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    match hello {
        Hello::Host { app_id, public_key } if valid_app(&app_id) => {
            host(connected, relay, app_id, public_key).await
        }
        Hello::Client { app_id, host_id } if valid_app(&app_id) && valid_host(&host_id) => {
            client(connected, relay, app_id, host_id).await
        }
        Hello::Attach { ticket }
            if ticket.len() == 32
                && ticket
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
        {
            let pending = relay.lock().pending.remove(&ticket);
            if let Some(pending) = pending {
                // Sending consumes the one-use ticket even if the waiting client has already left.
                if let Err(mut returned) = pending.attachment.send(connected) {
                    refuse(&mut returned.socket, relay.0.limits.write_timeout).await;
                }
            } else {
                refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
            }
        }
        _ => refuse(&mut connected.socket, relay.0.limits.write_timeout).await,
    }
}

async fn host(mut connected: Connected, relay: Relay, app: String, encoded_key: String) {
    let Some(bytes) = canonical::<32>(&encoded_key) else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    let Ok(key) = VerifyingKey::from_bytes(&bytes) else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    let id = host_id(&app, &bytes);
    if relay
        .0
        .limits
        .allowed_hosts
        .as_ref()
        .is_some_and(|allowed| !allowed.contains(&id))
    {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    }
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    if !send_json(
        &mut connected.socket,
        serde_json::json!({"type":"challenge","nonce":STANDARD.encode(nonce)}),
        relay.0.limits.write_timeout,
    )
    .await
    {
        return;
    }
    let Some(auth) =
        metadata::<Authentication>(&mut connected.socket, relay.0.limits.handshake_timeout).await
    else {
        return;
    };
    let signature = canonical::<64>(&auth.signature).map(|value| Signature::from_bytes(&value));
    if auth.kind != "authenticate"
        || signature.as_ref().is_none_or(|sig| {
            key.verify_strict(&registration_message(&app, &id, &nonce), sig)
                .is_err()
        })
    {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    }
    let host_key = (app, id.clone());
    let mut generation = [0; 16];
    OsRng.fill_bytes(&mut generation);
    let (commands, mut receiver) = mpsc::channel(8);
    let (cancelled, _) = watch::channel(false);
    let inserted = {
        let mut inner = relay.lock();
        if inner.hosts.contains_key(&host_key) || inner.hosts.len() >= relay.0.limits.max_hosts {
            false
        } else {
            inner.hosts.insert(
                host_key.clone(),
                Host {
                    generation,
                    commands,
                    cancelled,
                    streams: Arc::new(Semaphore::new(relay.0.limits.max_streams_per_host)),
                },
            );
            true
        }
    };
    if !inserted {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    }
    let _guard = HostGuard {
        relay: relay.clone(),
        key: host_key,
        generation,
    };
    if !send_json(
        &mut connected.socket,
        serde_json::json!({"type":"registered","host_id":id}),
        relay.0.limits.write_timeout,
    )
    .await
    {
        return;
    }
    let interval = relay
        .0
        .limits
        .host_ping_interval
        .max(Duration::from_millis(1));
    let mut probe = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    let mut last_received = Instant::now();
    loop {
        tokio::select! {
            _ = probe.tick() => {
                if last_received.elapsed() >= relay.0.limits.host_idle_timeout { break; }
                if !matches!(timeout(relay.0.limits.write_timeout,
                    connected.socket.send(Message::Ping(Vec::new().into()))).await, Ok(Ok(()))) { break; }
            },
            value = receiver.recv() => match value {
                Some(value) => if !matches!(timeout(relay.0.limits.write_timeout, connected.socket.send(Message::Text(value.into()))).await, Ok(Ok(()))) { break; },
                None => break,
            },
            incoming = connected.socket.recv() => match incoming {
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => { last_received = Instant::now(); },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => break,
            },
        }
    }
}

struct HostGuard {
    relay: Relay,
    key: (String, String),
    generation: [u8; 16],
}
impl Drop for HostGuard {
    fn drop(&mut self) {
        let mut inner = self.relay.lock();
        if inner
            .hosts
            .get(&self.key)
            .is_some_and(|h| h.generation == self.generation)
        {
            if let Some(host) = inner.hosts.remove(&self.key) {
                host.cancelled.send_replace(true);
            }
            inner
                .pending
                .retain(|_, p| p.host != self.key || p.generation != self.generation);
        }
    }
}

async fn client(mut connected: Connected, relay: Relay, app: String, id: String) {
    let key = (app, id);
    let observed_host = { relay.lock().hosts.get(&key).cloned() };
    let Some(host) = observed_host else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    let Ok(_global) = relay.0.streams.clone().try_acquire_owned() else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    let Ok(_local) = host.streams.clone().try_acquire_owned() else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    let mut cancelled = host.cancelled.subscribe();
    let mut ticket_bytes = [0; 16];
    OsRng.fill_bytes(&mut ticket_bytes);
    let ticket = hex::encode(ticket_bytes);
    let mut session_bytes = [0; 16];
    OsRng.fill_bytes(&mut session_bytes);
    let session = hex::encode(session_bytes);
    let (sender, receiver) = oneshot::channel();
    {
        let mut inner = relay.lock();
        // Do not insert a new pending stream after a concurrent host disconnect.
        if inner
            .hosts
            .get(&key)
            .is_none_or(|h| h.generation != host.generation)
        {
            return;
        }
        inner.pending.insert(
            ticket.clone(),
            Pending {
                host: key.clone(),
                generation: host.generation,
                attachment: sender,
            },
        );
    }
    let pending_guard = PendingGuard {
        relay: relay.clone(),
        ticket: ticket.clone(),
    };
    let open = serde_json::json!({"type":"open","session_id":session,"ticket":ticket}).to_string();
    if host.commands.try_send(open).is_err() {
        return;
    }
    let attachment = tokio::select! {
        value = timeout(relay.0.limits.attach_timeout, receiver) => value.ok().and_then(Result::ok),
        _ = cancelled.changed() => None,
    };
    drop(pending_guard);
    let Some(mut attachment) = attachment else {
        refuse(&mut connected.socket, relay.0.limits.write_timeout).await;
        return;
    };
    if *cancelled.borrow() {
        return;
    }
    let ready = serde_json::json!({"type":"ready"});
    if !send_json(
        &mut attachment.socket,
        ready.clone(),
        relay.0.limits.write_timeout,
    )
    .await
        || !send_json(&mut connected.socket, ready, relay.0.limits.write_timeout).await
    {
        return;
    }
    // Keep both connection permits explicit across the bridge await. Partial field moves do not
    // release the remaining fields early, but named ownership makes this invariant reviewable.
    let connection_permits = (connected._permit, attachment._permit);
    bridge(
        connected.socket,
        attachment.socket,
        &relay.0.limits,
        cancelled,
    )
    .await;
    drop(connection_permits);
}
struct PendingGuard {
    relay: Relay,
    ticket: String,
}
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.relay.lock().pending.remove(&self.ticket);
    }
}

async fn bridge(a: WebSocket, b: WebSocket, limits: &Limits, mut cancelled: watch::Receiver<bool>) {
    let (a_out, a_in) = a.split();
    let (b_out, b_in) = b.split();
    let (activity, mut observed) = watch::channel(Instant::now());
    let forward_a = forward(a_in, b_out, activity.clone(), limits.write_timeout);
    let forward_b = forward(b_in, a_out, activity, limits.write_timeout);
    let idle = async {
        loop {
            let deadline = *observed.borrow() + limits.stream_idle_timeout;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline.into()) => break,
                changed = observed.changed() => if changed.is_err() { break; },
            }
        }
    };
    tokio::select! {
        _ = forward_a => {}, _ = forward_b => {}, _ = idle => {},
        _ = sleep(limits.stream_lifetime) => {}, _ = cancelled.changed() => {},
    }
    // Both split halves are dropped together, so neither peer retains a half-open forwarding path.
}
async fn forward(
    mut input: futures_util::stream::SplitStream<WebSocket>,
    mut output: futures_util::stream::SplitSink<WebSocket, Message>,
    activity: watch::Sender<Instant>,
    write_timeout: Duration,
) {
    while let Some(Ok(message)) = input.next().await {
        match message {
            Message::Binary(bytes) if bytes.len() <= WIRE_LIMIT => {
                activity.send_replace(Instant::now());
                if !matches!(
                    timeout(write_timeout, output.send(Message::Binary(bytes))).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => break,
        }
    }
}

fn valid_app(app: &str) -> bool {
    !app.is_empty()
        && app.len() <= 128
        && app
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn valid_host(id: &str) -> bool {
    id.len() == 52
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
fn canonical<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = STANDARD.decode(value).ok()?;
    if STANDARD.encode(&bytes) != value {
        return None;
    }
    bytes.try_into().ok()
}
async fn metadata<T: serde::de::DeserializeOwned>(
    socket: &mut WebSocket,
    duration: Duration,
) -> Option<T> {
    match timeout(duration, socket.recv()).await.ok()??.ok()? {
        Message::Text(text) if text.len() <= METADATA_LIMIT => serde_json::from_str(&text).ok(),
        _ => None,
    }
}
async fn send_json(socket: &mut WebSocket, value: serde_json::Value, duration: Duration) -> bool {
    matches!(
        timeout(
            duration,
            socket.send(Message::Text(value.to_string().into()))
        )
        .await,
        Ok(Ok(()))
    )
}
async fn refuse(socket: &mut WebSocket, duration: Duration) {
    let _ = timeout(duration, socket.send(Message::Close(None))).await;
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn many_source_addresses_do_not_fill_a_registry_or_block_new_sources_at_1024() {
        let mut filter = AdmissionFilter::new(1024);
        let now = Instant::now();
        for address in 0_u32..1024 {
            assert!(filter.admit(IpAddr::V4((0x0a000000 + address).into()), now, 256));
        }
        assert!(filter.admit("192.0.2.1".parse().unwrap(), now, 256));
        assert_eq!(filter.rows.iter().map(Vec::len).sum::<usize>(), 4096);
    }

    #[test]
    fn active_abusers_stay_limited_and_collisions_expire_after_the_window() {
        let mut filter = AdmissionFilter::new(1);
        let now = Instant::now();
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();
        assert!(filter.admit(first, now, 2));
        assert!(filter.admit(first, now, 2));
        assert!(!filter.admit(first, now, 2));
        assert!(!filter.admit(second, now, 2));
        assert!(filter.admit(second, now + Duration::from_secs(60), 2));
        assert!(filter.admit(second, now + Duration::from_secs(60), 2));
        assert!(!filter.admit(second, now + Duration::from_secs(60), 2));
        assert!(!AdmissionFilter::new(0).admit(first, now, 2));
    }
}
