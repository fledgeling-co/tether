//! QUIC DATAGRAM transport delegated by an existing authenticated Noise session.
//! This crate accepts no service target from a remote client and logs no capabilities.
mod pin;
use bytes::Bytes;
use quinn::{Connection, Endpoint, TransportConfig, VarInt};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    net::UdpSocket,
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};
use zeroize::Zeroizing;

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_DATAGRAM: usize = 1200;
pub const DEFAULT_DATAGRAM: usize = 1152;
pub const LEASE_TTL: Duration = Duration::from_secs(5);
pub const CONNECT_WAIT: Duration = Duration::from_secs(10);
const CHECK: Duration = Duration::from_millis(250);
const ALPN: &[u8] = b"tether-media-v1";
/// Datagrams held for the application between reads. A video keyframe arrives as a burst of a
/// hundred or more datagrams, so a smaller queue drops most of it before the app can read.
pub const RECEIVE_QUEUE: usize = 512;
/// Bytes of datagrams QUIC holds in each direction for one session.
const DATAGRAM_BUFFER: usize = 1 << 20;
const QUEUE: usize = RECEIVE_QUEUE;
const GLOBAL_LEASES: usize = 64;
const PEER_LEASES: usize = 8;

#[derive(Clone)]
pub struct Context {
    pub app: String,
    pub peer: [u8; 32],
    pub binding: [u8; 32],
    pub service: String,
}
#[derive(Clone)]
pub struct Offer {
    pub lease_id: [u8; 16],
    pub token: Zeroizing<[u8; 32]>,
    pub cert_pin: [u8; 32],
    pub port: u16,
    pub max_datagram: usize,
}
pub struct Stats {
    pub rtt_ms: f64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub dropped: u64,
}
#[derive(Default)]
struct Counters {
    tx: AtomicU64,
    rx: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    dropped: AtomicU64,
}
struct Rate {
    since: Instant,
    packets: u32,
    bytes: usize,
}
impl Rate {
    fn new() -> Self {
        Self {
            since: Instant::now(),
            packets: 0,
            bytes: 0,
        }
    }
    fn accept(&mut self, n: usize) -> bool {
        if self.since.elapsed() >= Duration::from_secs(1) {
            *self = Self::new();
        }
        if self.packets >= 4096 || self.bytes.saturating_add(n) > 4 * 1024 * 1024 {
            return false;
        }
        self.packets += 1;
        self.bytes += n;
        true
    }
}
fn transport() -> TransportConfig {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window(64u32.into())
        .receive_window(128u32.into())
        .send_window(65536)
        // A video keyframe is a burst of a hundred or more datagrams. A 32 KB buffer kept only the
        // last 28 of them and dropped the rest oldest first, so no keyframe ever arrived whole.
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER))
        .datagram_send_buffer_size(DATAGRAM_BUFFER)
        .max_idle_timeout(Some(
            Duration::from_secs(5).try_into().expect("fixed duration"),
        ))
        .keep_alive_interval(Some(Duration::from_secs(2)));
    config
}
struct Lease {
    context: Context,
    token: Zeroizing<[u8; 32]>,
    target: SocketAddr,
    heartbeat: Mutex<Instant>,
    live: AtomicBool,
    consumed: AtomicBool,
    authorize: Arc<dyn Fn() -> bool + Send + Sync>,
    connection: Mutex<Option<Connection>>,
}
impl Lease {
    fn valid(&self) -> bool {
        self.live.load(Ordering::Acquire)
            && self
                .heartbeat
                .lock()
                .is_ok_and(|time| time.elapsed() < LEASE_TTL)
    }
    fn close(&self) {
        self.live.store(false, Ordering::Release);
        if let Ok(connection) = self.connection.lock() {
            if let Some(connection) = connection.as_ref() {
                connection.close(0u32.into(), b"lease closed");
            }
        }
    }
}
struct ActiveLease(Arc<Lease>);
impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.0.close();
    }
}
struct State {
    leases: Mutex<HashMap<[u8; 16], Arc<Lease>>>,
}
impl State {
    fn remove(&self, id: &[u8; 16]) {
        let lease = self
            .leases
            .lock()
            .ok()
            .and_then(|mut leases| leases.remove(id));
        if let Some(lease) = lease {
            lease.close();
        }
    }
}
pub struct LeaseGuard {
    id: [u8; 16],
    state: Arc<State>,
}
impl LeaseGuard {
    pub fn heartbeat(&self) -> Result<()> {
        let lease = self
            .state
            .leases
            .lock()
            .map_err(|_| "media unavailable")?
            .get(&self.id)
            .cloned()
            .ok_or("media lease closed")?;
        if !lease.valid() || !(lease.authorize)() {
            return Err("media lease closed".into());
        }
        *lease.heartbeat.lock().map_err(|_| "media unavailable")? = Instant::now();
        Ok(())
    }
    pub fn is_live(&self) -> bool {
        self.state
            .leases
            .lock()
            .is_ok_and(|leases| leases.get(&self.id).is_some_and(|lease| lease.valid()))
    }
    pub fn close(&self) {
        self.state.remove(&self.id);
    }
}
impl Drop for LeaseGuard {
    fn drop(&mut self) {
        self.close();
    }
}
pub struct Server {
    endpoint: Endpoint,
    state: Arc<State>,
    pin: [u8; 32],
    task: JoinHandle<()>,
}
impl Server {
    pub fn bind(address: SocketAddr) -> Result<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["tether.invalid".into()])?;
        let der = cert.cert.der().clone();
        let pin = Sha256::digest(der.as_ref()).into();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![der], key.into())?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        tls.max_early_data_size = 0;
        tls.send_tls13_tickets = 0;
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
        ));
        config.transport = Arc::new(transport());
        config
            .migration(false)
            .max_incoming(16)
            .incoming_buffer_size(65536)
            .incoming_buffer_size_total(16 * 65536);
        let endpoint = Endpoint::server(config, address)?;
        let state = Arc::new(State {
            leases: Mutex::new(HashMap::new()),
        });
        let task = tokio::spawn(serve(endpoint.clone(), state.clone()));
        Ok(Self {
            endpoint,
            state,
            pin,
            task,
        })
    }
    pub fn address(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
    pub fn open(
        &self,
        context: Context,
        target: SocketAddr,
        authorize: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Result<(Offer, LeaseGuard)> {
        let valid_scope = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        if !valid_scope(&context.app)
            || !valid_scope(&context.service)
            || !target.ip().is_loopback()
            || target.port() == 0
            || !(authorize)()
        {
            return Err("media service refused".into());
        }
        let mut leases = self.state.leases.lock().map_err(|_| "media unavailable")?;
        if leases.len() >= GLOBAL_LEASES
            || leases
                .values()
                .filter(|lease| {
                    lease.context.app == context.app && lease.context.peer == context.peer
                })
                .count()
                >= PEER_LEASES
        {
            return Err("media lease quota".into());
        }
        let mut id = [0; 16];
        let mut token = Zeroizing::new([0; 32]);
        OsRng.try_fill_bytes(&mut id)?;
        OsRng.try_fill_bytes(token.as_mut())?;
        if leases.contains_key(&id) {
            return Err("media unavailable".into());
        }
        leases.insert(
            id,
            Arc::new(Lease {
                context,
                token: token.clone(),
                target,
                heartbeat: Mutex::new(Instant::now()),
                live: AtomicBool::new(true),
                consumed: AtomicBool::new(false),
                authorize,
                connection: Mutex::new(None),
            }),
        );
        Ok((
            Offer {
                lease_id: id,
                token,
                cert_pin: self.pin,
                port: self.endpoint.local_addr()?.port(),
                max_datagram: DEFAULT_DATAGRAM,
            },
            LeaseGuard {
                id,
                state: self.state.clone(),
            },
        ))
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.close(0u32.into(), b"host closed");
        if let Ok(mut leases) = self.state.leases.lock() {
            for (_, lease) in leases.drain() {
                lease.close();
            }
        }
    }
}
async fn serve(endpoint: Endpoint, state: Arc<State>) {
    let slots = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    let mut check = interval(CHECK);
    let mut admission = (Instant::now(), 0u32);
    loop {
        tokio::select! {
                    incoming=endpoint.accept()=>{let Some(incoming)=incoming else{break;};if !incoming.remote_address_validated(){let _=incoming.retry();continue;}
        if admission.0.elapsed()>=Duration::from_secs(1){admission=(Instant::now(),0);}
        if admission.1>=32 {incoming.refuse();continue;}admission.1+=1;let Ok(permit)=slots.clone().try_acquire_owned() else {incoming.refuse();continue;};let state=state.clone();tasks.spawn(async move{let _=forward(incoming,state,permit).await;});},
                    _=check.tick()=>{let snapshot=if let Ok(leases)=state.leases.lock(){leases.iter().map(|(id,lease)|(*id,lease.clone())).collect::<Vec<_>>()}else{break;};for (id,lease) in snapshot{if !lease.valid() || !(lease.authorize)(){state.remove(&id);}}},
                    _=tasks.join_next(),if !tasks.is_empty()=>{}
                }
    }
}
async fn forward(
    incoming: quinn::Incoming,
    state: Arc<State>,
    pending: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    let (connection, lease, socket, _active) = timeout(Duration::from_millis(2500), async {
        let connection = incoming.await?;
        let (mut send,auth)={
        let authenticate=async {let (send,mut receive)=connection.accept_bi().await?;let auth=Zeroizing::new(receive.read_to_end(48).await?);Ok::<_,Error>((send,auth))};
        tokio::pin!(authenticate);
        let mut dropped=0;
        loop {tokio::select! {biased;
            packet=connection.read_datagram()=>{packet?;dropped+=1;if dropped>32{return Err("preauthentication packet limit".into());}},
            authenticated=&mut authenticate=>break authenticated?
        }}
        };
        if auth.len() != 48 {
            return Err::<_, Error>("media authentication refused".into());
        }
        let id: [u8; 16] = auth[..16].try_into()?;
        let lease = state
            .leases
            .lock()
            .map_err(|_| "media unavailable")?
            .get(&id)
            .cloned()
            .ok_or("media authentication refused")?;
        if !lease.valid()
            || !(lease.authorize)()
            || !bool::from(lease.token.as_ref().ct_eq(&auth[16..]))
            || lease
                .consumed
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err("media authentication refused".into());
        }
        let active=ActiveLease(lease.clone());
        *lease.connection.lock().map_err(|_| "media unavailable")? = Some(connection.clone());
        let bind = if lease.target.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(lease.target).await?;
        if !lease.valid() || !(lease.authorize)() {
            return Err("media service refused".into());
        }
        send.write_all(&[1]).await?;
        send.finish()?;
        Ok((connection, lease, socket,active))
    })
    .await??;
    drop(pending);
    let limit = connection
        .max_datagram_size()
        .unwrap_or(0)
        .min(DEFAULT_DATAGRAM);
    if limit == 0 {
        return Err("media datagrams unavailable".into());
    }
    let mut bytes = [0; MAX_DATAGRAM + 1];
    let mut inbound = Rate::new();
    let mut outbound = Rate::new();
    let mut check = interval(CHECK);
    let result:Result<()>=async {loop {tokio::select! {
        _=check.tick()=>{if !lease.valid(){return Err("media lease closed".into());}},
        packet=connection.read_datagram()=>{let packet=packet?;if !lease.valid(){return Err("media lease closed".into());}
if packet.len()>limit || !inbound.accept(packet.len()){continue;}socket.send(&packet).await?;},
        n=socket.recv(&mut bytes)=>{let n=n?;if !lease.valid(){return Err("media lease closed".into());}
if n>limit || !outbound.accept(n){continue;}let _=connection.send_datagram(Bytes::copy_from_slice(&bytes[..n]));}
    }}}.await;
    lease.close();
    result
}

struct PacketQueue {
    data: Mutex<VecDeque<Vec<u8>>>,
    wake: Condvar,
    closed: AtomicBool,
}
impl PacketQueue {
    fn close(&self) {
        if let Ok(mut data) = self.data.lock() {
            self.closed.store(true, Ordering::Release);
            data.clear();
        }
        self.wake.notify_all();
    }
    fn receive(&self) -> Option<Vec<u8>> {
        let mut data = self.data.lock().ok()?;
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        data.pop_front()
    }
    fn wait(&self, timeout: Duration) -> std::result::Result<Option<Vec<u8>>, &'static str> {
        if timeout > Duration::from_millis(100) {
            return Err("invalid_request");
        }
        let deadline = Instant::now() + timeout;
        let mut data = self.data.lock().map_err(|_| "media_closed")?;
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err("media_closed");
            }
            if let Some(packet) = data.pop_front() {
                return Ok(Some(packet));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            data = self
                .wake
                .wait_timeout(data, remaining)
                .map_err(|_| "media_closed")?
                .0;
        }
    }
}
pub struct Client {
    endpoint: Endpoint,
    connection: Connection,
    limit: usize,
    incoming: Arc<PacketQueue>,
    rate: Mutex<Rate>,
    counters: Arc<Counters>,
    reader: JoinHandle<()>,
}
async fn connect_tls(address: SocketAddr, digest: [u8; 32]) -> Result<(Endpoint, Connection)> {
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut endpoint = Endpoint::client(bind.parse()?)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(pin::Pin {
        digest,
        provider: provider.clone(),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(Arc::new(transport()));
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(address, "tether.invalid")?.await?;
    Ok((endpoint, connection))
}
impl Client {
    pub async fn connect(address: SocketAddr, offer: Offer) -> Result<Self> {
        Self::connect_candidates(vec![address], offer).await
    }
    /// Race at most four pinned TLS handshakes; transmit the one-use token only on the winner.
    pub async fn connect_candidates(addresses: Vec<SocketAddr>, offer: Offer) -> Result<Self> {
        if addresses.is_empty()
            || addresses.len() > 4
            || addresses.iter().any(|address| address.port() != offer.port)
        {
            return Err("invalid media candidates".into());
        }
        let (endpoint, connection) = timeout(CONNECT_WAIT, async {
            let mut tasks = JoinSet::new();
            for address in addresses {
                let pin = offer.cert_pin;
                tasks.spawn(connect_tls(address, pin));
            }
            let (endpoint, connection) = loop {
                match tasks.join_next().await {
                    Some(Ok(Ok(ready))) => break ready,
                    Some(_) => continue,
                    None => return Err::<_, Error>("media connection refused".into()),
                }
            };
            tasks.abort_all();
            let (mut send, mut receive) = connection.open_bi().await?;
            let mut auth = Zeroizing::new(Vec::with_capacity(48));
            auth.extend_from_slice(&offer.lease_id);
            auth.extend_from_slice(offer.token.as_ref());
            send.write_all(&auth).await?;
            send.finish()?;
            if receive.read_to_end(1).await? != [1] {
                return Err::<_, Error>("media authentication refused".into());
            }
            Ok((endpoint, connection))
        })
        .await??;
        let limit = connection
            .max_datagram_size()
            .unwrap_or(0)
            .min(DEFAULT_DATAGRAM)
            .min(offer.max_datagram);
        if limit == 0 {
            return Err("media datagrams unavailable".into());
        }
        let incoming = Arc::new(PacketQueue {
            data: Mutex::new(VecDeque::with_capacity(64)),
            wake: Condvar::new(),
            closed: AtomicBool::new(false),
        });
        let queue = incoming.clone();
        let counters = Arc::new(Counters::default());
        let stats = counters.clone();
        let peer = connection.clone();
        let reader = tokio::spawn(async move {
            let mut rate = Rate::new();
            while let Ok(packet) = peer.read_datagram().await {
                if packet.len() > limit || !rate.accept(packet.len()) {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                stats.rx.fetch_add(packet.len() as u64, Ordering::Relaxed);
                stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                if let Ok(mut data) = queue.data.lock() {
                    if queue.closed.load(Ordering::Acquire) {
                        break;
                    }
                    if data.len() >= QUEUE {
                        data.pop_front();
                        stats.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    data.push_back(packet.to_vec());
                } else {
                    break;
                }
                queue.wake.notify_one();
            }
            queue.close();
        });
        Ok(Self {
            endpoint,
            connection,
            limit,
            incoming,
            rate: Mutex::new(Rate::new()),
            counters,
            reader,
        })
    }
    pub fn max_datagram(&self) -> usize {
        self.limit
            .min(self.connection.max_datagram_size().unwrap_or(0))
    }
    pub fn is_closed(&self) -> bool {
        self.incoming.closed.load(Ordering::Acquire) || self.connection.close_reason().is_some()
    }
    pub fn send(&self, bytes: &[u8]) -> std::result::Result<(), &'static str> {
        if self.is_closed() {
            return Err("media_closed");
        }
        if bytes.len() > self.max_datagram() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Err("media_packet_too_large");
        }
        let mut rate = self.rate.lock().map_err(|_| "media_closed")?;
        if !rate.accept(bytes.len())
            || self.connection.datagram_send_buffer_space() < bytes.len() + 16
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Err("media_backpressure");
        }
        if self
            .connection
            .send_datagram(Bytes::copy_from_slice(bytes))
            .is_err()
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return Err(if self.is_closed() {
                "media_closed"
            } else {
                "media_backpressure"
            });
        }
        self.counters
            .tx
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    pub fn receive(&self) -> Option<Vec<u8>> {
        self.incoming.receive()
    }
    /// Blocking caller-thread wait. Native wrappers run this on an off-UI queue, never a Tokio worker.
    pub fn receive_wait(
        &self,
        timeout: Duration,
    ) -> std::result::Result<Option<Vec<u8>>, &'static str> {
        self.incoming.wait(timeout)
    }
    pub fn stats(&self) -> Stats {
        Stats {
            rtt_ms: self.connection.rtt().as_secs_f64() * 1000.0,
            bytes_sent: self.counters.tx.load(Ordering::Relaxed),
            bytes_received: self.counters.rx.load(Ordering::Relaxed),
            packets_sent: self.counters.tx_packets.load(Ordering::Relaxed),
            packets_received: self.counters.rx_packets.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
        }
    }
    pub fn close(&self) {
        self.incoming.close();
        self.connection.close(VarInt::from_u32(0), b"client closed");
        self.endpoint.close(VarInt::from_u32(0), b"client closed");
        self.reader.abort();
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocking_packet_wait_wakes_on_enqueue_and_close_and_times_out_bounded() {
        let queue = Arc::new(PacketQueue {
            data: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            closed: AtomicBool::new(false),
        });
        assert!(queue.wait(Duration::from_millis(101)).is_err());
        assert!(queue.wait(Duration::ZERO).unwrap().is_none());
        let incoming = queue.clone();
        let worker = std::thread::spawn(move || incoming.wait(Duration::from_millis(100)));
        {
            queue.data.lock().unwrap().push_back(b"packet".to_vec());
        }
        queue.wake.notify_one();
        assert_eq!(worker.join().unwrap().unwrap().unwrap(), b"packet");
        let incoming = queue.clone();
        let worker = std::thread::spawn(move || incoming.wait(Duration::from_millis(100)));
        queue.close();
        assert_eq!(worker.join().unwrap(), Err("media_closed"));
    }
    #[tokio::test]
    async fn authorization_callbacks_never_run_under_global_lease_table_lock() -> Result<()> {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let server = Server::bind("127.0.0.1:0".parse()?)?;
        let state = server.state.clone();
        let authorize = Arc::new(move || state.leases.try_lock().is_ok());
        let (_, guard) = server.open(
            Context {
                app: "test.app".into(),
                peer: [1; 32],
                binding: [2; 32],
                service: "video".into(),
            },
            target.local_addr()?,
            authorize,
        )?;
        guard.heartbeat()?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(guard.is_live());
        guard.heartbeat()?;
        Ok(())
    }
    #[tokio::test]
    async fn packets_before_token_authentication_are_dropped_and_never_reach_loopback() -> Result<()>
    {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let server = Server::bind("127.0.0.1:0".parse()?)?;
        let (offer, guard) = server.open(
            Context {
                app: "test.app".into(),
                peer: [1; 32],
                binding: [2; 32],
                service: "video".into(),
            },
            target.local_addr()?,
            Arc::new(|| true),
        )?;
        let (_endpoint, connection) = connect_tls(server.address()?, offer.cert_pin).await?;
        connection.send_datagram(Bytes::from_static(b"before-authentication"))?;
        let mut buffer = [0; 1201];
        assert!(timeout(Duration::from_millis(30), target.recv(&mut buffer))
            .await
            .is_err());
        guard.heartbeat()?;
        let (mut send, mut receive) = connection.open_bi().await?;
        let mut auth = Zeroizing::new(Vec::new());
        auth.extend_from_slice(&offer.lease_id);
        auth.extend_from_slice(offer.token.as_ref());
        send.write_all(&auth).await?;
        send.finish()?;
        assert_eq!(receive.read_to_end(1).await?, [1]);
        assert!(timeout(Duration::from_millis(30), target.recv(&mut buffer))
            .await
            .is_err());
        connection.send_datagram(Bytes::from_static(b"after-authentication"))?;
        let n = timeout(Duration::from_secs(2), target.recv(&mut buffer)).await??;
        assert_eq!(&buffer[..n], b"after-authentication");
        Ok(())
    }
}
