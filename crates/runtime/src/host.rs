use crate::{
    carrier::{self, Carrier, Result, WAIT},
    controls::{HostStatus, OwnerInspection, PairingStatus, ServiceSummary},
    protocol::{self, Session},
    storage::{self, Device, HostConfig, ServiceKind},
    transfer,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
#[cfg(unix)]
use sha2::Digest;
use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tether_core::{Confirmation, Identity, Pairing, Role};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use zeroize::Zeroizing;
#[derive(Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum RelayStatus {
    Registered { id: String },
    Disconnected,
    Listening { address: String },
}

const PAIR_LIFETIME: Duration = Duration::from_secs(300);
const STREAMS: usize = 8;
const TOTAL_SESSIONS: usize = 24;

struct Window {
    code: Zeroizing<String>,
    generation: u128,
    expires: Instant,
    attempts: u8,
    consumed: bool,
    services: BTreeSet<String>,
}
#[derive(Clone)]
pub struct Host(Arc<Inner>);
struct Inner {
    path: PathBuf,
    app: String,
    identity: Identity,
    registration: SigningKey,
    window: Mutex<Option<Window>>,
    streams: Arc<Semaphore>,
    services: Arc<Semaphore>,
    presence: Mutex<HashMap<[u8; 32], Presence>>,
    media: tokio::sync::OnceCell<Arc<tether_media::Server>>,
    direct_bind: Mutex<Option<std::net::IpAddr>>,
}
struct Presence {
    seen: Instant,
    unix_ms: u64,
    active: u32,
}
struct ActivePeer {
    host: Host,
    peer: [u8; 32],
}
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
impl Drop for ActivePeer {
    fn drop(&mut self) {
        if let Ok(mut presence) = self.host.0.presence.lock() {
            if let Some(entry) = presence.get_mut(&self.peer) {
                entry.active = entry.active.saturating_sub(1);
                entry.seen = Instant::now();
                entry.unix_ms = unix_ms();
            }
        }
    }
}
impl Host {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let config: HostConfig = storage::load(path.as_ref())?;
        config.validate()?;
        Ok(Self(Arc::new(Inner {
            path: path.as_ref().to_owned(),
            app: config.app_id.clone(),
            identity: config.identity()?,
            registration: SigningKey::from_bytes(&storage::key(&config.registration_key)?),
            window: Mutex::new(None),
            streams: Arc::new(Semaphore::new(TOTAL_SESSIONS)),
            services: Arc::new(Semaphore::new(STREAMS)),
            presence: Mutex::new(HashMap::new()),
            media: tokio::sync::OnceCell::new(),
            direct_bind: Mutex::new(None),
        })))
    }
    pub fn app_id(&self) -> &str {
        &self.0.app
    }
    pub fn inspect(&self, expected_app: &str) -> Result<OwnerInspection> {
        self.owner_scope(expected_app)?;
        let current = self.current()?;
        Ok(OwnerInspection {
            app_id: current.app_id,
            host_id: self.public_route_id(),
            services: current
                .services
                .into_iter()
                .map(|(id, service)| ServiceSummary {
                    id,
                    kind: service.kind,
                })
                .collect(),
        })
    }
    pub fn owner_scope(&self, expected_app: &str) -> Result<()> {
        storage::app_id(expected_app)?;
        if expected_app != self.0.app {
            return Err("owner application scope mismatch".into());
        }
        self.current()?;
        Ok(())
    }
    pub fn pairing_status(&self) -> Result<PairingStatus> {
        let guard = self.0.window.lock().map_err(|_| "pairing unavailable")?;
        let Some(window) = guard.as_ref() else {
            return Ok(PairingStatus {
                open: false,
                expires_in_seconds: 0,
                attempts_remaining: 0,
            });
        };
        let remaining = window.expires.saturating_duration_since(Instant::now());
        let open = !window.consumed && window.attempts < 3 && !remaining.is_zero();
        Ok(PairingStatus {
            open,
            expires_in_seconds: if open {
                remaining.as_millis().div_ceil(1000) as u64
            } else {
                0
            },
            attempts_remaining: if open { 3 - window.attempts } else { 0 },
        })
    }
    fn known_peer(&self, peer: &[u8; 32]) -> Result<bool> {
        let config = self.current()?;
        Ok(config
            .devices
            .get(&storage::device_id(peer))
            .is_some_and(|device| storage::key(&device.public_key).ok().as_ref() == Some(peer)))
    }
    fn status_for(&self, peer: &[u8; 32]) -> Result<HostStatus> {
        let config = self.current()?;
        let device = config
            .devices
            .get(&storage::device_id(peer))
            .ok_or("device refused")?;
        if storage::key(&device.public_key)? != *peer {
            return Err("device refused".into());
        }
        Ok(HostStatus {
            services: device
                .services
                .iter()
                .filter_map(|id| {
                    config.services.get(id).map(|service| ServiceSummary {
                        id: id.clone(),
                        kind: service.kind,
                    })
                })
                .collect(),
        })
    }
    pub fn owner_clients(&self, expected_app: &str) -> Result<serde_json::Value> {
        self.owner_scope(expected_app)?;
        let config = self.current()?;
        let mut presence = self.0.presence.lock().map_err(|_| "presence unavailable")?;
        presence
            .retain(|_, entry| entry.active > 0 || entry.seen.elapsed() < Duration::from_secs(45));
        Ok(json!(config.devices.iter().map(|(id,device)| {
            let entry=storage::key(&device.public_key).ok().and_then(|key|presence.get(&key));
            json!({"device":id,"services":device.services,"recently_seen":entry.is_some_and(|entry|entry.seen.elapsed()<Duration::from_secs(45)),"active_sessions":entry.map_or(0,|entry|entry.active),"last_seen_unix_ms":entry.map(|entry|entry.unix_ms)})
        }).collect::<Vec<_>>()))
    }
    pub fn owner_revoke(&self, expected_app: &str, device: &str) -> Result<()> {
        self.owner_scope(expected_app)?;
        if device.len() != 64 || !device.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid device identity".into());
        }
        let identity = self.0.identity.public();
        let registration = self.0.registration.to_bytes();
        storage::update_host(&self.0.path, |config| {
            if config.app_id != expected_app
                || config.identity()?.public() != identity
                || storage::key(&config.registration_key)? != registration
            {
                return Err("host identity changed".into());
            }
            if config
                .devices
                .remove(&device.to_ascii_lowercase())
                .is_none()
            {
                return Err("unknown device".into());
            }
            Ok(())
        })
    }
    fn activity(&self, peer: [u8; 32]) -> Result<ActivePeer> {
        let mut presence = self.0.presence.lock().map_err(|_| "presence unavailable")?;
        presence
            .retain(|_, entry| entry.active > 0 || entry.seen.elapsed() < Duration::from_secs(45));
        if presence.len() >= 1024 && !presence.contains_key(&peer) {
            if let Some(oldest) = presence
                .iter()
                .filter(|(_, entry)| entry.active == 0)
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(key, _)| *key)
            {
                presence.remove(&oldest);
            } else {
                return Err("presence quota".into());
            }
        }
        let entry = presence.entry(peer).or_insert(Presence {
            seen: Instant::now(),
            unix_ms: unix_ms(),
            active: 0,
        });
        entry.active = entry.active.saturating_add(1);
        entry.seen = Instant::now();
        entry.unix_ms = unix_ms();
        Ok(ActivePeer {
            host: self.clone(),
            peer,
        })
    }
    pub fn public_route_id(&self) -> String {
        carrier::host_id(&self.0.app, &self.0.registration.verifying_key().to_bytes())
    }
    pub fn open_pairing(&self) -> Result<String> {
        let config = self.current()?;
        let mut random = [0; 8];
        OsRng.try_fill_bytes(&mut random)?;
        let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let code: String = random
            .iter()
            .map(|byte| alphabet[(byte & 31) as usize] as char)
            .collect();
        *self.0.window.lock().map_err(|_| "pairing unavailable")? = Some(Window {
            code: Zeroizing::new(code.clone()),
            generation: rand::random(),
            expires: Instant::now() + PAIR_LIFETIME,
            attempts: 0,
            consumed: false,
            services: config.services.keys().cloned().collect(),
        });
        Ok(code)
    }
    fn current(&self) -> Result<HostConfig> {
        let config: HostConfig = storage::load(&self.0.path)?;
        config.validate()?;
        if config.app_id != self.0.app
            || config.identity()?.public() != self.0.identity.public()
            || storage::key(&config.registration_key)? != self.0.registration.to_bytes()
        {
            return Err("host identity changed; restart required".into());
        }
        Ok(config)
    }
    fn authorized(&self, peer: &[u8; 32], service: &str) -> Result<()> {
        if !self.current()?.authorize(peer, service) {
            return Err("service refused".into());
        }
        Ok(())
    }
    fn anchored(&self, peer: &[u8; 32], service: &str, expected: &storage::Service) -> Result<()> {
        let config = self.current()?;
        if !config.authorize(peer, service)
            || config.services.get(service).is_none_or(|current| {
                current.kind != expected.kind || current.target != expected.target
            })
        {
            return Err("service was removed or changed".into());
        }
        Ok(())
    }
    fn begin(
        &self,
        peer: [u8; 32],
        binding: [u8; 32],
        element: &[u8],
    ) -> Result<(u128, Confirmation, Vec<u8>)> {
        let mut guard = self.0.window.lock().map_err(|_| "pairing unavailable")?;
        let window = guard.as_mut().ok_or("pairing not open")?;
        if window.consumed || window.attempts >= 3 || Instant::now() >= window.expires {
            return Err("pairing refused".into());
        }
        let (exchange, reply) = Pairing::start(
            Role::Host,
            &window.code,
            &self.0.app,
            binding,
            peer,
            self.0.identity.public(),
        )?;
        let confirmation = exchange.finish(element)?;
        window.attempts += 1;
        Ok((window.generation, confirmation, reply))
    }
    fn consume(&self, generation: u128) -> Result<BTreeSet<String>> {
        let mut guard = self.0.window.lock().map_err(|_| "pairing unavailable")?;
        let window = guard.as_mut().ok_or("pairing refused")?;
        if window.generation != generation || window.consumed || Instant::now() >= window.expires {
            return Err("pairing refused".into());
        }
        window.consumed = true;
        Ok(window.services.clone())
    }
    pub async fn handle(&self, carrier: Carrier) -> Result<()> {
        let mut session = protocol::respond(carrier, &self.0.identity, &self.0.app).await?;
        let request = session.receive().await?;
        if request["v"] != 1 {
            return Err("unsupported protocol".into());
        }
        let _activity = if self.known_peer(&session.peer)? {
            Some(self.activity(session.peer)?)
        } else {
            None
        };
        match request["type"].as_str() {
            Some("pair.start") => self.pair(session, request).await,
            Some("media.open") => self.media_session(session, request).await,
            Some("host.status") | Some("peer.leave") => {
                if request.as_object().is_none_or(|fields| fields.len() != 2) {
                    return session
                        .send(json!({"type":"error","v":1,"code":"invalid_request"}))
                        .await;
                }
                if !self.known_peer(&session.peer)? {
                    return session
                        .send(json!({"type":"error","v":1,"code":"peer_revoked"}))
                        .await;
                }
                if request["type"] == "host.status" {
                    let status = self.status_for(&session.peer)?;
                    return session
                        .send(json!({"type":"host.status","v":1,"services":status.services}))
                        .await;
                }
                let path = self.0.path.clone();
                let peer = session.peer;
                let app = self.0.app.clone();
                let host_key = self.0.identity.public();
                let registration = self.0.registration.to_bytes();
                tokio::task::spawn_blocking(move || {
                    storage::update_host(&path, |config| {
                        if config.app_id != app
                            || config.identity()?.public() != host_key
                            || storage::key(&config.registration_key)? != registration
                        {
                            return Err("host identity changed".into());
                        }
                        let id = storage::device_id(&peer);
                        if config.devices.get(&id).is_none_or(|device| {
                            storage::key(&device.public_key).ok() != Some(peer)
                        }) {
                            return Err("device refused".into());
                        }
                        config.devices.remove(&id);
                        Ok(())
                    })
                })
                .await??;
                session.send(json!({"type":"peer.left","v":1})).await
            }
            Some("pair.status") => {
                if !self.known_peer(&session.peer)? {
                    return session
                        .send(json!({"type":"error","v":1,"code":"peer_revoked"}))
                        .await;
                }
                session.send(json!({"type":"pair.done","v":1})).await
            }
            Some("service.open") => {
                if !self.known_peer(&session.peer)? {
                    return session
                        .send(json!({"type":"error","v":1,"code":"peer_revoked"}))
                        .await;
                }
                let service = request["service"]
                    .as_str()
                    .ok_or("missing service")?
                    .to_owned();
                if self.authorized(&session.peer, &service).is_err() {
                    return session
                        .send(json!({"type":"error","v":1,"code":"service_denied"}))
                        .await;
                }
                let Ok(_service) = self.0.services.clone().try_acquire_owned() else {
                    return session
                        .send(json!({"v":1,"type":"error","code":"service_capacity"}))
                        .await;
                };
                let config = self.current()?;
                let target = config
                    .services
                    .get(&service)
                    .ok_or("service refused")?
                    .clone();
                let peer = session.peer;
                let host = self.clone();
                match target.kind {
                    ServiceKind::Tcp => {
                        let socket = timeout(WAIT, TcpStream::connect(target.target)).await??;
                        self.anchored(&peer, &service, &target)?;
                        session
                            .send(json!({"type":"service.ready","v":1,"kind":"tcp"}))
                            .await?;
                        transfer::tcp(session, socket, move || {
                            host.anchored(&peer, &service, &target)
                        })
                        .await
                    }
                    ServiceKind::Udp => {
                        let bind = if target.target.is_ipv4() {
                            "127.0.0.1:0"
                        } else {
                            "[::1]:0"
                        };
                        let socket = UdpSocket::bind(bind).await?;
                        socket.connect(target.target).await?;
                        self.anchored(&peer, &service, &target)?;
                        session
                            .send(json!({"type":"service.ready","v":1,"kind":"udp"}))
                            .await?;
                        transfer::udp(session, socket, move || {
                            host.anchored(&peer, &service, &target)
                        })
                        .await
                    }
                }
            }
            _ => Err("request refused".into()),
        }
    }
    async fn media_session(&self, mut session: Session, request: serde_json::Value) -> Result<()> {
        if !self.known_peer(&session.peer)? {
            return session
                .send(json!({"v":1,"type":"error","code":"peer_revoked"}))
                .await;
        }
        let Some(service) = request["service"]
            .as_str()
            .filter(|_| request.as_object().is_some_and(|fields| fields.len() == 3))
        else {
            return session
                .send(json!({"v":1,"type":"error","code":"invalid_request"}))
                .await;
        };
        let service = service.to_owned();
        if self.authorized(&session.peer, &service).is_err() {
            return session
                .send(json!({"v":1,"type":"error","code":"service_denied"}))
                .await;
        }
        let config = self.current()?;
        let target = config
            .services
            .get(&service)
            .ok_or("media service refused")?;
        if target.kind != ServiceKind::Udp {
            return session
                .send(json!({"v":1,"type":"error","code":"service_denied"}))
                .await;
        }
        let Ok(_service) = self.0.services.clone().try_acquire_owned() else {
            return session
                .send(json!({"v":1,"type":"error","code":"service_capacity"}))
                .await;
        };
        let local = match &session.carrier {
            Carrier::Direct(socket) => socket.local_addr()?,
            _ => {
                return session
                    .send(json!({"v":1,"type":"error","code":"media_unavailable"}))
                    .await
            }
        };
        let bound = self
            .0
            .direct_bind
            .lock()
            .map_err(|_| "media unavailable")?
            .unwrap_or(local.ip());
        let bind = std::net::SocketAddr::new(bound, 0);
        let server = self
            .0
            .media
            .get_or_try_init(|| async {
                Ok::<_, crate::carrier::Error>(Arc::new(tether_media::Server::bind(bind)?))
            })
            .await?;
        if server.address()?.is_ipv4() != local.is_ipv4() {
            return session
                .send(json!({"v":1,"type":"error","code":"media_unavailable"}))
                .await;
        }
        let host = self.clone();
        let peer = session.peer;
        let granted = service.clone();
        let fixed = target.clone();
        let (offer, lease) = server.open(
            tether_media::Context {
                app: self.0.app.clone(),
                peer,
                binding: session.binding,
                service,
            },
            target.target,
            Arc::new(move || {
                host.current().is_ok_and(|config| {
                    config.authorize(&peer, &granted)
                        && config.services.get(&granted).is_some_and(|service| {
                            service.kind == fixed.kind && service.target == fixed.target
                        })
                })
            }),
        )?;
        let id = STANDARD.encode(offer.lease_id);
        session.send(json!({"v":1,"type":"media.ready","lease_id":id,"token":STANDARD.encode(offer.token.as_ref()),"cert_pin":STANDARD.encode(offer.cert_pin),"port":offer.port,"max_datagram":offer.max_datagram,"heartbeat_seconds":2,"lease_ttl_seconds":5})).await?;
        let mut heartbeat_rate = (Instant::now(), 0u8);
        loop {
            let request = timeout(tether_media::LEASE_TTL, session.receive()).await??;
            if heartbeat_rate.0.elapsed() >= Duration::from_secs(1) {
                heartbeat_rate = (Instant::now(), 0);
            }
            if heartbeat_rate.1 >= 8 {
                return Err("media heartbeat rate exceeded".into());
            }
            heartbeat_rate.1 += 1;
            if request["v"] != 1
                || request["lease_id"] != id
                || request.as_object().is_none_or(|fields| fields.len() != 3)
            {
                return Err("media heartbeat refused".into());
            }
            match request["type"].as_str() {
                Some("media.heartbeat") => {
                    lease.heartbeat()?;
                    session.send(json!({"v":1,"type":"media.alive"})).await?;
                }
                Some("media.close") => {
                    lease.close();
                    return session.send(json!({"v":1,"type":"media.closed"})).await;
                }
                _ => return Err("media heartbeat refused".into()),
            }
        }
    }
    async fn pair(&self, mut session: Session, request: serde_json::Value) -> Result<()> {
        let element = STANDARD.decode(request["element"].as_str().ok_or("missing element")?)?;
        let (generation, confirmation, reply) =
            self.begin(session.peer, session.binding, &element)?;
        session.send(json!({"type":"pair.reply","v":1,"element":STANDARD.encode(reply),"proof":STANDARD.encode(confirmation.outbound())})).await?;
        let confirm = session.receive().await?;
        if confirm["type"] != "pair.confirm" || confirm["v"] != 1 {
            return Err("pairing refused".into());
        }
        confirmation
            .verify_peer(&STANDARD.decode(confirm["proof"].as_str().ok_or("missing proof")?)?)?;
        let services = self.consume(generation)?;
        session.send(json!({"type":"pair.ready","v":1})).await?;
        let ack = session.receive().await?;
        if ack["type"] != "pair.ack" || ack["v"] != 1 {
            return Err("pairing refused".into());
        }
        // The client has durably stored its pending private record before ack. No device record exists before it.
        let public = session.peer;
        let path = self.0.path.clone();
        let host_key = self.0.identity.public();
        let app = self.0.app.clone();
        tokio::task::spawn_blocking(move || {
            storage::update_host(&path, |config| {
                if config.app_id != app || config.identity()?.public() != host_key {
                    return Err("host identity changed".into());
                }
                config.devices.insert(
                    storage::device_id(&public),
                    Device {
                        public_key: STANDARD.encode(public),
                        services,
                    },
                );
                Ok(())
            })
        })
        .await??;
        drop(self.activity(public)?);
        session.send(json!({"type":"pair.done","v":1})).await
    }
    pub async fn serve_direct(&self, listener: TcpListener) -> Result<()> {
        let bind = listener.local_addr()?.ip();
        {
            let mut scope = self
                .0
                .direct_bind
                .lock()
                .map_err(|_| "listener unavailable")?;
            if scope.is_some_and(|ip| ip != bind) {
                return Err("host listener scope changed".into());
            }
            *scope = Some(bind);
        }
        let mut tasks = JoinSet::new();
        let mut current = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = current.tick() => {self.current()?;},
                connection = listener.accept() => {
                    let (socket, _) = connection?;
                    let Ok(permit) = self.0.streams.clone().try_acquire_owned() else { continue; };
                    let host = self.clone();
                    tasks.spawn(async move { let _permit = permit; let _ = host.handle(Carrier::Direct(socket)).await; });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
    pub async fn serve_relay(
        &self,
        url: &str,
        dev: bool,
        application_tls: Option<&str>,
    ) -> Result<()> {
        self.serve_relay_events(url, dev, application_tls, None, None)
            .await
    }
    pub async fn serve_relay_events(
        &self,
        url: &str,
        dev: bool,
        application_tls: Option<&str>,
        events: Option<tokio::sync::mpsc::Sender<RelayStatus>>,
        fixed_target: Option<std::net::SocketAddr>,
    ) -> Result<()> {
        carrier::check_relay_url(url, dev)?;
        if let Some(service) = application_tls {
            if self
                .current()?
                .services
                .get(service)
                .is_none_or(|target| target.kind != ServiceKind::Tcp)
            {
                return Err("application TLS requires a TCP service".into());
            }
        }
        let mut delay = Duration::from_secs(1);
        loop {
            self.current()?;
            let started = Instant::now();
            let _ = self
                .relay_once(url, dev, application_tls, events.as_ref(), fixed_target)
                .await;
            if let Some(events) = &events {
                events
                    .send(RelayStatus::Disconnected)
                    .await
                    .map_err(|_| "status consumer closed")?;
            }
            if started.elapsed() > Duration::from_secs(30) {
                delay = Duration::from_secs(1);
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }
    async fn relay_once(
        &self,
        url: &str,
        dev: bool,
        application_tls: Option<&str>,
        events: Option<&tokio::sync::mpsc::Sender<RelayStatus>>,
        fixed_target: Option<std::net::SocketAddr>,
    ) -> Result<()> {
        let target = if let Some(service) = application_tls {
            let config = self.current()?;
            let target = config.services.get(service).ok_or("service refused")?;
            if target.kind != ServiceKind::Tcp {
                return Err("application TLS requires a TCP service".into());
            }
            if fixed_target.is_some_and(|expected| expected != target.target) {
                return Err("service target does not match managed profile".into());
            }
            Some(target.target)
        } else {
            None
        };
        let (mut control, id) =
            carrier::register(url, &self.0.app, &self.0.registration, dev).await?;
        if let Some(events) = events {
            events
                .send(RelayStatus::Registered { id })
                .await
                .map_err(|_| "status consumer closed")?;
        }
        let tls_service = application_tls.map(str::to_owned);
        let mut tasks = JoinSet::new();
        let mut settings = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _=settings.tick()=> {
                    let current=self.current()?;
                    if let Some(service)=application_tls {
                        if current.services.get(service).is_none_or(|value|value.kind!=ServiceKind::Tcp || Some(value.target)!=target) {return Err("application service changed".into());}
                    }
                },
                message = carrier::receive_control(&mut control) => {
                    let message = message?;
                    if message["type"] != "open" { return Err("unexpected relay control".into()); }
                    let ticket = message["ticket"].as_str().ok_or("missing stream ticket")?.to_owned();
                    let Ok(permit) = self.0.streams.clone().try_acquire_owned() else { continue; };
                    let host = self.clone(); let url = url.to_owned();
                    let tls_service=tls_service.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let result: Result<()> = async {
                            let connection = carrier::relay_attach(&url, &ticket, dev).await?;
                            if let Some(target) = target {
                                let _service=host.0.services.clone().try_acquire_owned().map_err(|_|"service capacity")?;
                                let socket = timeout(WAIT, TcpStream::connect(target)).await??;
                                let service=tls_service.ok_or("missing application TLS service")?;
                                transfer::application_tls_guarded(connection,socket,move||{
                                    if host.current()?.services.get(&service).is_none_or(|current|current.kind!=ServiceKind::Tcp || current.target!=target) {return Err("service was removed or changed".into());} Ok(())
                                }).await
                            } else { host.handle(connection).await }
                        }.await;
                        let _ = result;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

#[cfg(unix)]
pub fn control_path(path: &Path) -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let path = canonical.as_path();
    let digest =
        storage::device_id(&sha2::Sha256::digest(path.as_os_str().as_encoded_bytes()).into());
    let owner = std::fs::metadata(path)
        .map(|metadata| metadata.uid())
        .unwrap_or(u32::MAX);
    // sockaddr_un paths are short on macOS; configuration paths can be substantially longer.
    Path::new("/tmp")
        .join(format!("tether-{owner}"))
        .join(format!("{}.sock", &digest[..24]))
}
#[cfg(unix)]
pub fn validate_control_directory(config: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let socket = control_path(config);
    let parent = socket.parent().ok_or("missing control directory")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o77 != 0
        || metadata.uid() != std::fs::metadata(config)?.uid()
    {
        return Err("control directory is not private".into());
    }
    Ok(())
}
#[cfg(unix)]
pub async fn serve_pairing_control(host: Host, config: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let path = control_path(config);
    let parent = path.parent().ok_or("missing control directory")?;
    if !parent.exists() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(parent)?;
    }
    validate_control_directory(config)?;
    if path.exists() {
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            return Err("host already running".into());
        }
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_socket() {
            return Err("control path is not a socket".into());
        }
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    struct SocketFile(PathBuf);
    impl Drop for SocketFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _socket_file = SocketFile(path.clone());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (mut socket, _) = listener.accept().await?;
        let mut command = Vec::new();
        let read = timeout(Duration::from_secs(1), async {
            loop {
                let byte = socket.read_u8().await?;
                if byte == b'\n' {
                    break;
                }
                if command.len() >= crate::owner::MAX_REQUEST {
                    return Err(std::io::Error::other("control exceeds limit"));
                }
                command.push(byte);
            }
            Ok::<_, std::io::Error>(())
        })
        .await;
        if !matches!(read, Ok(Ok(()))) {
            continue;
        }
        let output = if command == b"pair-code" {
            match host.open_pairing() {
                Ok(code) => format!("{code}\n").into_bytes(),
                Err(_) => continue,
            }
        } else {
            let Ok(request) = crate::owner::parse(&command) else {
                continue;
            };
            let response = crate::owner::dispatch(host.clone(), request).await;
            crate::owner::encode(&response)?
        };
        let _ = timeout(Duration::from_secs(1), socket.write_all(&output)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    fn setup() -> Result<(Host, PathBuf)> {
        let dir =
            std::env::temp_dir().join(format!("tether-window-{:032x}", rand::random::<u128>()));
        let file = dir.join("host.json");
        let services = BTreeMap::from([(
            "api".into(),
            storage::Service {
                kind: ServiceKind::Tcp,
                target: "127.0.0.1:1".parse()?,
            },
        )]);
        storage::create(&file, &HostConfig::new("test.app", services)?)?;
        Ok((Host::load(file)?, dir))
    }
    #[test]
    fn owner_presence_distinguishes_active_recent_and_unseen_without_persisting_it() -> Result<()> {
        let (host, dir) = setup()?;
        let peer = Identity::generate()?.public();
        storage::update_host(&host.0.path, |config| {
            config.devices.insert(
                storage::device_id(&peer),
                Device {
                    public_key: STANDARD.encode(peer),
                    services: BTreeSet::from(["api".into()]),
                },
            );
            Ok(())
        })?;
        let before = std::fs::read(&host.0.path)?;
        let initial = host.owner_clients("test.app")?;
        assert_eq!(initial[0]["active_sessions"], 0);
        assert_eq!(initial[0]["recently_seen"], false);
        let active = host.activity(peer)?;
        let current = host.owner_clients("test.app")?;
        assert_eq!(current[0]["active_sessions"], 1);
        assert_eq!(current[0]["recently_seen"], true);
        drop(active);
        assert_eq!(host.owner_clients("test.app")?[0]["active_sessions"], 0);
        assert_eq!(host.owner_clients("test.app")?[0]["recently_seen"], true);
        host.0.presence.lock().unwrap().get_mut(&peer).unwrap().seen =
            Instant::now() - Duration::from_secs(46);
        assert_eq!(host.owner_clients("test.app")?[0]["recently_seen"], false);
        assert!(std::fs::read(&host.0.path)? == before);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[test]
    fn window_limits_expiry_rotation_and_one_concurrent_winner() -> Result<()> {
        let (host, dir) = setup()?;
        let identity = Identity::generate()?;
        let code = host.open_pairing()?;
        let (_, element) = Pairing::start(
            Role::Client,
            &code,
            "test.app",
            [3; 32],
            identity.public(),
            host.0.identity.public(),
        )?;
        let first = host.begin(identity.public(), [3; 32], &element)?.0;
        let second = host.begin(identity.public(), [3; 32], &element)?.0;
        let third = host.begin(identity.public(), [3; 32], &element)?.0;
        assert!(host.begin(identity.public(), [3; 32], &element).is_err());
        assert!(host.consume(third).is_ok());
        assert!(host.consume(first).is_err());
        assert!(host.consume(second).is_err());
        host.open_pairing()?;
        assert!(host.consume(first).is_err());
        let mut guard = host.0.window.lock().unwrap();
        guard.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
        drop(guard);
        assert!(host.begin(identity.public(), [3; 32], &element).is_err());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[test]
    fn malformed_peer_elements_spend_no_online_guess() -> Result<()> {
        let (host, dir) = setup()?;
        host.open_pairing()?;
        let identity = Identity::generate()?;
        for _ in 0..8 {
            assert!(host.begin(identity.public(), [3; 32], &[0; 33]).is_err());
        }
        assert_eq!(host.0.window.lock().unwrap().as_ref().unwrap().attempts, 0);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
