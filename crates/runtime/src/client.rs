use crate::{
    carrier::{self, Carrier, Result, WAIT},
    controls::{HostStatus, ServiceSummary},
    protocol::{self, Session},
    storage::{self, ClientConfig, ServiceKind},
    transfer,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use tether_core::{Identity, Pairing, Role, MAX_PLAINTEXT};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::timeout,
};

#[derive(Clone)]
pub enum Route {
    Direct(SocketAddr),
    Private(String),
    Cloud {
        url: String,
        host_id: String,
        allow_loopback_dev: bool,
    },
}
pub fn validate_private_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.len() > 300 {
        return Err("invalid private endpoint".into());
    }
    let parsed = url::Url::parse(&format!("tcp://{endpoint}"))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.host_str().is_none()
        || parsed.port().is_none_or(|p| p == 0)
        || !parsed.path().is_empty()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("invalid private endpoint".into());
    }
    Ok(())
}
impl Route {
    pub async fn connect(&self, app: &str) -> Result<Carrier> {
        match self {
            Self::Direct(address) => Ok(Carrier::Direct(
                timeout(WAIT, TcpStream::connect(address)).await??,
            )),
            Self::Private(endpoint) => {
                validate_private_endpoint(endpoint)?;
                Ok(Carrier::Direct(
                    timeout(WAIT, TcpStream::connect(endpoint)).await??,
                ))
            }
            Self::Cloud {
                url,
                host_id,
                allow_loopback_dev,
            } => carrier::relay_client(url, app, host_id, *allow_loopback_dev).await,
        }
    }
    fn from_config(config: &ClientConfig, dev: bool) -> Result<Self> {
        match (&config.direct, &config.relay_url, &config.host_id) {
            (Some(address), None, None) => {
                validate_private_endpoint(address)?;
                Ok(Self::Private(address.clone()))
            }
            (None, Some(url), Some(host_id)) => {
                carrier::check_relay_url(url, dev)?;
                if host_id.len() != 52
                    || !host_id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
                {
                    return Err("invalid public route".into());
                }
                Ok(Self::Cloud {
                    url: url.clone(),
                    host_id: host_id.clone(),
                    allow_loopback_dev: dev,
                })
            }
            _ => Err("choose exactly one private or cloud route".into()),
        }
    }
}

pub async fn pair(path: &Path, app: &str, route: Route, code: &str) -> Result<()> {
    storage::app_id(app)?;
    tether_core::normalize_code(code)?;
    if path.exists() {
        return Err("client configuration already exists; recover pending pairing or choose another private file".into());
    }
    let identity = Identity::generate()?;
    let mut session = protocol::initiate(route.connect(app).await?, &identity, app, None).await?;
    let (exchange, element) = Pairing::start(
        Role::Client,
        code,
        app,
        session.binding,
        identity.public(),
        session.peer,
    )?;
    session
        .send(json!({"type":"pair.start","v":1,"element":STANDARD.encode(element)}))
        .await?;
    let reply = session.receive().await?;
    if reply["type"] != "pair.reply" || reply["v"] != 1 {
        return Err("pairing refused".into());
    }
    let confirmation =
        exchange.finish(&STANDARD.decode(reply["element"].as_str().ok_or("missing element")?)?)?;
    confirmation.verify_peer(&STANDARD.decode(reply["proof"].as_str().ok_or("missing proof")?)?)?;
    session
        .send(json!({"type":"pair.confirm","v":1,"proof":STANDARD.encode(confirmation.outbound())}))
        .await?;
    let ready = session.receive().await?;
    if ready["type"] != "pair.ready" || ready["v"] != 1 {
        return Err("pairing refused".into());
    }
    let (direct, relay_url, host_id) = match route {
        Route::Direct(address) => (Some(address.to_string()), None, None),
        Route::Private(address) => (Some(address), None, None),
        Route::Cloud { url, host_id, .. } => (None, Some(url), Some(host_id)),
    };
    let config = ClientConfig {
        version: 1,
        app_id: app.to_owned(),
        private_key: STANDARD.encode(identity.private()),
        host_key: STANDARD.encode(session.peer),
        host_id,
        relay_url,
        direct,
        confirmed: false,
    };
    // A pending record is durable before ack; it is not usable for forwarding until pair.done.
    storage::create(path, &config)?;
    session.send(json!({"type":"pair.ack","v":1})).await?;
    let done = session.receive().await?;
    if done["type"] != "pair.done" || done["v"] != 1 {
        return Err("pairing remains pending".into());
    }
    storage::confirm_client(path, &config)?;
    Ok(())
}

fn validate(config: &ClientConfig) -> Result<()> {
    storage::app_id(&config.app_id)?;
    if config.version != 1 {
        return Err("unsupported client configuration".into());
    }
    storage::key(&config.private_key)?;
    storage::key(&config.host_key)?;
    Ok(())
}
async fn connect(config: &ClientConfig, dev: bool) -> Result<Session> {
    validate(config)?;
    let identity = Identity::from_private(storage::key(&config.private_key)?)?;
    let route = Route::from_config(config, dev)?;
    protocol::initiate(
        route.connect(&config.app_id).await?,
        &identity,
        &config.app_id,
        Some(storage::key(&config.host_key)?),
    )
    .await
}
pub async fn recover(path: &Path, dev: bool) -> Result<()> {
    let config: ClientConfig = storage::load(path)?;
    let mut session = connect(&config, dev).await?;
    session.send(json!({"type":"pair.status","v":1})).await?;
    let reply = session.receive().await?;
    protocol::check_control_reply(&reply)?;
    if reply["type"] != "pair.done" || reply["v"] != 1 {
        return Err("pairing is not confirmed by the host".into());
    }
    storage::confirm_client(path, &config)
}
pub async fn service(path: &Path, name: &str, kind: ServiceKind, dev: bool) -> Result<Session> {
    storage::app_id(name)?;
    let config: ClientConfig = storage::load(path)?;
    if !config.confirmed {
        return Err("pairing remains pending; recover it first".into());
    }
    let mut session = connect(&config, dev).await?;
    session
        .send(json!({"type":"service.open","v":1,"service":name}))
        .await?;
    let reply = session.receive().await?;
    protocol::check_control_reply(&reply)?;
    let expected = match kind {
        ServiceKind::Tcp => "tcp",
        ServiceKind::Udp => "udp",
    };
    if reply["type"] != "service.ready" || reply["v"] != 1 || reply["kind"] != expected {
        return Err("service refused".into());
    }
    Ok(session)
}
pub async fn host_status(path: &Path, dev: bool) -> Result<HostStatus> {
    let config: ClientConfig = storage::load(path)?;
    if !config.confirmed {
        return Err("pairing remains pending".into());
    }
    let mut session = connect(&config, dev).await?;
    session.send(json!({"type":"host.status","v":1})).await?;
    let reply = session.receive().await?;
    protocol::check_control_reply(&reply)?;
    if reply["type"] != "host.status"
        || reply["v"] != 1
        || reply.as_object().is_none_or(|v| v.len() != 3)
    {
        return Err("invalid host status".into());
    }
    let services: Vec<ServiceSummary> = serde_json::from_value(reply["services"].clone())?;
    if services.len() > 32 {
        return Err("host status exceeds limit".into());
    }
    let mut ids = std::collections::BTreeSet::new();
    for service in &services {
        storage::app_id(&service.id)?;
        if !ids.insert(&service.id) {
            return Err("duplicate service identity".into());
        }
    }
    Ok(HostStatus { services })
}
/// Explicit remote self-revocation. The caller retains local trust until an explicit protected-store operation.
pub async fn leave(path: &Path, dev: bool) -> Result<()> {
    let config: ClientConfig = storage::load(path)?;
    if !config.confirmed {
        return Err("pairing remains pending".into());
    }
    let mut session = connect(&config, dev).await?;
    session.send(json!({"type":"peer.leave","v":1})).await?;
    let reply = session.receive().await?;
    protocol::check_control_reply(&reply)?;
    if reply["type"] != "peer.left"
        || reply["v"] != 1
        || reply.as_object().is_none_or(|v| v.len() != 2)
    {
        return Err("invalid leave acknowledgment".into());
    }
    Ok(())
}
pub async fn forward_tcp(
    path: PathBuf,
    name: String,
    listener: TcpListener,
    dev: bool,
) -> Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err("local proxy must bind loopback".into());
    }
    let slots = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (socket, _) = incoming?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let path = path.clone(); let name = name.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let result: Result<()> = async {
                        let session = service(&path, &name, ServiceKind::Tcp, dev).await?;
                        transfer::tcp(session, socket, || Ok(())).await
                    }.await;
                    let _ = result;
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
pub async fn forward_udp(path: PathBuf, name: String, socket: UdpSocket, dev: bool) -> Result<()> {
    if !socket.local_addr()?.ip().is_loopback() {
        return Err("local proxy must bind loopback".into());
    }
    transfer::configure_udp(&socket)?;
    let socket = Arc::new(socket);
    let mut peers = HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new();
    let mut tasks = JoinSet::new();
    let mut buffer = [0; MAX_PLAINTEXT + 1];
    loop {
        tokio::select! {
            incoming = socket.recv_from(&mut buffer) => {
                let (length, peer) = incoming?;
                if length > MAX_PLAINTEXT { continue; }
                if let Some(sender) = peers.get(&peer) { let _ = sender.try_send(buffer[..length].to_vec()); continue; }
                if peers.len() >= 8 { continue; }
                let (sender, receiver) = mpsc::channel(2); peers.insert(peer, sender);
                let path = path.clone(); let name = name.clone(); let socket = socket.clone(); let first = buffer[..length].to_vec();
                tasks.spawn(async move {
                    let result: Result<()> = async {
                        let session = service(&path, &name, ServiceKind::Udp, dev).await?;
                        transfer::udp_proxy(session, socket, first, peer, receiver).await
                    }.await;
                    let _ = result; peer
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => { if let Some(Ok(peer)) = completed { peers.remove(&peer); } }
        }
    }
}

pub struct Media {
    pub client: Arc<tether_media::Client>,
    heartbeat: tokio::task::JoinHandle<()>,
}
impl Drop for Media {
    fn drop(&mut self) {
        self.heartbeat.abort();
        self.client.close();
    }
}
/// Explicit private-route QUIC media. Reliable cloud packet forwarding remains a separate service API.
pub async fn open_media(path: &Path, name: &str) -> Result<Media> {
    storage::app_id(name)?;
    let config: ClientConfig = storage::load(path)?;
    if !config.confirmed || config.direct.is_none() || config.relay_url.is_some() {
        return Err("media requires a paired private route".into());
    }
    let mut session = connect(&config, false).await?;
    let mut address = match &session.carrier {
        Carrier::Direct(socket) => socket.peer_addr()?,
        _ => return Err("media requires private route".into()),
    };
    session
        .send(json!({"v":1,"type":"media.open","service":name}))
        .await?;
    let reply = session.receive().await?;
    protocol::check_control_reply(&reply)?;
    if reply["v"] != 1
        || reply["type"] != "media.ready"
        || reply["heartbeat_seconds"] != 2
        || reply["lease_ttl_seconds"] != 5
    {
        return Err("invalid media offer".into());
    }
    let id = reply["lease_id"]
        .as_str()
        .ok_or("invalid media offer")?
        .to_owned();
    let offer = tether_media::Offer {
        lease_id: STANDARD
            .decode(&id)?
            .try_into()
            .map_err(|_| "invalid media lease")?,
        token: zeroize::Zeroizing::new(
            STANDARD
                .decode(reply["token"].as_str().ok_or("invalid media offer")?)?
                .try_into()
                .map_err(|_| "invalid media token")?,
        ),
        cert_pin: STANDARD
            .decode(reply["cert_pin"].as_str().ok_or("invalid media offer")?)?
            .try_into()
            .map_err(|_| "invalid media pin")?,
        port: reply["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port > 0)
            .ok_or("invalid media port")?,
        max_datagram: reply["max_datagram"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 1200)
            .ok_or("invalid media limit")? as usize,
    };
    address.set_port(offer.port);
    let target: Arc<std::sync::Mutex<Option<std::sync::Weak<tether_media::Client>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let weak = target.clone();
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let status = alive.clone();
    let heartbeat = tokio::spawn(async move {
        let result: Result<()> = async {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + std::time::Duration::from_secs(2),
                std::time::Duration::from_secs(2),
            );
            loop {
                interval.tick().await;
                session
                    .send(json!({"v":1,"type":"media.heartbeat","lease_id":id}))
                    .await?;
                let reply = timeout(std::time::Duration::from_secs(2), session.receive()).await??;
                if reply["v"] != 1 || reply["type"] != "media.alive" {
                    return Err("media heartbeat refused".into());
                }
            }
        }
        .await;
        let _ = result;
        status.store(false, std::sync::atomic::Ordering::Release);
        if let Ok(target) = weak.lock() {
            if let Some(client) = target.as_ref().and_then(std::sync::Weak::upgrade) {
                client.close();
            }
        };
    });
    match tether_media::Client::connect(address, offer).await {
        Ok(client) => {
            let client = Arc::new(client);
            *target.lock().map_err(|_| "media unavailable")? = Some(Arc::downgrade(&client));
            if !alive.load(std::sync::atomic::Ordering::Acquire) {
                heartbeat.abort();
                client.close();
                return Err("media control closed".into());
            }
            Ok(Media { client, heartbeat })
        }
        Err(error) => {
            heartbeat.abort();
            Err(error)
        }
    }
}
