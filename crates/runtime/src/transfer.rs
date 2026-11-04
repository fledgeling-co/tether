use crate::{
    carrier::{Carrier, Reader, Result, WAIT},
    protocol::Session,
};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tether_core::{SecureTransport, MAX_PLAINTEXT};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time::{interval, timeout, Duration},
};

struct Activity {
    started: Instant,
    touched: Instant,
}
impl Activity {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            started: now,
            touched: now,
        }
    }
    fn touch(&mut self) {
        self.touched = Instant::now();
    }
    fn check(&self) -> Result<()> {
        if self.touched.elapsed() > Duration::from_secs(60)
            || self.started.elapsed() > Duration::from_secs(3600)
        {
            return Err("stream deadline reached".into());
        }
        Ok(())
    }
}

pub fn configure_udp(socket: &UdpSocket) -> Result<()> {
    // macOS defaults to a 9216-byte UDP send buffer; the public record limit is 16KiB.
    let socket = socket2::SockRef::from(socket);
    socket.set_send_buffer_size(65_536)?;
    socket.set_recv_buffer_size(262_144)?;
    Ok(())
}

struct Reading(tokio::task::JoinHandle<()>);
impl Drop for Reading {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn incoming(mut reader: Reader) -> (mpsc::Receiver<Result<Vec<u8>>>, Reading) {
    let (sender, receiver) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        loop {
            let value = reader.receive().await;
            let failed = value.is_err();
            if sender.send(value).await.is_err() || failed {
                break;
            }
        }
    });
    (receiver, Reading(task))
}

pub async fn tcp(
    session: Session,
    target: TcpStream,
    authorize: impl Fn() -> Result<()> + Send + Sync,
) -> Result<()> {
    pump_tcp(session.carrier, Some(session.cipher), target, authorize).await
}

/// Explicit application-TLS adapter only. The inner application authenticates TLS and owns authorization.
pub async fn application_tls(carrier: Carrier, target: TcpStream) -> Result<()> {
    pump_tcp(carrier, None, target, || Ok(())).await
}
pub async fn application_tls_guarded(
    carrier: Carrier,
    target: TcpStream,
    authorize: impl Fn() -> Result<()> + Send + Sync,
) -> Result<()> {
    pump_tcp(carrier, None, target, authorize).await
}

async fn pump_tcp(
    carrier: Carrier,
    cipher: Option<SecureTransport>,
    mut target: TcpStream,
    authorize: impl Fn() -> Result<()> + Send + Sync,
) -> Result<()> {
    let (mut reader, mut writer) = carrier.split();
    let (mut target_reader, mut target_writer) = target.split();
    let encrypted = cipher.is_some();
    let cipher = Mutex::new(cipher);
    let activity = Mutex::new(Activity::new());
    let result = {
        let to_target = async {
            loop {
                let record = reader.receive().await?;
                authorize()?;
                activity.lock().map_err(|_| "stream unavailable")?.touch();
                let bytes = {
                    let mut cipher = cipher.lock().map_err(|_| "stream unavailable")?;
                    match cipher.as_mut() {
                        Some(cipher) => cipher.decrypt(&record)?,
                        None => record,
                    }
                };
                let limit = if encrypted {
                    MAX_PLAINTEXT
                } else {
                    crate::carrier::MAX_FRAME
                };
                if bytes.len() > limit {
                    return Err::<(), crate::carrier::Error>("record exceeds limit".into());
                }
                if bytes.is_empty() {
                    target_writer.shutdown().await?;
                    return Ok(());
                }
                timeout(WAIT, target_writer.write_all(&bytes)).await??;
            }
        };
        let from_target = async {
            let mut bytes = [0; MAX_PLAINTEXT];
            loop {
                let n = target_reader.read(&mut bytes).await?;
                authorize()?;
                activity.lock().map_err(|_| "stream unavailable")?.touch();
                let record = {
                    let mut cipher = cipher.lock().map_err(|_| "stream unavailable")?;
                    match cipher.as_mut() {
                        Some(cipher) => cipher.encrypt(&bytes[..n])?,
                        None => bytes[..n].to_vec(),
                    }
                };
                writer.send(&record).await?;
                if n == 0 {
                    return Ok::<(), crate::carrier::Error>(());
                }
            }
        };
        let duplex = async {
            tokio::try_join!(to_target, from_target)?;
            Ok::<(), crate::carrier::Error>(())
        };
        let guard = async {
            let mut check = interval(Duration::from_millis(500));
            loop {
                check.tick().await;
                authorize()?;
                activity.lock().map_err(|_| "stream unavailable")?.check()?;
            }
        };
        tokio::select! {result=duplex=>result,result=guard=>result}
    };
    writer.close().await;
    result
}

pub async fn udp(
    session: Session,
    socket: UdpSocket,
    authorize: impl Fn() -> Result<()> + Send,
) -> Result<()> {
    configure_udp(&socket)?;
    let (reader, mut writer) = session.carrier.split();
    let (mut received, _reading) = incoming(reader);
    let mut cipher = session.cipher;
    let mut buffer = [0; MAX_PLAINTEXT + 1];
    let mut check = interval(Duration::from_millis(500));
    let mut activity = Activity::new();
    let result: Result<()> = async {
        loop {
            tokio::select! {
                _ = check.tick() => {authorize()?;activity.check()?;},
                record = received.recv() => {
                    authorize()?;
                    activity.touch();
                    let bytes = cipher.decrypt(&record.ok_or("carrier closed")??)?;
                    timeout(WAIT, socket.send(&bytes)).await??;
                }
                length = socket.recv(&mut buffer) => {
                    authorize()?;
                    activity.touch();
                    let length = length?;
                    if length > MAX_PLAINTEXT { return Err("datagram exceeds limit".into()); }
                    writer.send(&cipher.encrypt(&buffer[..length])?).await?;
                }
            }
        }
    }
    .await;
    writer.close().await;
    result
}

pub async fn udp_proxy(
    session: Session,
    socket: Arc<UdpSocket>,
    first: Vec<u8>,
    peer: std::net::SocketAddr,
    mut outgoing: mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    let (reader, mut writer) = session.carrier.split();
    let (mut received, _reading) = incoming(reader);
    let mut cipher = session.cipher;
    writer.send(&cipher.encrypt(&first)?).await?;
    let mut activity = Activity::new();
    let mut check = interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            _=check.tick()=>activity.check()?,
            record = received.recv() => {
                activity.touch();
                let bytes = cipher.decrypt(&record.ok_or("carrier closed")??)?;
                timeout(WAIT, socket.send_to(&bytes, peer)).await??;
            }
            bytes = outgoing.recv() => {
                activity.touch();
                let bytes = bytes.ok_or("proxy closed")?;
                writer.send(&cipher.encrypt(&bytes)?).await?;
            }
        }
    }
}
