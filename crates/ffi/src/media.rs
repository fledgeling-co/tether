//! Asynchronous QUIC handles; no registry lock is held during DNS or network I/O.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use tether_media::{Client, Offer};
use zeroize::Zeroizing;
const MAX_HANDLES: usize = 64;
enum Phase {
    Connecting,
    Ready(Arc<Client>),
    Failed,
    Closed,
}
struct Handle {
    waiter: AtomicBool,
    phase: Mutex<Phase>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
impl Handle {
    fn arm(
        &self,
        runtime: &tokio::runtime::Runtime,
        future: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), &'static str> {
        let mut task = self.task.lock().map_err(|_| "media_unavailable")?;
        if matches!(
            *self.phase.lock().map_err(|_| "media_unavailable")?,
            Phase::Closed
        ) {
            return Err("media_closed");
        }
        *task = Some(runtime.spawn(future));
        Ok(())
    }
    fn close(&self) {
        let Ok(mut task) = self.task.lock() else {
            return;
        };
        if let Ok(mut phase) = self.phase.lock() {
            if let Phase::Ready(client) = &*phase {
                client.close();
            }
            *phase = Phase::Closed;
        }
        if let Some(task) = task.take() {
            task.abort();
        }
    }
}
struct Registry {
    next: u64,
    handles: HashMap<u64, Arc<Handle>>,
}
static HANDLES: OnceLock<Mutex<Registry>> = OnceLock::new();
static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
static RESOLVERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    HANDLES.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            handles: HashMap::new(),
        })
    })
}
fn field<'a>(request: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    request[key].as_str().ok_or("invalid_request")
}
fn fixed<const N: usize>(request: &Value, key: &str) -> Result<[u8; N], &'static str> {
    let bytes = Zeroizing::new(
        STANDARD
            .decode(field(request, key)?)
            .map_err(|_| "invalid_request")?,
    );
    bytes.as_slice().try_into().map_err(|_| "invalid_request")
}
fn address(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((prefix, zone)) = value.split_once('%') {
        return prefix.parse::<std::net::Ipv6Addr>().is_ok()
            && !zone.is_empty()
            && zone.len() <= 32
            && zone
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            && (!zone.bytes().all(|byte| byte.is_ascii_digit())
                || zone.parse::<u32>().is_ok_and(|index| index > 0));
    }
    value.len() <= 253
        && !value.is_empty()
        && value.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
pub fn perform(request: &Value) -> Result<Value, &'static str> {
    let command = field(request, "command")?;
    if command == "media.client.start" {
        let name = field(request, "address")?.to_owned();
        if !address(&name) {
            return Err("invalid_request");
        }
        let port = request["port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or("invalid_request")?;
        let offer = Offer {
            lease_id: fixed(request, "lease_id")?,
            token: Zeroizing::new(fixed(request, "token")?),
            cert_pin: fixed(request, "cert_pin")?,
            port,
            max_datagram: 1200,
        };
        let runtime = RUNTIME
            .get_or_init(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .max_blocking_threads(2)
                    .enable_all()
                    .build()
                    .ok()
            })
            .as_ref()
            .ok_or("media_unavailable")?;
        let item = Arc::new(Handle {
            waiter: AtomicBool::new(false),
            phase: Mutex::new(Phase::Connecting),
            task: Mutex::new(None),
        });
        let handle = {
            let mut registry = registry().lock().map_err(|_| "media_unavailable")?;
            if registry.handles.len() >= MAX_HANDLES {
                return Err("media_handle_quota");
            }
            let id = registry.next;
            registry.next = registry.next.checked_add(1).ok_or("media_handle_quota")?;
            registry.handles.insert(id, item.clone());
            id
        };
        let state = item.clone();
        item.arm(runtime, async move {
            let result = tokio::time::timeout(tether_media::CONNECT_WAIT, async {
                let resolved = if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                    vec![std::net::SocketAddr::new(ip, port)]
                } else {
                    let permit = RESOLVERS
                        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
                        .clone()
                        .try_acquire_owned()
                        .map_err(|_| "media resolution busy")?;
                    tokio::task::spawn_blocking(
                        move || -> std::io::Result<Vec<std::net::SocketAddr>> {
                            use std::net::ToSocketAddrs;
                            let _permit = permit;
                            let mut resolved = Vec::new();
                            for address in (name.as_str(), port).to_socket_addrs()?.take(16) {
                                if !resolved.contains(&address) {
                                    resolved.push(address);
                                }
                            }
                            Ok(resolved)
                        },
                    )
                    .await??
                };
                let mut targets = Vec::new();
                if let Some(address) = resolved.iter().find(|address| address.is_ipv4()) {
                    targets.push(*address);
                }
                if let Some(address) = resolved.iter().find(|address| address.is_ipv6()) {
                    targets.push(*address);
                }
                for address in resolved {
                    if !targets.contains(&address) {
                        targets.push(address);
                    }
                    if targets.len() == 4 {
                        break;
                    }
                }
                Client::connect_candidates(targets, offer).await
            })
            .await;
            if let Ok(mut phase) = state.phase.lock() {
                if matches!(*phase, Phase::Closed) {
                    return;
                }
                *phase = match result {
                    Ok(Ok(client)) => Phase::Ready(Arc::new(client)),
                    _ => Phase::Failed,
                };
            };
        })?;
        return Ok(json!({"handle":handle,"state":"connecting"}));
    }
    let id = request["handle"].as_u64().ok_or("invalid_handle")?;
    let item = {
        let mut registry = registry().lock().map_err(|_| "media_unavailable")?;
        if command == "media.close" {
            registry.handles.remove(&id)
        } else {
            registry.handles.get(&id).cloned()
        }
        .ok_or("invalid_handle")?
    };
    if command == "media.close" {
        item.close();
        return Ok(json!({"state":"closed"}));
    }
    let phase = item.phase.lock().map_err(|_| "media_unavailable")?;
    let client = match &*phase {
        Phase::Ready(client) if !client.is_closed() => client.clone(),
        _ => {
            let state = match &*phase {
                Phase::Connecting => "connecting",
                Phase::Failed => "failed",
                _ => "closed",
            };
            return if matches!(
                command,
                "media.poll" | "media.receive" | "media.receive_wait"
            ) {
                Ok(json!({"state":state}))
            } else {
                Err(if state == "connecting" {
                    "media_not_ready"
                } else {
                    "media_closed"
                })
            };
        }
    };
    drop(phase);
    match command {
        "media.poll" => Ok(json!({"state":"ready","max_datagram":client.max_datagram()})),
        "media.send" => {
            let encoded = field(request, "data")?;
            if encoded.len() > 1600 {
                return Err("media_packet_too_large");
            }
            let bytes = STANDARD.decode(encoded).map_err(|_| "invalid_request")?;
            client.send(&bytes)?;
            Ok(json!({"accepted":true}))
        }
        "media.receive_wait" => {
            let millis = request["timeout_ms"]
                .as_u64()
                .filter(|value| *value <= 100)
                .ok_or("invalid_request")?;
            if item
                .waiter
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err("media_receive_busy");
            }
            struct Waiting<'a>(&'a AtomicBool);
            impl Drop for Waiting<'_> {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _waiting = Waiting(&item.waiter);
            match client.receive_wait(std::time::Duration::from_millis(millis)) {
                Ok(Some(data)) => Ok(json!({"state":"data","data":STANDARD.encode(data)})),
                Ok(None) => Ok(json!({"state":"pending"})),
                Err("media_closed") => Ok(json!({"state":"closed"})),
                Err(error) => Err(error),
            }
        }
        "media.receive" => Ok(match client.receive() {
            Some(data) => json!({"state":"data","data":STANDARD.encode(data)}),
            None => json!({"state":"pending"}),
        }),
        "media.stats" => {
            let stats = client.stats();
            Ok(
                json!({"rtt_ms":stats.rtt_ms,"bytes_sent":stats.bytes_sent,"bytes_received":stats.bytes_received,"packets_sent":stats.packets_sent,"packets_received":stats.packets_received,"dropped":stats.dropped}),
            )
        }
        _ => Err("invalid_command"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn media_addresses_and_handles_are_bounded_and_cancellation_is_explicit() {
        for value in [
            "127.0.0.1",
            "::1",
            "host.local",
            "my-host.example.test",
            "fe80::1%en0",
            "fe80::1%3",
        ] {
            assert!(address(value));
        }
        for value in [
            "",
            "user@host",
            "wss://host",
            "host/path",
            "host?query",
            "-bad.local",
            "fe80::1%0",
            "fe80::1%bad/zone",
            "host%en0",
        ] {
            assert!(!address(value));
        }
        assert!(perform(&json!({"command":"media.poll","handle":u64::MAX})).is_err());
    }
    #[test]
    fn closing_a_reserved_handle_before_task_install_never_starts_connection_work() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let item = Handle {
            waiter: AtomicBool::new(false),
            phase: Mutex::new(Phase::Connecting),
            task: Mutex::new(None),
        };
        item.close();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = ran.clone();
        assert_eq!(
            item.arm(&runtime, async move {
                state.store(true, std::sync::atomic::Ordering::Release);
            }),
            Err("media_closed")
        );
        assert!(!ran.load(std::sync::atomic::Ordering::Acquire));
        assert!(item.task.lock().unwrap().is_none());
    }
    #[tokio::test]
    async fn native_json_media_api_roundtrips_encoded_packets_and_reports_stats() {
        use tether_media::{Context, Server};
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut bytes = [0; 1201];
            while let Ok((n, peer)) = socket.recv_from(&mut bytes).await {
                let _ = socket.send_to(&bytes[..n], peer).await;
            }
        });
        let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let (offer, guard) = server
            .open(
                Context {
                    app: "test.ffi".into(),
                    peer: [1; 32],
                    binding: [2; 32],
                    service: "audio".into(),
                },
                target,
                Arc::new(|| true),
            )
            .unwrap();
        let started=perform(&json!({"command":"media.client.start","address":"localhost","port":offer.port,"cert_pin":STANDARD.encode(offer.cert_pin),"lease_id":STANDARD.encode(offer.lease_id),"token":STANDARD.encode(offer.token.as_ref())})).unwrap();
        let id = started["handle"].as_u64().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(4), async {
            loop {
                guard.heartbeat().unwrap();
                let state = perform(&json!({"command":"media.poll","handle":id})).unwrap();
                if state["state"] == "ready" {
                    assert!(state["max_datagram"].as_u64().unwrap() <= 1152);
                    break;
                }
                assert_ne!(state["state"], "failed");
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        let bytes = include_bytes!("../../../tests/fixtures/media/audio.ogg");
        perform(&json!({"command":"media.send","handle":id,"data":STANDARD.encode(bytes)}))
            .unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking(move || loop {
                let data =
                    perform(&json!({"command":"media.receive_wait","handle":id,"timeout_ms":100}))
                        .unwrap();
                if data["state"] == "data" {
                    break STANDARD.decode(data["data"].as_str().unwrap()).unwrap();
                }
                assert_eq!(data["state"], "pending");
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.as_slice(), bytes.as_slice());
        let stats = perform(&json!({"command":"media.stats","handle":id})).unwrap();
        assert_eq!(stats["packets_sent"], 1);
        assert_eq!(stats["bytes_received"], bytes.len());
        assert_eq!(
            perform(&json!({"command":"media.receive_wait","handle":id,"timeout_ms":101}))
                .unwrap_err(),
            "invalid_request"
        );
        let item = registry().lock().unwrap().handles.get(&id).unwrap().clone();
        let waiter = tokio::task::spawn_blocking(move || {
            perform(&json!({"command":"media.receive_wait","handle":id,"timeout_ms":100}))
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !item.waiter.load(Ordering::Acquire) {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            perform(&json!({"command":"media.receive_wait","handle":id,"timeout_ms":0}))
                .unwrap_err(),
            "media_receive_busy"
        );
        // Closing another caller's owned handle wakes its parked receiver without holding the registry.
        perform(&json!({"command":"media.close","handle":id})).unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(80), waiter)
                .await
                .unwrap()
                .unwrap()
                .unwrap()["state"],
            "closed"
        );
        assert!(perform(&json!({"command":"media.poll","handle":id})).is_err());
        echo.abort();
    }
}
