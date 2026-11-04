use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tether::{
    carrier::Result,
    client::{self, Route},
    host::Host,
    storage::{self, ClientConfig, HostConfig, Service, ServiceKind},
};
use tether_relay::{Limits, Relay};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

struct Fixture {
    root: PathBuf,
    host: Host,
    config: PathBuf,
    route: Route,
    accepted: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(tether::host::control_path(&self.config));
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
impl Fixture {
    async fn new(cloud: bool) -> Result<Self> {
        let root =
            std::env::temp_dir().join(format!("tether-network-{:032x}", rand::random::<u128>()));
        #[cfg(unix)]
        {
            std::fs::create_dir(&root)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_address = tcp.local_addr()?;
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let udp_address = udp.local_addr()?;
        tether::transfer::configure_udp(&udp)?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = tcp.accept().await else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut bytes = [0; 8192];
                    while let Ok(count) = socket.read(&mut bytes).await {
                        if count == 0 {
                            break;
                        }
                        if socket.write_all(&bytes[..count]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let udp_task = tokio::spawn(async move {
            let mut bytes = [0; 32769];
            loop {
                let Ok((count, peer)) = udp.recv_from(&mut bytes).await else {
                    break;
                };
                let _ = udp.send_to(&bytes[..count], peer).await;
            }
        });
        let services = BTreeMap::from([
            (
                "api".into(),
                Service {
                    kind: ServiceKind::Tcp,
                    target: tcp_address,
                },
            ),
            (
                "video".into(),
                Service {
                    kind: ServiceKind::Udp,
                    target: udp_address,
                },
            ),
        ]);
        let config = root.join("host.json");
        storage::create(&config, &HostConfig::new("test.app", services)?)?;
        let host = Host::load(&config)?;
        let mut tasks = vec![tcp_task, udp_task];
        let route = if cloud {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let relay = Relay::new(Limits {
                allowed_hosts: Some(HashSet::from([host.public_route_id()])),
                ..Limits::default()
            });
            let state = relay.clone();
            tasks.push(tokio::spawn(async move {
                let _ = tether_relay::serve(listener, relay).await;
            }));
            let url = format!("ws://{address}/v1/relay");
            let server = host.clone();
            let destination = url.clone();
            tasks.push(tokio::spawn(async move {
                let _ = server.serve_relay(&destination, true, None).await;
            }));
            timeout(Duration::from_secs(3), async {
                while state.stats().hosts == 0 {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            Route::Cloud {
                url,
                host_id: host.public_route_id(),
                allow_loopback_dev: true,
            }
        } else {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let server = host.clone();
            tasks.push(tokio::spawn(async move {
                let _ = server.serve_direct(listener).await;
            }));
            Route::Direct(address)
        };
        Ok(Self {
            root,
            host,
            config,
            route,
            accepted,
            tasks,
        })
    }
    async fn pair(&self, name: &str) -> Result<PathBuf> {
        let code = self.host.open_pairing()?;
        let path = self.root.join(format!("{name}.json"));
        client::pair(&path, "test.app", self.route.clone(), &code).await?;
        Ok(path)
    }
}

#[tokio::test]
async fn real_relay_tcp_proxy_pairs_persists_chunks_and_propagates_half_close() -> Result<()> {
    let mut f = Fixture::new(true).await?;
    let client = f.pair("client").await?;
    let saved: ClientConfig = storage::load(&client)?;
    assert!(saved.confirmed);
    let host: HostConfig = storage::load(&f.config)?;
    assert_eq!(host.devices.len(), 1);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    f.tasks.push(tokio::spawn(async move {
        let _ = client::forward_tcp(client, "api".into(), listener, true).await;
    }));
    let mut socket = TcpStream::connect(address).await?;
    let expected: Vec<u8> = (0..90000).map(|i| (i % 251) as u8).collect();
    socket.write_all(&expected).await?;
    socket.shutdown().await?;
    let mut actual = Vec::new();
    timeout(Duration::from_secs(5), socket.read_to_end(&mut actual)).await??;
    assert_eq!(actual, expected);
    assert_eq!(f.accepted.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn real_relay_udp_proxy_preserves_empty_maximum_datagrams_and_separate_local_peers(
) -> Result<()> {
    let mut f = Fixture::new(true).await?;
    let path = f.pair("client").await?;
    let proxy = UdpSocket::bind("127.0.0.1:0").await?;
    let address = proxy.local_addr()?;
    f.tasks.push(tokio::spawn(async move {
        let _ = client::forward_udp(path, "video".into(), proxy, true).await;
    }));
    let a = UdpSocket::bind("127.0.0.1:0").await?;
    let b = UdpSocket::bind("127.0.0.1:0").await?;
    tether::transfer::configure_udp(&a)?;
    tether::transfer::configure_udp(&b)?;
    for (socket, expected) in [
        (&a, vec![4; 16384]),
        (&b, b"other-local-peer".to_vec()),
        (&a, Vec::new()),
        (&b, vec![9; 137]),
    ] {
        socket.send_to(&expected, address).await?;
        let mut bytes = [0; 16385];
        let (count, _) = timeout(Duration::from_secs(4), socket.recv_from(&mut bytes)).await??;
        assert_eq!(&bytes[..count], expected);
    }
    a.send_to(&vec![1; 16385], address).await?;
    let mut bytes = [0; 16385];
    assert!(timeout(Duration::from_millis(150), a.recv_from(&mut bytes))
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn private_direct_pairing_and_tcp_need_no_relay() -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("client").await?;
    let mut session = client::service(&path, "api", ServiceKind::Tcp, false).await?;
    session
        .carrier
        .send(&session.cipher.encrypt(b"private")?)
        .await?;
    let bytes = session.carrier.receive().await?;
    assert_eq!(session.cipher.decrypt(&bytes)?, b"private");
    Ok(())
}

#[tokio::test]
async fn private_hostname_endpoint_is_an_explicit_route_without_cloud_fallback() -> Result<()> {
    let f = Fixture::new(false).await?;
    let Route::Direct(address) = f.route else {
        unreachable!()
    };
    let route = Route::Private(format!("localhost:{}", address.port()));
    let path = f.root.join("hostname.json");
    let code = f.host.open_pairing()?;
    client::pair(&path, "test.app", route, &code).await?;
    assert!(client::service(&path, "api", ServiceKind::Tcp, false)
        .await
        .is_ok());
    assert!(client::validate_private_endpoint("user:pass@localhost:7445").is_err());
    assert!(client::validate_private_endpoint("localhost:7445/path").is_err());
    Ok(())
}

#[tokio::test]
async fn noise_terminating_mitm_cannot_relay_a_pairing_confirmation() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    let upstream = f.route.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    f.tasks.push(tokio::spawn(async move {
        let result: Result<()> = async {
            let (socket, _) = listener.accept().await?;
            let identity = tether_core::Identity::generate()?;
            let mut downstream = tether::protocol::respond(
                tether::carrier::Carrier::Direct(socket),
                &identity,
                "test.app",
            )
            .await?;
            let mut host = tether::protocol::initiate(
                upstream.connect("test.app").await?,
                &identity,
                "test.app",
                None,
            )
            .await?;
            host.send(downstream.receive().await?).await?;
            downstream.send(host.receive().await?).await?;
            host.send(downstream.receive().await?).await?;
            Ok(())
        }
        .await;
        let _ = result;
    }));
    let code = f.host.open_pairing()?;
    let path = f.root.join("mitm.json");
    assert!(
        client::pair(&path, "test.app", Route::Direct(address), &code)
            .await
            .is_err()
    );
    assert!(!path.exists());
    assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
    assert_eq!(f.accepted.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn host_persistence_failure_never_sends_done_or_confirms_pending_client() -> Result<()> {
    let f = Fixture::new(false).await?;
    let code = f.host.open_pairing()?;
    let identity = tether_core::Identity::generate()?;
    let mut session = tether::protocol::initiate(
        f.route.connect("test.app").await?,
        &identity,
        "test.app",
        None,
    )
    .await?;
    let (exchange, element) = tether_core::Pairing::start(
        tether_core::Role::Client,
        &code,
        "test.app",
        session.binding,
        identity.public(),
        session.peer,
    )?;
    session
        .send(serde_json::json!({"type":"pair.start","v":1,"element":STANDARD.encode(element)}))
        .await?;
    let reply = session.receive().await?;
    let confirmation = exchange.finish(&STANDARD.decode(reply["element"].as_str().unwrap())?)?;
    confirmation.verify_peer(&STANDARD.decode(reply["proof"].as_str().unwrap())?)?;
    session.send(serde_json::json!({"type":"pair.confirm","v":1,"proof":STANDARD.encode(confirmation.outbound())})).await?;
    assert_eq!(session.receive().await?["type"], "pair.ready");
    let Route::Direct(address) = f.route else {
        unreachable!()
    };
    let pending = ClientConfig {
        version: 1,
        app_id: "test.app".into(),
        private_key: STANDARD.encode(identity.private()),
        host_key: STANDARD.encode(session.peer),
        direct: Some(address.to_string()),
        relay_url: None,
        host_id: None,
        confirmed: false,
    };
    let path = f.root.join("pending.json");
    storage::create(&path, &pending)?;
    let backup = f.root.join("host-backup.json");
    std::fs::rename(&f.config, &backup)?;
    session
        .send(serde_json::json!({"type":"pair.ack","v":1}))
        .await?;
    assert!(session.receive().await.is_err());
    assert!(!storage::load::<ClientConfig>(&path)?.confirmed);
    assert!(storage::load::<HostConfig>(&backup)?.devices.is_empty());
    std::fs::rename(backup, &f.config)?;
    Ok(())
}

#[tokio::test]
async fn encrypted_record_replay_is_refused_and_never_echoed_twice() -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("client").await?;
    let mut session = client::service(&path, "api", ServiceKind::Tcp, false).await?;
    let record = session.cipher.encrypt(b"one-record")?;
    session.carrier.send(&record).await?;
    let reply = session.carrier.receive().await?;
    assert_eq!(session.cipher.decrypt(&reply)?, b"one-record");
    session.carrier.send(&record).await?;
    assert!(session.carrier.receive().await.is_err());
    assert_eq!(f.accepted.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn attacker_cannot_skip_mutual_confirmation_and_commit_a_phone() -> Result<()> {
    let f = Fixture::new(false).await?;
    let actual = f.host.open_pairing()?;
    let wrong = if actual == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    let identity = tether_core::Identity::generate()?;
    let mut session = tether::protocol::initiate(
        f.route.connect("test.app").await?,
        &identity,
        "test.app",
        None,
    )
    .await?;
    let (_, element) = tether_core::Pairing::start(
        tether_core::Role::Client,
        wrong,
        "test.app",
        session.binding,
        identity.public(),
        session.peer,
    )?;
    session
        .send(serde_json::json!({"type":"pair.start","v":1,"element":STANDARD.encode(element)}))
        .await?;
    assert_eq!(session.receive().await?["type"], "pair.reply");
    session
        .send(serde_json::json!({"type":"pair.confirm","v":1,"proof":STANDARD.encode([0;32])}))
        .await?;
    assert!(session.receive().await.is_err());
    assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
    Ok(())
}

#[tokio::test]
async fn actual_client_library_keeps_pending_record_when_host_never_sends_done() -> Result<()> {
    let mut f = Fixture::new(false).await?;
    let code = f.host.open_pairing()?;
    let host_code = code.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    f.tasks.push(tokio::spawn(async move {
        let result:Result<()>=async {
            let (socket,_)=listener.accept().await?;let identity=tether_core::Identity::generate()?;
            let mut session=tether::protocol::respond(tether::carrier::Carrier::Direct(socket),&identity,"test.app").await?;
            let request=session.receive().await?;
            let (exchange,element)=tether_core::Pairing::start(tether_core::Role::Host,&host_code,"test.app",session.binding,session.peer,identity.public())?;
            let confirmation=exchange.finish(&STANDARD.decode(request["element"].as_str().unwrap())?)?;
            session.send(serde_json::json!({"type":"pair.reply","v":1,"element":STANDARD.encode(element),"proof":STANDARD.encode(confirmation.outbound())})).await?;
            let confirm=session.receive().await?;confirmation.verify_peer(&STANDARD.decode(confirm["proof"].as_str().unwrap())?)?;
            session.send(serde_json::json!({"type":"pair.ready","v":1})).await?;
            assert_eq!(session.receive().await?["type"],"pair.ack");
            // Simulates a failed durable host commit: no done is sent.
            Ok(())
        }.await;let _=result;
    }));
    let path = f.root.join("pending-real-client.json");
    assert!(
        client::pair(&path, "test.app", Route::Direct(address), &code)
            .await
            .is_err()
    );
    assert!(!storage::load::<ClientConfig>(&path)?.confirmed);
    assert!(client::service(&path, "api", ServiceKind::Tcp, false)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn drop_after_pending_store_before_ack_can_be_explicitly_abandoned_and_paired_again(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let code = f.host.open_pairing()?;
    let identity = tether_core::Identity::generate()?;
    let mut session = tether::protocol::initiate(
        f.route.connect("test.app").await?,
        &identity,
        "test.app",
        None,
    )
    .await?;
    let (exchange, element) = tether_core::Pairing::start(
        tether_core::Role::Client,
        &code,
        "test.app",
        session.binding,
        identity.public(),
        session.peer,
    )?;
    session
        .send(serde_json::json!({"type":"pair.start","v":1,"element":STANDARD.encode(element)}))
        .await?;
    let reply = session.receive().await?;
    let confirmation = exchange.finish(&STANDARD.decode(reply["element"].as_str().unwrap())?)?;
    confirmation.verify_peer(&STANDARD.decode(reply["proof"].as_str().unwrap())?)?;
    session.send(serde_json::json!({"type":"pair.confirm","v":1,"proof":STANDARD.encode(confirmation.outbound())})).await?;
    assert_eq!(session.receive().await?["type"], "pair.ready");
    let Route::Direct(address) = f.route else {
        unreachable!()
    };
    let pending = ClientConfig {
        version: 1,
        app_id: "test.app".into(),
        private_key: STANDARD.encode(identity.private()),
        host_key: STANDARD.encode(session.peer),
        direct: Some(address.to_string()),
        relay_url: None,
        host_id: None,
        confirmed: false,
    };
    let path = f.root.join("pending-before-ack.json");
    storage::create(&path, &pending)?;
    drop(session); // A real socket closes before pair.ack; the host has no durable device record.
    sleep(Duration::from_millis(30)).await;
    assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
    assert!(client::recover(&path, false).await.is_err());
    assert!(storage::abandon_pending(&path, "other.app").is_err());
    assert!(path.exists());
    assert_eq!(
        storage::abandon_pending(&path, "test.app")?,
        storage::device_id(&identity.public())
    );
    assert!(!path.exists());
    let fresh = f.host.open_pairing()?;
    client::pair(&path, "test.app", f.route.clone(), &fresh).await?;
    assert!(storage::load::<ClientConfig>(&path)?.confirmed);
    assert!(storage::abandon_pending(&path, "test.app").is_err());
    assert!(path.exists());
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn owner_pair_code_cli_uses_private_local_control_and_prints_only_explicit_codes(
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = Fixture::new(false).await?;
    let executable = env!("CARGO_BIN_EXE_tether");
    let description = tokio::process::Command::new(executable)
        .args(["host", "describe", "--config"])
        .arg(&f.config)
        .output()
        .await?;
    assert!(description.status.success());
    assert_eq!(
        String::from_utf8(description.stdout)?.trim(),
        f.host.public_route_id()
    );
    let mut child = tokio::process::Command::new(executable)
        .args(["host", "run", "--config"])
        .arg(&f.config)
        .args(["--direct", "127.0.0.1:0", "--pair"])
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let mut reader = BufReader::new(child.stdout.take().ok_or("missing test output")?);
    let mut first = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut first)).await??;
    assert_eq!(first.len(), 9);
    assert!(tether_core::normalize_code(first.trim()).is_ok());
    let control = tether::host::control_path(&f.config);
    timeout(Duration::from_secs(2), async {
        while !control.exists() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let second = tokio::process::Command::new(executable)
        .args(["host", "pair-code", "--config"])
        .arg(&f.config)
        .output()
        .await?;
    assert!(second.status.success());
    let second = String::from_utf8(second.stdout)?;
    assert_eq!(second.len(), 9);
    assert!(tether_core::normalize_code(second.trim()).is_ok());
    child.kill().await?;
    child.wait().await?;
    Ok(())
}

#[tokio::test]
async fn wrong_codes_burn_three_starts_and_scope_mismatch_never_pairs() -> Result<()> {
    let f = Fixture::new(false).await?;
    let code = f.host.open_pairing()?;
    let wrong = if code == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    for i in 0..3 {
        assert!(client::pair(
            &f.root.join(format!("wrong-{i}.json")),
            "test.app",
            f.route.clone(),
            wrong
        )
        .await
        .is_err());
    }
    assert!(client::pair(
        &f.root.join("burned.json"),
        "test.app",
        f.route.clone(),
        &code
    )
    .await
    .is_err());
    let code = f.host.open_pairing()?;
    assert!(client::pair(
        &f.root.join("scope.json"),
        "other.app",
        f.route.clone(),
        &code
    )
    .await
    .is_err());
    assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
    assert_eq!(f.accepted.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn unpaired_wrong_host_unauthorized_service_and_revoked_peers_cannot_open_targets(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("client").await?;
    let mut saved: ClientConfig = storage::load(&path)?;
    saved.private_key = STANDARD.encode(tether_core::Identity::generate()?.private());
    let unknown = f.root.join("unknown.json");
    storage::create(&unknown, &saved)?;
    assert!(client::service(&unknown, "api", ServiceKind::Tcp, false)
        .await
        .is_err());
    let mut saved: ClientConfig = storage::load(&path)?;
    saved.host_key = STANDARD.encode(tether_core::Identity::generate()?.public());
    let impostor = f.root.join("impostor.json");
    storage::create(&impostor, &saved)?;
    assert!(client::service(&impostor, "api", ServiceKind::Tcp, false)
        .await
        .is_err());
    storage::update_host(&f.config, |config| {
        for device in config.devices.values_mut() {
            device.services.remove("video");
        }
        Ok(())
    })?;
    assert!(client::service(&path, "video", ServiceKind::Udp, false)
        .await
        .is_err());
    assert_eq!(f.accepted.load(Ordering::SeqCst), 0);
    let mut session = client::service(&path, "api", ServiceKind::Tcp, false).await?;
    session
        .carrier
        .send(&session.cipher.encrypt(b"before-revoke")?)
        .await?;
    let frame = session.carrier.receive().await?;
    assert_eq!(session.cipher.decrypt(&frame)?, b"before-revoke");
    storage::update_host(&f.config, |config| {
        config.devices.clear();
        Ok(())
    })?;
    assert!(timeout(Duration::from_secs(2), session.carrier.receive())
        .await?
        .is_err());
    assert!(client::service(&path, "api", ServiceKind::Tcp, false)
        .await
        .is_err());
    Ok(())
}

#[tokio::test]
async fn failed_client_persistence_leaves_no_host_device_and_pending_records_cannot_forward(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let code = f.host.open_pairing()?;
    let public = f.root.join("unsafe");
    std::fs::create_dir(&public)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755))?;
    }
    assert!(client::pair(
        &public.join("client.json"),
        "test.app",
        f.route.clone(),
        &code
    )
    .await
    .is_err());
    sleep(Duration::from_millis(30)).await;
    assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
    let path = f.pair("confirmed").await?;
    let mut saved: ClientConfig = storage::load(&path)?;
    saved.confirmed = false;
    let pending = f.root.join("pending.json");
    storage::create(&pending, &saved)?;
    assert!(client::service(&pending, "api", ServiceKind::Tcp, false)
        .await
        .is_err());
    client::recover(&pending, false).await?;
    assert!(storage::load::<ClientConfig>(&pending)?.confirmed);
    Ok(())
}

#[test]
fn relay_urls_and_private_configuration_fail_closed() -> Result<()> {
    assert!(tether::carrier::check_relay_url("ws://example.com/v1/relay", true).is_err());
    assert!(tether::carrier::check_relay_url("ws://127.0.0.1:8888/v1/relay", false).is_err());
    assert!(
        tether::carrier::check_relay_url("wss://user:pass@example.com/v1/relay", false).is_err()
    );
    assert!(HostConfig::new("bad/scope", BTreeMap::new()).is_err());
    let services = BTreeMap::from([(
        "api".into(),
        Service {
            kind: ServiceKind::Tcp,
            target: "8.8.8.8:80".parse()?,
        },
    )]);
    assert!(HostConfig::new("test.app", services).is_err());
    Ok(())
}

#[tokio::test]
async fn managed_cli_reports_verified_registration_and_exits_when_its_owner_pipe_closes(
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut f = Fixture::new(false).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let relay = Relay::new(Limits {
        allowed_hosts: Some(HashSet::from([f.host.public_route_id()])),
        ..Limits::default()
    });
    let state = relay.clone();
    f.tasks.push(tokio::spawn(async move {
        let _ = tether_relay::serve(listener, relay).await;
    }));
    let profile: HostConfig = storage::load(&f.config)?;
    let target = profile.services["api"].target.to_string();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tether"))
        .args(["host", "forward-tls", "--config"])
        .arg(&f.config)
        .args([
            "--relay",
            &format!("ws://{address}/v1/relay"),
            "--service",
            "api",
            "--application-tls",
            "--expected-app",
            "test.app",
            "--expected-target",
            &target,
            "--managed-stdin",
            "--status-json",
            "--allow-loopback-dev",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut output = BufReader::new(child.stdout.take().ok_or("missing managed output")?);
    let mut line = String::new();
    timeout(Duration::from_secs(3), output.read_line(&mut line)).await??;
    let event: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!(event["event"], "registered");
    assert_eq!(event["id"], f.host.public_route_id());
    assert_eq!(event.as_object().unwrap().len(), 2);
    drop(child.stdin.take());
    assert!(timeout(Duration::from_secs(2), child.wait())
        .await??
        .success());
    timeout(Duration::from_secs(2), async {
        while state.stats().hosts != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(f.config.exists());
    Ok(())
}

#[tokio::test]
async fn managed_cli_refuses_wrong_profile_scope_or_target_before_registration() -> Result<()> {
    let f = Fixture::new(false).await?;
    for (app, target) in [("other.app", "127.0.0.1:1"), ("test.app", "127.0.0.1:1")] {
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_tether"))
            .args(["host", "forward-tls", "--config"])
            .arg(&f.config)
            .args([
                "--relay",
                "ws://127.0.0.1:1/v1/relay",
                "--service",
                "api",
                "--application-tls",
                "--expected-app",
                app,
                "--expected-target",
                target,
                "--managed-stdin",
                "--status-json",
                "--allow-loopback-dev",
            ])
            .output()
            .await?;
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn authenticated_status_self_leave_and_owner_revocation_are_scoped_and_durable() -> Result<()>
{
    for cloud in [false, true] {
        let f = Fixture::new(cloud).await?;
        let first = f.pair("first-controls").await?;
        let second = f.pair("second-controls").await?;
        let second_config: ClientConfig = storage::load(&second)?;
        let second_id = storage::device_id(
            &tether_core::Identity::from_private(storage::key(&second_config.private_key)?)?
                .public(),
        );
        storage::update_host(&f.config, |config| {
            config
                .devices
                .get_mut(&second_id)
                .unwrap()
                .services
                .remove("video");
            Ok(())
        })?;
        let status = client::host_status(&second, true).await?;
        assert_eq!(status.services.len(), 1);
        assert_eq!(status.services[0].id, "api");
        assert_eq!(client::host_status(&first, true).await?.services.len(), 2);
        let mut active = client::service(&first, "api", ServiceKind::Tcp, true).await?;
        active
            .carrier
            .send(&active.cipher.encrypt(b"open")?)
            .await?;
        let record = active.carrier.receive().await?;
        assert_eq!(active.cipher.decrypt(&record)?, b"open");
        // A peer cannot supply another device identity to self-revocation.
        let first_config: ClientConfig = storage::load(&first)?;
        let identity =
            tether_core::Identity::from_private(storage::key(&first_config.private_key)?)?;
        let mut malformed = tether::protocol::initiate(
            f.route.connect("test.app").await?,
            &identity,
            "test.app",
            Some(storage::key(&first_config.host_key)?),
        )
        .await?;
        malformed
            .send(serde_json::json!({"v":1,"type":"peer.leave","client_id":second_id}))
            .await?;
        assert_eq!(malformed.receive().await?["code"], "invalid_request");
        assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 2);
        client::leave(&first, true).await?;
        assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 1);
        assert!(storage::load::<ClientConfig>(&first)?.confirmed); // explicit local forget only
        let error = client::host_status(&first, true).await.unwrap_err();
        assert_eq!(
            error.downcast_ref::<tether::protocol::RemoteError>(),
            Some(&tether::protocol::RemoteError::PeerRevoked)
        );
        assert!(timeout(Duration::from_secs(2), active.carrier.receive())
            .await?
            .is_err());
        assert_eq!(client::host_status(&second, true).await?.services.len(), 1);
        assert!(f.host.owner_revoke("other.app", &second_id).is_err());
        f.host.owner_revoke("test.app", &second_id)?;
        assert!(storage::load::<HostConfig>(&f.config)?.devices.is_empty());
        assert!(client::service(&second, "api", ServiceKind::Tcp, true)
            .await
            .is_err());
        assert!(storage::load::<ClientConfig>(&second)?.confirmed);
    }
    Ok(())
}

#[tokio::test]
async fn managed_owner_pipe_reports_bound_listener_and_correlated_scoped_commands() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let f = Fixture::new(false).await?;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tether"))
        .args(["host", "run", "--config"])
        .arg(&f.config)
        .args([
            "--direct",
            "127.0.0.1:0",
            "--expected-app",
            "test.app",
            "--managed-stdin",
            "--status-json",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().ok_or("missing input")?;
    let mut output = BufReader::new(child.stdout.take().ok_or("missing output")?);
    let mut line = String::new();
    timeout(Duration::from_secs(3), output.read_line(&mut line)).await??;
    let event: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!(event["event"], "listening");
    let address = event["address"].as_str().unwrap();
    assert!(!address.ends_with(":0"));
    let _connected = TcpStream::connect(address).await?;
    for (command, app, ok) in [
        ("inspect", "test.app", true),
        ("pair-code", "other.app", false),
        ("pair-code", "test.app", true),
        ("pairing-status", "test.app", true),
        ("clients", "test.app", true),
    ] {
        let request = serde_json::json!({"v":1,"request_id":"00112233-4455-4677-8899-aabbccddeeff","command":command,"expected_app":app});
        input.write_all(&tether::owner::encode(&request)?).await?;
        line.clear();
        timeout(Duration::from_secs(3), output.read_line(&mut line)).await??;
        let reply: serde_json::Value = serde_json::from_str(&line)?;
        assert_eq!(reply["event"], "reply");
        assert_eq!(reply["request_id"], request["request_id"]);
        assert_eq!(reply["ok"], ok);
        if command == "inspect" {
            assert_eq!(reply["payload"]["app_id"], "test.app");
            assert!(reply["payload"].get("private_key").is_none());
            assert_eq!(reply["payload"]["services"].as_array().unwrap().len(), 2);
        }
        if command == "pair-code" && ok {
            let payload = &reply["payload"];
            assert_eq!(payload["attempts_remaining"], 3);
            assert!(payload["expires_in_seconds"].as_u64().unwrap() <= 300);
            tether_core::normalize_code(payload["code"].as_str().unwrap())?;
        }
    }
    // Hold the durable-store lock so command dispatch cannot finish; EOF still stops the helper.
    use fs2::FileExt;
    storage::update_host(&f.config, |_| Ok(()))?;
    let lock_path = PathBuf::from(format!("{}.lock", f.config.display()));
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(lock_path)?;
    lock.lock_exclusive()?;
    let blocked = serde_json::json!({"v":1,"request_id":"00112233-4455-4677-8899-aabbccddeeff","command":"revoke","expected_app":"test.app","client_id":"0".repeat(64)});
    input.write_all(&tether::owner::encode(&blocked)?).await?;
    sleep(Duration::from_millis(50)).await;
    drop(input);
    assert!(timeout(Duration::from_secs(2), child.wait())
        .await??
        .success());
    Ok(())
}

#[tokio::test]
#[ignore = "explicit bounded throughput baseline; writes only aggregate nonsecret measurements"]
async fn benchmark_existing_secure_transport_and_tcp_udp_paths() -> Result<()> {
    let client_identity = tether_core::Identity::generate()?;
    let host_identity = tether_core::Identity::generate()?;
    let mut a = tether_core::NoiseHandshake::initiator(&client_identity, "test.benchmark")?;
    let mut b = tether_core::NoiseHandshake::responder(&host_identity, "test.benchmark")?;
    b.read_message(&a.write_message(&[])?)?;
    a.read_message(&b.write_message(&[])?)?;
    b.read_message(&a.write_message(&[])?)?;
    let mut encryptor = a.into_transport()?;
    let mut decryptor = b.into_transport()?;
    let bytes = vec![0x5a; 16384];
    let blocks = 256;
    let started = std::time::Instant::now();
    for _ in 0..blocks {
        assert_eq!(decryptor.decrypt(&encryptor.encrypt(&bytes)?)?, bytes);
    }
    let mut results = vec![
        serde_json::json!({"path":"synthetic-inprocess-noise","payload_bytes":bytes.len()*blocks,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0}),
    ];
    for cloud in [false, true] {
        let mut f = Fixture::new(cloud).await?;
        let paired = f.pair("benchmark").await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let path = paired.clone();
        f.tasks.push(tokio::spawn(async move {
            let _ = client::forward_tcp(path, "api".into(), listener, true).await;
        }));
        let socket = TcpStream::connect(address).await?;
        let (mut reader, mut writer) = socket.into_split();
        let payload = vec![0x5a; 4 * 1024 * 1024];
        let expected = payload.clone();
        let started = std::time::Instant::now();
        let write = tokio::spawn(async move {
            writer.write_all(&payload).await?;
            writer.shutdown().await
        });
        let mut received = vec![0; expected.len()];
        timeout(Duration::from_secs(30), reader.read_exact(&mut received)).await??;
        write.await??;
        assert_eq!(received, expected);
        results.push(serde_json::json!({"path":if cloud{"relay-tcp-proxy"}else{"direct-tcp-proxy"},"payload_bytes":received.len(),"elapsed_ms":started.elapsed().as_secs_f64()*1000.0}));
        let proxy = UdpSocket::bind("127.0.0.1:0").await?;
        let address = proxy.local_addr()?;
        let path = paired.clone();
        f.tasks.push(tokio::spawn(async move {
            let _ = client::forward_udp(path, "video".into(), proxy, true).await;
        }));
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.connect(address).await?;
        let payload = vec![0xa5; 1400];
        let mut received = vec![0; 1401];
        let mut latency = Vec::new();
        // Warm pairing/Noise route establishment is excluded from per-datagram timings.
        socket.send(&payload).await?;
        timeout(Duration::from_secs(3), socket.recv(&mut received)).await??;
        let started = std::time::Instant::now();
        for _ in 0..128 {
            let sent = std::time::Instant::now();
            socket.send(&payload).await?;
            let n = timeout(Duration::from_secs(3), socket.recv(&mut received)).await??;
            assert_eq!(&received[..n], payload);
            latency.push(sent.elapsed().as_secs_f64() * 1000.0);
        }
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        latency.sort_by(f64::total_cmp);
        results.push(serde_json::json!({"path":if cloud{"relay-udp-over-websocket"}else{"direct-udp-over-tcp"},"payload_bytes":payload.len()*128,"datagrams":128,"elapsed_ms":elapsed,"rtt_p50_ms":latency[64],"rtt_p95_ms":latency[121]}));
    }
    println!(
        "{}",
        serde_json::json!({"benchmark":"loopback-debug-baseline","media_fast_path":false,"measurements":results})
    );
    Ok(())
}

#[tokio::test]
async fn owner_scope_rechecks_replaced_profile_and_same_app_host_pin_is_not_interchangeable(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let g = Fixture::new(false).await?;
    let first = f.pair("isolated").await?;
    let mut changed: ClientConfig = storage::load(&first)?;
    if let Route::Direct(address) = &g.route {
        changed.direct = Some(address.to_string());
    } else {
        unreachable!()
    }
    let swapped = f.root.join("swapped-host.json");
    storage::create(&swapped, &changed)?;
    assert!(client::host_status(&swapped, false).await.is_err());
    assert!(storage::load::<HostConfig>(&g.config)?.devices.is_empty());
    assert!(f.host.inspect("other.app").is_err());
    storage::update_host(&f.config, |config| {
        config.app_id = "other.app".into();
        Ok(())
    })?;
    let request=tether::owner::parse(br#"{"v":1,"request_id":"00112233-4455-4677-8899-aabbccddeeff","command":"pair-code","expected_app":"test.app"}"#)?;
    let reply = tether::owner::dispatch(f.host.clone(), request).await;
    assert_eq!(reply["ok"], false);
    assert!(reply.get("payload").is_none());
    assert!(f.host.open_pairing().is_err());
    Ok(())
}

#[tokio::test]
async fn authenticated_private_media_opens_only_udp_grants_and_closes_with_owner_revoke(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("media").await?;
    assert!(client::open_media(&path, "api").await.is_err());
    let media = client::open_media(&path, "video").await?;
    let encoded = include_bytes!("../../../tests/fixtures/media/video.h264");
    let mut reassembled = Vec::new();
    for packet in encoded.chunks(media.client.max_datagram()) {
        media.client.send(packet)?;
        let received = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(packet) = media.client.receive() {
                    return packet;
                }
                sleep(Duration::from_millis(1)).await;
            }
        })
        .await?;
        reassembled.extend_from_slice(&received);
    }
    assert_eq!(reassembled.as_slice(), encoded.as_slice());
    let config: ClientConfig = storage::load(&path)?;
    let identity = tether_core::Identity::from_private(storage::key(&config.private_key)?)?;
    f.host
        .owner_revoke("test.app", &storage::device_id(&identity.public()))?;
    timeout(Duration::from_secs(2), async {
        while !media.client.is_closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(client::open_media(&path, "video").await.is_err());
    let cloud = Fixture::new(true).await?;
    let path = cloud.pair("cloud-media").await?;
    assert!(client::open_media(&path, "video").await.is_err());
    Ok(())
}

#[tokio::test]
async fn eight_data_streams_leave_capacity_for_other_clients_status_and_leave() -> Result<()> {
    for cloud in [false, true] {
        let f = Fixture::new(cloud).await?;
        let first = f.pair("capacity-first").await?;
        let second = f.pair("capacity-second").await?;
        let third = f.pair("capacity-control").await?;
        let mut streams = Vec::new();
        for path in [&first, &second] {
            for _ in 0..4 {
                streams.push(client::service(path, "api", ServiceKind::Tcp, true).await?);
            }
        }
        assert_eq!(streams.len(), 8);
        assert!(client::service(&third, "api", ServiceKind::Tcp, true)
            .await
            .is_err());
        assert_eq!(client::host_status(&third, true).await?.services.len(), 2);
        assert_eq!(client::host_status(&first, true).await?.services.len(), 2);
        client::leave(&third, true).await?;
        assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 2);
        assert_eq!(client::host_status(&second, true).await?.services.len(), 2);
        client::leave(&first, true).await?;
        for session in streams.iter_mut().take(4) {
            assert!(timeout(Duration::from_secs(2), session.carrier.receive())
                .await?
                .is_err());
        }
        assert!(client::service(&second, "api", ServiceKind::Tcp, true)
            .await
            .is_ok());
    }
    Ok(())
}

#[tokio::test]
async fn live_tcp_and_udp_streams_close_when_their_original_service_target_changes() -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("target-anchor").await?;
    let mut tcp = client::service(&path, "api", ServiceKind::Tcp, false).await?;
    let mut udp = client::service(&path, "video", ServiceKind::Udp, false).await?;
    for session in [&mut tcp, &mut udp] {
        session
            .carrier
            .send(&session.cipher.encrypt(b"before")?)
            .await?;
        let response = session.carrier.receive().await?;
        assert_eq!(session.cipher.decrypt(&response)?, b"before");
    }
    storage::update_host(&f.config, |config| {
        config.services.get_mut("api").unwrap().target = "127.0.0.1:9".parse()?;
        config.services.get_mut("video").unwrap().kind = ServiceKind::Tcp;
        Ok(())
    })?;
    for session in [&mut tcp, &mut udp] {
        let frame = session.cipher.encrypt(b"after")?;
        let _ = session.carrier.send(&frame).await;
        assert!(timeout(Duration::from_secs(2), session.carrier.receive())
            .await?
            .is_err());
    }
    Ok(())
}

#[tokio::test]
async fn media_noise_heartbeat_flood_is_bounded_and_closes_its_own_lease() -> Result<()> {
    let f = Fixture::new(false).await?;
    let path = f.pair("heartbeat-rate").await?;
    let config: ClientConfig = storage::load(&path)?;
    let identity = tether_core::Identity::from_private(storage::key(&config.private_key)?)?;
    let mut session = tether::protocol::initiate(
        f.route.connect("test.app").await?,
        &identity,
        "test.app",
        Some(storage::key(&config.host_key)?),
    )
    .await?;
    session
        .send(serde_json::json!({"v":1,"type":"media.open","service":"video"}))
        .await?;
    let offer = session.receive().await?;
    assert_eq!(offer["type"], "media.ready");
    for _ in 0..8 {
        session
            .send(serde_json::json!({"v":1,"type":"media.heartbeat","lease_id":offer["lease_id"]}))
            .await?;
        assert_eq!(session.receive().await?["type"], "media.alive");
    }
    session
        .send(serde_json::json!({"v":1,"type":"media.heartbeat","lease_id":offer["lease_id"]}))
        .await?;
    assert!(timeout(Duration::from_secs(2), session.receive())
        .await?
        .is_err());
    Ok(())
}

#[tokio::test]
async fn device_capacity_remains_manageable_and_refused_pair_commit_preserves_prior_profile(
) -> Result<()> {
    let f = Fixture::new(false).await?;
    let existing = f.pair("at-capacity-existing").await?;
    storage::update_host(&f.config, |config| {
        for _ in 0..255 {
            let public = tether_core::Identity::generate()?.public();
            config.devices.insert(
                storage::device_id(&public),
                storage::Device {
                    public_key: STANDARD.encode(public),
                    services: std::collections::BTreeSet::from(["api".into()]),
                },
            );
        }
        Ok(())
    })?;
    let before = std::fs::read(&f.config)?;
    assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 256);
    let clients = f.host.owner_clients("test.app")?;
    assert_eq!(clients.as_array().unwrap().len(), 256);
    assert!(tether::owner::encode(&serde_json::json!({"event":"reply","request_id":"00112233-4455-4677-8899-aabbccddeeff","ok":true,"payload":clients}))?.len()<=tether::owner::MAX_REPLY);
    let pending = f.root.join("capacity-pending.json");
    let code = f.host.open_pairing()?;
    assert!(client::pair(&pending, "test.app", f.route.clone(), &code)
        .await
        .is_err());
    assert!(std::fs::read(&f.config)? == before);
    assert!(!storage::load::<ClientConfig>(&pending)?.confirmed);
    assert!(client::recover(&pending, false).await.is_err());
    assert_eq!(
        client::host_status(&existing, false).await?.services.len(),
        2
    );
    client::leave(&existing, false).await?;
    assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 255);
    storage::abandon_pending(&pending, "test.app")?;
    let code = f.host.open_pairing()?;
    client::pair(&pending, "test.app", f.route.clone(), &code).await?;
    assert_eq!(storage::load::<HostConfig>(&f.config)?.devices.len(), 256);
    assert!(storage::load::<ClientConfig>(&pending)?.confirmed);
    Ok(())
}

#[tokio::test]
async fn simultaneous_four_megabyte_tcp_echo_does_not_deadlock_either_carrier() -> Result<()> {
    for cloud in [false, true] {
        let mut f = Fixture::new(cloud).await?;
        let path = f.pair("large-duplex").await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        f.tasks.push(tokio::spawn(async move {
            let _ = client::forward_tcp(path, "api".into(), listener, true).await;
        }));
        let socket = TcpStream::connect(address).await?;
        let (mut read, mut write) = socket.into_split();
        let payload = vec![0x5a; 4 * 1024 * 1024];
        let expected = payload.clone();
        let sender = tokio::spawn(async move {
            write.write_all(&payload).await?;
            write.shutdown().await
        });
        let mut received = vec![0; expected.len()];
        timeout(Duration::from_secs(25), read.read_exact(&mut received)).await??;
        sender.await??;
        assert!(received == expected);
        let mut last = [0; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), read.read(&mut last)).await??,
            0
        );
    }
    Ok(())
}
