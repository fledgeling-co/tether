//! A service configured with an identity key learns which paired device opened each stream,
//! and a local process without the key cannot pass as one.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::{collections::BTreeMap, time::Duration};
use tether::{
    carrier::Result,
    client::{self, Route},
    host::Host,
    identify,
    storage::{self, ClientConfig, HostConfig, Service, ServiceKind},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

/// Accepts connections, challenges each one, and reports the device key it proved.
async fn identifying_service(listener: TcpListener, key: [u8; 32], seen: mpsc::Sender<[u8; 32]>) {
    while let Ok((mut socket, _)) = listener.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let nonce: [u8; 32] = rand::random();
            let mut challenge = identify::CHALLENGE_MAGIC.to_vec();
            challenge.push(identify::VERSION);
            challenge.extend_from_slice(&nonce);
            if socket.write_all(&challenge).await.is_err() {
                return;
            }
            let mut answer = [0u8; identify::PROOF_LEN];
            if socket.read_exact(&mut answer).await.is_err() {
                return;
            }
            let mut device = [0u8; 32];
            device.copy_from_slice(&answer[5..37]);
            let mut mac = [0u8; 32];
            mac.copy_from_slice(&answer[37..]);
            if &answer[..4] != identify::PROOF_MAGIC
                || !identify::verify(&key, "router", &nonce, &device, &mac)
            {
                return;
            }
            let _ = seen.send(device).await;
            let _ = socket.write_all(b"identified").await;
        });
    }
}

#[tokio::test]
async fn an_identifying_service_learns_the_paired_device_on_every_stream() -> Result<()> {
    let root =
        std::env::temp_dir().join(format!("tether-identify-{:032x}", rand::random::<u128>()));
    #[cfg(unix)]
    {
        std::fs::create_dir(&root)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    }
    let key: [u8; 32] = rand::random();
    let target = TcpListener::bind("127.0.0.1:0").await?;
    let services = BTreeMap::from([(
        "router".into(),
        Service {
            kind: ServiceKind::Tcp,
            target: target.local_addr()?,
            identity: Some(STANDARD.encode(key)),
        },
    )]);
    let (seen_tx, mut seen) = mpsc::channel(4);
    let service_task = tokio::spawn(identifying_service(target, key, seen_tx));
    let config = root.join("host.json");
    storage::create(&config, &HostConfig::new("test.app", services)?)?;
    let host = Host::load(&config)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let route = Route::Direct(listener.local_addr()?);
    let server = host.clone();
    let host_task = tokio::spawn(async move {
        let _ = server.serve_direct(listener).await;
    });

    let code = host.open_pairing()?;
    let client_path = root.join("client.json");
    client::pair(&client_path, "test.app", route, &code).await?;
    let saved: ClientConfig = storage::load(&client_path)?;
    let device = tether_core::Identity::from_private(storage::key(&saved.private_key)?)?.public();

    let proxy = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy.local_addr()?;
    let forward_task = tokio::spawn(async move {
        let _ = client::forward_tcp(client_path, "router".into(), proxy, true).await;
    });

    for _ in 0..2 {
        let mut socket = TcpStream::connect(proxy_address).await?;
        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(5), socket.read_exact(&mut reply)).await??;
        assert_eq!(&reply, b"identified");
        let proved = timeout(Duration::from_secs(5), seen.recv())
            .await?
            .ok_or("no proof")?;
        assert_eq!(
            proved, device,
            "the proof names the device the host authenticated"
        );
    }

    // A local process that connects straight to the service has no key and no proof.
    let mut direct = TcpStream::connect(host_target(&config)?).await?;
    let mut challenge = [0u8; identify::CHALLENGE_LEN];
    direct.read_exact(&mut challenge).await?;
    direct.write_all(&[0u8; identify::PROOF_LEN]).await?;
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(2), direct.read_to_end(&mut rest)).await;
    assert!(rest.is_empty(), "a forged proof is refused without a reply");
    assert!(seen.try_recv().is_err());

    for task in [service_task, host_task, forward_task] {
        task.abort();
    }
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(tether::host::control_path(&config));
    }
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn host_target(config: &std::path::Path) -> Result<std::net::SocketAddr> {
    let saved: HostConfig = storage::load(config)?;
    Ok(saved.services["router"].target)
}

#[test]
fn identity_is_refused_on_udp_and_must_be_a_32_byte_key() {
    let udp = BTreeMap::from([(
        "video".into(),
        Service {
            kind: ServiceKind::Udp,
            target: "127.0.0.1:9".parse().unwrap(),
            identity: Some(STANDARD.encode([1u8; 32])),
        },
    )]);
    assert!(HostConfig::new("test.app", udp).is_err());
    let short = BTreeMap::from([(
        "router".into(),
        Service {
            kind: ServiceKind::Tcp,
            target: "127.0.0.1:9".parse().unwrap(),
            identity: Some(STANDARD.encode([1u8; 16])),
        },
    )]);
    assert!(HostConfig::new("test.app", short).is_err());
}
