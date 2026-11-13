use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tether_media::{Client, Context, Result, Server};
use tokio::{
    net::UdpSocket,
    time::{sleep, timeout},
};
fn context(peer: u8) -> Context {
    Context {
        app: "test.app".into(),
        peer: [peer; 32],
        binding: [3; 32],
        service: "video".into(),
    }
}
async fn echo() -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let task = tokio::spawn(async move {
        let mut bytes = [0; 1600];
        while let Ok((n, peer)) = socket.recv_from(&mut bytes).await {
            let _ = socket.send_to(&bytes[..n], peer).await;
        }
    });
    Ok((address, task))
}
async fn receive(client: &Client) -> Result<Vec<u8>> {
    timeout(Duration::from_secs(3), async {
        loop {
            if let Some(bytes) = client.receive() {
                return bytes;
            }
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(Into::into)
}
#[tokio::test]
async fn real_quic_packets_preserve_empty_and_maximum_boundaries_and_close_on_revocation(
) -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let authorized = Arc::new(AtomicBool::new(true));
    let scope = authorized.clone();
    let (offer, lease) = server.open(
        context(1),
        target,
        Arc::new(move || scope.load(Ordering::Acquire)),
    )?;
    let client = Client::connect(server.address()?, offer).await?;
    for bytes in [Vec::new(), vec![7; client.max_datagram()]] {
        client.send(&bytes)?;
        assert_eq!(receive(&client).await?, bytes);
    }
    assert_eq!(client.send(&vec![1; 1201]), Err("media_packet_too_large"));
    assert_eq!(client.stats().packets_received, 2);
    assert_eq!(client.stats().packets_sent, 2);
    authorized.store(false, Ordering::Release);
    timeout(Duration::from_secs(2), async {
        while !client.is_closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(!lease.is_live());
    assert_eq!(client.send(b"after"), Err("media_closed"));
    echo.abort();
    Ok(())
}
#[tokio::test]
async fn wrong_pin_wrong_token_replay_and_concurrent_reuse_fail_closed() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, _lease) = server.open(context(1), target, Arc::new(|| true))?;
    let mut forged = offer.clone();
    forged.cert_pin[0] ^= 1;
    assert!(Client::connect(server.address()?, forged).await.is_err());
    let mut forged = offer.clone();
    forged.token[0] ^= 1;
    assert!(Client::connect(server.address()?, forged).await.is_err());
    let (a, b) = tokio::join!(
        Client::connect(server.address()?, offer.clone()),
        Client::connect(server.address()?, offer.clone())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(Client::connect(server.address()?, offer).await.is_err());
    echo.abort();
    Ok(())
}
#[tokio::test]
async fn lease_scope_quotas_and_owner_close_are_bounded() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    assert!(server
        .open(context(1), "192.0.2.1:99".parse()?, Arc::new(|| true))
        .is_err());
    assert!(server.open(context(1), target, Arc::new(|| false)).is_err());
    let mut invalid = context(1);
    invalid.service = "bad/scope".into();
    assert!(server.open(invalid, target, Arc::new(|| true)).is_err());
    let mut guards = Vec::new();
    for _ in 0..8 {
        guards.push(server.open(context(1), target, Arc::new(|| true))?.1);
    }
    assert!(server.open(context(1), target, Arc::new(|| true)).is_err());
    for peer in 2..=8 {
        for _ in 0..8 {
            guards.push(server.open(context(peer), target, Arc::new(|| true))?.1);
        }
    }
    assert!(server.open(context(9), target, Arc::new(|| true)).is_err());
    drop(guards);
    let (offer, guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    guard.close();
    timeout(Duration::from_secs(2), async {
        while !client.is_closed() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    echo.abort();
    Ok(())
}
#[tokio::test]
async fn idle_parent_noise_lease_expires_without_heartbeat() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    timeout(Duration::from_secs(7), async {
        while !client.is_closed() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(!guard.is_live());
    assert!(guard.heartbeat().is_err());
    echo.abort();
    Ok(())
}
#[tokio::test]
async fn bounded_receive_queue_counts_drops_without_allocating_unbounded_packets() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, _guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    for _ in 0..tether_media::RECEIVE_QUEUE * 3 {
        let _ = client.send(&[1; 100]);
        sleep(Duration::from_micros(250)).await;
    }
    sleep(Duration::from_millis(50)).await;
    assert!(client.stats().dropped > 0);
    let mut count = 0;
    while client.receive().is_some() {
        count += 1;
    }
    assert!(count <= tether_media::RECEIVE_QUEUE);
    echo.abort();
    Ok(())
}

#[tokio::test]
async fn actual_encoded_h264_and_opus_packets_reassemble_byte_exact() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    for source in [
        include_bytes!("../../../tests/fixtures/media/video.h264").as_slice(),
        include_bytes!("../../../tests/fixtures/media/audio.ogg").as_slice(),
    ] {
        assert!(!source.is_empty());
        let mut received = Vec::new();
        for packet in source.chunks(client.max_datagram()) {
            guard.heartbeat()?;
            client.send(packet)?;
            received.extend_from_slice(&receive(&client).await?);
        }
        assert_eq!(received, source);
    }
    echo.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "explicit loopback/impaired encoded-packet benchmark; no decoded/live-media claim"]
async fn benchmark_encoded_packets_direct_and_impaired() -> Result<()> {
    let video = include_bytes!("../../../tests/fixtures/media/video.h264");
    let audio = include_bytes!("../../../tests/fixtures/media/audio.ogg");
    let payloads = video
        .chunks(1100)
        .chain(audio.chunks(1100))
        .map(|packet| packet.to_vec())
        .collect::<Vec<_>>();
    let mut results = Vec::new();
    for impaired in [false, true] {
        let (target, echo) = echo().await?;
        let server = Server::bind("127.0.0.1:0".parse()?)?;
        let (mut offer, guard) = server.open(context(1), target, Arc::new(|| true))?;
        let mut proxy_task = None;
        let address = if impaired {
            let socket = UdpSocket::bind("127.0.0.1:0").await?;
            let address = socket.local_addr()?;
            let destination = server.address()?;
            proxy_task = Some(tokio::spawn(async move {
                let mut client = None;
                let mut pending = Vec::<(tokio::time::Instant, Vec<u8>, SocketAddr)>::new();
                let mut bytes = [0; 65536];
                let mut count = 0usize;
                let mut tick = tokio::time::interval(Duration::from_millis(1));
                loop {
                    tokio::select! {
                        packet=socket.recv_from(&mut bytes)=>{let Ok((n,peer))=packet else{break;};let target=if peer==destination{let Some(peer)=client else{continue;};peer}else{client=Some(peer);destination};count+=1;if count.is_multiple_of(97) || pending.len()>=64 {continue;}pending.push((tokio::time::Instant::now()+Duration::from_millis(5+(count%3) as u64*2),bytes[..n].to_vec(),target));},
                        _=tick.tick()=>{let now=tokio::time::Instant::now();let mut i=0;while i<pending.len(){if pending[i].0<=now{let (_,bytes,target)=pending.swap_remove(i);let _=socket.send_to(&bytes,target).await;}else{i+=1;}}}
                    }
                }
            }));
            address
        } else {
            server.address()?
        };
        offer.port = address.port();
        let client = Client::connect(address, offer).await?;
        let mut sent = Vec::new();
        let mut latencies = Vec::new();
        let mut received = std::collections::HashSet::new();
        let mut bytes_sent = 0usize;
        let mut bytes_received = 0usize;
        let started = std::time::Instant::now();
        for sequence in 0u32..128 {
            guard.heartbeat()?;
            let mut packet = sequence.to_be_bytes().to_vec();
            packet.extend_from_slice(&payloads[sequence as usize % payloads.len()]);
            sent.push(std::time::Instant::now());
            client.send(&packet)?;
            bytes_sent += packet.len();
            sleep(Duration::from_millis(3)).await;
            while let Some(packet) = client.receive() {
                let id = u32::from_be_bytes(packet[..4].try_into()?) as usize;
                if received.insert(id) {
                    latencies.push(sent[id].elapsed().as_secs_f64() * 1000.0);
                    bytes_received += packet.len();
                }
            }
        }
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        while tokio::time::Instant::now() < until && received.len() < sent.len() {
            guard.heartbeat()?;
            while let Some(packet) = client.receive() {
                let id = u32::from_be_bytes(packet[..4].try_into()?) as usize;
                if received.insert(id) {
                    latencies.push(sent[id].elapsed().as_secs_f64() * 1000.0);
                    bytes_received += packet.len();
                }
            }
            sleep(Duration::from_millis(1)).await;
        }
        assert!(!received.is_empty());
        latencies.sort_by(f64::total_cmp);
        let stats = client.stats();
        results.push(format!("{{\"path\":\"{}\",\"sent_packets\":{},\"received_packets\":{},\"sent_bytes\":{},\"received_bytes\":{},\"elapsed_ms\":{},\"rtt_p50_ms\":{},\"rtt_p95_ms\":{},\"quic_rtt_ms\":{},\"local_dropped\":{},\"max_payload\":{}}}",if impaired{"quic-datagram-impaired"}else{"quic-datagram-direct"},sent.len(),received.len(),bytes_sent,bytes_received,started.elapsed().as_secs_f64()*1000.0,latencies[latencies.len()/2],latencies[latencies.len()*95/100],stats.rtt_ms,stats.dropped,client.max_datagram()));
        if let Some(task) = proxy_task {
            task.abort();
        }
        echo.abort();
    }
    println!("{{\"benchmark\":\"encoded-h264-opus-packet-loopback\",\"decoded_media\":false,\"sender_interval_ms\":3,\"packet_budget\":128,\"impairment\":\"5-9ms each direction; every97th UDPwirepacket dropped; bounded64queue\",\"measurements\":[{}]}}",results.join(","));
    Ok(())
}

#[tokio::test]
async fn pinned_candidate_race_uses_reachable_family_and_sends_token_only_once() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, _guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect_candidates(
        vec![
            SocketAddr::new("::1".parse()?, offer.port),
            server.address()?,
        ],
        offer.clone(),
    )
    .await?;
    client.send(b"chosen-family")?;
    assert_eq!(receive(&client).await?, b"chosen-family");
    assert!(Client::connect(server.address()?, offer).await.is_err());
    echo.abort();
    Ok(())
}

#[tokio::test]
async fn postauthentication_client_disconnect_closes_lease_even_if_noise_owner_remains(
) -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("127.0.0.1:0".parse()?)?;
    let (offer, guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    client.close();
    timeout(Duration::from_secs(2), async {
        while guard.is_live() {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    assert!(guard.heartbeat().is_err());
    echo.abort();
    Ok(())
}

#[tokio::test]
async fn actual_ipv6_private_quic_endpoint_roundtrips_encoded_opus() -> Result<()> {
    let (target, echo) = echo().await?;
    let server = Server::bind("[::1]:0".parse()?)?;
    let (offer, _guard) = server.open(context(1), target, Arc::new(|| true))?;
    let client = Client::connect(server.address()?, offer).await?;
    let encoded = include_bytes!("../../../tests/fixtures/media/audio.ogg");
    client.send(encoded)?;
    assert_eq!(receive(&client).await?.as_slice(), encoded.as_slice());
    echo.abort();
    Ok(())
}
