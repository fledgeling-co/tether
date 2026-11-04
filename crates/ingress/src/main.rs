use clap::Parser;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tether_ingress::{serve_with_shutdown, valid_suffix};
use tether_relay::{Limits, Relay};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};

#[derive(Parser)]
#[command(about = "Opaque companion relay and TLS passthrough ingress")]
struct Args {
    #[arg(long, env = "TETHER_DOMAIN_SUFFIX")]
    domain_suffix: Option<String>,
    #[arg(long, env = "TETHER_ALLOWED_HOSTS", value_delimiter = ',')]
    allow_host: Vec<String>,
    #[arg(long)]
    allow_open_registration: bool,
    #[arg(long, default_value = "127.0.0.1:8787")]
    ws_listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:8788")]
    tls_listen: SocketAddr,
    #[arg(long)]
    health_check: Option<SocketAddr>,
}

async fn wait_shutdown(mut signal: watch::Receiver<bool>) {
    if !*signal.borrow() {
        let _ = signal.changed().await;
    }
}
async fn signal() {
    #[cfg(unix)]
    {
        if let Ok(mut termination) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = termination.recv() => {}, _ = tokio::signal::ctrl_c() => {} }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
async fn health(address: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !address.ip().is_loopback() {
        return Err("health check address must be loopback".into());
    }
    timeout(Duration::from_secs(3), async {
        let mut socket = TcpStream::connect(address).await?;
        socket
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut bytes = Vec::new();
        socket.take(4096).read_to_end(&mut bytes).await?;
        if !bytes.starts_with(b"HTTP/1.1 200 ") || !bytes.ends_with(b"ok\n") {
            return Err("relay health check failed".into());
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    if let Some(address) = args.health_check {
        return health(address).await;
    }
    let suffix = args.domain_suffix.ok_or("--domain-suffix is required")?;
    if !valid_suffix(&suffix) {
        return Err("invalid domain suffix".into());
    }
    let mut limits = Limits::default();
    if args.allow_open_registration {
        if !args.allow_host.is_empty()
            || !args.ws_listen.ip().is_loopback()
            || !args.tls_listen.ip().is_loopback()
        {
            return Err("open registration is only for explicit loopback development without a host allowlist".into());
        }
        limits.allowed_hosts = None;
    } else {
        if args.allow_host.is_empty() {
            return Err(
                "supply --allow-host public IDs or TETHER_ALLOWED_HOSTS before starting".into(),
            );
        }
        if args.allow_host.iter().any(|id| {
            id.len() != 52
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        }) {
            return Err("invalid public host ID".into());
        }
        limits.allowed_hosts = Some(args.allow_host.into_iter().collect::<HashSet<_>>());
    }
    let relay = Relay::new(limits);
    let web = TcpListener::bind(args.ws_listen).await?;
    let raw = TcpListener::bind(args.tls_listen).await?;
    let web_address = web.local_addr()?;
    let loopback = if web_address.is_ipv6() {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    let relay_url = format!(
        "ws://{}/v1/relay",
        SocketAddr::new(loopback, web_address.port())
    );
    let (shutdown, signal_receiver) = watch::channel(false);
    let web_signal = signal_receiver.clone();
    let router = relay.router();
    let mut web_task = tokio::spawn(async move {
        axum::serve(
            web,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_shutdown(web_signal))
        .await
    });
    let mut raw_task = tokio::spawn(serve_with_shutdown(
        raw,
        relay,
        relay_url,
        suffix,
        wait_shutdown(signal_receiver),
    ));
    tokio::select! {
        result = &mut web_task => { shutdown.send_replace(true); raw_task.abort(); result??; },
        result = &mut raw_task => { shutdown.send_replace(true); web_task.abort(); result??; },
        _ = signal() => {
            shutdown.send_replace(true);
            if timeout(Duration::from_secs(5), async { let _ = (&mut web_task).await; let _ = (&mut raw_task).await; }).await.is_err() {
                web_task.abort(); raw_task.abort();
            }
        },
    }
    Ok(())
}
