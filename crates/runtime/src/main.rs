use clap::{Parser, Subcommand, ValueEnum};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Read},
    net::SocketAddr,
    path::PathBuf,
};
use tether::{
    carrier::Result,
    client::{self, Route},
    host::Host,
    storage::{self, HostConfig, Service, ServiceKind},
};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser)]
#[command(
    name = "tether",
    about = "App-scoped private/cloud forwarding with Mac-owned authorization"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Host {
        #[command(subcommand)]
        command: HostCommand,
    },
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
}
#[derive(Subcommand)]
enum HostCommand {
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        app: String,
        #[arg(
            long,
            required = true,
            help = "Fixed loopback target, for example api=tcp://127.0.0.1:8882"
        )]
        service: Vec<String>,
        #[arg(
            long,
            help = "Prove the connecting device to a TCP service with a 32-byte key file the service also holds, for example api=/path/identity.key"
        )]
        identify: Vec<String>,
    },
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        direct: Option<SocketAddr>,
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        allow_loopback_dev: bool,
        #[arg(long, help = "Open a five-minute pairing window and print its code")]
        pair: bool,
        #[arg(long, conflicts_with = "pair")]
        status_json: bool,
        #[arg(long)]
        managed_stdin: bool,
        #[arg(long)]
        expected_app: Option<String>,
    },
    ForwardTls {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        relay: String,
        #[arg(long)]
        service: String,
        #[arg(
            long,
            help = "Acknowledge that the fixed origin service authenticates TLS1.3 and its own clients"
        )]
        application_tls: bool,
        #[arg(long)]
        allow_loopback_dev: bool,
        #[arg(long)]
        status_json: bool,
        #[arg(long)]
        managed_stdin: bool,
        #[arg(long)]
        expected_app: Option<String>,
        #[arg(long)]
        expected_target: Option<SocketAddr>,
    },
    PairCode {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_app: Option<String>,
    },
    Inspect {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_app: String,
    },
    Describe {
        #[arg(long)]
        config: PathBuf,
    },
    List {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        expected_app: Option<String>,
    },
    Revoke {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        device: String,
        #[arg(long)]
        expected_app: Option<String>,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    Tcp,
    Udp,
}
#[derive(Subcommand)]
enum ClientCommand {
    /// Explicitly delete an unconfirmed local record; never resets a confirmed pairing.
    AbandonPending {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        app: String,
    },
    Pair {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        app: String,
        #[arg(long)]
        direct: Option<String>,
        #[arg(long)]
        relay: Option<String>,
        #[arg(long)]
        host_id: Option<String>,
        #[arg(long)]
        allow_loopback_dev: bool,
        #[arg(
            long,
            help = "Read the pairing code from standard input, not the process argument list"
        )]
        code_stdin: bool,
    },
    Forward {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        service: String,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long, value_enum, default_value = "tcp")]
        kind: Kind,
        #[arg(long)]
        allow_loopback_dev: bool,
    },
    Recover {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        allow_loopback_dev: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("{}", storage::fixed_error(error.into()));
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(execute(cli));
    // Cancelling DNS I/O can leave a blocking resolver task. Owner EOF must still terminate the helper.
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    if let Err(error) = result {
        eprintln!("{}", storage::fixed_error(error));
        std::process::exit(1);
    }
}
async fn status_output(
    enabled: bool,
    mut receiver: tokio::sync::mpsc::Receiver<tether::host::RelayStatus>,
) -> Result<()> {
    if !enabled {
        return futures_util::future::pending().await;
    }
    while let Some(event) = receiver.recv().await {
        tether::owner::print(&serde_json::to_value(&event)?)?;
    }
    Ok(())
}
/// Read a service identity key: a private regular file holding 32 raw bytes or their base64.
fn identity_key(path: &std::path::Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err("identity key must be a small regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("identity key must not be readable by other users".into());
        }
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(path)?);
    let key = if bytes.len() == 32 {
        bytes.to_vec()
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(std::str::from_utf8(&bytes)?.trim())
            .map_err(|_| "identity key is neither 32 bytes nor base64")?
    };
    if key.len() != 32 {
        return Err("identity key must be 32 bytes".into());
    }
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(key))
}

async fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Host { command } => match command {
            HostCommand::Init {
                config,
                app,
                service,
                identify,
            } => {
                let mut services = BTreeMap::new();
                for description in service {
                    let (name, endpoint) = description.split_once('=').ok_or("invalid service")?;
                    let (kind, target) = endpoint.split_once("://").ok_or("invalid service")?;
                    let kind = match kind {
                        "tcp" => ServiceKind::Tcp,
                        "udp" => ServiceKind::Udp,
                        _ => return Err("invalid service kind".into()),
                    };
                    if services
                        .insert(
                            name.to_owned(),
                            Service {
                                kind,
                                target: target.parse()?,
                                identity: None,
                            },
                        )
                        .is_some()
                    {
                        return Err("duplicate service".into());
                    }
                }
                for description in identify {
                    let (name, path) = description.split_once('=').ok_or("invalid identity key")?;
                    let service = services
                        .get_mut(name)
                        .ok_or("identity names an unknown service")?;
                    service.identity = Some(identity_key(std::path::Path::new(path))?);
                }
                storage::create(&config, &HostConfig::new(&app, services)?)?;
            }
            HostCommand::Describe { config } => {
                println!("{}", Host::load(config)?.public_route_id())
            }
            HostCommand::Inspect {
                config,
                expected_app,
            } => {
                let host = Host::load(config)?;
                tether::owner::print(&serde_json::to_value(host.inspect(&expected_app)?)?)?;
            }
            HostCommand::List {
                config,
                expected_app,
            } => {
                let host = Host::load(config)?;
                tether::owner::print(
                    &host.owner_clients(expected_app.as_deref().unwrap_or(host.app_id()))?,
                )?;
            }
            HostCommand::Revoke {
                config,
                device,
                expected_app,
            } => {
                let host = Host::load(config)?;
                host.owner_revoke(expected_app.as_deref().unwrap_or(host.app_id()), &device)?;
            }
            HostCommand::Run {
                config,
                direct,
                relay,
                allow_loopback_dev,
                pair,
                status_json,
                managed_stdin,
                expected_app,
            } => {
                let host = Host::load(&config)?;
                if let Some(app) = &expected_app {
                    host.owner_scope(app)?;
                }
                let owner = tether::owner::input(managed_stdin, status_json);
                if pair {
                    println!("{}", host.open_pairing()?);
                }
                let direct = if direct.is_none() && relay.is_none() {
                    Some("127.0.0.1:7445".parse()?)
                } else {
                    direct
                };
                let (events, receiver) = tokio::sync::mpsc::channel(8);
                let private = async {
                    if let Some(address) = direct {
                        let listener = TcpListener::bind(address).await?;
                        if status_json {
                            events
                                .send(tether::host::RelayStatus::Listening {
                                    address: listener.local_addr()?.to_string(),
                                })
                                .await?;
                        }
                        host.serve_direct(listener).await
                    } else {
                        futures_util::future::pending().await
                    }
                };
                let cloud = async {
                    if let Some(url) = relay {
                        host.serve_relay_events(
                            &url,
                            allow_loopback_dev,
                            None,
                            if status_json {
                                Some(events.clone())
                            } else {
                                None
                            },
                            None,
                        )
                        .await
                    } else {
                        futures_util::future::pending().await
                    }
                };
                #[cfg(unix)]
                let control = tether::host::serve_pairing_control(host.clone(), &config);
                #[cfg(not(unix))]
                let control = futures_util::future::pending::<Result<()>>();
                tokio::select! { result=private=>result?, result=cloud=>result?, result=control=>result?, result=status_output(status_json,receiver)=>result?, _=owner.closed=>{}, result=tether::owner::serve(host.clone(),owner.commands)=>result?, _=tokio::signal::ctrl_c()=>{} }
            }
            HostCommand::PairCode {
                config,
                expected_app,
            } => {
                let host = Host::load(&config)?;
                let app = expected_app.as_deref().unwrap_or(host.app_id());
                host.owner_scope(app)?;
                #[cfg(unix)]
                {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let path = tether::host::control_path(&config);
                    tether::host::validate_control_directory(&config)?;
                    let mut socket = tokio::net::UnixStream::connect(path).await?;
                    let request = serde_json::json!({"v":1,"request_id":"00000000-0000-4000-8000-000000000000","command":"pair-code","expected_app":app});
                    socket.write_all(&tether::owner::encode(&request)?).await?;
                    let mut bytes = Vec::new();
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        socket
                            .take(tether::owner::MAX_REPLY as u64)
                            .read_to_end(&mut bytes),
                    )
                    .await??;
                    let response: serde_json::Value = serde_json::from_slice(&bytes)?;
                    if response["ok"] != true {
                        return Err("owner command refused".into());
                    }
                    let code = response["payload"]["code"].as_str().ok_or("missing code")?;
                    tether_core::normalize_code(code)?;
                    println!("{code}");
                }
                #[cfg(not(unix))]
                return Err("use host run --pair on this platform".into());
            }
            HostCommand::ForwardTls {
                config,
                relay,
                service,
                application_tls,
                allow_loopback_dev,
                status_json,
                managed_stdin,
                expected_app,
                expected_target,
            } => {
                if !application_tls {
                    return Err("explicit application-TLS acknowledgment required".into());
                }
                let profile: HostConfig = storage::load(&config)?;
                profile.validate()?;
                if expected_app
                    .as_ref()
                    .is_some_and(|app| app != &profile.app_id)
                {
                    return Err("profile scope mismatch".into());
                }
                if expected_target.is_some_and(|target| {
                    profile
                        .services
                        .get(&service)
                        .is_none_or(|configured| configured.target != target)
                }) {
                    return Err("profile target mismatch".into());
                }
                let host = Host::load(config)?;
                if let Some(app) = &expected_app {
                    host.owner_scope(app)?;
                }
                let owner = tether::owner::input(managed_stdin, status_json);
                let (events, receiver) = tokio::sync::mpsc::channel(8);
                tokio::select! {result=host.serve_relay_events(&relay,allow_loopback_dev,Some(&service),if status_json{Some(events)}else{None},expected_target)=>result?, result=status_output(status_json,receiver)=>result?, _=owner.closed=>{}, result=tether::owner::serve(host.clone(),owner.commands)=>result?, _=tokio::signal::ctrl_c()=>{}}
            }
        },
        Command::Client { command } => match command {
            ClientCommand::AbandonPending { config, app } => {
                println!("{}", storage::abandon_pending(&config, &app)?);
            }
            ClientCommand::Pair {
                config,
                app,
                direct,
                relay,
                host_id,
                allow_loopback_dev,
                code_stdin,
            } => {
                if !code_stdin {
                    return Err("provide code on stdin with --code-stdin".into());
                }
                let mut code = zeroize::Zeroizing::new(String::new());
                io::stdin().lock().take(64).read_line(&mut code)?;
                let route = match (direct, relay, host_id) {
                    (Some(address), None, None) => Route::Private(address),
                    (None, Some(url), Some(host_id)) => Route::Cloud {
                        url,
                        host_id,
                        allow_loopback_dev,
                    },
                    _ => return Err("choose exactly one private or cloud route".into()),
                };
                client::pair(&config, &app, route, code.trim()).await?;
            }
            ClientCommand::Recover {
                config,
                allow_loopback_dev,
            } => client::recover(&config, allow_loopback_dev).await?,
            ClientCommand::Forward {
                config,
                service,
                listen,
                kind,
                allow_loopback_dev,
            } => {
                if !listen.ip().is_loopback() {
                    return Err("local proxy must bind loopback".into());
                }
                match kind {
                    Kind::Tcp => {
                        client::forward_tcp(
                            config,
                            service,
                            TcpListener::bind(listen).await?,
                            allow_loopback_dev,
                        )
                        .await?
                    }
                    Kind::Udp => {
                        client::forward_udp(
                            config,
                            service,
                            UdpSocket::bind(listen).await?,
                            allow_loopback_dev,
                        )
                        .await?
                    }
                }
            }
        },
    }
    Ok(())
}
