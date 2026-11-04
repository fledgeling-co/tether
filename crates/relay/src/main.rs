use std::net::SocketAddr;
use tether_relay::{serve, Limits, Relay};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let address: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:8787".into())
        .parse()?;
    let mut limits = Limits::default();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--allow-host" => {
                let id = args.next().ok_or("--allow-host needs a public host ID")?;
                if id.len() != 52
                    || !id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
                {
                    return Err("invalid public host ID".into());
                }
                if let Some(allowed) = limits.allowed_hosts.as_mut() {
                    allowed.insert(id);
                } else {
                    return Err("do not combine host allowlists and open registration".into());
                }
            }
            "--allow-open-registration" if address.ip().is_loopback() => {
                if limits
                    .allowed_hosts
                    .as_ref()
                    .is_some_and(|ids| !ids.is_empty())
                {
                    return Err("do not combine host allowlists and open registration".into());
                }
                limits.allowed_hosts = None;
            }
            "--allow-open-registration" => {
                return Err("open registration is limited to loopback development".into())
            }
            _ => return Err("unknown relay argument".into()),
        }
    }
    let listener = tokio::net::TcpListener::bind(address).await?;
    serve(listener, Relay::new(limits)).await?;
    Ok(())
}
