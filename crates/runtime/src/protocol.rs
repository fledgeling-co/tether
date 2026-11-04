use crate::carrier::{Carrier, Result, WAIT};
use serde_json::Value;
use tether_core::{Identity, NoiseHandshake, SecureTransport};
use tokio::time::timeout;
pub const MAX_CONTROL: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteError {
    PeerRevoked,
    ServiceDenied,
    InvalidRequest,
    Refused,
}
impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::PeerRevoked => "peer is not authorized",
            Self::ServiceDenied => "service is not granted",
            Self::InvalidRequest => "invalid control request",
            Self::Refused => "remote control refused",
        })
    }
}
impl std::error::Error for RemoteError {}
pub fn check_control_reply(value: &Value) -> Result<()> {
    if value["type"] == "error" && value["v"] == 1 {
        return Err(match value["code"].as_str() {
            Some("peer_revoked") => RemoteError::PeerRevoked,
            Some("service_denied") => RemoteError::ServiceDenied,
            Some("invalid_request") => RemoteError::InvalidRequest,
            _ => RemoteError::Refused,
        }
        .into());
    }
    Ok(())
}

pub struct Session {
    pub carrier: Carrier,
    pub cipher: SecureTransport,
    pub peer: [u8; 32],
    pub binding: [u8; 32],
}

pub async fn initiate(
    mut carrier: Carrier,
    identity: &Identity,
    app: &str,
    pin: Option<[u8; 32]>,
) -> Result<Session> {
    let mut handshake = NoiseHandshake::initiator(identity, app)?;
    carrier.send(&handshake.write_message(&[])?).await?;
    handshake.read_message(&timeout(WAIT, carrier.receive()).await??)?;
    let peer = handshake.remote_static().ok_or("missing host identity")?;
    // Existing pairings refuse a substituted host before message3 discloses the client static key.
    if pin.is_some_and(|expected| expected != peer) {
        return Err("host identity refused".into());
    }
    carrier.send(&handshake.write_message(&[])?).await?;
    let binding = handshake.handshake_hash();
    Ok(Session {
        carrier,
        cipher: handshake.into_transport()?,
        peer,
        binding,
    })
}

pub async fn respond(mut carrier: Carrier, identity: &Identity, app: &str) -> Result<Session> {
    let mut handshake = NoiseHandshake::responder(identity, app)?;
    handshake.read_message(&timeout(WAIT, carrier.receive()).await??)?;
    carrier.send(&handshake.write_message(&[])?).await?;
    handshake.read_message(&timeout(WAIT, carrier.receive()).await??)?;
    let peer = handshake.remote_static().ok_or("missing client identity")?;
    let binding = handshake.handshake_hash();
    Ok(Session {
        carrier,
        cipher: handshake.into_transport()?,
        peer,
        binding,
    })
}
impl Session {
    pub async fn send(&mut self, value: Value) -> Result<()> {
        let bytes = serde_json::to_vec(&value)?;
        if bytes.len() > MAX_CONTROL {
            return Err("control exceeds limit".into());
        }
        self.carrier.send(&self.cipher.encrypt(&bytes)?).await
    }
    pub async fn receive(&mut self) -> Result<Value> {
        let ciphertext = timeout(WAIT, self.carrier.receive()).await??;
        let bytes = self.cipher.decrypt(&ciphertext)?;
        if bytes.len() > MAX_CONTROL {
            return Err("control exceeds limit".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
