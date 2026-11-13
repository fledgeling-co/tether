//! Socket-free Tether v1 cryptography. Callers own per-app identities, storage, expiry,
//! online-guess budgets, peer authorization, revocation and transport lifecycle.
//!
//! Noise handshake payloads are empty. Its encrypted transport can then carry PAKE/control
//! records; only callers that have verified the peer allowlist may open application services.
//! The relay never needs either identity secret, pairing code, or plaintext records.
//!
//! Secret owners here wipe their own buffers. Upstream SPAKE2/Snow internal key/scalar copies
//! are not guaranteed to be wiped; this is not an audited implementation.

mod noise;
mod pairing;
mod sas;

pub use noise::{Identity, NoiseHandshake, SecureTransport, MAX_CIPHERTEXT, MAX_PLAINTEXT};
pub use pairing::{normalize_code, Confirmation, Pairing, Role};
pub use sas::{SasClient, SasCode, SasHost, SAS_NONCE};

/// Fixed failures deliberately carry no received bytes, passwords, identities or library errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidAppId,
    InvalidIdentity,
    InvalidCode,
    InvalidBinding,
    InvalidMessage,
    InvalidState,
    EarlyData,
    FrameTooLarge,
    Authentication,
    Crypto,
    Retired,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidAppId => "invalid application scope",
            Self::InvalidIdentity => "invalid device identity",
            Self::InvalidCode => "invalid pairing code",
            Self::InvalidBinding => "invalid channel binding",
            Self::InvalidMessage => "invalid protocol message",
            Self::InvalidState => "invalid protocol state",
            Self::EarlyData => "handshake application data refused",
            Self::FrameTooLarge => "record exceeds protocol limit",
            Self::Authentication => "authentication refused",
            Self::Crypto => "cryptographic operation refused",
            Self::Retired => "channel retired",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn validate_app_id(app_id: &str) -> Result<()> {
    if app_id.is_empty()
        || app_id.len() > 64
        || !app_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::InvalidAppId);
    }
    Ok(())
}

pub(crate) fn field(output: &mut Vec<u8>, value: &[u8]) {
    // All field lengths are bounded by the public input validation before reaching this helper.
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
