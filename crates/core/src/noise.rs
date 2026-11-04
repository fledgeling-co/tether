use crate::{field, validate_app_id, Error, Result};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT: usize = 16_384;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 16;
const HANDSHAKE_LIMIT: usize = 512;
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// The caller stores one distinct identity per application. This type never chooses a global key.
/// `private()` explicitly copies secret bytes; callers must immediately put them in protected storage.
#[derive(Clone)]
pub struct Identity {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let pair = snow::Builder::new(PATTERN.parse().map_err(|_| Error::Crypto)?)
            .generate_keypair()
            .map_err(|_| Error::Crypto)?;
        let private = Zeroizing::new(pair.private);
        let bytes: [u8; 32] = private.as_slice().try_into().map_err(|_| Error::Crypto)?;
        Self::from_private(bytes)
    }

    pub fn from_private(private: [u8; 32]) -> Result<Self> {
        if private == [0; 32] {
            return Err(Error::InvalidIdentity);
        }
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            private: Zeroizing::new(private),
            public,
        })
    }

    pub fn public(&self) -> [u8; 32] {
        self.public
    }
    pub fn private(&self) -> [u8; 32] {
        *self.private
    }
}

/// A Noise XX exchange. The authenticated peer key is available only once Noise has learned it.
/// Before service traffic, callers compare both static keys with the pairing allowlist.
pub struct NoiseHandshake {
    state: Option<snow::HandshakeState>,
    remote: Option<[u8; 32]>,
    hash: [u8; 32],
}

impl NoiseHandshake {
    pub fn initiator(identity: &Identity, app_id: &str) -> Result<Self> {
        Self::new(identity, app_id, true)
    }
    pub fn responder(identity: &Identity, app_id: &str) -> Result<Self> {
        Self::new(identity, app_id, false)
    }
    fn new(identity: &Identity, app_id: &str, initiator: bool) -> Result<Self> {
        validate_app_id(app_id)?;
        let mut prologue = Vec::new();
        field(&mut prologue, b"tether/noise/v1");
        field(&mut prologue, app_id.as_bytes());
        let builder = snow::Builder::new(PATTERN.parse().map_err(|_| Error::Crypto)?)
            .local_private_key(identity.private.as_ref())
            .map_err(|_| Error::Crypto)?
            .prologue(&prologue)
            .map_err(|_| Error::Crypto)?;
        let state = if initiator {
            builder.build_initiator()
        } else {
            builder.build_responder()
        }
        .map_err(|_| Error::Crypto)?;
        let mut result = Self {
            state: Some(state),
            remote: None,
            hash: [0; 32],
        };
        result.update_metadata();
        Ok(result)
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        if !payload.is_empty() {
            self.state = None;
            return Err(Error::EarlyData);
        }
        let mut out = vec![0; HANDSHAKE_LIMIT];
        let result = self
            .state
            .as_mut()
            .ok_or(Error::Retired)?
            .write_message(payload, &mut out);
        match result {
            Ok(n) => {
                out.truncate(n);
                self.update_metadata();
                Ok(out)
            }
            Err(_) => {
                self.state = None;
                Err(Error::Crypto)
            }
        }
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if message.len() > HANDSHAKE_LIMIT {
            self.state = None;
            return Err(Error::FrameTooLarge);
        }
        let mut out = Zeroizing::new(vec![0; HANDSHAKE_LIMIT]);
        let result = self
            .state
            .as_mut()
            .ok_or(Error::Retired)?
            .read_message(message, &mut out);
        match result {
            Ok(0) => {
                self.update_metadata();
                Ok(Vec::new())
            }
            Ok(_) => {
                self.state = None;
                Err(Error::EarlyData)
            }
            Err(_) => {
                self.state = None;
                Err(Error::Crypto)
            }
        }
    }

    pub fn remote_static(&self) -> Option<[u8; 32]> {
        self.remote
    }
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.hash
    }
    pub fn is_finished(&self) -> bool {
        self.state
            .as_ref()
            .is_some_and(snow::HandshakeState::is_handshake_finished)
    }

    pub fn into_transport(mut self) -> Result<SecureTransport> {
        let state = self.state.take().ok_or(Error::Retired)?;
        let transport = state
            .into_transport_mode()
            .map_err(|_| Error::InvalidState)?;
        Ok(SecureTransport {
            state: Some(transport),
        })
    }

    fn update_metadata(&mut self) {
        if let Some(state) = &self.state {
            self.hash.copy_from_slice(state.get_handshake_hash());
            self.remote = state
                .get_remote_static()
                .and_then(|key| key.try_into().ok());
        }
    }
}

/// Ordered authenticated records. Failed decryption retires the channel; it cannot be retried.
pub struct SecureTransport {
    state: Option<snow::TransportState>,
}
impl SecureTransport {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::FrameTooLarge);
        }
        let mut out = vec![0; plaintext.len() + 16];
        let result = self
            .state
            .as_mut()
            .ok_or(Error::Retired)?
            .write_message(plaintext, &mut out);
        match result {
            Ok(n) => {
                out.truncate(n);
                Ok(out)
            }
            Err(_) => {
                self.state = None;
                Err(Error::Crypto)
            }
        }
    }
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !(16..=MAX_CIPHERTEXT).contains(&ciphertext.len()) {
            self.state = None;
            return Err(Error::FrameTooLarge);
        }
        let mut out = Zeroizing::new(vec![0; ciphertext.len() - 16]);
        let result = self
            .state
            .as_mut()
            .ok_or(Error::Retired)?
            .read_message(ciphertext, &mut out);
        match result {
            Ok(n) => Ok(out[..n].to_vec()),
            Err(_) => {
                self.state = None;
                Err(Error::Authentication)
            }
        }
    }
}
