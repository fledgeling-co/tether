//! Nearby pairing by comparison: both devices show a six-digit code derived from the
//! authenticated Noise channel and each owner approves it.
//!
//! The client commits to its nonce before it sees the host's, and the host's nonce is fixed
//! before the client reveals. A device in the middle runs two separate channels with different
//! bindings, and cannot choose either nonce after learning the other side's, so it matches the
//! two displayed codes with probability 10^-6 per attempt. Callers bound attempts and expiry.
use crate::{field, validate_app_id, Error, Result};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SAS_NONCE: usize = 32;
const DIGITS: u64 = 1_000_000;

/// Six decimal digits. Display it as two groups of three; compare it as a whole.
#[derive(Clone, PartialEq, Eq)]
pub struct SasCode(Zeroizing<String>);
impl SasCode {
    pub fn digits(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for SasCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SasCode(..)")
    }
}

struct Context {
    bytes: Vec<u8>,
}
impl Context {
    fn new(
        app_id: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
    ) -> Result<Self> {
        validate_app_id(app_id)?;
        if binding == [0; 32] {
            return Err(Error::InvalidBinding);
        }
        if client_key == [0; 32] || host_key == [0; 32] || client_key == host_key {
            return Err(Error::InvalidIdentity);
        }
        let mut bytes = Vec::new();
        for value in [app_id.as_bytes(), &binding, &client_key, &host_key] {
            field(&mut bytes, value);
        }
        Ok(Self { bytes })
    }
    fn commitment(&self, client_nonce: &[u8; SAS_NONCE]) -> [u8; 32] {
        let mut hash = Sha256::new();
        let mut label = Vec::new();
        field(&mut label, b"tether/sas-commit/v1");
        hash.update(&label);
        hash.update(&self.bytes);
        let mut nonce = Vec::new();
        field(&mut nonce, client_nonce);
        hash.update(&nonce);
        hash.finalize().into()
    }
    fn code(
        &self,
        client_nonce: &[u8; SAS_NONCE],
        host_nonce: &[u8; SAS_NONCE],
    ) -> Result<SasCode> {
        let mut salt = Vec::new();
        field(&mut salt, b"tether/sas-code/v1");
        salt.extend_from_slice(&self.bytes);
        let salt = Sha256::digest(&salt);
        let mut ikm = Zeroizing::new(Vec::with_capacity(2 * SAS_NONCE));
        ikm.extend_from_slice(client_nonce);
        ikm.extend_from_slice(host_nonce);
        let mut out = Zeroizing::new([0u8; 8]);
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(b"tether/sas-digits/v1", out.as_mut())
            .map_err(|_| Error::Crypto)?;
        // 2^64 mod 10^6 is negligible bias for a six-digit comparison code.
        let value = u64::from_be_bytes(*out) % DIGITS;
        Ok(SasCode(Zeroizing::new(format!("{value:06}"))))
    }
}

fn nonce() -> Result<Zeroizing<[u8; SAS_NONCE]>> {
    let mut value = Zeroizing::new([0u8; SAS_NONCE]);
    OsRng
        .try_fill_bytes(value.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(value)
}

fn fixed(bytes: &[u8]) -> Result<[u8; SAS_NONCE]> {
    bytes.try_into().map_err(|_| Error::InvalidMessage)
}

fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The client side: commit, then reveal once the host's nonce has arrived.
pub struct SasClient {
    context: Context,
    nonce: Zeroizing<[u8; SAS_NONCE]>,
}
impl SasClient {
    /// Returns the state and the commitment to send first.
    pub fn start(
        app_id: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
    ) -> Result<(Self, [u8; 32])> {
        let context = Context::new(app_id, binding, client_key, host_key)?;
        let nonce = nonce()?;
        let commitment = context.commitment(&nonce);
        Ok((Self { context, nonce }, commitment))
    }
    /// Consumes the host nonce. Returns the nonce to reveal and the code to display.
    pub fn finish(self, host_nonce: &[u8]) -> Result<([u8; SAS_NONCE], SasCode)> {
        let host_nonce = fixed(host_nonce)?;
        let code = self.context.code(&self.nonce, &host_nonce)?;
        Ok((*self.nonce, code))
    }
}

/// The host side: hold the client's commitment, answer with a nonce, verify the reveal.
pub struct SasHost {
    context: Context,
    commitment: [u8; 32],
    nonce: Zeroizing<[u8; SAS_NONCE]>,
}
impl SasHost {
    /// Returns the state and the nonce to send. The commitment is fixed before this nonce exists.
    pub fn start(
        app_id: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
        commitment: &[u8],
    ) -> Result<(Self, [u8; SAS_NONCE])> {
        let context = Context::new(app_id, binding, client_key, host_key)?;
        let commitment: [u8; 32] = commitment.try_into().map_err(|_| Error::InvalidMessage)?;
        let nonce = nonce()?;
        let reply = *nonce;
        Ok((
            Self {
                context,
                commitment,
                nonce,
            },
            reply,
        ))
    }
    /// Refuses a reveal that does not open the commitment.
    pub fn finish(self, client_nonce: &[u8]) -> Result<SasCode> {
        let client_nonce = fixed(client_nonce)?;
        if !equal(&self.context.commitment(&client_nonce), &self.commitment) {
            return Err(Error::Authentication);
        }
        self.context.code(&client_nonce, &self.nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const APP: &str = "dev.simdeck.app";
    fn keys() -> ([u8; 32], [u8; 32], [u8; 32]) {
        ([7; 32], [1; 32], [2; 32])
    }

    #[test]
    fn both_sides_derive_the_same_six_digits() -> Result<()> {
        let (binding, client, host) = keys();
        let (c, commitment) = SasClient::start(APP, binding, client, host)?;
        let (h, host_nonce) = SasHost::start(APP, binding, client, host, &commitment)?;
        let (reveal, client_code) = c.finish(&host_nonce)?;
        let host_code = h.finish(&reveal)?;
        assert_eq!(client_code, host_code);
        assert_eq!(client_code.digits().len(), 6);
        assert!(client_code.digits().bytes().all(|b| b.is_ascii_digit()));
        Ok(())
    }

    #[test]
    fn a_reveal_that_does_not_open_the_commitment_is_refused() -> Result<()> {
        let (binding, client, host) = keys();
        let (_c, commitment) = SasClient::start(APP, binding, client, host)?;
        let (h, _) = SasHost::start(APP, binding, client, host, &commitment)?;
        assert_eq!(h.finish(&[9; 32]).unwrap_err(), Error::Authentication);
        Ok(())
    }

    #[test]
    fn different_channels_give_unrelated_codes() -> Result<()> {
        // A relay in the middle holds two channels with different bindings and keys.
        let (_, client, host) = keys();
        let mut same = 0;
        for i in 0..200u8 {
            let (c, commitment) = SasClient::start(APP, [i | 1; 32], client, host)?;
            let (h, nonce) = SasHost::start(APP, [i | 1; 32], client, host, &commitment)?;
            let (reveal, a) = c.finish(&nonce)?;
            assert_eq!(h.finish(&reveal)?, a);
            let (c2, commitment2) = SasClient::start(APP, [i | 2; 32], client, [3; 32])?;
            let (h2, nonce2) = SasHost::start(APP, [i | 2; 32], client, [3; 32], &commitment2)?;
            let (reveal2, b) = c2.finish(&nonce2)?;
            assert_eq!(h2.finish(&reveal2)?, b);
            same += usize::from(a == b);
        }
        assert!(
            same <= 1,
            "codes from separate channels matched {same} times in 200"
        );
        Ok(())
    }

    #[test]
    fn the_code_binds_the_application_and_both_keys() -> Result<()> {
        let (binding, client, host) = keys();
        let (c, commitment) = SasClient::start(APP, binding, client, host)?;
        // The host sees a different client key than the client used: its commitment check fails.
        let (h, nonce) = SasHost::start(APP, binding, [5; 32], host, &commitment)?;
        let (reveal, _) = c.finish(&nonce)?;
        assert_eq!(h.finish(&reveal).unwrap_err(), Error::Authentication);
        let (_, commitment) = SasClient::start(APP, binding, client, host)?;
        assert!(SasHost::start("other.app", binding, client, host, &commitment).is_ok());
        Ok(())
    }

    #[test]
    fn malformed_inputs_are_refused_without_panicking() {
        let (binding, client, host) = keys();
        assert_eq!(
            SasClient::start(APP, [0; 32], client, host).err(),
            Some(Error::InvalidBinding)
        );
        assert_eq!(
            SasClient::start(APP, binding, client, client).err(),
            Some(Error::InvalidIdentity)
        );
        assert_eq!(
            SasHost::start(APP, binding, client, host, &[1; 31]).err(),
            Some(Error::InvalidMessage)
        );
        let (c, _) = SasClient::start(APP, binding, client, host).unwrap();
        assert_eq!(c.finish(&[1; 5]).err(), Some(Error::InvalidMessage));
    }
}
