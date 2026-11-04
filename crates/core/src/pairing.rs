use crate::{field, validate_app_id, Error, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Host,
}

/// Accept the displayed two-group code, ASCII Crockford aliases and case, never arbitrary punctuation.
pub fn normalize_code(code: &str) -> Result<String> {
    if code.len() > 32 {
        return Err(Error::InvalidCode);
    }
    let mut normalized = String::with_capacity(8);
    for c in code.bytes() {
        let upper = match c {
            b'-' | b' ' => continue,
            b'a'..=b'z' => c.to_ascii_uppercase(),
            b if b.is_ascii() => b,
            _ => return Err(Error::InvalidCode),
        };
        let canonical = match upper {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            b => b,
        };
        if !b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&canonical) {
            return Err(Error::InvalidCode);
        }
        normalized.push(canonical as char);
    }
    if normalized.len() != 8 {
        return Err(Error::InvalidCode);
    }
    Ok(normalized)
}

/// One ephemeral balanced PAKE, consumed by finish. It never owns online attempt policy.
pub struct Pairing {
    exchange: Spake2<Ed25519Group>,
    role: Role,
    context: Vec<u8>,
}
impl Pairing {
    pub fn start(
        role: Role,
        code: &str,
        app_id: &str,
        binding: [u8; 32],
        client_key: [u8; 32],
        host_key: [u8; 32],
    ) -> Result<(Self, Vec<u8>)> {
        validate_app_id(app_id)?;
        if binding == [0; 32] {
            return Err(Error::InvalidBinding);
        }
        if client_key == [0; 32] || host_key == [0; 32] || client_key == host_key {
            return Err(Error::InvalidIdentity);
        }
        let code = Zeroizing::new(normalize_code(code)?);
        let mut identity_a = Vec::new();
        field(&mut identity_a, b"tether/pairing/v1/client");
        field(&mut identity_a, app_id.as_bytes());
        let mut identity_b = Vec::new();
        field(&mut identity_b, b"tether/pairing/v1/host");
        field(&mut identity_b, app_id.as_bytes());
        let password = Password::new(code.as_bytes());
        let id_a = Identity::new(&identity_a);
        let id_b = Identity::new(&identity_b);
        // Make OS entropy failure an ordinary refusal instead of allowing OsRng::fill_bytes
        // inside the upstream start_* convenience functions to panic. The temporary RNG belongs
        // to the library call and its internal state has the upstream wipe limitation above.
        let mut seed = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Crypto)?;
        let rng = ChaCha20Rng::from_seed(*seed);
        let (exchange, message) = match role {
            Role::Client => Spake2::<Ed25519Group>::start_a_with_rng(&password, &id_a, &id_b, rng),
            Role::Host => Spake2::<Ed25519Group>::start_b_with_rng(&password, &id_a, &id_b, rng),
        };
        let mut context = Vec::new();
        for value in [
            b"tether/pairing-confirmation/v1".as_slice(),
            app_id.as_bytes(),
            &binding,
            &client_key,
            &host_key,
        ] {
            field(&mut context, value);
        }
        Ok((
            Self {
                exchange,
                role,
                context,
            },
            message,
        ))
    }

    pub fn finish(self, peer_message: &[u8]) -> Result<Confirmation> {
        // The library validates the side byte. Add canonical prime-subgroup validation before
        // its decompression-only parser; all arithmetic remains in curve25519-dalek.
        if peer_message.len() != 33 {
            return Err(Error::InvalidMessage);
        }
        let mut encoded = [0; 32];
        encoded.copy_from_slice(&peer_message[1..]);
        let point = CompressedEdwardsY(encoded)
            .decompress()
            .ok_or(Error::InvalidMessage)?;
        if point.is_small_order()
            || !point.is_torsion_free()
            || point.compress().to_bytes() != encoded
        {
            return Err(Error::InvalidMessage);
        }
        let key = Zeroizing::new(
            self.exchange
                .finish(peer_message)
                .map_err(|_| Error::Authentication)?,
        );
        let digest = Sha256::digest(&self.context);
        let hkdf = Hkdf::<Sha256>::new(Some(&digest), &key);
        let mut keys = Zeroizing::new([0; 64]);
        hkdf.expand(b"tether/pairing-confirmation-keys/v1", keys.as_mut())
            .map_err(|_| Error::Crypto)?;
        let (send, receive) = match self.role {
            Role::Client => (&keys[..32], &keys[32..]),
            Role::Host => (&keys[32..], &keys[..32]),
        };
        let mut expected = [0; 32];
        expected.copy_from_slice(receive);
        let outbound = confirmation(send, &digest)?;
        Ok(Confirmation {
            outbound,
            expected_key: Zeroizing::new(expected),
            context_hash: digest.into(),
        })
    }
}

fn confirmation(key: &[u8], context: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| Error::Crypto)?;
    mac.update(context);
    Ok(mac.finalize().into_bytes().into())
}

/// Mutual key confirmation. Each direction has an independent key, so reflection cannot verify.
pub struct Confirmation {
    outbound: [u8; 32],
    expected_key: Zeroizing<[u8; 32]>,
    context_hash: [u8; 32],
}
impl Confirmation {
    pub fn outbound(&self) -> [u8; 32] {
        self.outbound
    }
    pub fn verify_peer(&self, peer: &[u8]) -> Result<()> {
        let mut mac =
            HmacSha256::new_from_slice(self.expected_key.as_ref()).map_err(|_| Error::Crypto)?;
        mac.update(&self.context_hash);
        mac.verify_slice(peer).map_err(|_| Error::Authentication)
    }
}
