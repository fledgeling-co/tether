//! Authenticated device identity for a forwarded TCP service.
//!
//! Without this, a forwarded TCP service sees a bare loopback connection: it cannot tell which
//! paired device opened the stream, and any local process can connect to the same port. A
//! service configured with an identity key gets a proof before any application byte:
//!
//! 1. The service writes a challenge: `TPIC`, version `1`, and 32 fresh random bytes.
//! 2. The host answers: `TPIP`, version `1`, the device's 32-byte Noise public key, and
//!    `HMAC-SHA256(key, "tether-peer-identity/v1\0" || len(service) || service || challenge || device)`.
//!
//! The key is shared only by the host's private configuration and the service, so a local
//! process without the key cannot forge a proof, and the service's fresh challenge stops one
//! proof being replayed on another connection. The device key is the one the Noise handshake
//! authenticated and the host's grant check admitted for this service.

use crate::carrier::Result;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CHALLENGE_MAGIC: &[u8; 4] = b"TPIC";
pub const PROOF_MAGIC: &[u8; 4] = b"TPIP";
pub const VERSION: u8 = 1;
/// Magic, version and a 32-byte challenge.
pub const CHALLENGE_LEN: usize = 4 + 1 + 32;
/// Magic, version, the 32-byte device key and the 32-byte proof.
pub const PROOF_LEN: usize = 4 + 1 + 32 + 32;
const LABEL: &[u8] = b"tether-peer-identity/v1\0";

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|byte| byte ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|byte| byte ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// The proof a host sends for `device` on `service` in answer to `challenge`.
pub fn proof(key: &[u8; 32], service: &str, challenge: &[u8; 32], device: &[u8; 32]) -> [u8; 32] {
    let length = [u8::try_from(service.len()).unwrap_or(u8::MAX)];
    hmac_sha256(
        key,
        &[LABEL, &length, service.as_bytes(), challenge, device],
    )
}

/// Whether `mac` proves `device` on `service` for `challenge`, compared in constant time.
pub fn verify(
    key: &[u8; 32],
    service: &str,
    challenge: &[u8; 32],
    device: &[u8; 32],
    mac: &[u8; 32],
) -> bool {
    let expected = proof(key, service, challenge, device);
    expected
        .iter()
        .zip(mac.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

/// Answer the service's challenge on a freshly connected stream. The caller bounds the time.
pub async fn present<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    key: &[u8; 32],
    service: &str,
    device: &[u8; 32],
) -> Result<()> {
    let mut challenge = [0u8; CHALLENGE_LEN];
    stream.read_exact(&mut challenge).await?;
    if &challenge[..4] != CHALLENGE_MAGIC || challenge[4] != VERSION {
        return Err("service did not send an identity challenge".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&challenge[5..]);
    let mac = proof(key, service, &nonce, device);
    let mut answer = Vec::with_capacity(PROOF_LEN);
    answer.extend_from_slice(PROOF_MAGIC);
    answer.push(VERSION);
    answer.extend_from_slice(device);
    answer.extend_from_slice(&mac);
    stream.write_all(&answer).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn hmac_matches_rfc_4231_test_cases_1_and_2() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(
                b"Jefe",
                &[b"what do ya ", b"want for nothing?"]
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_hashes_a_key_longer_than_the_block() {
        // RFC 4231 test case 6: a 131-byte key.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn a_proof_binds_key_service_challenge_and_device() {
        let (key, challenge, device) = ([7u8; 32], [9u8; 32], [3u8; 32]);
        let mac = proof(&key, "router", &challenge, &device);
        assert!(verify(&key, "router", &challenge, &device, &mac));
        assert!(!verify(&[8u8; 32], "router", &challenge, &device, &mac));
        assert!(!verify(&key, "routes", &challenge, &device, &mac));
        assert!(!verify(&key, "router", &[10u8; 32], &device, &mac));
        assert!(!verify(&key, "router", &challenge, &[4u8; 32], &mac));
    }

    #[tokio::test]
    async fn the_host_answers_a_challenge_the_service_can_verify() -> Result<()> {
        let (mut host, mut service) = tokio::io::duplex(256);
        let (key, device, nonce) = ([5u8; 32], [6u8; 32], [11u8; 32]);
        let mut challenge = CHALLENGE_MAGIC.to_vec();
        challenge.push(VERSION);
        challenge.extend_from_slice(&nonce);
        service.write_all(&challenge).await?;
        present(&mut host, &key, "router", &device).await?;
        let mut answer = [0u8; PROOF_LEN];
        service.read_exact(&mut answer).await?;
        assert_eq!(&answer[..4], PROOF_MAGIC);
        assert_eq!(answer[4], VERSION);
        assert_eq!(&answer[5..37], &device);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&answer[37..]);
        assert!(verify(&key, "router", &nonce, &device, &mac));
        Ok(())
    }

    #[tokio::test]
    async fn a_service_that_sends_no_challenge_is_refused() -> Result<()> {
        let (mut host, mut service) = tokio::io::duplex(256);
        service.write_all(&[0u8; CHALLENGE_LEN]).await?;
        assert!(present(&mut host, &[1u8; 32], "router", &[2u8; 32])
            .await
            .is_err());
        Ok(())
    }
}
