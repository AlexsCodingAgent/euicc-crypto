//! ECDH key agreement over NIST P-256, as used to derive the RSP session keys.
//!
//! SGP.22 §5.7.5: the eUICC and the SM-DP+ each generate an ephemeral P-256 key
//! pair, exchange the public points, and agree on a shared secret. That shared
//! secret is then run through the KDF in [`crate::kdf`] to produce the session
//! encryption and MAC keys.
//!
//! The shared secret is a raw X coordinate (32 bytes), not a hashed value —
//! SGP.22 applies the KDF afterwards.

use crate::ecdsa::PUBLIC_KEY_LEN;
use crate::{Error, Result};
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::rand::SystemRandom;

/// Length of a P-256 ECDH shared secret (the X coordinate).
pub const SHARED_SECRET_LEN: usize = 32;

/// An ephemeral P-256 private key held for the duration of a session.
///
/// The private key is consumed by [`EphemeralKey::agree`], matching the
/// one-shot nature of the exchange: an eUICC uses a fresh ephemeral key for
/// each RSP session and must not reuse it.
pub struct EphemeralKey {
    inner: EphemeralPrivateKey,
    public: Vec<u8>,
}

impl std::fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKey")
            .field("public", &crate::hex(&self.public))
            .finish_non_exhaustive()
    }
}

impl EphemeralKey {
    /// Generate a fresh ephemeral P-256 key pair.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let inner = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|_| Error::Crypto("ECDH key generation failed".into()))?;
        let public = inner
            .compute_public_key()
            .map_err(|_| Error::Crypto("ECDH public key derivation failed".into()))?
            .as_ref()
            .to_vec();
        Ok(EphemeralKey { inner, public })
    }

    /// The uncompressed public point (`0x04 ‖ X ‖ Y`).
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Agree on a shared secret with the peer's uncompressed public point.
    ///
    /// Consumes `self`, because a ring `EphemeralPrivateKey` is single-use.
    pub fn agree(self, peer_public: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
        if peer_public.len() != PUBLIC_KEY_LEN || peer_public[0] != 0x04 {
            return Err(Error::Malformed(format!(
                "peer public key must be {PUBLIC_KEY_LEN} bytes starting 0x04, \
                 got {} bytes starting {:#04x}",
                peer_public.len(),
                peer_public.first().copied().unwrap_or(0)
            )));
        }
        let peer = UnparsedPublicKey::new(&ECDH_P256, peer_public);
        let agreed = agreement::agree_ephemeral(self.inner, &peer, |secret| {
            if secret.len() != SHARED_SECRET_LEN {
                return Err(Error::Crypto(format!(
                    "ECDH secret is {} bytes, expected {SHARED_SECRET_LEN}",
                    secret.len()
                )));
            }
            let mut out = [0u8; SHARED_SECRET_LEN];
            out.copy_from_slice(secret);
            Ok(out)
        })
        .map_err(|_| Error::Crypto("ECDH agreement failed".into()))?;
        agreed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_the_same_secret() {
        let a = EphemeralKey::generate().unwrap();
        let b = EphemeralKey::generate().unwrap();
        let a_pub = a.public_key().to_vec();
        let b_pub = b.public_key().to_vec();

        let secret_a = a.agree(&b_pub).unwrap();
        let secret_b = b.agree(&a_pub).unwrap();
        assert_eq!(secret_a, secret_b);
        assert_eq!(secret_a.len(), SHARED_SECRET_LEN);
        // A real secret is not all-zero.
        assert!(secret_a.iter().any(|&x| x != 0));
    }

    #[test]
    fn different_peers_give_different_secrets() {
        let a = EphemeralKey::generate().unwrap();
        let b = EphemeralKey::generate().unwrap();
        let c = EphemeralKey::generate().unwrap();
        let s_ab = a.agree(b.public_key()).unwrap();
        let s_ac = c.agree(b.public_key()).unwrap();
        assert_ne!(s_ab, s_ac);
    }

    #[test]
    fn ephemeral_keys_are_unique_per_generation() {
        let a = EphemeralKey::generate().unwrap();
        let b = EphemeralKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn public_key_is_uncompressed_p256() {
        let k = EphemeralKey::generate().unwrap();
        assert_eq!(k.public_key().len(), PUBLIC_KEY_LEN);
        assert_eq!(k.public_key()[0], 0x04);
    }

    #[test]
    fn agree_rejects_a_malformed_peer_key() {
        let a = EphemeralKey::generate().unwrap();
        assert!(a.agree(&[0x04; 64]).is_err());
    }
}
