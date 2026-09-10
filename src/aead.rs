//! AES-128-GCM, used to encrypt the bound profile package and to protect
//! session records.
//!
//! SGP.22 §5.7.5 uses AES-128-GCM where the nonce is derived from the session
//! and a counter. Because nonce reuse is catastrophic for GCM, the API here
//! takes the nonce explicitly and documents the caller's obligation rather
//! than inventing a scheme.

use crate::{Error, Result};
use ring::aead;

/// AES-128-GCM key length.
pub const KEY_LEN: usize = 16;

/// AES-128-GCM nonce length.
pub const NONCE_LEN: usize = 12;

/// Length of the GCM authentication tag.
pub const TAG_LEN: usize = 16;

/// An AES-128-GCM key.
pub struct Key {
    inner: aead::LessSafeKey,
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(AES-128-GCM, redacted)")
    }
}

impl Key {
    /// Build a key from 16 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(Error::Malformed(format!(
                "AES-128-GCM key must be {KEY_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, bytes)
            .map_err(|_| Error::Crypto("invalid AES-128-GCM key".into()))?;
        Ok(Key {
            inner: aead::LessSafeKey::new(unbound),
        })
    }

    /// Encrypt `plaintext`, appending the 16-byte tag, with `aad` authenticated
    /// but not encrypted.
    ///
    /// **The caller must never reuse `nonce` with the same key.** In SGP.22 the
    /// nonce is derived from the session context, which is why it is a
    /// parameter here rather than generated internally.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        check_nonce(nonce)?;
        let nonce = aead::Nonce::assume_unique_for_key(to_nonce(nonce));
        let mut buf = plaintext.to_vec();
        self.inner
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut buf)
            .map_err(|_| Error::Crypto("AES-GCM encryption failed".into()))?;
        Ok(buf)
    }

    /// Decrypt `ciphertext` (which must include the tag), verifying `aad`.
    pub fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        check_nonce(nonce)?;
        if ciphertext.len() < TAG_LEN {
            return Err(Error::Malformed(format!(
                "ciphertext is {} bytes, shorter than the {TAG_LEN}-byte tag",
                ciphertext.len()
            )));
        }
        let nonce = aead::Nonce::assume_unique_for_key(to_nonce(nonce));
        let mut buf = ciphertext.to_vec();
        let plain = self
            .inner
            .open_in_place(nonce, aead::Aad::from(aad), &mut buf)
            .map_err(|_| Error::Crypto("AES-GCM decryption or tag check failed".into()))?;
        Ok(plain.to_vec())
    }
}

fn check_nonce(nonce: &[u8]) -> Result<()> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::Malformed(format!(
            "AES-GCM nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    Ok(())
}

fn to_nonce(nonce: &[u8]) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(nonce);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::new(&[0x2bu8; KEY_LEN]).unwrap()
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let k = key();
        let nonce = [0u8; NONCE_LEN];
        let msg = b"bound profile package segment";
        let ct = k.seal(&nonce, b"aad", msg).unwrap();
        assert_eq!(ct.len(), msg.len() + TAG_LEN);
        let pt = k.open(&nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn nist_aes_gcm_test_case_2_is_reproduced() {
        // NIST GCM spec test case 2: zero key, zero IV, zero plaintext.
        // Ciphertext is empty and the tag is a known 16-byte value.
        let k = Key::new(&[0u8; KEY_LEN]).unwrap();
        let ct = k.seal(&[0u8; NONCE_LEN], b"", b"").unwrap();
        assert_eq!(ct.len(), TAG_LEN);
        let expected = "58e2fccefa7e3061367f1d57a4e7455a";
        assert_eq!(crate::hex(&ct), expected);
    }

    #[test]
    fn nist_aes_gcm_test_case_3_is_reproduced() {
        // Same key and IV, 16 zero bytes of plaintext.
        let k = Key::new(&[0u8; KEY_LEN]).unwrap();
        let ct = k.seal(&[0u8; NONCE_LEN], b"", &[0u8; 16]).unwrap();
        let expected = "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf";
        assert_eq!(crate::hex(&ct), expected);
    }

    #[test]
    fn open_rejects_a_tampered_ciphertext() {
        let k = key();
        let nonce = [1u8; NONCE_LEN];
        let mut ct = k.seal(&nonce, b"aad", b"secret").unwrap();
        ct[0] ^= 0x01;
        assert!(k.open(&nonce, b"aad", &ct).is_err());
    }

    #[test]
    fn open_rejects_tampered_aad() {
        let k = key();
        let nonce = [2u8; NONCE_LEN];
        let ct = k.seal(&nonce, b"aad", b"secret").unwrap();
        assert!(k.open(&nonce, b"other", &ct).is_err());
    }

    #[test]
    fn open_rejects_a_wrong_nonce() {
        let k = key();
        let ct = k.seal(&[3u8; NONCE_LEN], b"", b"secret").unwrap();
        assert!(k.open(&[4u8; NONCE_LEN], b"", &ct).is_err());
    }

    #[test]
    fn open_rejects_a_wrong_key() {
        let ct = key().seal(&[5u8; NONCE_LEN], b"", b"secret").unwrap();
        let other = Key::new(&[7u8; KEY_LEN]).unwrap();
        assert!(other.open(&[5u8; NONCE_LEN], b"", &ct).is_err());
    }

    #[test]
    fn open_rejects_short_ciphertext() {
        assert!(key().open(&[0u8; NONCE_LEN], b"", &[0u8; 4]).is_err());
        assert!(key().open(&[0u8; NONCE_LEN], b"", &[]).is_err());
    }

    #[test]
    fn key_and_nonce_lengths_are_enforced() {
        assert!(Key::new(&[0u8; 15]).is_err());
        assert!(Key::new(&[0u8; 17]).is_err());
        assert!(Key::new(&[]).is_err());
        let k = key();
        assert!(k.seal(&[0u8; 11], b"", b"x").is_err());
        assert!(k.open(&[0u8; 13], b"", &[0u8; 20]).is_err());
    }

    #[test]
    fn distinct_nonces_produce_distinct_ciphertexts() {
        let k = key();
        let a = k.seal(&[0u8; NONCE_LEN], b"", b"same plaintext").unwrap();
        let b = k.seal(&[1u8; NONCE_LEN], b"", b"same plaintext").unwrap();
        assert_ne!(a, b);
    }
}
