//! ECDSA over NIST P-256 with SHA-256, as used by SGP.22 for `serverSignature1`,
//! `euiccSignature1` and the eIM package signature.
//!
//! # Encoding
//!
//! SGP.22 carries signatures as a **raw 64-byte `r‖s` concatenation**, not as
//! ASN.1 DER. This module therefore works in the raw form throughout: it is
//! what the wire format wants and it is what the underlying library produces.
//!
//! This module previously wrapped `ring`, which speaks ASN.1 DER and does not
//! expose the raw form, so it carried a hand-written DER<->raw conversion in
//! both directions. That conversion was, by the module's own admission, the
//! most bug-prone part of the file, and it existed only because of an encoding
//! mismatch between the library and the protocol. `p256` removes the mismatch,
//! so the conversion is gone rather than transliterated.
//!
//! `to_der` and `from_der` remain for the cases that genuinely need DER — a
//! certificate signature is DER, for instance — but they now delegate to the
//! library rather than parsing bytes here.
//!
//! # Which library
//!
//! `p256` is the RustCrypto implementation of NIST P-256, used across the
//! Rust ecosystem. It replaces `ring` for ECC. See
//! `docs/dependency-review.md` for the reasoning and the verification.

use crate::{Error, Result};
use p256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as P256Signature, SigningKey, VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;

/// Length of a raw `r‖s` signature: two 32-byte scalars.
pub const SIGNATURE_LEN: usize = 64;

/// Length of an SEC1 uncompressed P-256 point: `0x04` then two 32-byte coords.
pub const PUBLIC_KEY_LEN: usize = 65;

/// Length of a P-256 scalar, in bytes.
const SCALAR_LEN: usize = 32;

/// A P-256 signing key pair.
pub struct KeyPair {
    inner: SigningKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private scalar is never printed.
        f.write_str("KeyPair(<redacted>)")
    }
}

/// A P-256 public key, stored as an SEC1 uncompressed point.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey(Vec<u8>);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Wrap an SEC1 uncompressed point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN || bytes[0] != 0x04 {
            return Err(Error::Malformed(format!(
                "P-256 public key must be {PUBLIC_KEY_LEN} bytes starting \
                 0x04, got {} bytes starting {:#04x}",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            )));
        }
        // Reject points that are not on the curve, rather than accepting them
        // and failing later at verification time with a less clear message.
        VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::Malformed("public key is not a valid point on P-256".into()))?;
        Ok(PublicKey(bytes.to_vec()))
    }

    /// The raw uncompressed point.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The raw uncompressed point, owned.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(&self.0)
            .map_err(|_| Error::Malformed("invalid P-256 public key".into()))
    }

    /// Verify a raw `r‖s` SGP.22 signature over `message`.
    pub fn verify(&self, message: &[u8], raw_signature: &[u8]) -> Result<()> {
        let sig = self.parse_signature(raw_signature)?;
        self.verifying_key()?
            .verify(message, &sig)
            .map_err(|_| Error::VerificationFailed)
    }

    /// Verify an ASN.1 DER signature over `message`.
    ///
    /// A certificate signature is DER (RFC 5280), not the raw form SGP.22 uses
    /// on the wire, so this path exists for certificate verification.
    pub fn verify_der(&self, message: &[u8], der_signature: &[u8]) -> Result<()> {
        let sig = P256Signature::from_der(der_signature)
            .map_err(|_| Error::Malformed("invalid DER signature".into()))?;
        self.verifying_key()?
            .verify(message, &sig)
            .map_err(|_| Error::VerificationFailed)
    }

    fn parse_signature(&self, raw: &[u8]) -> Result<P256Signature> {
        if raw.len() != SIGNATURE_LEN {
            return Err(Error::Malformed(format!(
                "raw signature must be {SIGNATURE_LEN} bytes, got {}",
                raw.len()
            )));
        }
        P256Signature::from_slice(raw)
            .map_err(|_| Error::Malformed("signature scalars out of range".into()))
    }
}

/// A raw `r‖s` signature.
///
/// `Debug` prints the bytes: a signature is public data and printing it is
/// useful when diagnosing a conformance failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature(Vec<u8>);

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    /// Wrap raw `r‖s` bytes.
    pub fn from_raw(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::Malformed(format!(
                "signature must be {SIGNATURE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        // Reject scalars that are not valid, at construction rather than at
        // verification time.
        P256Signature::from_slice(bytes)
            .map_err(|_| Error::Malformed("signature scalars out of range".into()))?;
        Ok(Signature(bytes.to_vec()))
    }

    /// The raw `r‖s` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The raw `r‖s` bytes, owned.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// The ASN.1 DER form, for the paths that need it.
    pub fn to_der(&self) -> Vec<u8> {
        self.try_to_der().unwrap_or_default()
    }

    /// The ASN.1 DER form, reporting failure rather than returning empty.
    pub fn try_to_der(&self) -> Result<Vec<u8>> {
        let sig = P256Signature::from_slice(&self.0)
            .map_err(|_| Error::Malformed("signature scalars out of range".into()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

impl KeyPair {
    /// Generate a fresh key pair from the system RNG.
    pub fn generate() -> Result<Self> {
        Ok(KeyPair {
            inner: SigningKey::random(&mut rand_core::OsRng),
        })
    }

    /// Load a key pair from PKCS#8 DER.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        use p256::pkcs8::DecodePrivateKey as _;
        let inner = SigningKey::from_pkcs8_der(pkcs8)
            .map_err(|e| Error::Malformed(format!("invalid PKCS#8 private key: {e}")))?;
        Ok(KeyPair { inner })
    }

    /// The public half.
    pub fn public_key(&self) -> PublicKey {
        let point = self
            .inner
            .verifying_key()
            .as_affine()
            .to_encoded_point(false);
        PublicKey(point.as_bytes().to_vec())
    }

    /// Sign `message`, producing a raw `r‖s` signature.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let sig: P256Signature = self.inner.sign(message);
        Ok(Signature(sig.to_bytes().to_vec()))
    }

    /// Sign `message`, producing an ASN.1 DER signature.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig: P256Signature = self.inner.sign(message);
        Ok(sig.to_der().as_bytes().to_vec())
    }

    /// The PKCS#8 DER encoding of the private key.
    ///
    /// Returns empty if the key cannot be encoded, which does not happen for
    /// keys produced by this module. Prefer [`Self::to_pkcs8_checked`] when the
    /// caller needs to distinguish.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        self.to_pkcs8_checked().unwrap_or_default()
    }

    /// The PKCS#8 DER encoding of the private key, reporting failure.
    ///
    /// Unlike the previous `ring`-backed implementation, which could not always
    /// expose the scalar, `p256` can always encode a key it holds.
    pub fn to_pkcs8_checked(&self) -> Result<Vec<u8>> {
        use p256::pkcs8::EncodePrivateKey as _;
        Ok(self
            .inner
            .to_pkcs8_der()
            .map_err(|e| Error::Crypto(format!("PKCS#8 encoding failed: {e}")))?
            .as_bytes()
            .to_vec())
    }

    /// The raw 32-byte private scalar.
    ///
    /// Exposed because the test PKI needs to construct certificates and
    /// because a caller may need to persist a key; it is deliberately not
    /// reachable via `Debug`.
    pub fn to_scalar_bytes(&self) -> [u8; SCALAR_LEN] {
        self.inner.to_bytes().into()
    }
}

/// Generate a fresh signing key pair.
pub fn generate_key_pair() -> Result<KeyPair> {
    KeyPair::generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_verifies_under_its_own_key() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"message").unwrap();
        kp.public_key().verify(b"message", sig.as_ref()).unwrap();
    }

    #[test]
    fn signatures_are_the_raw_sixty_four_byte_form() {
        // SGP.22 carries r||s as 64 bytes. This is the whole reason for using
        // p256 rather than a DER-speaking library.
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"message").unwrap();
        assert_eq!(sig.as_ref().len(), SIGNATURE_LEN);
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"message").unwrap();
        assert_eq!(
            kp.public_key()
                .verify(b"messagf", sig.as_ref())
                .unwrap_err(),
            Error::VerificationFailed
        );
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let kp = KeyPair::generate().unwrap();
        let mut sig = kp.sign(b"message").unwrap().to_vec();
        sig[0] ^= 0x01;
        assert!(kp.public_key().verify(b"message", &sig).is_err());
    }

    #[test]
    fn verify_rejects_a_different_key() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let sig = a.sign(b"message").unwrap();
        assert!(b.public_key().verify(b"message", sig.as_ref()).is_err());
    }

    #[test]
    fn signatures_are_deterministic_per_rfc6979() {
        // The previous library produced a fresh signature each time because it
        // drew a random nonce. `p256` derives the nonce deterministically from
        // the key and message per RFC 6979, so signing the same message twice
        // gives identical bytes.
        //
        // This is a behaviour change and is recorded rather than asserted away:
        // it is an improvement, since a deterministic nonce removes the RNG
        // from the signing path and the nonce-reuse failure mode with it.
        let kp = KeyPair::generate().unwrap();
        let a = kp.sign(b"same message").unwrap();
        let b = kp.sign(b"same message").unwrap();
        assert_eq!(a, b, "RFC 6979 signing is deterministic");
        kp.public_key().verify(b"same message", a.as_ref()).unwrap();

        // Different messages must still give different signatures.
        let c = kp.sign(b"other message").unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn rfc6979_test_vector() {
        // RFC 6979 Appendix A.2.5, P-256 with SHA-256 over "sample".
        // The expected r and s are published in the RFC, so this pins the
        // signing implementation to an external vector rather than only
        // checking self-consistency.
        use p256::ecdsa::signature::Signer as _;
        let x = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
        let raw = hex_to_bytes(x);
        let sk = SigningKey::from_slice(&raw).unwrap();
        let sig: P256Signature = sk.sign(b"sample");
        let bytes = sig.to_bytes();
        // r and s, each 32 bytes.
        assert_eq!(
            crate::hex(&bytes[..32]),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
        );
        assert_eq!(
            crate::hex(&bytes[32..]),
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn der_and_raw_round_trip_both_ways() {
        let kp = KeyPair::generate().unwrap();
        let msg = b"message";
        let raw = kp.sign(msg).unwrap();
        let der = raw.try_to_der().unwrap();

        // The DER form must verify through the DER path.
        kp.public_key().verify_der(msg, &der).unwrap();
        // And converting back must give the original raw bytes.
        let back = P256Signature::from_der(&der).unwrap().to_bytes().to_vec();
        assert_eq!(back, raw.to_vec());
    }

    #[test]
    fn the_public_key_is_an_uncompressed_point() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_LEN);
        assert_eq!(pk.as_ref()[0], 0x04);
    }

    #[test]
    fn a_point_not_on_the_curve_is_rejected() {
        let mut bad = vec![0x04u8; PUBLIC_KEY_LEN];
        bad[1] = 0x01; // almost certainly not on the curve
        assert!(PublicKey::from_bytes(&bad).is_err());
    }

    #[test]
    fn a_wrong_length_public_key_is_rejected() {
        assert!(PublicKey::from_bytes(&[0x04u8; 64]).is_err());
        assert!(PublicKey::from_bytes(&[0x04u8; 66]).is_err());
        assert!(PublicKey::from_bytes(&[]).is_err());
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_rejected() {
        assert!(Signature::from_raw(&[0u8; 63]).is_err());
        assert!(Signature::from_raw(&[0u8; 65]).is_err());
    }

    #[test]
    fn keys_round_trip_through_pkcs8() {
        let kp = KeyPair::generate().unwrap();
        let der = kp.to_pkcs8_checked().unwrap();
        let back = KeyPair::from_pkcs8(&der).unwrap();
        assert_eq!(back.public_key(), kp.public_key());
        assert_eq!(back.to_scalar_bytes(), kp.to_scalar_bytes());
    }

    #[test]
    fn a_restored_key_produces_verifiable_signatures() {
        let kp = KeyPair::generate().unwrap();
        let restored = KeyPair::from_pkcs8(&kp.to_pkcs8_checked().unwrap()).unwrap();
        let sig = restored.sign(b"message").unwrap();
        kp.public_key().verify(b"message", sig.as_ref()).unwrap();
    }

    #[test]
    fn debug_does_not_leak_the_private_scalar() {
        let kp = KeyPair::generate().unwrap();
        let rendered = format!("{kp:?}");
        assert!(rendered.contains("redacted"));
        let scalar = kp.to_scalar_bytes();
        assert!(
            !rendered.contains(&crate::hex(&scalar)),
            "Debug must not print the private scalar"
        );
    }

    #[test]
    fn many_signatures_all_verify() {
        // A broad sweep, because the DER conversion this replaced was the
        // bug-prone part and rare encodings are where it failed.
        let kp = KeyPair::generate().unwrap();
        for i in 0..64u8 {
            let msg = [i; 32];
            let sig = kp.sign(&msg).unwrap();
            kp.public_key().verify(&msg, sig.as_ref()).unwrap();
        }
    }
}
