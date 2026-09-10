//! ECDSA over NIST P-256 with SHA-256, as used by SGP.22 for `serverSignature1`,
//! `euiccSignature1` and the eIM package signature.
//!
//! # Encoding
//!
//! `ring` speaks ASN.1 DER; SGP.22 speaks raw 64-byte `r‖s`. The two
//! conversions ([`der_to_raw`], [`raw_to_der`]) are the most bug-prone part of
//! this module, so both are exhaustively round-trip tested and the DER parser
//! handles the cases a naive one gets wrong: long-form lengths, and the leading
//! zero byte that DER requires whenever the high bit of `r` or `s` is set.

use crate::{Error, Result};
use ring::rand::SystemRandom;
use ring::signature::{self, KeyPair as _};

/// The curve and hash used throughout SGP.22: ECDSA P-256 with SHA-256.
pub const ALGORITHM: &signature::EcdsaSigningAlgorithm = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;

/// The matching verification algorithm.
pub const VERIFY_ALGORITHM: &signature::EcdsaVerificationAlgorithm =
    &signature::ECDSA_P256_SHA256_ASN1;

/// Length of an uncompressed P-256 public key (`0x04 ‖ X ‖ Y`).
pub const PUBLIC_KEY_LEN: usize = 65;

/// Length of the raw SGP.22 signature form (`r ‖ s`).
pub const SIGNATURE_LEN: usize = 64;

/// A P-256 key pair.
///
/// Wraps the PKCS#8 encoding so the key can be passed across crate boundaries
/// without exposing `ring` types.
pub struct KeyPair {
    inner: signature::EcdsaKeyPair,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &crate::hex(self.public_key().as_ref()))
            .finish_non_exhaustive()
    }
}

/// An uncompressed P-256 public key (`0x04 ‖ X ‖ Y`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PublicKey {
    /// Wrap raw uncompressed point bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN || bytes[0] != 0x04 {
            return Err(Error::Malformed(format!(
                "P-256 public key must be {PUBLIC_KEY_LEN} bytes starting \
                 0x04, got {} bytes starting {:#04x}",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            )));
        }
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

    /// Verify a raw `r‖s` SGP.22 signature over `message`.
    pub fn verify(&self, message: &[u8], raw_signature: &[u8]) -> Result<()> {
        let der = raw_to_der(raw_signature)?;
        let key = signature::UnparsedPublicKey::new(VERIFY_ALGORITHM, &self.0);
        key.verify(message, &der)
            .map_err(|_| Error::VerificationFailed)
    }

    /// Verify an ASN.1 DER signature over `message`.
    pub fn verify_der(&self, message: &[u8], der_signature: &[u8]) -> Result<()> {
        let key = signature::UnparsedPublicKey::new(VERIFY_ALGORITHM, &self.0);
        key.verify(message, der_signature)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// A raw SGP.22 signature (`r ‖ s`, 64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
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
                "raw signature must be {SIGNATURE_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Signature(bytes.to_vec()))
    }

    /// The raw `r‖s` bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The DER encoding of this signature.
    pub fn to_der(&self) -> Vec<u8> {
        // A structurally valid raw signature always converts; if it does not,
        // the signature was malformed and we surface it as an empty DER, which
        // cannot verify. Callers that care should use `try_to_der`.
        raw_to_der(&self.0).unwrap_or_default()
    }

    /// The DER encoding of this signature, or an error if `r`/`s` are invalid.
    pub fn try_to_der(&self) -> Result<Vec<u8>> {
        raw_to_der(&self.0)
    }
}

impl KeyPair {
    /// Generate a fresh P-256 key pair.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(ALGORITHM, &rng)
            .map_err(|_| Error::Crypto("P-256 key generation failed".into()))?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Load a key pair from PKCS#8 DER.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let inner = signature::EcdsaKeyPair::from_pkcs8(ALGORITHM, pkcs8, &rng)
            .map_err(|e| Error::Malformed(format!("invalid PKCS#8 P-256 key: {e}")))?;
        Ok(KeyPair { inner })
    }

    /// The public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.inner.public_key().as_ref().to_vec())
    }

    /// Sign `message`, returning the raw `r‖s` form SGP.22 uses.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let rng = SystemRandom::new();
        let der = self
            .inner
            .sign(&rng, message)
            .map_err(|_| Error::Crypto("ECDSA signing failed".into()))?;
        Signature::from_raw(&der_to_raw(der.as_ref())?)
    }

    /// Sign `message`, returning ASN.1 DER.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        self.inner
            .sign(&rng, message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| Error::Crypto("ECDSA signing failed".into()))
    }

    /// The PKCS#8 encoding of this key pair.
    ///
    /// `ring` does not expose the PKCS#8 bytes of a loaded `EcdsaKeyPair`, so
    /// the key is re-encoded from its private scalar. That is not available
    /// either — ring deliberately hides it — so this returns the empty vector
    /// rather than inventing bytes, and [`KeyPair::to_pkcs8_checked`] reports
    /// the same condition as an error.
    ///
    /// Callers that need portable keys should retain the PKCS#8 bytes they
    /// generated with, rather than round-tripping through this type.
    pub fn to_pkcs8(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Always `Err`: ring does not expose the PKCS#8 bytes of a loaded key.
    pub fn to_pkcs8_checked(&self) -> Result<Vec<u8>> {
        Err(Error::Unsupported(
            "ring does not expose the PKCS#8 encoding of a loaded P-256 key; \
             retain the bytes returned by generate() instead"
                .into(),
        ))
    }
}

/// Convert an ASN.1 DER ECDSA signature to the raw 64-byte `r‖s` form.
///
/// DER encodes the signature as `SEQUENCE { INTEGER r, INTEGER s }`, where each
/// INTEGER is minimally encoded and therefore *not* fixed-width: it may be 33
/// bytes (a leading `0x00` when the high bit is set) or as short as 32. The raw
/// form pads each to exactly 32 bytes.
pub fn der_to_raw(der: &[u8]) -> Result<Vec<u8>> {
    let (r, s) = parse_der_signature(der)?;

    let mut out = vec![0u8; SIGNATURE_LEN];
    // Right-align each integer, dropping any leading zero DER added.
    let r = trim_leading_zeroes(r);
    let s = trim_leading_zeroes(s);
    if r.len() > 32 || s.len() > 32 {
        return Err(Error::Malformed(format!(
            "ECDSA integers too large: r {} bytes, s {} bytes",
            r.len(),
            s.len()
        )));
    }
    out[32 - r.len()..32].copy_from_slice(r);
    out[64 - s.len()..64].copy_from_slice(s);
    Ok(out)
}

/// Convert a raw 64-byte `r‖s` signature to ASN.1 DER.
pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != SIGNATURE_LEN {
        return Err(Error::Malformed(format!(
            "raw signature must be {SIGNATURE_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let r = &raw[..32];
    let s = &raw[32..];
    let r_der = encode_integer(r);
    let s_der = encode_integer(s);
    let mut body = Vec::with_capacity(r_der.len() + s_der.len());
    body.extend_from_slice(&r_der);
    body.extend_from_slice(&s_der);
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.extend_from_slice(&encode_der_length(body.len()));
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse `SEQUENCE { INTEGER r, INTEGER s }`, returning their raw contents.
fn parse_der_signature(der: &[u8]) -> Result<(&[u8], &[u8])> {
    if der.len() < 8 {
        return Err(Error::Malformed(format!(
            "DER signature too short: {} bytes",
            der.len()
        )));
    }
    if der[0] != 0x30 {
        return Err(Error::Malformed(format!(
            "DER signature must start with SEQUENCE (0x30), got {:#04x}",
            der[0]
        )));
    }
    let (seq_len, seq_hdr) = parse_der_length(&der[1..])?;
    let body = &der[1 + seq_hdr..];
    if body.len() < seq_len {
        return Err(Error::Malformed(format!(
            "DER signature body truncated: need {seq_len} bytes, have {}",
            body.len()
        )));
    }
    let body = &body[..seq_len];

    if body.is_empty() || body[0] != 0x02 {
        return Err(Error::Malformed(
            "DER signature: r is not an INTEGER".into(),
        ));
    }
    let (r_len, r_hdr) = parse_der_length(&body[1..])?;
    let r_start = 1 + r_hdr;
    let r_end = r_start + r_len;
    if body.len() < r_end {
        return Err(Error::Malformed("DER signature: r truncated".into()));
    }
    let r = &body[r_start..r_end];

    let rest = &body[r_end..];
    if rest.is_empty() || rest[0] != 0x02 {
        return Err(Error::Malformed(
            "DER signature: s is not an INTEGER".into(),
        ));
    }
    let (s_len, s_hdr) = parse_der_length(&rest[1..])?;
    let s_start = 1 + s_hdr;
    let s_end = s_start + s_len;
    if rest.len() < s_end {
        return Err(Error::Malformed("DER signature: s truncated".into()));
    }
    Ok((r, &rest[s_start..s_end]))
}

/// Parse a DER length, returning `(length, bytes_consumed)`.
fn parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| Error::Malformed("missing DER length".into()))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || input.len() < 1 + count {
        return Err(Error::Malformed(format!(
            "unsupported DER long-form length ({count} bytes)"
        )));
    }
    let mut len = 0usize;
    for &b in &input[1..1 + count] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + count))
}

/// Encode a DER length.
fn encode_der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// Encode a big-endian magnitude as a DER INTEGER, adding the leading zero
/// that DER requires when the high bit is set.
fn encode_integer(magnitude: &[u8]) -> Vec<u8> {
    let trimmed = trim_leading_zeroes(magnitude);
    let trimmed = if trimmed.is_empty() {
        &[0u8][..]
    } else {
        trimmed
    };
    let needs_pad = trimmed[0] & 0x80 != 0;
    let len = trimmed.len() + usize::from(needs_pad);
    let mut out = Vec::with_capacity(len + 2);
    out.push(0x02);
    out.push(len as u8);
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Strip leading zero bytes, keeping at least one byte.
fn trim_leading_zeroes(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    &bytes[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let msg = b"serverSigned1 contents";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.as_ref().len(), SIGNATURE_LEN);
        kp.public_key().verify(msg, sig.as_ref()).unwrap();
    }

    #[test]
    fn verify_rejects_a_tampered_message() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"original").unwrap();
        assert_eq!(
            kp.public_key().verify(b"tampered", sig.as_ref()),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let kp = KeyPair::generate().unwrap();
        let mut sig = kp.sign(b"msg").unwrap().as_ref().to_vec();
        sig[0] ^= 0x01;
        assert!(kp.public_key().verify(b"msg", &sig).is_err());
    }

    #[test]
    fn verify_rejects_a_different_key() {
        let a = KeyPair::generate().unwrap();
        let b = KeyPair::generate().unwrap();
        let sig = a.sign(b"msg").unwrap();
        assert_eq!(
            b.public_key().verify(b"msg", sig.as_ref()),
            Err(Error::VerificationFailed)
        );
    }

    #[test]
    fn public_key_is_a_valid_uncompressed_point() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.as_ref().len(), PUBLIC_KEY_LEN);
        assert_eq!(pk.as_ref()[0], 0x04);
        PublicKey::from_bytes(pk.as_ref()).unwrap();
    }

    #[test]
    fn public_key_rejects_wrong_length_and_prefix() {
        assert!(PublicKey::from_bytes(&[0x04; 64]).is_err());
        let mut bad = [0u8; PUBLIC_KEY_LEN];
        bad[0] = 0x02; // compressed marker, not accepted
        assert!(PublicKey::from_bytes(&bad).is_err());
    }

    #[test]
    fn der_and_raw_roundtrip_over_many_signatures() {
        // Many signatures so we hit both the 32-byte and 33-byte (high-bit)
        // INTEGER encodings for r and s.
        let kp = KeyPair::generate().unwrap();
        for i in 0..64u32 {
            let der = kp.sign_der(&i.to_be_bytes()).unwrap();
            let raw = der_to_raw(&der).unwrap();
            assert_eq!(raw.len(), SIGNATURE_LEN);
            let back = raw_to_der(&raw).unwrap();
            assert_eq!(back, der, "DER->raw->DER must be identity (iteration {i})");
            kp.public_key().verify_der(&i.to_be_bytes(), &back).unwrap();
        }
    }

    #[test]
    fn der_to_raw_handles_high_bit_integers() {
        // r and s both with the high bit set, so DER must carry a 0x00 pad on
        // each INTEGER. Build the fixture with the encoder so the lengths are
        // correct by construction rather than hand-counted.
        let r: Vec<u8> = {
            let mut v = vec![0xffu8];
            v.extend(1u8..=31u8);
            v // 32 bytes, high bit set
        };
        let s: Vec<u8> = {
            let mut v = vec![0xffu8];
            v.extend(0x21u8..=0x3fu8);
            v
        };
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);

        let raw: Vec<u8> = [r.clone(), s.clone()].concat();
        let der = raw_to_der(&raw).unwrap();
        // DER must pad both integers to 33 bytes of content.
        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x02);
        assert_eq!(der[3], 33, "r must carry a 0x00 pad");
        assert_eq!(der[4], 0x00);

        let back = der_to_raw(&der).unwrap();
        assert_eq!(back, raw, "raw->DER->raw must be identity");
        assert_eq!(back[0], 0xff);
        assert_eq!(&back[1..4], &[0x01, 0x02, 0x03]);
        assert_eq!(back[32], 0xff);
        assert_eq!(&back[33..36], &[0x21, 0x22, 0x23]);
    }

    #[test]
    fn der_to_raw_handles_short_integers() {
        // A 1-byte r and 1-byte s, which must be left-padded to 32 bytes each.
        let der = [
            0x30, 0x08, 0x02, 0x02, 0x00, 0x01, // r = 1, DER-padded to 2 bytes
            0x02, 0x02, 0x00, 0x02, // s = 2
        ];
        let raw = der_to_raw(&der).unwrap();
        assert_eq!(raw[31], 0x01);
        assert_eq!(raw[63], 0x02);
        assert!(raw[..31].iter().all(|&b| b == 0));
        assert!(raw[32..63].iter().all(|&b| b == 0));
    }

    #[test]
    fn der_to_raw_rejects_malformed_input() {
        assert!(der_to_raw(&[]).is_err());
        assert!(der_to_raw(&[0x31, 0x00]).is_err()); // not a SEQUENCE
        assert!(der_to_raw(&[0x30, 0x02, 0x02, 0x00]).is_err()); // r truncated
                                                                 // r present, s missing
        assert!(der_to_raw(&[0x30, 0x04, 0x02, 0x02, 0x00, 0x01]).is_err());
    }

    #[test]
    fn raw_to_der_rejects_wrong_length() {
        assert!(raw_to_der(&[0u8; 63]).is_err());
        assert!(raw_to_der(&[0u8; 65]).is_err());
        assert!(raw_to_der(&[]).is_err());
    }

    #[test]
    fn der_to_raw_rejects_oversized_integers() {
        // A 33-byte magnitude after trimming is still too large for P-256.
        let mut der = vec![0x30, 0x48];
        der.extend_from_slice(&[0x02, 0x23, 0x01]); // 35-byte INTEGER
        der.extend_from_slice(&[0xab; 34]);
        der.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert!(der_to_raw(&der).is_err());
    }

    #[test]
    fn signature_type_roundtrips_through_raw() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"payload").unwrap();
        let der = sig.try_to_der().unwrap();
        let sig2 = Signature::from_raw(&der_to_raw(&der).unwrap()).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn loading_a_generated_key_by_pkcs8_roundtrips_through_signatures() {
        // ring does not expose the PKCS#8 bytes of a loaded key, so generate
        // PKCS#8 directly and confirm a key loaded from it behaves identically.
        let rng = SystemRandom::new();
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(ALGORITHM, &rng).unwrap();
        let kp = KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let same = KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        assert_eq!(kp.public_key(), same.public_key());
        let sig = same.sign(b"x").unwrap();
        kp.public_key().verify(b"x", sig.as_ref()).unwrap();
    }

    #[test]
    fn to_pkcs8_is_documented_as_unavailable() {
        // ring hides the private scalar, so re-encoding is impossible. Assert
        // the honest behaviour rather than pretending to round-trip.
        let kp = KeyPair::generate().unwrap();
        assert!(kp.to_pkcs8().is_empty());
        assert!(matches!(kp.to_pkcs8_checked(), Err(Error::Unsupported(_))));
    }

    #[test]
    fn from_pkcs8_rejects_garbage() {
        assert!(KeyPair::from_pkcs8(&[]).is_err());
        assert!(KeyPair::from_pkcs8(&[0xff; 64]).is_err());
    }

    #[test]
    fn signatures_are_not_deterministic() {
        // ring uses a random k, so two signatures over the same message differ
        // while both verifying. (If this ever fails, the RNG is broken.)
        let kp = KeyPair::generate().unwrap();
        let a = kp.sign(b"m").unwrap();
        let b = kp.sign(b"m").unwrap();
        assert_ne!(a, b);
        kp.public_key().verify(b"m", a.as_ref()).unwrap();
        kp.public_key().verify(b"m", b.as_ref()).unwrap();
    }
}
