//! Key derivation: SHA-256 digests and the HKDF used to turn an ECDH shared
//! secret into RSP session keys.
//!
//! SGP.22 §5.7.5 specifies the session keys as an HKDF-SHA-256 expansion of the
//! ECDH shared secret, with the session's own context as the info parameter.
//! The exact `info` strings differ between the consumer and IoT profiles, so
//! the caller supplies them; this module does not guess.

use crate::{Error, Result};
use ring::digest;
use ring::hkdf;

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-256 of `data`, as a `Vec` for convenience.
pub fn sha256_vec(data: &[u8]) -> Vec<u8> {
    sha256(data).to_vec()
}

/// Expand `shared_secret` into `N` bytes with HKDF-SHA-256.
///
/// `salt` and `info` are the SGP.22 context values; both are byte slices so the
/// caller can pass the spec's constants verbatim.
pub fn hkdf_sha256<const N: usize>(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; N]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, Len(N))
        .map_err(|_| Error::Crypto(format!("HKDF expand to {N} bytes failed")))?;
    let mut out = [0u8; N];
    okm.fill(&mut out)
        .map_err(|_| Error::Crypto("HKDF output fill failed".into()))?;
    Ok(out)
}

/// HKDF-SHA-256 expansion into a `Vec` of arbitrary length.
pub fn hkdf_sha256_vec(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(shared_secret);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, Len(len))
        .map_err(|_| Error::Crypto(format!("HKDF expand to {len} bytes failed")))?;
    let mut out = vec![0u8; len];
    okm.fill(&mut out)
        .map_err(|_| Error::Crypto("HKDF output fill failed".into()))?;
    Ok(out)
}

/// Key length marker for `ring`'s HKDF API.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Constant-time equality, for comparing MACs and derived keys.
///
/// Returns `true` only if the slices have equal length and contents. The
/// comparison does not short-circuit on the first differing byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_the_known_vector_for_abc() {
        // FIPS 180-4: SHA-256("abc")
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(crate::hex(&sha256(b"abc")), expected);
    }

    #[test]
    fn sha256_matches_the_known_vector_for_the_empty_string() {
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(crate::hex(&sha256(b"")), expected);
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        // RFC 5869 Appendix A.1, with SHA-256 substituted for SHA-256 as used
        // there (the RFC's case 1 uses SHA-256 with these inputs).
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let okm: [u8; 42] = hkdf_sha256(&ikm, &salt, &info).unwrap();
        let expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(crate::hex(&okm), expected);
    }

    #[test]
    fn hkdf_vec_matches_the_const_generic_version() {
        let secret = b"shared secret";
        let a: [u8; 32] = hkdf_sha256(secret, b"salt", b"info").unwrap();
        let b = hkdf_sha256_vec(secret, b"salt", b"info", 32).unwrap();
        assert_eq!(a.to_vec(), b);
    }

    #[test]
    fn hkdf_is_deterministic_and_context_sensitive() {
        let secret = b"shared";
        let a: [u8; 32] = hkdf_sha256(secret, b"salt", b"info-a").unwrap();
        let b: [u8; 32] = hkdf_sha256(secret, b"salt", b"info-a").unwrap();
        let c: [u8; 32] = hkdf_sha256(secret, b"salt", b"info-b").unwrap();
        let d: [u8; 32] = hkdf_sha256(secret, b"salt2", b"info-a").unwrap();
        assert_eq!(a, b, "same inputs must agree");
        assert_ne!(a, c, "different info must give different keys");
        assert_ne!(a, d, "different salt must give different keys");
    }

    #[test]
    fn constant_time_eq_behaves_like_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
