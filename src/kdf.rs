//! Key derivation: SHA-256 digests, HMAC, and HKDF.
//!
//! # HKDF is not the RSP session-key KDF
//!
//! The functions here are general-purpose. SGP.22's session keys and initial MAC
//! chaining value are **not** derived with HKDF: §2.6.4.2 specifies the **X9.63**
//! KDF, which is [`crate::x963`]. The string `HKDF` does not occur anywhere in
//! SGP.22 v3.1 or SGP.32 v1.3.
//!
//! An earlier version of this comment claimed "SGP.22 §5.7.5 specifies the
//! session keys as an HKDF-SHA-256 expansion of the ECDH shared secret". That
//! was wrong twice over: §5.7.5 is the `InitialiseSecureChannel` function
//! definition rather than a KDF specification, and the only KDF in the document
//! is X9.63. Use [`crate::x963::x963_kdf`] for BSP.
//!
//! # Why these are not implemented here
//!
//! HKDF, HMAC and SHA-256 come from the RustCrypto crates rather than being
//! written in this crate. The previous hand-rolled versions passed RFC 5869
//! test case 1 and the FIPS 180-4 vectors, but passing a published vector is
//! not the same as being the reference implementation, and key derivation sits
//! on the critical path for every session key. `hmac` additionally supplies a
//! constant-time tag comparison, which removes a hand-written constant-time
//! comparison from this codebase. See `docs/dependency-review.md`.

use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&Sha256::digest(data));
    out
}

/// SHA-256 of `data`, as a `Vec` for convenience.
pub fn sha256_vec(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
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
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Crypto(format!("HKDF expand to {N} bytes failed")))?;
    Ok(out)
}

/// HKDF-SHA-256 expansion into a `Vec` of arbitrary length.
pub fn hkdf_sha256_vec(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Crypto(format!("HKDF expand to {len} bytes failed")))?;
    Ok(out)
}

/// The HKDF-Extract step on its own, returning the pseudorandom key.
///
/// SGP.22 derives some values from the PRK directly rather than from the
/// expanded output, so this is exposed separately.
pub fn hkdf_extract(shared_secret: &[u8], salt: &[u8]) -> [u8; SHA256_LEN] {
    let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), shared_secret);
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(prk.as_slice());
    out
}

/// HMAC-SHA-256 of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SHA256_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Verify an HMAC-SHA-256 tag in constant time.
///
/// Uses the crate's `verify_slice`, which is constant-time, rather than
/// comparing the computed tag with `==`.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.verify_slice(tag).is_ok()
}

/// Constant-time equality, for comparing MACs and derived keys.
///
/// Returns `true` only if the slices have equal length and contents. The
/// comparison does not short-circuit on the first differing byte. This remains
/// here for callers comparing values that are not HMAC tags; HMAC tag
/// verification should use [`hmac_sha256_verify`], which delegates to the
/// crate's constant-time implementation.
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
    fn sha256_agrees_with_rings_independent_implementation() {
        // Two implementations in the dependency graph, so they must agree.
        for input in [&b""[..], b"abc", b"the quick brown fox"] {
            let ours = sha256(input);
            let theirs = ring::digest::digest(&ring::digest::SHA256, input);
            assert_eq!(ours.as_slice(), theirs.as_ref());
        }
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        // RFC 5869 Appendix A.1.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let okm: [u8; 42] = hkdf_sha256(&ikm, &salt, &info).unwrap();
        let expected =
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(crate::hex(&okm), expected);
    }

    #[test]
    fn hkdf_extract_matches_rfc5869_test_case_1_prk() {
        // The PRK is published separately in the RFC, and SGP.22 uses the
        // extract step on its own, so it is checked independently of expand.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13).collect();
        assert_eq!(
            crate::hex(&hkdf_extract(&ikm, &salt)),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
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
    fn hkdf_rejects_an_over_long_output() {
        // HKDF output is bounded at 255 * HashLen. Exceeding it must error
        // rather than silently truncate.
        let secret = b"shared";
        assert!(hkdf_sha256_vec(secret, b"salt", b"info", 255 * SHA256_LEN + 1).is_err());
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            crate::hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_matches_rfc4231_test_case_2() {
        let got = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            crate::hex(&got),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_agrees_with_rings_independent_implementation() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"key");
        let ours = hmac_sha256(b"key", b"message");
        assert_eq!(ours.as_slice(), ring::hmac::sign(&key, b"message").as_ref());
    }

    #[test]
    fn hmac_verification_accepts_the_right_tag_and_rejects_others() {
        let key = b"key";
        let data = b"message";
        let tag = hmac_sha256(key, data);
        assert!(hmac_sha256_verify(key, data, &tag));
        assert!(!hmac_sha256_verify(key, b"other", &tag));
        assert!(!hmac_sha256_verify(b"keg", data, &tag));
        // A truncated tag must not be accepted.
        assert!(!hmac_sha256_verify(key, data, &tag[..31]));
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
