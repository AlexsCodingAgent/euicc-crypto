//! The X9.63 key derivation function, as SGP.22 uses it (§2.6.4.2).
//!
//! # Why this exists next to `kdf::hkdf_sha256`
//!
//! `kdf::hkdf_sha256` is HKDF (RFC 5869). SGP.22 does **not** use HKDF: the
//! session keys and initial MAC chaining value are derived with the X9.63 KDF,
//! and the string `HKDF` does not occur anywhere in SGP.22 v3.1 or SGP.32 v1.3.
//! The module comment in `kdf.rs` that says "SGP.22 §5.7.5 specifies the session
//! keys as an HKDF-SHA-256 expansion" is wrong -- §5.7.5 is the
//! `InitialiseSecureChannel` function definition, not a KDF specification -- and
//! is corrected by this module's existence.
//!
//! The two functions differ in a way that matters: HKDF extracts then expands
//! with its own counter and the info string as HMAC input, while X9.63 hashes
//! `Z ‖ Counter ‖ SharedInfo` directly. The same inputs produce different keys,
//! so one cannot be substituted for the other.
//!
//! # Definition
//!
//! From BSI TR-03111 / ANSI X9.63, with SHA-256 as the hash:
//!
//! ```text
//! KDF(Z, SharedInfo, KeyDataLen):
//!   counter = 1
//!   KeyData = ""
//!   while len(KeyData) < KeyDataLen:
//!       KeyData ‖= Hash(Z ‖ Counter_be32 ‖ SharedInfo)
//!       counter += 1
//!   return KeyData[0..KeyDataLen]
//! ```
//!
//! The counter is big-endian, 4 bytes, and starts at 1.

use crate::kdf::{sha256_vec, SHA256_LEN};
use crate::{Error, Result};

/// Derive `len` bytes from a shared secret with the X9.63 KDF and SHA-256.
///
/// `shared_info` is the specification's `SharedInfo`; this module does not build
/// it, because its components come from the caller's session context. See
/// [`bsp_shared_info`] for the BSP shape.
pub fn x963_kdf(shared_secret: &[u8], shared_info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Err(Error::Malformed("X9.63 KDF asked for 0 bytes".into()));
    }
    // Each iteration yields one hash. Nine iterations is 288 bytes, far more than
    // any RSP use; the bound stops a caller asking for gigabytes by accident from
    // spinning here, and matches X9.63's own recommendation not to exceed 2^32-1
    // blocks by an amount that could never be hit in practice.
    const MAX_ITERATIONS: usize = 9;
    let iterations = len.div_ceil(SHA256_LEN);
    if iterations > MAX_ITERATIONS {
        return Err(Error::Malformed(format!(
            "X9.63 KDF asked for {len} bytes, which needs {iterations} hash blocks \
             (limit {MAX_ITERATIONS})"
        )));
    }

    let mut key_data = Vec::with_capacity(iterations * SHA256_LEN);
    for counter in 1..=iterations as u32 {
        let mut input = Vec::with_capacity(shared_secret.len() + 4 + shared_info.len());
        input.extend_from_slice(shared_secret);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(shared_info);
        key_data.extend_from_slice(&sha256_vec(&input));
    }
    key_data.truncate(len);
    Ok(key_data)
}

/// Build BSP's `SharedInfo` for the session-key derivation (SGP.22 §2.6.4.2).
///
/// ```text
/// SharedInfo = KeyType (1) ‖ KeyLength (1) ‖ HostID-LV ‖ EID-LV
/// ```
///
/// `HostID-LV` and `EID-LV` are **length-prefixed**: the length octet is part of
/// the input, not stripped. That is the detail this constructor exists to get
/// right once, rather than at each call site.
///
/// The length octets are one byte each. SGP.22 does not describe a longer form,
/// and both values are bounded well below 256 in practice (an EID is 32 bytes),
/// so a longer value is reported rather than silently truncated.
pub fn bsp_shared_info(
    key_type: u8,
    key_length: u8,
    host_id: &[u8],
    eid: &[u8],
) -> Result<Vec<u8>> {
    if host_id.len() > 255 {
        return Err(Error::Malformed(format!(
            "HostID is {} bytes; the length prefix is one octet",
            host_id.len()
        )));
    }
    if eid.len() > 255 {
        return Err(Error::Malformed(format!(
            "EID is {} bytes; the length prefix is one octet",
            eid.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + 1 + host_id.len() + 1 + eid.len());
    out.push(key_type);
    out.push(key_length);
    out.push(host_id.len() as u8);
    out.extend_from_slice(host_id);
    out.push(eid.len() as u8);
    out.extend_from_slice(eid);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::sha256_vec;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_first_block_is_the_hash_of_z_counter_1_and_shared_info() {
        // The definition, written out: no extraction step, and the counter is
        // between Z and SharedInfo, big-endian.
        let z = b"a shared secret";
        let info = b"shared info";
        let got = x963_kdf(z, info, 32).unwrap();

        let mut expected_input = z.to_vec();
        expected_input.extend_from_slice(&1u32.to_be_bytes());
        expected_input.extend_from_slice(info);
        assert_eq!(got, sha256_vec(&expected_input));
    }

    #[test]
    fn later_blocks_increment_the_counter() {
        // 64 bytes is two blocks; the second must use counter 2, and the result
        // must be the concatenation rather than a repeat of the first block.
        let z = b"z";
        let got = x963_kdf(z, b"info", 64).unwrap();
        assert_eq!(got.len(), 64);
        assert_ne!(got[..32], got[32..], "counter did not advance");

        let mut second_input = z.to_vec();
        second_input.extend_from_slice(&2u32.to_be_bytes());
        second_input.extend_from_slice(b"info");
        assert_eq!(got[32..], sha256_vec(&second_input)[..]);
    }

    #[test]
    fn truncates_to_the_requested_length() {
        // A length that is not a multiple of the hash yields a prefix of the
        // blocks, not a padded or rounded-up result.
        let got = x963_kdf(b"z", b"info", 48).unwrap();
        let full = x963_kdf(b"z", b"info", 64).unwrap();
        assert_eq!(got.len(), 48);
        assert_eq!(got, full[..48]);
    }

    #[test]
    fn shared_info_and_secret_both_affect_the_output() {
        let a = x963_kdf(b"z1", b"info", 32).unwrap();
        let b = x963_kdf(b"z2", b"info", 32).unwrap();
        let c = x963_kdf(b"z1", b"other", 32).unwrap();
        assert_ne!(a, b, "the secret must affect the output");
        assert_ne!(a, c, "SharedInfo must affect the output");
    }

    #[test]
    fn bsp_shared_info_length_prefixes_both_identifiers() {
        // The length octets are part of the input. Getting this wrong changes
        // every derived key, so it is asserted against a hand-built expectation.
        let info = bsp_shared_info(0x01, 0x10, &[0xAA, 0xBB], &[0xCC]).unwrap();
        assert_eq!(info, vec![0x01, 0x10, 0x02, 0xAA, 0xBB, 0x01, 0xCC]);

        // An empty identifier still contributes its zero length octet.
        let empty = bsp_shared_info(0x01, 0x10, &[], &[]).unwrap();
        assert_eq!(empty, vec![0x01, 0x10, 0x00, 0x00]);
    }

    #[test]
    fn rejects_what_it_cannot_represent() {
        assert!(x963_kdf(b"z", b"i", 0).is_err());
        // 10 blocks exceeds the limit.
        assert!(x963_kdf(b"z", b"i", 10 * 32).is_err());
        // A one-octet length prefix cannot hold 256 bytes.
        assert!(bsp_shared_info(1, 16, &[0u8; 256], &[]).is_err());
        assert!(bsp_shared_info(1, 16, &[], &[0u8; 256]).is_err());
    }

    #[test]
    fn matches_the_x963_reference_construction_for_a_32_byte_eid() {
        // The realistic BSP shape: KeyType 0x01, KeyLength 0x10, a HostID and a
        // 32-byte EID. Recomputed from the definition rather than from a stored
        // literal, so this pins the construction, not one output.
        let z = unhex("0123456789abcdef0123456789abcdef");
        let eid = vec![0x87u8; 32];
        let info = bsp_shared_info(0x01, 0x10, b"SM-DP+.example.com", &eid).unwrap();

        let mut expected_input = z.clone();
        expected_input.extend_from_slice(&1u32.to_be_bytes());
        expected_input.extend_from_slice(&info);
        assert_eq!(
            hex(&x963_kdf(&z, &info, 32).unwrap()),
            hex(&sha256_vec(&expected_input))
        );
    }
}
