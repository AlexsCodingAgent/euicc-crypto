//! BSP session keys: the three values derived from the ECKA shared secret.
//!
//! SGP.22 §2.6.4.2 derives `KeyData` with the X9.63 KDF and then splits it
//! (Table 4c):
//!
//! | KeyData    | Key                      |
//! |------------|--------------------------|
//! | `1 .. L`   | Initial MAC chaining value |
//! | `L+1 .. 2L`| S-ENC                    |
//! | `2L+1 .. 3L`| S-MAC                   |
//!
//! `L` is the key length — 16 for AES-CBC-128, which is what BSP uses.
//!
//! # Why the split is in one place
//!
//! The order is not the order the names suggest: the *initial MAC chaining value*
//! comes first, then the encryption key, then the MAC key. A derivation that
//! assigned S-ENC to the first 16 bytes would produce two keys that are each
//! wrong in a way no round-trip test catches, because encryption and decryption
//! would agree with each other while disagreeing with the eUICC. So the split
//! lives here, asserted, rather than at each call site.
//!
//! # The `keyType` / `keyLength` inputs
//!
//! Both go into `SharedInfo` and therefore change the derived keys. SGP.22 does
//! not enumerate `keyType` values in the section that defines the derivation, so
//! [`BspKeyType`] carries the values used by the test environment and marks them
//! as such.

use crate::x963::{bsp_shared_info, x963_kdf};
use crate::{Error, Result};

/// The AES-128 key length, and so `L` in SGP.22 Table 4c.
pub const KEY_LEN: usize = 16;

/// Total `KeyData` length: three keys of `KEY_LEN`.
pub const KEY_DATA_LEN: usize = 3 * KEY_LEN;

/// `keyType` values for the BSP session-key derivation.
///
/// SGP.22 §2.6.4.2 lists `Key type (1 byte)` as a component of `SharedInfo` but
/// does not enumerate the values in that section. These are the values the test
/// environment uses; they are named rather than written as bare literals so a
/// reader can see which one a call site chose, and so a future correction has one
/// place to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BspKeyType {
    /// Keys for protecting command data (S-ENC / S-MAC / MAC chaining).
    SessionKeys = 0x01,
    /// Keys for protecting Profile data, when a session replaces its keys with
    /// the profile's own (the §4.2.6 `ReplaceSessionKeys` substitution).
    ProfileKeys = 0x02,
}

/// The three keys SGP.22 Table 4c defines, plus the length they were derived at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BspSessionKeys {
    /// Initial MAC chaining value — seeds the C-MAC chain.
    pub mac_chaining: Vec<u8>,
    /// S-ENC — the AES-CBC encryption key.
    pub s_enc: Vec<u8>,
    /// S-MAC — the key the C-MAC is computed with.
    pub s_mac: Vec<u8>,
}

impl BspSessionKeys {
    /// Derive the three keys from the ECKA shared secret.
    ///
    /// `host_id` and `eid` are the length-prefixed components of `SharedInfo`;
    /// `key_type` and `key_len` are the other two.
    pub fn derive(
        shared_secret: &[u8],
        key_type: BspKeyType,
        key_len: u8,
        host_id: &[u8],
        eid: &[u8],
    ) -> Result<Self> {
        let len = key_len as usize;
        let info = bsp_shared_info(key_type as u8, key_len, host_id, eid)?;
        let key_data = x963_kdf(shared_secret, &info, 3 * len)?;
        Self::from_key_data(&key_data, len)
    }

    /// Split `KeyData` per Table 4c.
    ///
    /// Separate from [`Self::derive`] so the split can be tested against a
    /// hand-built KeyData, without a KDF in the way.
    pub fn from_key_data(key_data: &[u8], key_len: usize) -> Result<Self> {
        let expected = 3 * key_len;
        if key_data.len() < expected {
            return Err(Error::Malformed(format!(
                "KeyData is {} bytes; three {key_len}-byte keys need {expected}",
                key_data.len()
            )));
        }
        Ok(Self {
            // Order matters: the MAC chaining value is first, not the cipher key.
            mac_chaining: key_data[..key_len].to_vec(),
            s_enc: key_data[key_len..2 * key_len].to_vec(),
            s_mac: key_data[2 * key_len..3 * key_len].to_vec(),
        })
    }

    /// Whether the three keys are all `KEY_LEN`, and distinct.
    ///
    /// Distinctness is not a specification requirement, but three keys that are
    /// equal means the split read the same bytes three times, which is the
    /// failure mode this module exists to prevent.
    pub fn is_well_formed(&self) -> bool {
        self.mac_chaining.len() == KEY_LEN
            && self.s_enc.len() == KEY_LEN
            && self.s_mac.len() == KEY_LEN
            && self.mac_chaining != self.s_enc
            && self.s_enc != self.s_mac
            && self.mac_chaining != self.s_mac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_4c_order_is_mac_chaining_then_senc_then_smac() {
        // 48 bytes, each value distinct so a mis-ordered split is visible.
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&[0xAA; 16]); // 1..L
        key_data.extend_from_slice(&[0xBB; 16]); // L+1..2L
        key_data.extend_from_slice(&[0xCC; 16]); // 2L+1..3L

        let keys = BspSessionKeys::from_key_data(&key_data, KEY_LEN).unwrap();
        assert_eq!(keys.mac_chaining, vec![0xAA; 16]);
        assert_eq!(keys.s_enc, vec![0xBB; 16]);
        assert_eq!(keys.s_mac, vec![0xCC; 16]);
        assert!(keys.is_well_formed());
    }

    #[test]
    fn a_short_key_data_is_reported_not_padded() {
        let err = BspSessionKeys::from_key_data(&[0u8; 47], KEY_LEN)
            .unwrap_err()
            .to_string();
        assert!(err.contains("47"), "{err}");
        assert!(err.contains("48"), "{err}");
    }

    #[test]
    fn derivation_uses_the_shared_info_components() {
        // Different HostID, EID or key type must all change the derived keys;
        // otherwise a component is being dropped from SharedInfo.
        let z = [0x11u8; 32];
        let base =
            BspSessionKeys::derive(&z, BspKeyType::SessionKeys, 16, b"host", &[0x87; 32]).unwrap();

        let other_host =
            BspSessionKeys::derive(&z, BspKeyType::SessionKeys, 16, b"other", &[0x87; 32]).unwrap();
        let other_eid =
            BspSessionKeys::derive(&z, BspKeyType::SessionKeys, 16, b"host", &[0x88; 32]).unwrap();
        let other_type =
            BspSessionKeys::derive(&z, BspKeyType::ProfileKeys, 16, b"host", &[0x87; 32]).unwrap();

        assert_ne!(base, other_host, "HostID must reach SharedInfo");
        assert_ne!(base, other_eid, "EID must reach SharedInfo");
        assert_ne!(base, other_type, "keyType must reach SharedInfo");
    }

    #[test]
    fn derived_keys_are_all_key_len_and_distinct() {
        let keys = BspSessionKeys::derive(
            &[0x42u8; 32],
            BspKeyType::SessionKeys,
            16,
            b"h",
            &[0x87; 32],
        )
        .unwrap();
        assert_eq!(keys.s_enc.len(), KEY_LEN);
        assert_eq!(keys.s_mac.len(), KEY_LEN);
        assert_eq!(keys.mac_chaining.len(), KEY_LEN);
        assert!(keys.is_well_formed(), "keys must not collide: {keys:?}");
    }

    #[test]
    fn derivation_is_deterministic() {
        let z = [0x7Fu8; 32];
        let a = BspSessionKeys::derive(&z, BspKeyType::SessionKeys, 16, b"h", &[0x87; 32]).unwrap();
        let b = BspSessionKeys::derive(&z, BspKeyType::SessionKeys, 16, b"h", &[0x87; 32]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn a_different_shared_secret_gives_different_keys() {
        let a = BspSessionKeys::derive(
            &[0x01u8; 32],
            BspKeyType::SessionKeys,
            16,
            b"h",
            &[0x87; 32],
        )
        .unwrap();
        let b = BspSessionKeys::derive(
            &[0x02u8; 32],
            BspKeyType::SessionKeys,
            16,
            b"h",
            &[0x87; 32],
        )
        .unwrap();
        assert_ne!(a, b);
    }
}
