//! BSP TLV framing: wrapping and unwrapping protected command TLVs.
//!
//! SGP.22 §2.6.4.3–2.6.4.5. BSP carries its protected data in **TLVs**, not
//! APDUs — the part inherited from the older SCP03t — so there are no status
//! words and errors are signalled by a tag `+ 0x80` (the same tag with the top
//! bit of the second tag octet set, making it a two-byte tag).
//!
//! # The two protection options
//!
//! - **MAC and encryption**: the data is padded with `80 00…`, encrypted with
//!   AES-CBC-128 under S-ENC, and a C-MAC is appended.
//! - **MAC only**: the data is carried in the clear with a C-MAC appended.
//!
//! The C-MAC covers the same fields either way:
//!
//! ```text
//! C-MAC = AES-CMAC-128(S-CMAC, MAC_chaining_value ‖ tag ‖ final_length ‖ data)[0..8]
//! ```
//!
//! where `data` is the *ciphered* field when the option is MAC-and-encryption,
//! and `final_length` is the length of what is actually carried (ciphertext plus
//! the 8-byte MAC), not the plaintext length.
//!
//! # The MAC chaining value
//!
//! Each block's MAC becomes the chaining value for the next, starting from the
//! initial MAC chaining value derived with the session keys. That chain is what
//! makes the sequence of blocks indivisible: a block cannot be reordered or
//! dropped without the following MAC failing.
//!
//! The MAC chaining value used for a block is the value *before* that block, and
//! the value advances to that block's full CMAC output (all 16 bytes — the
//! truncation to 8 applies to the transmitted C-MAC, not to the chain).

use crate::bsp_keys::{BspSessionKeys, KEY_LEN};
use crate::cbc128;
use crate::wire::{der_length, read_tlv};
use crate::{Error, Result};
use aes::Aes128;
use cmac::{Cmac, Mac};

/// Tag for a protected command whose data is encrypted as well as MACed.
pub const TAG_MAC_AND_ENCRYPT: u32 = 0x86;

/// Tag for a protected command with a C-MAC only (data in the clear).
///
/// Not used by BSP's own command set, which fixes the option to MAC and
/// encryption, but defined so a caller can recognise one rather than reading it
/// as an unknown tag.
pub const TAG_MAC_ONLY: u32 = 0x87;

/// The length of a transmitted C-MAC: the 8 most significant CMAC bytes.
pub const CMAC_LEN: usize = 8;

/// A protected command TLV: the tag, the carried bytes, and the C-MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedTlv {
    /// The tag of the protected object, e.g. `0x86`, or `0x88` for a Metadata
    /// segment under MAC-only protection.
    pub tag: u32,
    /// The carried field: ciphertext when encrypted, plaintext when not.
    pub data: Vec<u8>,
    /// The C-MAC that accompanied it.
    pub cmac: Vec<u8>,
}

/// Encrypt-and-MAC `plaintext` under `tag`, advancing the MAC chain.
///
/// `block_number` selects the ICV for the encryption (1-based, and it advances
/// for MAC-only blocks too, per §2.6.4.5). `chaining` is updated in place to this
/// block's full CMAC output.
pub fn wrap_encrypt(
    keys: &BspSessionKeys,
    tag: u32,
    plaintext: &[u8],
    block_number: u32,
    chaining: &mut [u8],
) -> Result<ProtectedTlv> {
    let ciphertext = cbc128::encrypt(&keys.s_enc, plaintext, block_number)?;
    let final_length = ciphertext.len() + CMAC_LEN;
    let cmac = compute_cmac(&keys.s_mac, chaining, tag, final_length, &ciphertext)?;
    let full = full_cmac(&keys.s_mac, chaining, tag, final_length, &ciphertext)?;
    // The chain advances to the full 16-byte CMAC, not the 8-byte value carried.
    chaining.copy_from_slice(&full);
    Ok(ProtectedTlv {
        tag,
        data: ciphertext,
        cmac,
    })
}

/// MAC `plaintext` under `tag` without encrypting it, advancing the MAC chain.
pub fn wrap_mac_only(
    keys: &BspSessionKeys,
    tag: u32,
    plaintext: &[u8],
    chaining: &mut [u8],
) -> Result<ProtectedTlv> {
    let final_length = plaintext.len() + CMAC_LEN;
    let cmac = compute_cmac(&keys.s_mac, chaining, tag, final_length, plaintext)?;
    let full = full_cmac(&keys.s_mac, chaining, tag, final_length, plaintext)?;
    chaining.copy_from_slice(&full);
    Ok(ProtectedTlv {
        tag,
        data: plaintext.to_vec(),
        cmac,
    })
}

/// Verify and decrypt a protected TLV, advancing the MAC chain.
///
/// The C-MAC is checked **before** the data is decrypted or returned, so a
/// tampered block is rejected rather than handed back as a bogus plaintext. That
/// ordering is the whole point of the MAC: a caller cannot forget to check it if
/// the check is the only way to get the data.
pub fn unwrap_encrypt(
    keys: &BspSessionKeys,
    tlv: &ProtectedTlv,
    block_number: u32,
    chaining: &mut [u8],
) -> Result<Vec<u8>> {
    let final_length = tlv.data.len() + CMAC_LEN;
    let expected = compute_cmac(&keys.s_mac, chaining, tlv.tag, final_length, &tlv.data)?;
    if !crate::kdf::constant_time_eq(&expected, &tlv.cmac) {
        return Err(Error::VerificationFailed);
    }
    let plaintext = cbc128::decrypt(&keys.s_enc, &tlv.data, block_number)?;
    let full = full_cmac(&keys.s_mac, chaining, tlv.tag, final_length, &tlv.data)?;
    chaining.copy_from_slice(&full);
    Ok(plaintext)
}

/// Verify a MAC-only TLV and return its data, advancing the MAC chain.
pub fn unwrap_mac_only(
    keys: &BspSessionKeys,
    tlv: &ProtectedTlv,
    chaining: &mut [u8],
) -> Result<Vec<u8>> {
    let final_length = tlv.data.len() + CMAC_LEN;
    let expected = compute_cmac(&keys.s_mac, chaining, tlv.tag, final_length, &tlv.data)?;
    if !crate::kdf::constant_time_eq(&expected, &tlv.cmac) {
        return Err(Error::VerificationFailed);
    }
    let full = full_cmac(&keys.s_mac, chaining, tlv.tag, final_length, &tlv.data)?;
    chaining.copy_from_slice(&full);
    Ok(tlv.data.clone())
}

/// Encode a [`ProtectedTlv`] as the bytes that go on the wire.
pub fn encode(tlv: &ProtectedTlv) -> Vec<u8> {
    let mut body = tlv.data.clone();
    body.extend_from_slice(&tlv.cmac);
    encode_raw_tlv(tlv.tag, &body)
}

/// Parse a protected TLV from the wire.
///
/// The final 8 bytes are the C-MAC and everything before them is the carried
/// field, which is why a body shorter than the MAC is rejected outright: it
/// cannot be a protected TLV.
pub fn decode(bytes: &[u8]) -> Result<ProtectedTlv> {
    let (tag, value, _) = read_tlv(bytes)
        .map_err(|e| Error::Malformed(format!("protected TLV is not a TLV: {e}")))?;
    if value.len() < CMAC_LEN {
        return Err(Error::Malformed(format!(
            "protected TLV body is {} bytes; at least a {CMAC_LEN}-byte C-MAC is needed",
            value.len()
        )));
    }
    let split = value.len() - CMAC_LEN;
    Ok(ProtectedTlv {
        tag: tag as u32,
        data: value[..split].to_vec(),
        cmac: value[split..].to_vec(),
    })
}

/// The truncated C-MAC that is transmitted: the 8 most significant bytes.
fn compute_cmac(
    s_cmac: &[u8],
    chaining: &[u8],
    tag: u32,
    final_length: usize,
    data: &[u8],
) -> Result<Vec<u8>> {
    let full = full_cmac(s_cmac, chaining, tag, final_length, data)?;
    Ok(full[..CMAC_LEN].to_vec())
}

/// The full CMAC output, which is what the MAC chain advances to.
///
/// Public so a provider wired to a dependency-free simulator can expose exactly
/// this operation: the C-MAC input layout *is* the protocol, and a caller that
/// built it themselves would be free to get the field order wrong. See
/// [`cmac_over_chaining`].
pub fn cmac_over_chaining(
    s_cmac: &[u8],
    chaining: &[u8],
    tag: u32,
    final_length: usize,
    data: &[u8],
) -> Result<Vec<u8>> {
    full_cmac(s_cmac, chaining, tag, final_length, data)
}

/// A raw AES-CMAC-128 over `data` under `key`, with no chaining or framing.
///
/// This is the cryptogram operation, not the C-MAC one: a cryptogram is a bare
/// CMAC of a single preimage, and reusing the C-MAC helper for it would prepend
/// a chaining value and a tag the peer does not include.
pub fn cmac_raw(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).map_err(|_| {
        Error::Malformed(format!(
            "CMAC key is {} bytes; AES-128 needs {KEY_LEN}",
            key.len()
        ))
    })?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// The full CMAC output, which is what the MAC chain advances to.
///
/// Private: [`cmac_over_chaining`] is the public face of this, so the truncation
/// and the chaining rule stay in one file.
fn full_cmac(
    s_cmac: &[u8],
    chaining: &[u8],
    tag: u32,
    final_length: usize,
    data: &[u8],
) -> Result<Vec<u8>> {
    if chaining.len() != KEY_LEN {
        return Err(Error::Malformed(format!(
            "MAC chaining value is {} bytes; {KEY_LEN} expected",
            chaining.len()
        )));
    }
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(s_cmac).map_err(|_| {
        Error::Malformed(format!(
            "S-CMAC is {} bytes; AES-128 needs {KEY_LEN}",
            s_cmac.len()
        ))
    })?;
    // MAC chaining value, the tag, the final length, then the data -- in that
    // order (§2.6.4.4 step 3).
    mac.update(chaining);
    mac.update(&encoded_tag(tag));
    mac.update(&encoded_length(final_length)?);
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// A tag as it appears on the wire, including any multi-byte form.
///
/// A `u32` tag is already the full encoded tag, so `0x86` is one octet and
/// `0xBF37` is two. The CMAC input uses the encoded tag, not a fixed-width
/// integer: a two-byte tag contributes two bytes.
fn encoded_tag(tag: u32) -> Vec<u8> {
    if tag <= 0xFF {
        vec![tag as u8]
    } else if tag <= 0xFFFF {
        vec![(tag >> 8) as u8, tag as u8]
    } else if tag <= 0xFF_FFFF {
        vec![(tag >> 16) as u8, (tag >> 8) as u8, tag as u8]
    } else {
        vec![
            (tag >> 24) as u8,
            (tag >> 16) as u8,
            (tag >> 8) as u8,
            tag as u8,
        ]
    }
}

/// Encode a TLV whose tag is already the full encoded tag.
///
/// [`der_length`] comes from `wire.rs` so the length form is the same one the
/// signature encoder produces; BSP's "final length" is that length, verbatim.
fn encode_raw_tlv(tag: u32, value: &[u8]) -> Vec<u8> {
    let mut out = encoded_tag(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// A length as DER encoded it, which the CMAC input uses verbatim.
///
/// BSP's "final length" is the length octet(s) of the TLV, so a length over 127
/// is the two-byte long form. Using a single byte for a long length would change
/// every MAC on a large segment.
fn encoded_length(len: usize) -> Result<Vec<u8>> {
    if len > 0xFFFF {
        return Err(Error::Malformed(format!(
            "protected TLV length {len} exceeds the two-byte long form"
        )));
    }
    Ok(der_length(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> BspSessionKeys {
        BspSessionKeys::from_key_data(&(1u8..=48).collect::<Vec<u8>>(), KEY_LEN).unwrap()
    }

    #[test]
    fn round_trips_encrypted_data() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"a command", 1, &mut chain).unwrap();
        assert_eq!(
            wrapped.data.len() % KEY_LEN,
            0,
            "ciphertext is block aligned"
        );
        assert_eq!(wrapped.cmac.len(), CMAC_LEN);
        assert_ne!(&wrapped.data[..9], b"a command", "must actually encrypt");

        // Verify with the *initial* chain, as a receiver would.
        let mut rx_chain = k.mac_chaining.clone();
        let out = unwrap_encrypt(&k, &wrapped, 1, &mut rx_chain).unwrap();
        assert_eq!(out, b"a command");
        assert_eq!(rx_chain, chain, "both sides advance the chain identically");
    }

    #[test]
    fn round_trips_mac_only_data_without_encrypting() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_mac_only(&k, 0x88, b"metadata", &mut chain).unwrap();
        assert_eq!(
            wrapped.data, b"metadata",
            "MAC-only leaves data in the clear"
        );

        let mut rx = k.mac_chaining.clone();
        assert_eq!(unwrap_mac_only(&k, &wrapped, &mut rx).unwrap(), b"metadata");
        assert_eq!(rx, chain);
    }

    #[test]
    fn the_chain_advances_so_blocks_are_ordered() {
        // Walks two blocks and checks the second's MAC depends on the first: a
        // receiver that saw only the second block cannot verify it.
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let first = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"segment one", 1, &mut chain).unwrap();
        let after_first = chain.clone();
        let second = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"segment two", 2, &mut chain).unwrap();
        assert_ne!(after_first, chain, "chain must advance");

        // Verifying the second block against the initial value fails.
        let mut fresh = k.mac_chaining.clone();
        assert!(unwrap_encrypt(&k, &second, 2, &mut fresh).is_err());

        // Verifying them in order succeeds.
        let mut rx = k.mac_chaining.clone();
        assert_eq!(
            unwrap_encrypt(&k, &first, 1, &mut rx).unwrap(),
            b"segment one"
        );
        assert_eq!(
            unwrap_encrypt(&k, &second, 2, &mut rx).unwrap(),
            b"segment two"
        );
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected_before_decryption() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let mut wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"payload", 1, &mut chain).unwrap();
        wrapped.data[0] ^= 0x01;

        let mut rx = k.mac_chaining.clone();
        match unwrap_encrypt(&k, &wrapped, 1, &mut rx) {
            Err(Error::VerificationFailed) => {}
            other => panic!("expected a MAC failure, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_mac_is_rejected() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let mut wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"payload", 1, &mut chain).unwrap();
        wrapped.cmac[0] ^= 0x80;
        let mut rx = k.mac_chaining.clone();
        assert!(unwrap_encrypt(&k, &wrapped, 1, &mut rx).is_err());
    }

    #[test]
    fn a_block_with_the_wrong_tag_is_rejected() {
        // The tag is part of the MAC input, so relabelling a block breaks it.
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let mut wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"payload", 1, &mut chain).unwrap();
        wrapped.tag = TAG_MAC_ONLY;
        let mut rx = k.mac_chaining.clone();
        assert!(unwrap_encrypt(&k, &wrapped, 1, &mut rx).is_err());
    }

    #[test]
    fn encode_decode_round_trip_carries_data_then_mac() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"data", 1, &mut chain).unwrap();

        let bytes = encode(&wrapped);
        let back = decode(&bytes).unwrap();
        assert_eq!(back, wrapped);
        // Tag, length, ciphertext, then the 8-byte MAC at the end.
        assert_eq!(bytes[0], 0x86);
        assert_eq!(back.cmac, bytes[bytes.len() - CMAC_LEN..]);
    }

    #[test]
    fn decode_rejects_a_body_too_short_to_hold_a_mac() {
        assert!(decode(&encode_raw_tlv(TAG_MAC_AND_ENCRYPT, &[0u8; 7])).is_err());
        assert!(decode(&encode_raw_tlv(TAG_MAC_AND_ENCRYPT, &[])).is_err());
        // Exactly 8 bytes is a valid MAC with no data.
        assert!(decode(&encode_raw_tlv(TAG_MAC_AND_ENCRYPT, &[0u8; 8])).is_ok());
    }

    #[test]
    fn an_empty_plaintext_still_protects_and_round_trips() {
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"", 1, &mut chain).unwrap();
        // Padding gives a full block even for no data.
        assert_eq!(wrapped.data.len(), KEY_LEN);
        let mut rx = k.mac_chaining.clone();
        assert_eq!(unwrap_encrypt(&k, &wrapped, 1, &mut rx).unwrap(), b"");
    }

    #[test]
    fn a_long_length_uses_the_two_byte_form_in_the_mac_input() {
        // Over 127 bytes the length octet is long-form, and that is what the MAC
        // covers. Asserted through the helper, since both sides must agree.
        assert_eq!(encoded_length(127).unwrap(), vec![127]);
        assert_eq!(encoded_length(128).unwrap(), vec![0x81, 128]);
        assert_eq!(encoded_length(256).unwrap(), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn a_long_plaintext_round_trips() {
        // Exercises the long-form length in the MAC input end to end.
        let k = keys();
        let big = vec![0x5Au8; 300];
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, &big, 1, &mut chain).unwrap();
        let mut rx = k.mac_chaining.clone();
        assert_eq!(unwrap_encrypt(&k, &wrapped, 1, &mut rx).unwrap(), big);
    }

    #[test]
    fn a_wrong_chaining_value_length_is_reported() {
        let k = keys();
        let mut bad = vec![0u8; 15];
        let err = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"x", 1, &mut bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("15"), "{err}");
    }

    #[test]
    fn the_public_cmac_helpers_agree_with_the_wrapping_they_expose() {
        // `cmac_over_chaining` must be exactly what `wrap_*` computes, or a
        // provider wired through it would produce MACs the card rejects.
        let k = keys();
        let mut chain = k.mac_chaining.clone();
        let wrapped = wrap_encrypt(&k, TAG_MAC_AND_ENCRYPT, b"payload", 1, &mut chain).unwrap();
        let final_length = wrapped.data.len() + CMAC_LEN;
        let direct = cmac_over_chaining(
            &k.s_mac,
            &k.mac_chaining,
            TAG_MAC_AND_ENCRYPT,
            final_length,
            &wrapped.data,
        )
        .unwrap();
        assert_eq!(&direct[..CMAC_LEN], &wrapped.cmac[..]);
    }

    #[test]
    fn cmac_raw_does_not_add_framing() {
        // A raw CMAC of one preimage must differ from the C-MAC of the same
        // bytes, since the C-MAC prefixes chaining, tag and length.
        let k = keys();
        let raw = cmac_raw(&k.s_mac, b"preimage").unwrap();
        let framed = cmac_over_chaining(&k.s_mac, &k.mac_chaining, 0x86, 8, b"preimage").unwrap();
        assert_eq!(raw.len(), 16);
        assert_ne!(raw, framed, "framing must change the output");
    }

    #[test]
    fn a_wrong_cmac_key_length_is_reported() {
        assert!(cmac_raw(&[0u8; 15], b"x").is_err());
    }
}
