//! SGP.22 wire encodings for signatures and the structures that carry them.
//!
//! # Why this module exists
//!
//! The primitives in [`crate::ecdsa`] produce and consume raw 64-byte `r‖s`
//! signatures. SGP.22 never puts those bytes on the wire bare: they are wrapped
//! in `[APPLICATION 55] OCTET STRING`, tag `5F37`, inside structures such as
//! `AuthenticateServerRequest`, `AuthenticateResponseOk` and
//! `NotificationMetadata`.
//!
//! Getting the tag or the length form wrong produces a value that verifies
//! perfectly in isolation and is rejected by a real eUICC. This module owns
//! that encoding so it is written once and tested against the tag values taken
//! from the ASN.1, rather than being re-derived at each call site.
//!
//! # Tags
//!
//! | Field | Tag | Encoding | Source |
//! |---|---|---|---|
//! | `serverSignature1` / `euiccSignature1` / `otherSignedNotification` | `5F37` | `[APPLICATION 55]` primitive, OCTET STRING | SGP.22 `RSPDefinitions` |
//! | `euiccCertificate` | `30` | universal SEQUENCE (a Certificate is `SEQUENCE OF`) | SGP.22 |
//! | `eumCertificate` | `30` | universal SEQUENCE | SGP.22 |
//!
//! `5F37` is a two-byte tag: `0x5F` is `APPLICATION | PRIMITIVE | 31`, and
//! `0x37` continues the tag number to 55. It is therefore read and written as a
//! multi-byte tag, not as a single byte with a length following it.

use crate::ecdsa::{CurveKind, Signature};
use crate::{Error, Result};

/// The `[APPLICATION 55]` tag used for every SGP.22 signature field.
pub const TAG_SIGNATURE: u16 = 0x5F37;

/// Encode a raw `r‖s` signature as a `5F37` OCTET STRING.
pub fn encode_signature(sig: &Signature) -> Vec<u8> {
    encode_signature_bytes(sig.as_ref())
}

/// Encode raw signature bytes as a `5F37` OCTET STRING.
pub fn encode_signature_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x5f, 0x37];
    out.extend_from_slice(&der_length(raw.len()));
    out.extend_from_slice(raw);
    out
}

/// Parse a `5F37` OCTET STRING back to a P-256 [`Signature`].
///
/// SGP.22's wire format carries no algorithm identifier alongside the
/// signature: the curve is implied by the certificate that will verify it. This
/// convenience wrapper assumes P-256, which is the mandatory curve for RSP. Use
/// [`parse_signature_on`] when the signing entity is on brainpoolP256r1.
pub fn parse_signature(data: &[u8]) -> Result<Signature> {
    parse_signature_on(CurveKind::P256, data)
}

/// Parse a `5F37` OCTET STRING back to a [`Signature`] on `curve`.
pub fn parse_signature_on(curve: CurveKind, data: &[u8]) -> Result<Signature> {
    Signature::from_raw(curve, &parse_signature_bytes(data)?)
}

/// Parse a `5F37` OCTET STRING and return the raw bytes.
pub fn parse_signature_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let (tag, value, _) = read_tlv(data)?;
    if tag != TAG_SIGNATURE {
        return Err(Error::Malformed(format!(
            "signature field tag is {tag:#06x}, expected {TAG_SIGNATURE:#06x}"
        )));
    }
    Ok(value.to_vec())
}

/// Read a TLV, returning `(tag, value, total_bytes)`. Handles both one- and
/// two-byte tags.
///
/// Public because BSP framing also needs to read and write TLVs; it shares this
/// implementation rather than carrying a second one that could disagree.
pub fn read_tlv(input: &[u8]) -> Result<(u16, &[u8], usize)> {
    let (tag, tag_bytes) = if input.first().is_some_and(|b| b & 0x1f == 0x1f) {
        if input.len() < 2 {
            return Err(Error::Malformed("truncated multi-byte tag".into()));
        }
        (((input[0] as u16) << 8) | input[1] as u16, 2usize)
    } else {
        (
            *input
                .first()
                .ok_or_else(|| Error::Malformed("empty input".into()))? as u16,
            1usize,
        )
    };
    let (len, len_bytes) = read_length(&input[tag_bytes..])?;
    let start = tag_bytes + len_bytes;
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::Malformed("TLV length overflow".into()))?;
    if input.len() < end {
        return Err(Error::Malformed(format!(
            "TLV {tag:#06x} declares {len} bytes, only {} remain",
            input.len().saturating_sub(start)
        )));
    }
    Ok((tag, &input[start..end], end))
}

/// Read a DER length, returning `(length, bytes_consumed)`.
fn read_length(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| Error::Malformed("missing length".into()))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count == 0x7f || count > 4 || input.len() < 1 + count {
        return Err(Error::Malformed(format!(
            "unsupported DER length form (marker {first:#04x}, {count} length bytes)"
        )));
    }
    if input[1] == 0 {
        return Err(Error::Malformed(
            "non-minimal DER length (leading zero)".into(),
        ));
    }
    let mut len = 0usize;
    for &b in &input[1..1 + count] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + count))
}

/// Encode a DER length.
///
/// Public for the same reason as [`read_tlv`].
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdsa::KeyPair;

    #[test]
    fn the_signature_tag_matches_the_asn1() {
        // [APPLICATION 55] primitive: 0x5F is APPLICATION|PRIMITIVE|0x1F and
        // 0x37 continues to tag number 55.
        assert_eq!(TAG_SIGNATURE, 0x5F37);
        assert_eq!(TAG_SIGNATURE >> 8, 0x5F);
        assert_eq!(TAG_SIGNATURE & 0xff, 0x37);
    }

    #[test]
    fn a_signature_roundtrips_through_the_wire_encoding() {
        let kp = KeyPair::generate().unwrap();
        let sig = kp.sign(b"signed bytes").unwrap();
        let encoded = encode_signature(&sig);
        // 2 tag bytes + 1 length byte (64 < 0x80) + 64 bytes of r||s.
        assert_eq!(encoded.len(), 2 + 1 + 64);
        assert_eq!(&encoded[..2], &[0x5f, 0x37]);
        assert_eq!(encoded[2], 64);
        let parsed = parse_signature(&encoded).unwrap();
        assert_eq!(parsed, sig);
    }

    #[test]
    fn the_encoded_signature_still_verifies() {
        // The point of the wrapper is that the bytes are unchanged, so the
        // signature must verify exactly as it did before encoding.
        let kp = KeyPair::generate().unwrap();
        let msg = b"serverSigned1 bytes";
        let sig = kp.sign(msg).unwrap();
        let encoded = encode_signature(&sig);
        let reparsed = parse_signature(&encoded).unwrap();
        kp.public_key().verify(msg, reparsed.as_ref()).unwrap();
    }

    #[test]
    fn parsing_rejects_the_wrong_tag() {
        // A universal OCTET STRING (0x04) is not the APPLICATION 55 tag.
        let mut wrong = vec![0x04, 64];
        wrong.extend_from_slice(&[0u8; 64]);
        let err = parse_signature(&wrong).unwrap_err();
        assert!(
            matches!(err, Error::Malformed(ref m) if m.contains("expected 0x5f37")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn parsing_rejects_a_truncated_value() {
        // Declares 64 bytes but supplies 10.
        let mut short = vec![0x5f, 0x37, 64];
        short.extend_from_slice(&[0u8; 10]);
        assert!(parse_signature(&short).is_err());
    }

    #[test]
    fn parsing_rejects_an_empty_signature_field() {
        assert!(parse_signature(&[0x5f, 0x37, 0x00]).is_err());
    }

    #[test]
    fn parsing_rejects_the_single_byte_form_of_the_tag() {
        // 0x37 alone would be [APPLICATION 55] with an implicit length, which
        // is not how SGP.22 encodes the field. The length byte that follows is
        // 0x00 under this misreading, so the value is empty and must fail.
        assert!(parse_signature(&[0x37, 0x40, 0u8]).is_err());
    }

    #[test]
    fn long_form_lengths_are_supported() {
        // A 200-byte payload needs a long-form length, exercising that path
        // even though a real signature is always 64 bytes.
        let raw = vec![0xABu8; 200];
        let encoded = encode_signature_bytes(&raw);
        assert_eq!(encoded[2], 0x81);
        assert_eq!(encoded[3], 200);
        assert_eq!(parse_signature_bytes(&encoded).unwrap(), raw);
    }

    #[test]
    fn length_parser_rejects_non_minimal_and_oversized_forms() {
        assert!(read_length(&[0x81, 0x00, 0x00]).is_err()); // non-minimal
        assert!(read_length(&[0x80]).is_err()); // indefinite, illegal in DER
        assert!(read_length(&[0x85, 1, 2, 3, 4, 5]).is_err()); // 5 length bytes
        assert!(read_length(&[]).is_err());
    }

    #[test]
    fn der_length_encoding_uses_the_shortest_form() {
        assert_eq!(der_length(0x7f), vec![0x7f]);
        assert_eq!(der_length(0x80), vec![0x81, 0x80]);
        assert_eq!(der_length(0xff), vec![0x81, 0xff]);
        assert_eq!(der_length(0x100), vec![0x82, 0x01, 0x00]);
    }
}
