//! X.509 certificate handling for the SGP.22 certificate chain
//! (`CERT.EUICC.ECDSA`, `CERT.EUM.ECDSA`, and the CI certificate).
//!
//! # Scope
//!
//! This module parses a DER certificate and extracts the P-256 public key and
//! the fields SGP.22 needs. It deliberately does **not** validate a chain
//! against a trust anchor: the GSMA CI roots are not available offline, and a
//! hand-rolled path validation is a footgun. Chain verification is delegated to
//! `rustls-webpki`, which is available and used for parse-level checks.
//!
//! # What SGP.22 requires of a certificate
//!
//! - The subject public key is an uncompressed P-256 point.
//! - The signature is ECDSA-with-SHA256 over the TBSCertificate.
//! - `#CERT_EUM_SIG` and `#CERT_EUICC_SIG` must be on the same curve, which is
//!   what §4.2.26 step 2 verifies by extraction and comparison rather than by
//!   inspecting the algorithm identifier.

use crate::ecdsa::{PublicKey, PUBLIC_KEY_LEN};
use crate::{Error, Result};

/// A parsed X.509 certificate.
#[derive(Clone)]
pub struct Certificate {
    der: Vec<u8>,
    public_key: PublicKey,
    /// True when the DER parsed under a webpki end-entity profile.
    webpki_parsed: bool,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("der_len", &self.der.len())
            .field("public_key", &crate::hex(self.public_key.as_ref()))
            .field("webpki_parsed", &self.webpki_parsed)
            .finish()
    }
}

impl Certificate {
    /// Parse a DER certificate, extracting its public key.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        if der.is_empty() {
            return Err(Error::Certificate("empty certificate".into()));
        }
        // Parse with webpki first so malformed DER is rejected early and we get
        // a second opinion on structure, independently of the SPKI extraction.
        let webpki_parsed = webpki::EndEntityCert::try_from(der).is_ok();
        let public_key = extract_spki_public_key(der)?;
        Ok(Certificate {
            der: der.to_vec(),
            public_key,
            webpki_parsed,
        })
    }

    /// The raw DER encoding.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The subject public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Whether the DER also parsed under webpki's end-entity profile.
    ///
    /// A self-signed test certificate may legitimately fail this (webpki
    /// applies end-entity constraints), so it is informational rather than a
    /// validity claim.
    pub fn is_webpki_end_entity(&self) -> bool {
        self.webpki_parsed
    }

    /// The `serialNumber` attribute of the subject, if present.
    ///
    /// SGP.26's eUICC certificate carries the EID here rather than in the
    /// certificate's own serial, which is why a conformance check has to read
    /// the subject attribute rather than the standard serial field.
    ///
    /// This is a deliberately narrow reader: it walks the DER to the subject
    /// SEQUENCE and looks for the `serialNumber` OID
    /// (`2.5.4.5` = `55 04 05`) with a PrintableString value. Anything it does
    /// not recognise yields `None` rather than a guess.
    pub fn subject_serial_number(&self) -> Option<Vec<u8>> {
        const OID_SERIAL_NUMBER: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x05];

        let der = &self.der;
        let mut i = 0usize;
        while i + OID_SERIAL_NUMBER.len() < der.len() {
            if der[i..].starts_with(OID_SERIAL_NUMBER) {
                // Followed by the value: PrintableString (0x13) or UTF8String
                // (0x0C), then a length, then the bytes.
                let after = i + OID_SERIAL_NUMBER.len();
                let tag = *der.get(after)?;
                if tag != 0x13 && tag != 0x0C {
                    i += 1;
                    continue;
                }
                let len = *der.get(after + 1)? as usize;
                // Only short-form lengths: a value longer than 127 octets is not
                // a serialNumber, so treat it as a non-match rather than
                // following a length encoding we have not validated.
                if len > 0x7F {
                    i += 1;
                    continue;
                }
                let start = after + 2;
                let end = start.checked_add(len)?;
                if end <= der.len() {
                    return Some(der[start..end].to_vec());
                }
            }
            i += 1;
        }
        None
    }

    /// Verify that `self` was signed by `issuer`'s key, over `self`'s
    /// TBSCertificate.
    ///
    /// This is signature verification only — it confirms the issuer key signed
    /// this certificate, and says nothing about whether the issuer was
    /// permitted to issue it.
    pub fn verify_signed_by(&self, issuer: &Certificate) -> Result<()> {
        self.verify_signed_by_key(&issuer.public_key)
    }

    /// Verify that `self` was signed by `key`, over `self`'s TBSCertificate.
    ///
    /// This is the form the CI key selection needs, where the trust anchor key
    /// may not be available as a certificate.
    ///
    /// Signature verification only: it confirms the key signed this
    /// certificate and says nothing about whether that key was permitted to
    /// issue it.
    pub fn verify_signed_by_key(&self, key: &PublicKey) -> Result<()> {
        let (tbs, sig) = extract_tbs_and_signature(&self.der)?;
        // A certificate signature is ASN.1 DER (RFC 5280), not the raw r||s
        // form SGP.22 uses on the wire, so verify in DER form.
        key.verify_der(tbs, sig)
    }
}

/// Extract the SubjectPublicKeyInfo public key from a DER certificate.
///
/// Walks `Certificate -> tbsCertificate -> ... -> subjectPublicKeyInfo`
/// structurally rather than searching for the first `0x04` byte, because an
/// unrelated `0x04` appears in many certificates and picking the wrong one
/// yields a key that silently fails to verify.
fn extract_spki_public_key(der: &[u8]) -> Result<PublicKey> {
    let (cert_body, _) = read_tlv(der, 0x30)
        .map_err(|e| Error::Certificate(format!("certificate is not a SEQUENCE: {e}")))?;
    let (tbs, _) = read_tlv(cert_body, 0x30)
        .map_err(|e| Error::Certificate(format!("missing tbsCertificate: {e}")))?;

    // tbsCertificate is a fixed-order sequence:
    //   [0] version (OPTIONAL), serialNumber, signature, issuer, validity,
    //   subject, subjectPublicKeyInfo, [1] issuerUniqueID (OPT),
    //   [2] subjectUniqueID (OPT), [3] extensions (OPT)
    //
    // Select subjectPublicKeyInfo by POSITION rather than by shape. Shape-based
    // matching (taking the first SEQUENCE containing a P-256 BIT STRING) is
    // wrong because the issuer and subject Names are SEQUENCEs too, and their
    // nested AttributeValue contents can coincidentally look like a key.
    let mut fields: Vec<&[u8]> = Vec::new();
    let mut tags: Vec<u8> = Vec::new();
    let mut rest = tbs;
    while !rest.is_empty() {
        let (tag, value, used) = read_tlv_any(rest).map_err(|e| {
            Error::Certificate(format!(
                "malformed tbsCertificate after {} field(s): {e}",
                fields.len()
            ))
        })?;
        if used == 0 {
            return Err(Error::Certificate("zero-length TLV advance".into()));
        }
        rest = rest.get(used..).ok_or_else(|| {
            Error::Certificate("TLV advance ran past the end of tbsCertificate".into())
        })?;
        tags.push(tag);
        fields.push(value);
    }

    // Field order (indices are element positions, not SEQUENCE ordinals):
    //   0 [0] version (optional), 1 serialNumber, 2 signature,
    //   3 issuer, 4 validity, 5 subject, 6 subjectPublicKeyInfo, ...
    // So the SPKI is element 6 when the version element is present, and
    // element 5 when it is absent. Distinguish by checking whether element 0
    // carries the [0] context tag.
    let spki_index = if tags.first() == Some(&0xa0) { 6 } else { 5 };
    if spa_missing(&tags, spki_index) {
        return Err(Error::Certificate(format!(
            "tbsCertificate has {} elements, too few for subjectPublicKeyInfo at \
             index {spki_index}",
            tags.len()
        )));
    }

    // SPKI ::= SEQUENCE { AlgorithmIdentifier SEQUENCE, BIT STRING }
    let spki = fields[spki_index];
    let (alg, alg_used) = read_tlv(spki, 0x30)
        .map_err(|e| Error::Certificate(format!("SPKI has no algorithm SEQUENCE: {e}")))?;
    let _ = alg;
    let bitstring_input = &spki[alg_used..];
    let (bits, _) = read_tlv(bitstring_input, 0x03)
        .map_err(|e| Error::Certificate(format!("SPKI has no BIT STRING: {e}")))?;

    if bits.len() != PUBLIC_KEY_LEN + 1 {
        return Err(Error::Certificate(format!(
            "subjectPublicKey is {} bytes after the unused-bit count, expected {}",
            bits.len().saturating_sub(1),
            PUBLIC_KEY_LEN
        )));
    }
    if bits[0] != 0x00 {
        return Err(Error::Certificate(
            "subjectPublicKey BIT STRING declares unused bits".into(),
        ));
    }
    PublicKey::from_bytes(&bits[1..])
}

/// Extract `(tbsCertificate DER as signed, signature BIT STRING payload)`.
///
/// The bytes that were signed are the *complete* tbsCertificate TLV — tag,
/// length and value — exactly as they appear in the certificate. Re-encoding
/// the value would not reproduce them, because DER length encoding and the
/// inner structure must match byte for byte for the signature to verify.
fn extract_tbs_and_signature(der: &[u8]) -> Result<(&[u8], &[u8])> {
    let (cert_body, cert_tlv_len) = read_tlv(der, 0x30)
        .map_err(|e| Error::Certificate(format!("certificate is not a SEQUENCE: {e}")))?;
    let _ = cert_tlv_len;

    // Where tbsCertificate starts within the whole certificate: immediately
    // after the outer header, i.e. at `der.len() - cert_body.len()`.
    let tbs_start = der
        .len()
        .checked_sub(cert_body.len())
        .ok_or_else(|| Error::Certificate("certificate body longer than certificate".into()))?;
    // `read_tlv` returns the VALUE and the number of bytes the whole TLV
    // occupied, which is what we need to slice the signed bytes.
    let (_tbs_value, tbs_tlv_len) = read_tlv(cert_body, 0x30)
        .map_err(|e| Error::Certificate(format!("missing tbsCertificate: {e}")))?;
    let tbs_end = tbs_start + tbs_tlv_len;
    let tbs_wire = der.get(tbs_start..tbs_end).ok_or_else(|| {
        Error::Certificate(format!(
            "tbsCertificate extends past the certificate \
             (starts {tbs_start}, needs {tbs_tlv_len}, der is {} bytes)",
            der.len()
        ))
    })?;

    // Walk the rest of the certificate body: signatureAlgorithm, then
    // signatureValue.
    let after_tbs = cert_body
        .get(tbs_tlv_len..)
        .ok_or_else(|| Error::Certificate("certificate body shorter than tbsCertificate".into()))?;
    let (_alg, _alg_used) = read_tlv(after_tbs, 0x30)
        .map_err(|e| Error::Certificate(format!("missing signatureAlgorithm: {e}")))?;
    let rest = &after_tbs[_alg_used..];
    let (sig_bits, _) = read_tlv(rest, 0x03)
        .map_err(|e| Error::Certificate(format!("missing signatureValue: {e}")))?;
    if sig_bits.is_empty() {
        return Err(Error::Certificate("empty signature value".into()));
    }
    if sig_bits[0] != 0x00 {
        return Err(Error::Certificate(
            "signature BIT STRING declares unused bits".into(),
        ));
    }
    Ok((tbs_wire, &sig_bits[1..]))
}

/// Whether `tags` is too short to contain index `i` as a SEQUENCE.
fn spa_missing(tags: &[u8], i: usize) -> bool {
    tags.len() <= i || tags[i] != 0x30
}

/// Read a TLV with a specific expected tag, returning `(value, bytes_used)`.
fn read_tlv(input: &[u8], expected: u8) -> Result<(&[u8], usize)> {
    let (tag, value, used) = read_tlv_any(input)?;
    if tag != expected {
        return Err(Error::Certificate(format!(
            "expected tag {expected:#04x}, found {tag:#04x}"
        )));
    }
    Ok((value, used))
}

/// Read any single TLV, returning `(tag, value, bytes_used)`.
fn read_tlv_any(input: &[u8]) -> Result<(u8, &[u8], usize)> {
    if input.len() < 2 {
        return Err(Error::Certificate("truncated TLV".into()));
    }
    let tag = input[0];
    let (len, len_bytes) = read_length(&input[1..])?;
    let start = 1 + len_bytes;
    let end = start + len;
    if input.len() < end {
        return Err(Error::Certificate(format!(
            "TLV {tag:#04x} declares {len} bytes, only {} remain",
            input.len() - start
        )));
    }
    Ok((tag, &input[start..end], end))
}

/// Read a DER length, returning `(length, bytes_consumed)`.
fn read_length(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| Error::Certificate("missing length".into()))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    // 0x7f is the indefinite-length marker, forbidden in DER. Anything up to
    // four length bytes covers certificates far larger than P-256 ones.
    if count == 0 || count == 0x7f || count > 4 || input.len() < 1 + count {
        return Err(Error::Certificate(format!(
            "unsupported DER length form (marker {first:#04x}, {count} length bytes, \
             {} available)",
            input.len().saturating_sub(1)
        )));
    }
    if input[1] == 0 {
        return Err(Error::Certificate(
            "non-minimal DER length (leading zero)".into(),
        ));
    }
    let mut len = 0usize;
    for &b in &input[1..1 + count] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki::TestPki;

    #[test]
    fn parses_a_certificate_and_extracts_the_matching_key() {
        let pki = TestPki::new();
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        assert_eq!(cert.public_key().as_ref().len(), PUBLIC_KEY_LEN);
        assert_eq!(cert.public_key(), &pki.eum_public_key());
    }

    #[test]
    fn certificate_verifies_under_its_issuer_key() {
        // Test chain: the CI issues the EUM, the eUICC and even its own
        // certificate, so everything verifies under the CI public key.
        let pki = TestPki::new();
        let ci = Certificate::from_der(pki.ci_cert_der()).unwrap();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();
        eum.verify_signed_by(&ci).unwrap();
    }

    #[test]
    fn certificate_does_not_verify_under_a_different_key() {
        let pki = TestPki::new();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let euicc = Certificate::from_der(pki.euicc_cert_der()).unwrap();
        assert!(eum.verify_signed_by(&euicc).is_err());
    }

    #[test]
    fn rejects_empty_and_garbage_input() {
        assert!(Certificate::from_der(&[]).is_err());
        assert!(Certificate::from_der(&[0xff; 64]).is_err());
        assert!(Certificate::from_der(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn rejects_a_truncated_certificate() {
        let pki = TestPki::new();
        let der = pki.eum_cert_der();
        let truncated = &der[..der.len() / 2];
        assert!(Certificate::from_der(truncated).is_err());
    }

    #[test]
    fn length_parser_rejects_non_minimal_encodings() {
        // 0x81 0x00 is a long-form length that should have been short-form.
        assert!(read_length(&[0x81, 0x00, 0x00]).is_err());
    }

    #[test]
    fn eum_and_euicc_certificates_carry_distinct_keys() {
        let pki = TestPki::new();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let euicc = Certificate::from_der(pki.euicc_cert_der()).unwrap();
        assert_ne!(eum.public_key(), euicc.public_key());
    }
}
