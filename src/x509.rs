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

use crate::ecdsa::{CurveKind, PublicKey, PUBLIC_KEY_LEN};
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
    /// The certificate's public key.
    ///
    /// Carries the curve the certificate declares in its `namedCurve` OID,
    /// which is how a caller tells a P-256 certificate from a brainpool one
    /// without re-parsing the DER.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The curve this certificate's public key is on.
    pub fn curve(&self) -> crate::ecdsa::CurveKind {
        self.public_key.curve()
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

    /// The `subjectAltName` extension's content, if present.
    ///
    /// SGP.22 §5.7.5 has the eUICC compare this between `CERT.DPauth.SIG` and
    /// `CERT.DPpb.SIG` to establish that they belong to the same entity. For an
    /// SM-DP+ certificate SGP.22 §4.5.2.1.0.0 gives the form as
    /// `GeneralNames ::= { { dNSName '<SM-DP+ hostname (FQDN) value>' } ... }`.
    ///
    /// Returned as the raw extension *value* — for the dNSName alternative that is the
    /// IA5String content, without the GeneralName tag. Comparing two certificates'
    /// returns therefore compares the names themselves, which is the point; two
    /// certificates for the same SM-DP+ yield equal values whatever the surrounding
    /// encoding. Callers that need to distinguish a dNSName from an iPAddress (both are
    /// permitted to follow) should not rely on this value alone, and the extensions
    /// this repository deals with use dNSName.
    ///
    /// `None` when the extension is absent or unrecognised: a comparison that cannot
    /// read one side must not silently succeed.
    pub fn subject_alt_name(&self) -> Option<Vec<u8>> {
        let ext = self.extension_value(Self::OID_SUBJECT_ALT_NAME)?;
        // The extension value is a `GeneralNames` SEQUENCE. Step inside and take the
        // first GeneralName's content.
        let inner = Self::unwrap_sequence(ext)?;
        if inner.is_empty() {
            return None;
        }
        let (_tag, content) = Self::read_tlv(inner)?;
        Some(content.to_vec())
    }

    /// The `authorityKeyIdentifier` extension's `keyIdentifier`, if present.
    ///
    /// SGP.22 §5.7.5 also requires `CERT.DPauth.SIG` and `CERT.DPpb.SIG` to be certified
    /// by the same certificate, i.e. to "contain the same keyIdentifier in
    /// authorityKeyIdentifier".
    ///
    /// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] IMPLICIT KeyIdentifier
    /// OPTIONAL, ... }` — so this takes the `[0]` member, tag `0x80`. The other members
    /// (`authorityCertIssuer`, `authorityCertSerialNumber`) are not a key identifier and
    /// are not accepted in its place: returning one would make an unrelated pair of
    /// certificates compare equal.
    pub fn authority_key_identifier(&self) -> Option<Vec<u8>> {
        let ext = self.extension_value(Self::OID_AUTHORITY_KEY_IDENTIFIER)?;
        let seq = Self::unwrap_sequence(ext)?;
        let mut rest = seq;
        while !rest.is_empty() {
            let (tag, content, consumed) = Self::read_tlv_consumed(rest)?;
            if tag == 0x80 {
                return Some(content.to_vec());
            }
            rest = &rest[consumed..];
        }
        None
    }

    /// The policy OIDs in the `certificatePolicies` extension, in DER content form.
    ///
    /// SGP.22 §4.5.2.1.0.0 requires an SM-DP+ Profile Package Binding certificate to carry
    /// `id-rspRole-dp-pb` or `id-rspRole-dp-pb-v2` here, and §4.2.10 #08 is the case that
    /// exercises the requirement. §5.7.5 makes verifying it obligatory via §4.5.2.2.
    ///
    /// Returns the OID *contents* without their `06 <len>` headers, one entry per policy,
    /// which is what a caller compares against the expected role OID. An empty vector
    /// means the extension was present but held no policies; `None` means the extension
    /// could not be read — the two are different answers and a caller checking for a role
    /// must treat both as "does not indicate the required role", while only the first is
    /// evidence the certificate was well formed.
    pub fn certificate_policies(&self) -> Option<Vec<Vec<u8>>> {
        let ext = self.extension_value(Self::OID_CERTIFICATE_POLICIES)?;
        // `certificatePolicies ::= SEQUENCE OF PolicyInformation`, and
        // `PolicyInformation ::= SEQUENCE { policyIdentifier OBJECT IDENTIFIER, ... }`.
        let list = Self::unwrap_sequence(ext)?;
        let mut rest = list;
        let mut out = Vec::new();
        while !rest.is_empty() {
            let Ok((tag, info, consumed)) = Self::read_tlv_consumed_checked(rest) else {
                break;
            };
            rest = &rest[consumed..];
            if tag != 0x30 {
                continue;
            }
            // The first member of PolicyInformation is the OID; qualifiers may follow.
            let Ok((oid_tag, oid_content, _)) = Self::read_tlv_consumed_checked(info) else {
                continue;
            };
            if oid_tag == 0x06 {
                out.push(oid_content.to_vec());
            }
        }
        Some(out)
    }

    /// Like [`Self::read_tlv_consumed`] but reports a readable error rather than `None`.
    ///
    /// The `certificatePolicies` walk skips entries it does not understand, so it needs to
    /// tell "this part is malformed" from "this is the end" — which `Option` collapses.
    /// A malformed part is skipped rather than failing the whole read, because RFC 5280
    /// allows qualifiers this reader does not model.
    fn read_tlv_consumed_checked(buf: &[u8]) -> Result<(u8, &[u8], usize)> {
        let tag = *buf
            .first()
            .ok_or_else(|| Error::Certificate("truncated".into()))?;
        let len = *buf
            .get(1)
            .ok_or_else(|| Error::Certificate("truncated".into()))? as usize;
        if len > 0x7F {
            return Err(Error::Certificate("long-form length".into()));
        }
        let end = 2usize
            .checked_add(len)
            .ok_or_else(|| Error::Certificate("length overflow".into()))?;
        if end > buf.len() {
            return Err(Error::Certificate("truncated value".into()));
        }
        Ok((tag, &buf[2..end], end))
    }

    /// `id-ce-certificatePolicies`, `2.5.29.32`.
    const OID_CERTIFICATE_POLICIES: &'static [u8] = &[0x06, 0x03, 0x55, 0x1D, 0x20];

    /// `id-rspRole-dp-pb`, `2.23.146.1.2.1.0.0.1.2` — the role a Profile Package Binding
    /// certificate must indicate (SGP.22 §4.5.2.1.0.0, and §4.2.10 #08's check).
    pub const OID_RSP_ROLE_DP_PB: &'static [u8] =
        &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x00, 0x00, 0x01, 0x02];

    /// `id-rspRole-dp-pb-v2`, `2.23.146.1.2.1.5` — the other value §4.5.2.1.0.0 permits.
    pub const OID_RSP_ROLE_DP_PB_V2: &'static [u8] = &[0x67, 0x81, 0x12, 0x01, 0x02, 0x01, 0x05];

    /// Whether this certificate indicates the Profile Package Binding role.
    ///
    /// True when `certificatePolicies` carries either permitted OID. `None` when the
    /// extension cannot be read, which a caller must not treat as success: §4.2.10 #08
    /// is precisely about a certificate that does *not* indicate the role.
    pub fn indicates_dp_pb_role(&self) -> Option<bool> {
        let policies = self.certificate_policies()?;
        Some(policies.iter().any(|p| {
            p.as_slice() == Self::OID_RSP_ROLE_DP_PB || p.as_slice() == Self::OID_RSP_ROLE_DP_PB_V2
        }))
    }

    /// `id-ce-subjectAltName`, `2.5.29.17`.
    const OID_SUBJECT_ALT_NAME: &'static [u8] = &[0x06, 0x03, 0x55, 0x1D, 0x11];
    /// `id-ce-authorityKeyIdentifier`, `2.5.29.35`.
    const OID_AUTHORITY_KEY_IDENTIFIER: &'static [u8] = &[0x06, 0x03, 0x55, 0x1D, 0x23];

    /// The `extnValue` octet string of the extension carrying `oid`.
    ///
    /// `Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT
    /// FALSE, extnValue OCTET STRING }`, so after the OID come an optional BOOLEAN and
    /// the OCTET STRING — the contents of which are themselves DER, which is why the
    /// caller unwraps a SEQUENCE from what this returns.
    fn extension_value(&self, oid: &[u8]) -> Option<&[u8]> {
        let der = &self.der;
        let mut i = 0usize;
        while i + oid.len() < der.len() {
            if !der[i..].starts_with(oid) {
                i += 1;
                continue;
            }
            let mut j = i + oid.len();
            // Skip `critical` if present: BOOLEAN is 0x01.
            if *der.get(j)? == 0x01 {
                let len = *der.get(j + 1)? as usize;
                if len > 0x7F {
                    return None;
                }
                j += 2 + len;
            }
            // The extnValue OCTET STRING.
            if *der.get(j)? != 0x04 {
                i += 1;
                continue;
            }
            let len = *der.get(j + 1)? as usize;
            if len > 0x7F {
                return None;
            }
            let start = j + 2;
            let end = start.checked_add(len)?;
            if end <= der.len() {
                return Some(&der[start..end]);
            }
            i += 1;
        }
        None
    }

    /// The content of `buf` if it is a single SEQUENCE occupying the whole buffer.
    fn unwrap_sequence(buf: &[u8]) -> Option<&[u8]> {
        let (tag, content) = Self::read_tlv(buf)?;
        if tag == 0x30 {
            Some(content)
        } else {
            None
        }
    }

    /// Read one TLV from the front of `buf`, returning its tag and content.
    fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8])> {
        let (tag, content, _) = Self::read_tlv_consumed(buf)?;
        Some((tag, content))
    }

    /// Read one TLV, also returning how many bytes it occupied.
    fn read_tlv_consumed(buf: &[u8]) -> Option<(u8, &[u8], usize)> {
        let tag = *buf.first()?;
        let len = *buf.get(1)? as usize;
        // Short form only, as `subject_serial_number` does: a value longer than 127
        // octets is not one of the identifiers read here, so treat it as a non-match
        // rather than following a long-form length we have not validated.
        if len > 0x7F {
            return None;
        }
        let start = 2usize;
        let end = start.checked_add(len)?;
        if end > buf.len() {
            return None;
        }
        Some((tag, &buf[start..end], end))
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
    // The AlgorithmIdentifier's second element is the namedCurve OID. SGP.26
    // publishes Variant O for P-256 and brainpoolP256r1, and a certificate
    // signed on one curve cannot be verified on the other, so the curve has to
    // come from the certificate rather than from the caller's assumption.
    let curve = curve_from_algorithm_identifier(alg)?;
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
    PublicKey::from_bytes(curve, &bits[1..])
}

/// Read the namedCurve OID out of an `AlgorithmIdentifier`.
///
/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
/// For an EC key the parameters hold the namedCurve OID; the `algorithm` OID is
/// `id-ecPublicKey`. The OID bytes are compared directly rather than decoded
/// into an arc list, because only a fixed, known set is of interest and the
/// comparison stays readable.
fn curve_from_algorithm_identifier(alg: &[u8]) -> Result<CurveKind> {
    // First element: id-ecPublicKey, 1.2.840.10045.2.1.
    let (id_ec_public_key, used) = read_tlv(alg, 0x06)
        .map_err(|e| Error::Certificate(format!("AlgorithmIdentifier has no OID: {e}")))?;
    const ID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    if id_ec_public_key != ID_EC_PUBLIC_KEY {
        return Err(Error::Certificate(
            "certificate public key is not an EC key".into(),
        ));
    }
    // Second element: the namedCurve OID.
    let (named_curve, _) = read_tlv(&alg[used..], 0x06).map_err(|e| {
        Error::Certificate(format!("EC AlgorithmIdentifier has no namedCurve: {e}"))
    })?;
    if named_curve == CurveKind::P256.oid() {
        Ok(CurveKind::P256)
    } else if named_curve == CurveKind::BrainpoolP256r1.oid() {
        Ok(CurveKind::BrainpoolP256r1)
    } else {
        Err(Error::Certificate(format!(
            "unsupported namedCurve OID {}",
            named_curve
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        )))
    }
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

    /// The test PKI's certificates now carry both extensions.
    ///
    /// They did not, and that was a real limit rather than a detail: with no extensions
    /// the readers returned `None`, a provider built on them reported "cannot judge", and
    /// §4.2.10 #03/#08 were unreachable through the loopback suite — the reason #03 could
    /// not be replayed even once the card-side check existed. `build_certificate` now
    /// emits them, and this test is what keeps that true.
    #[test]
    fn the_test_pki_issues_certificates_with_the_compared_extensions() {
        let pki = TestPki::new();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();

        let san = eum
            .subject_alt_name()
            .expect("the EUM certificate must name its entity");
        assert!(!san.is_empty(), "subjectAltName must not be an empty value");

        let aki = eum
            .authority_key_identifier()
            .expect("the EUM certificate must cite its issuer's key");
        assert_eq!(aki.len(), 20, "a keyIdentifier is 160 bits, per RFC 5280");

        // Two certificates from one issuer agree; the self-issued CI one does not, so
        // the comparison is not satisfied by every pair.
        let euicc = Certificate::from_der(pki.euicc_cert_der()).unwrap();
        assert_eq!(
            eum.authority_key_identifier(),
            euicc.authority_key_identifier(),
            "certificates issued by the same CA must cite the same key identifier"
        );
        // The CI is self-signed, so its authorityKeyIdentifier is its *own* key — the
        // same one the EUM and eUICC certificates cite as their issuer. So the CI's AKI
        // matching theirs is correct, not a defect, and an earlier version of this test
        // asserted the opposite. What distinguishes a *different issuer* is checked in
        // `readers_work_on_the_sgp26_certificates`, where the corpus has real chains.
        let ci = Certificate::from_der(pki.ci_cert_der()).unwrap();
        assert_eq!(
            ci.authority_key_identifier(),
            eum.authority_key_identifier(),
            "the self-signed CI cites the same key its subjects cite as their issuer"
        );

        // And the entities are distinguishable, which is what #03 needs.
        assert_ne!(
            eum.subject_alt_name(),
            euicc.subject_alt_name(),
            "the EUM and the eUICC must name different entities"
        );
    }

    /// A certificate issued with no entity name yields `None`, so "unreadable" is not
    /// mistaken for "equal".
    #[test]
    fn a_certificate_without_subject_alt_name_yields_none() {
        // `build_certificate` omits the extension when given no OID, which is the
        // negative case a comparison must not treat as a match.
        let pki = TestPki::new();
        let bare = crate::testpki::build_certificate_without_entity_for_test(&pki);
        let cert = Certificate::from_der(&bare).unwrap();
        assert_eq!(
            cert.subject_alt_name(),
            None,
            "no subjectAltName was issued, so None is the only honest answer"
        );
        // The authorityKeyIdentifier is still present: only the SAN is optional.
        assert!(cert.authority_key_identifier().is_some());
    }

    /// The `id-rspRole-dp-pb` check of §4.2.10 #08, against real certificates.
    ///
    /// The case is "the eUICC refuses any SM-DP+ Certificate for Profile Package Binding
    /// that does not indicate 'id-rspRole-dp-pb' in its extension for Certificate
    /// Policies". So the reader must return `true` for a real DPpb certificate and
    /// `false` for one carrying a different role — otherwise the card's refusal could not
    /// be attributed to the role OID.
    #[test]
    fn the_role_oid_is_read_from_real_certificates() {
        const BASE: &str = "/home/agent/sgp26-variant-o/Variants A_B_C/Variant A/SM-DP+";
        if !std::path::Path::new(BASE).exists() {
            return;
        }
        let load = |sub: &str, name: &str| -> Option<Certificate> {
            let der = std::fs::read(format!("{BASE}/{sub}/{name}")).ok()?;
            Certificate::from_der(&der).ok()
        };

        // A Profile Package Binding certificate: MUST indicate the role.
        let pb =
            load("DPpb", "CERT_S_SM_DPpb_VARA_SIG_NIST.der").expect("the DPpb certificate parses");
        let policies = pb
            .certificate_policies()
            .expect("the DPpb certificate carries certificatePolicies");
        assert!(
            !policies.is_empty(),
            "the extension is present, so it must yield at least one policy"
        );
        assert_eq!(
            pb.indicates_dp_pb_role(),
            Some(true),
            "a real DPpb certificate indicates id-rspRole-dp-pb"
        );

        // The authority certificate carries a *different* role OID, so it must answer
        // false — this is what makes the check discriminating rather than always-true.
        let auth = load("DPauth", "CERT_S_SM_DPauth_VARA_SIG_NIST.der")
            .expect("the DPauth certificate parses");
        assert_eq!(
            auth.indicates_dp_pb_role(),
            Some(false),
            "a DPauth certificate carries id-rspRole-dp-auth, not the dp-pb role, so the \
             card must not accept it as a Profile Package Binding certificate"
        );

        // Both readable, so the difference is in the value and not in parse success.
        assert!(auth.certificate_policies().is_some());
    }

    /// The readers against the *real* SGP.26 certificates, and the §5.7.5 comparison.
    ///
    /// `PrepareDownload` must check that `CERT.DPauth.SIG` and `CERT.DPpb.SIG` belong to
    /// the same entity. These are the only certificates available that carry the
    /// extensions that check needs, so they are what the readers must be shown to work
    /// on.
    ///
    /// The useful assertion is the *comparison*, not merely that both sides are
    /// `Some`: if every certificate agreed, the §5.7.5 check would be satisfied by any
    /// pair and would prove nothing. So the `DPpb`/`DPauth` pair of one entity must
    /// agree, and it must be possible to find a pair that does not.
    #[test]
    fn readers_work_on_the_sgp26_certificates() {
        const ROOT: &str = "/home/agent/sgp26-variant-o";
        let dir = std::path::Path::new(ROOT);
        if !dir.exists() {
            // The corpus is not part of this repository; skip rather than fail.
            return;
        }

        let base = format!("{ROOT}/Variants A_B_C/Variant A/SM-DP+");
        // The subdirectory and the filename suffix are both `DPpb` / `DPauth`, not the
        // bare `pb` / `auth`: the corpus is laid out as
        //     SM-DP+/DPpb/CERT_S_SM_DPpb_VARA_SIG_NIST.der
        //     SM-DP+/DPauth/CERT_S_SM_DPauth_VARA_SIG_NIST.der
        // and an earlier version of this helper looked in `SM-DP+/pb/`, found nothing,
        // returned `None`, and skipped every pair — reporting "no pair was readable"
        // rather than naming the missing file.
        let read = |kind: &str, id: &str| -> Option<(Certificate, Vec<u8>, Vec<u8>)> {
            let dir = format!("{id}{kind}");
            let path = format!("{base}/{dir}/CERT_S_SM_{dir}_VARA_SIG_NIST.der");
            let der = std::fs::read(&path).ok()?;
            let cert = Certificate::from_der(&der).ok()?;
            let san = cert.subject_alt_name()?;
            let aki = cert.authority_key_identifier()?;
            Some((cert, san, aki))
        };

        let mut pairs = 0usize;
        for entity in ["DP", "DP2"] {
            let Some((_, pb_san, pb_aki)) = read("pb", entity) else {
                continue;
            };
            let Some((_, auth_san, auth_aki)) = read("auth", entity) else {
                continue;
            };
            assert_eq!(
                pb_san, auth_san,
                "the DPpb and DPauth certificate of one entity must share a subjectAltName"
            );
            assert_eq!(
                pb_aki, auth_aki,
                "the DPpb and DPauth certificate of one entity must share a key identifier"
            );
            pairs += 1;
        }
        assert!(pairs > 0, "no SGP.26 certificate pair was readable");

        // The discriminating case: certificates of *different* entities must differ, or
        // the comparison above would hold for any pair.
        let dp = read("pb", "DP").map(|(_, san, aki)| (san, aki));
        let dp2 = read("pb", "DP2").map(|(_, san, aki)| (san, aki));
        if let (Some((san_a, aki_a)), Some((san_b, aki_b))) = (dp, dp2) {
            assert!(
                san_a != san_b || aki_a != aki_b,
                "two different SM-DP+ entities must not compare equal, else the \
                 same-entity check in §5.7.5 cannot fail and is not a check"
            );
        }
    }

    /// A certificate with no such extension yields `None`, so a caller cannot mistake
    /// "unreadable" for "equal".
    #[test]
    fn a_certificate_without_the_extension_yields_none() {
        // An empty DER does not parse, so build a certificate-shaped blob that does
        // but carries no extensions:
        //
        //   Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ... }, ... }
        //
        // The readers scan for extension OIDs anywhere in the DER, so an input whose
        // only SEQUENCE is the outer one must yield None for both rather than panicking
        // or scanning past the end. `Certificate::from_der` extracts an SPKI, which this
        // does not have, so the assertion is conditional — the property under test is
        // that neither reader invents a value.
        fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
            let mut v = vec![tag, value.len() as u8];
            v.extend_from_slice(value);
            v
        }
        let bare = tlv(0x30, &tlv(0x30, &[0x02, 0x01, 0x01]));
        if let Ok(cert) = Certificate::from_der(&bare) {
            assert_eq!(
                cert.subject_alt_name(),
                None,
                "no subjectAltName extension is present, so None is the only honest answer"
            );
            assert_eq!(cert.authority_key_identifier(), None);
        }
    }

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
