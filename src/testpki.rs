//! A self-consistent P-256 test PKI for the SGP.33 suites.
//!
//! # Purpose, and its limits
//!
//! The SGP.22 protocol needs an eUICC certificate, an EUM certificate and a CI
//! public key before `AuthenticateServer` can do anything. The real material is
//! SGP.26 test certificates, which are not available offline.
//!
//! [`TestPki`] builds an equivalent-shaped chain with locally generated P-256
//! keys so the *code paths* can be exercised end to end. It is **not** a
//! substitute for SGP.26: the key identifiers here are locally chosen, there is
//! no GSMA CI root, and nothing produced by this module should be treated as a
//! conformance artefact.
//!
//! # Structure
//!
//! `TestPki` holds three P-256 key pairs and the DER certificates for the EUM
//! and the eUICC. Certificates are minimally valid self-signed X.509 v3
//! structures carrying the subject public key, encoded here rather than pulled
//! from a certificate-generation crate (none is available offline).
//!
//! The certificates are intentionally minimal: enough structure for the parser
//! in [`crate::x509`] and for `rustls-webpki`'s DER reader to walk, without
//! claiming to be fully conformant CA-issued certificates.

use crate::ecdsa::{KeyPair, PublicKey};
use crate::kdf::sha256;
use crate::Result;

/// How the test material is labelled, so it cannot be mistaken for real
/// certificates in logs or dumps.
pub const TEST_CN_PREFIX: &str = "SGP.33 TEST ONLY";

/// A self-consistent test chain.
pub struct TestPki {
    /// The CI key pair whose identifier the eUICC trusts.
    pub ci: KeyPair,
    /// The EUM key pair.
    pub eum: KeyPair,
    /// The eUICC key pair.
    pub euicc: KeyPair,
    eum_cert: Vec<u8>,
    euicc_cert: Vec<u8>,
    ci_cert: Vec<u8>,
    ci_pk_id: Vec<u8>,
}

impl std::fmt::Debug for TestPki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestPki")
            .field("ci_pk_id", &crate::hex(&self.ci_pk_id))
            .finish_non_exhaustive()
    }
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPki {
    /// Generate a fresh chain. Key generation is randomised, so each call
    /// produces different (but equally valid) material.
    pub fn new() -> Self {
        Self::try_new().expect("test PKI key generation must succeed")
    }

    /// Generate a fresh chain, returning errors rather than panicking.
    pub fn try_new() -> Result<Self> {
        let ci = KeyPair::generate()?;
        let eum = KeyPair::generate()?;
        let euicc = KeyPair::generate()?;

        // The CI public key identifier is a truncated SHA-256 of the CI public
        // key in the real scheme (SGP.22 §5.7.5 allows truncation). 20 bytes is
        // within the permitted range and is used here.
        let ci_pk_id = sha256(ci.public_key().as_ref())[..20].to_vec();

        // The EUM certificate is signed by the CI; the eUICC certificate is
        // signed by the CI as well (in the test scheme the CI stands in for the
        // issuing authority). This gives a two-level chain whose signatures can
        // be checked with the primitives here.
        let eum_cert = build_certificate("eum", &eum.public_key(), &ci)?;
        let euicc_cert = build_certificate("euicc", &euicc.public_key(), &ci)?;
        let ci_cert = build_certificate("ci", &ci.public_key(), &ci)?;

        Ok(TestPki {
            ci,
            eum,
            euicc,
            eum_cert,
            euicc_cert,
            ci_cert,
            ci_pk_id,
        })
    }

    /// DER of the EUM certificate (`CERT.EUM.ECDSA`).
    pub fn eum_cert_der(&self) -> &[u8] {
        &self.eum_cert
    }

    /// DER of the eUICC certificate (`CERT.EUICC.ECDSA`).
    pub fn euicc_cert_der(&self) -> &[u8] {
        &self.euicc_cert
    }

    /// DER of the CI certificate.
    pub fn ci_cert_der(&self) -> &[u8] {
        &self.ci_cert
    }

    /// The CI public key identifier the eUICC advertises in
    /// `EUICCInfo1.euiccCiPKIdListForVerification`.
    pub fn ci_pk_id(&self) -> &[u8] {
        &self.ci_pk_id
    }

    /// The EUM public key.
    pub fn eum_public_key(&self) -> PublicKey {
        self.eum.public_key()
    }

    /// The eUICC public key.
    pub fn euicc_public_key(&self) -> PublicKey {
        self.euicc.public_key()
    }

    /// The CI public key.
    pub fn ci_public_key(&self) -> PublicKey {
        self.ci.public_key()
    }

    /// Issue a certificate for an arbitrary subject key, signed by the CI.
    ///
    /// This is what the RSP server side needs: `serverCertificate` must be a
    /// certificate for the SM-DP+'s own key, issued by the CI the eUICC trusts.
    /// The subject key is supplied rather than generated so the caller keeps
    /// the private half and can sign with it.
    pub fn issue_for(&self, subject: &KeyPair, label: &str) -> Vec<u8> {
        build_certificate(label, &subject.public_key(), &self.ci)
            .expect("issuing a test certificate must succeed")
    }
}

/// Build a minimal self-issued X.509 certificate for `subject_key`, signed by
/// `issuer`.
///
/// The structure is:
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate SEQUENCE {
///     [0] { INTEGER 2 }                 -- v3
///     INTEGER serialNumber
///     SEQUENCE { OID ecdsa-with-SHA256, NULL }
///     Name issuer                       -- CN only
///     SEQUENCE { UTCTime notBefore, UTCTime notAfter }
///     Name subject                      -- CN only
///     SEQUENCE { SEQUENCE { OID id-ecPublicKey, OID prime256v1 },
///                BIT STRING subjectPublicKey }
///   }
///   SEQUENCE { OID ecdsa-with-SHA256 }
///   BIT STRING signatureValue
/// }
/// ```
fn build_certificate(label: &str, subject_key: &PublicKey, issuer: &KeyPair) -> Result<Vec<u8>> {
    const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    // A fixed UTC time so certificate generation is reproducible in structure.
    const UTC_TIME: &[u8] = b"250101000000Z";

    let cn = format!("{TEST_CN_PREFIX} {label}");

    // serialNumber: derived from the subject key so it varies per certificate.
    //
    // DER INTEGERs are minimally encoded and must be positive, so a leading
    // zero byte is added when the high bit of the first content byte is set.
    // Build the content first and only then wrap it in a TLV — inserting the
    // pad byte after wrapping would leave the declared length one byte short.
    let mut serial_bytes = sha256(subject_key.as_ref())[..8].to_vec();
    if serial_bytes[0] & 0x80 != 0 {
        serial_bytes.insert(0, 0x00);
    }
    let serial = tlv(0x02, &serial_bytes);

    let version = tlv(0xa0, &tlv(0x02, &[0x02]));
    let sig_alg = tlv(
        0x30,
        &[tlv(0x06, OID_ECDSA_SHA256), tlv(0x05, &[])].concat(),
    );
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, cn.as_bytes())].concat(),
            ),
        ),
    );
    let validity = tlv(0x30, &[tlv(0x17, UTC_TIME), tlv(0x17, UTC_TIME)].concat());
    let spki_alg = tlv(
        0x30,
        &[tlv(0x06, OID_EC_PUBLIC_KEY), tlv(0x06, OID_PRIME256V1)].concat(),
    );
    let spki = tlv(
        0x30,
        &[
            spki_alg,
            tlv(0x03, &[&[0x00u8][..], subject_key.as_ref()].concat()),
        ]
        .concat(),
    );

    let tbs = tlv(
        0x30,
        &[
            version.as_slice(),
            &serial,
            &sig_alg,
            &name, // issuer
            &validity,
            &name, // subject (self-issued)
            &spki,
        ]
        .concat(),
    );

    let signature = issuer.sign_der(&tbs)?;
    let cert = tlv(
        0x30,
        &[
            tbs,
            sig_alg,
            tlv(0x03, &[&[0x00u8][..], &signature].concat()),
        ]
        .concat(),
    );
    Ok(cert)
}

/// Encode a DER TLV with a short-form or long-form length as needed.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_length(value.len()));
    out.extend_from_slice(value);
    out
}

/// Encode a DER length.
fn der_length(len: usize) -> Vec<u8> {
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
    use crate::x509::Certificate;

    #[test]
    fn generates_three_distinct_keys() {
        let pki = TestPki::new();
        assert_ne!(pki.eum_public_key(), pki.euicc_public_key());
        assert_ne!(pki.eum_public_key(), pki.ci_public_key());
        assert_ne!(pki.euicc_public_key(), pki.ci_public_key());
    }

    #[test]
    fn ci_pk_id_is_twenty_bytes_and_deterministic_for_the_key() {
        let pki = TestPki::new();
        assert_eq!(pki.ci_pk_id().len(), 20);
        let expected = &sha256(pki.ci_public_key().as_ref())[..20];
        assert_eq!(pki.ci_pk_id(), expected);
    }

    #[test]
    fn certificates_are_parsable_and_carry_the_right_keys() {
        let pki = TestPki::new();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let euicc = Certificate::from_der(pki.euicc_cert_der()).unwrap();
        let ci = Certificate::from_der(pki.ci_cert_der()).unwrap();
        assert_eq!(eum.public_key(), &pki.eum_public_key());
        assert_eq!(euicc.public_key(), &pki.euicc_public_key());
        assert_eq!(ci.public_key(), &pki.ci_public_key());
    }

    #[test]
    fn every_certificate_verifies_under_the_ci_key() {
        let pki = TestPki::new();
        let ci = Certificate::from_der(pki.ci_cert_der()).unwrap();
        Certificate::from_der(pki.eum_cert_der())
            .unwrap()
            .verify_signed_by(&ci)
            .unwrap();
        Certificate::from_der(pki.euicc_cert_der())
            .unwrap()
            .verify_signed_by(&ci)
            .unwrap();
    }

    #[test]
    fn a_certificate_does_not_verify_under_the_wrong_issuer() {
        let pki = TestPki::new();
        let eum = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let euicc_as_issuer = Certificate::from_der(pki.euicc_cert_der()).unwrap();
        assert!(eum.verify_signed_by(&euicc_as_issuer).is_err());
    }

    #[test]
    fn two_pkis_are_independent() {
        let a = TestPki::new();
        let b = TestPki::new();
        assert_ne!(a.ci_pk_id(), b.ci_pk_id());
        let a_ci = Certificate::from_der(a.ci_cert_der()).unwrap();
        let b_eum = Certificate::from_der(b.eum_cert_der()).unwrap();
        assert!(
            b_eum.verify_signed_by(&a_ci).is_err(),
            "chains must not cross-verify"
        );
    }

    #[test]
    fn certificates_are_labelled_as_test_material() {
        let pki = TestPki::new();
        let der = pki.eum_cert_der();
        // The CN must appear so a dumped certificate is self-describing.
        let needle = TEST_CN_PREFIX.as_bytes();
        assert!(
            der.windows(needle.len()).any(|w| w == needle),
            "certificate must carry the {TEST_CN_PREFIX} label"
        );
    }

    #[test]
    fn der_length_encoding_handles_both_forms() {
        assert_eq!(der_length(0x7f), vec![0x7f]);
        assert_eq!(der_length(0x80), vec![0x81, 0x80]);
        assert_eq!(der_length(0xff), vec![0x81, 0xff]);
        assert_eq!(der_length(0x100), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn generated_certificate_has_a_long_form_length() {
        // A real P-256 certificate exceeds 127 bytes, so this exercises the
        // long-form path in `der_length` rather than the short form only.
        let pki = TestPki::new();
        let der = pki.eum_cert_der();
        assert!(
            der.len() > 0x80,
            "certificate should need a long-form length"
        );
        assert_eq!(der[0], 0x30);
        assert!(der[1] & 0x80 != 0, "top-level length should be long-form");
    }
}
