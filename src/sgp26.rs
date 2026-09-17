//! The GSMA SGP.26 test certificates and keys, loaded from disk.
//!
//! # Why this exists next to [`crate::testpki::TestPki`]
//!
//! [`crate::testpki::TestPki`] generates a *self-consistent* chain: real P-256 keys, real
//! signatures, but locally chosen identifiers. It exercises the code paths and
//! can do nothing more, because the identifiers it invents are the ones the
//! tests then look for. That is the failure mode this module removes — the
//! `#EID1` incident, where a sequence and the card agreed on a fabricated value
//! and the assertion proved nothing.
//!
//! This module loads the **published SGP.26 material** instead. The certificates
//! chain to the GSMA Test CI, `CERT_EUICC_ECDSA_NIST.der` carries the EID
//! `89049032123451234512345678901235` that SGP.23 Annex A defines as `#EID1`, and
//! `PK_S_EIMsign_ECDSA_NIST.pem` is the key SGP.33-1 Annex A names as
//! `EIM_PUBLIC_KEY_DATA_PK`. So a sequence asserting against these values is
//! asserting against the specification rather than against the harness.
//!
//! The two are interchangeable behind the same accessors, so the loopback can
//! prefer this one and fall back to `TestPki` when the fixtures are absent —
//! and say which it used.
//!
//! # Provenance and licence
//!
//! The files in `fixtures/sgp26/variant-o/` are reproduced unmodified from the
//! GSMA's own published packages:
//!
//! - `SGP.26-v3.0-Certificates_01_12_2023.zip` → `SGP.26v3_Files/Variant O/`
//!   (`Valid Test Cases/{CertificateIssuer,EUM,eUICC}`)
//! - `SGP.26_v3.0-2023_files_v2_EIM.zip` → `Valid Test Cases/EIM/EIMsign/`
//!
//! They are test material and are `Non-confidential` per SGP.26. They are
//! **not** secret: the counterpart private keys ship in the same package, and
//! SGP.26 never publishes the production CI private key. They work against test
//! eUICCs only.
//!
//! See `docs/test-material-sources.md` in `tuddenham_IPAd` for the full annex
//! chain and the download URLs.
//!
//! # Curve
//!
//! Variant O is published for both NIST P-256 and brainpoolP256r1. The file
//! names differ only in the `_NIST` / `_BRP` suffix, so the loader is
//! parameterised by [`CurveKind`] rather than duplicated. The SGP.33-1 "BRP"
//! test sequences need the brainpool set, and SGP.26 populates both in the
//! same package.
//!
//! The `_NIST` set is what [`Sgp26VariantO::load`] reads; use
//! [`Sgp26VariantO::load_curve`] for brainpool.

use crate::ecdsa::{CurveKind, KeyPair, PublicKey};
use crate::x509::Certificate;
use crate::Result;

/// The published SGP.26 Variant O material for one curve.
pub struct Sgp26VariantO {
    /// Which curve this material is on.
    pub curve: CurveKind,
    /// `CERT_CI_ECDSA_<curve>.der` — the Test CI certificate, self-signed.
    pub ci: Certificate,
    /// `CERT_EUM_ECDSA_<curve>.der` — issued by the Test CI.
    pub eum: Certificate,
    /// `CERT_EUICC_ECDSA_<curve>.der` — issued by the EUM.
    ///
    /// Its subject serialNumber is the ASCII EID.
    pub euicc: Certificate,
    /// `PK_EUICC_ECDSA_<curve>.pem` — the eUICC's public key.
    pub euicc_public: PublicKey,
    /// `SK_EUICC_ECDSA_<curve>.pem` — the eUICC's private key.
    ///
    /// Present because the harness plays the eUICC's role in `AuthenticateServer`
    /// and has to sign the authentication response.
    pub euicc_private: KeyPair,
    /// `PK_S_EIMsign_ECDSA_<curve>.pem` — `EIM_PUBLIC_KEY_DATA_PK`.
    ///
    /// The key an eUICC verifies eUICC Package signatures against (SGP.32
    /// §3.3.1). SGP.33-1 Annex A defines `EIM_PUBLIC_KEY_DATA_PK` as
    /// `eimPublicKey #PK_S_EIMsign_ECDSA`.
    pub eim_public: PublicKey,
    /// `SK_S_EIMsign_ECDSA_<curve>.pem` — the counterpart private key.
    ///
    /// SGP.26 publishes the eIM signing key pair, not just the public half, so
    /// the harness can produce a signature the eUICC verifies under the
    /// published key. Signing with a locally generated key while advertising
    /// this one would be a mismatch that looks like a verification failure.
    pub eim_private: KeyPair,

    /// `PK_S_SM_DPauth_ECDSA_<curve>.pem` — `CERT_S_SM_DPauth`'s public key.
    pub dp_auth_public: Option<PublicKey>,
    /// `SK_S_SM_DPauth_ECDSA_<curve>.pem` — the SM-DP+ authentication key.
    pub dp_auth_private: Option<KeyPair>,

    /// `SK_EUM_ECDSA_<curve>.pem` — the EUM's signing key.
    ///
    /// `CERT_EUM_ECDSA_<curve>.der` is the certificate the eUICC trusts for an SM-DP+
    /// session (`CERT.DPauth.SIG`), so a sequence that must authenticate a session the way
    /// the published material intends needs this half. `None` when the subset omits it.
    pub eum_private: Option<KeyPair>,

    /// `CERT_S_SM_DPpb_ECDSA_<curve>.der` — the SM-DP+ Profile Package Binding
    /// certificate.
    ///
    /// This is `CERT.DPpb.SIG`: the `smdpCertificate` in `PrepareDownload` and the key
    /// `smdpSignature2` is verified under.
    pub dp_pb: Option<Certificate>,

    /// `SK_S_SM_DPpb_ECDSA_<curve>.pem` — the key that signs `smdpSigned2`.
    pub dp_pb_private: Option<KeyPair>,

    /// `CERT_S_SM_DPauth_ECDSA_<curve>.der` — the SM-DP+ authentication certificate.
    ///
    /// This is `CERT.DPauth.SIG`: the certificate an RSP session is authenticated with, and
    /// the one `PrepareDownload` compares against the request's `smdpCertificate` under
    /// SGP.22 §5.7.5's same-entity rule. It is a *different certificate* from
    /// `CERT_S_SM_DPpb_ECDSA_<curve>.der` with the *same* subjectAltName — which is exactly
    /// the relationship the rule tests, and the reason a session authenticated with the EUM
    /// certificate is not a valid stand-in for one authenticated with this.
    pub dp_auth_cert: Option<Certificate>,

    /// `CERT_S_SM_DSauth_INV_SIGN_<curve>.der` — an SM-DS authentication certificate whose
    /// signature is invalid.
    ///
    /// §4.2.18 SM-DS_ErrorCases #01 names this file exactly. It is deliberately the *wrong*
    /// certificate for the case: the certificate is a well-formed `CERT.DSauth.SIG` on the
    /// right curve, and it is the signature over it that does not verify. That is what makes
    /// the case about a bad certificate rather than about a wrong role — and it is why the
    /// card must return `invalidCertificate`, not `invalidOid`, when it is presented.
    pub ds_auth_invalid_signature_cert: Option<Certificate>,
}

impl CurveKind {
    /// The SGP.26 Variant O file-name suffix for this curve.
    ///
    /// SGP.26 names the brainpool material `_BRP` and the NIST material
    /// `_NIST`; everything else about the file names is identical.
    pub const fn sgp26_suffix(&self) -> &'static str {
        match self {
            CurveKind::P256 => "NIST",
            CurveKind::BrainpoolP256r1 => "BRP",
        }
    }
}

impl Sgp26VariantO {
    /// The fixture directory, relative to this crate's manifest.
    pub const DIR: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/sgp26/variant-o");

    /// Load the NIST P-256 Variant O material from [`Self::DIR`].
    ///
    /// Returns `Err` rather than panicking if a file is missing or malformed, so
    /// a caller can fall back to [`crate::testpki::TestPki`] deliberately instead
    /// of the suite dying at startup.
    pub fn load() -> Result<Self> {
        Self::load_curve(CurveKind::P256)
    }

    /// Load the Variant O material for `curve` from [`Self::DIR`].
    pub fn load_curve(curve: CurveKind) -> Result<Self> {
        Self::load_curve_from(curve, Self::DIR)
    }

    /// Load from an explicit directory, for `curve`.
    pub fn load_from(dir: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::load_curve_from(CurveKind::P256, dir)
    }

    /// Load one curve's material from an explicit directory.
    pub fn load_curve_from(curve: CurveKind, dir: impl AsRef<std::path::Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let sfx = curve.sgp26_suffix();
        let read = |name: &str| -> Result<Vec<u8>> {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|e| {
                crate::Error::Certificate(format!("SGP.26 fixture {}: {e}", path.display()))
            })
        };

        let euicc = Certificate::from_der(&read(&format!("CERT_EUICC_ECDSA_{sfx}.der"))?)?;
        let euicc_public =
            public_key_from_pem(curve, &read(&format!("PK_EUICC_ECDSA_{sfx}.pem"))?)?;

        // The SM-DP+ authentication pair is optional: some Variant O subsets
        // publish it and some do not, and a missing pair is not an error.
        let dp_auth_public = read(&format!("PK_S_SM_DPauth_ECDSA_{sfx}.pem"))
            .ok()
            .and_then(|pem| public_key_from_pem(curve, &pem).ok());
        let dp_auth_private = read(&format!("SK_S_SM_DPauth_ECDSA_{sfx}.pem"))
            .ok()
            .and_then(|pem| private_key_from_pem(curve, &pem).ok());

        // The EUM's private half and the Profile Package Binding pair. Optional for the
        // same reason as the authentication pair above: a subset need not carry every
        // file, and `verify` is where a caller that needs one finds out it is wrong.
        let eum_private = read(&format!("SK_EUM_ECDSA_{sfx}.pem"))
            .ok()
            .and_then(|pem| private_key_from_pem(curve, &pem).ok());
        let dp_pb = read(&format!("CERT_S_SM_DPpb_ECDSA_{sfx}.der"))
            .ok()
            .and_then(|der| Certificate::from_der(&der).ok());
        let dp_pb_private = read(&format!("SK_S_SM_DPpb_ECDSA_{sfx}.pem"))
            .ok()
            .and_then(|pem| private_key_from_pem(curve, &pem).ok());
        // The authentication certificate may be named with or without the `DP` infix: the
        // published set uses `CERT_S_SM_DPauth_ECDSA_<curve>.der` in `Variant O` and
        // `CERT_S_SM_DP2auth_...` in the `Variants A_B_C` tree for the second DP. Try both
        // rather than pinning one spelling.
        let dp_auth_cert = ["CERT_S_SM_DPauth_ECDSA_", "CERT_S_SM_DP2auth_ECDSA_"]
            .iter()
            .find_map(|prefix| read(&format!("{prefix}{sfx}.der")).ok())
            .and_then(|der| Certificate::from_der(&der).ok());

        // The invalid-signature certificate is in `Invalid Test Cases/`, which is a
        // different subtree from the rest of the fixture set, so it is loaded by its own
        // name rather than through the `sfx` pattern.
        let ds_auth_invalid_signature_cert = read(&format!("CERT_S_SM_DSauth_INV_SIGN_{sfx}.der"))
            .ok()
            .and_then(|der| Certificate::from_der(&der).ok());

        Ok(Sgp26VariantO {
            curve,
            ci: Certificate::from_der(&read(&format!("CERT_CI_ECDSA_{sfx}.der"))?)?,
            eum: Certificate::from_der(&read(&format!("CERT_EUM_ECDSA_{sfx}.der"))?)?,
            euicc,
            euicc_public,
            euicc_private: private_key_from_pem(
                curve,
                &read(&format!("SK_EUICC_ECDSA_{sfx}.pem"))?,
            )?,
            eim_public: public_key_from_pem(
                curve,
                &read(&format!("PK_S_EIMsign_ECDSA_{sfx}.pem"))?,
            )?,
            eim_private: private_key_from_pem(
                curve,
                &read(&format!("SK_S_EIMsign_ECDSA_{sfx}.pem"))?,
            )?,
            dp_auth_public,
            dp_auth_private,
            eum_private,
            dp_pb,
            dp_pb_private,
            dp_auth_cert,
            ds_auth_invalid_signature_cert,
        })
    }

    /// Check the loaded material is internally consistent.
    ///
    /// Every check is one a wrong or truncated fixture would fail, so a caller
    /// that gets `Ok` can rely on the material rather than merely on its
    /// presence. Run by [`Self::load`] callers that want the guarantee; exposed
    /// separately so a test can assert on individual failures.
    pub fn verify(&self) -> Result<()> {
        // The private key must match the certificate's public key, or the
        // harness would sign responses the eUICC cannot verify and the failure
        // would look like a protocol bug.
        if self.euicc_private.public_key().as_ref() != self.euicc.public_key().as_ref() {
            return Err(crate::Error::Certificate(
                "SK_EUICC_ECDSA_NIST.pem does not match the key in CERT_EUICC_ECDSA_NIST.der"
                    .into(),
            ));
        }
        // The eUICC certificate must be issued by the EUM.
        self.euicc.verify_signed_by(&self.eum)?;
        // And the EUM certificate by the CI.
        self.eum.verify_signed_by(&self.ci)?;
        // The eIM key pair must correspond, because the harness signs with the
        // private half while the eUICC advertises the public half in its eIM
        // configuration data. A mismatch surfaces as a signature that will not
        // verify, which reads as a protocol failure rather than a bad fixture.
        if self.eim_private.public_key().as_ref() != self.eim_public.as_ref() {
            return Err(crate::Error::Certificate(
                "SK_S_EIMsign_ECDSA_NIST.pem does not match PK_S_EIMsign_ECDSA_NIST.pem".into(),
            ));
        }
        // A present-but-mismatched key is the failure worth catching: it parses, it
        // signs, and the eUICC rejects the result for a reason that looks like a protocol
        // bug. Absence is fine (a subset need not carry every file), so each check is
        // skipped when either half is missing.
        if let Some(k) = &self.eum_private {
            if k.public_key().as_ref() != self.eum.public_key().as_ref() {
                return Err(crate::Error::Certificate(format!(
                    "SK_EUM_ECDSA_{sfx}.pem does not match the key in CERT_EUM_ECDSA_{sfx}.der",
                    sfx = self.curve.sgp26_suffix()
                )));
            }
        }
        if let (Some(k), Some(cert)) = (&self.dp_pb_private, &self.dp_pb) {
            if k.public_key().as_ref() != cert.public_key().as_ref() {
                return Err(crate::Error::Certificate(format!(
                    "SK_S_SM_DPpb_ECDSA_{sfx}.pem does not match the key in \
                     CERT_S_SM_DPpb_ECDSA_{sfx}.der",
                    sfx = self.curve.sgp26_suffix()
                )));
            }
            // And the binding certificate must carry the role §4.5.2.1.0.0 requires,
            // since a sequence presenting it would otherwise be refused for its role and
            // the failure would be attributed to whatever the sequence was testing.
            if cert.indicates_dp_pb_role() == Some(false) {
                return Err(crate::Error::Certificate(format!(
                    "CERT_S_SM_DPpb_ECDSA_{sfx}.der does not indicate id-rspRole-dp-pb",
                    sfx = self.curve.sgp26_suffix()
                )));
            }
        }
        Ok(())
    }

    /// The EID the material carries, as the 16 octets SGP.23 Annex A defines.
    ///
    /// # Two encodings of one identifier
    ///
    /// The certificate's `serialNumber` attribute holds the EID as a
    /// **32-character ASCII string** (`"89049032123451234512345678901235"`),
    /// which is how a human reads an EID off a card. SGP.23 Annex A gives
    /// `#EID1` as the **16 octets** `89 04 90 32 12 34 51 23 45 12 34 56 78 90 12
    /// 35` — the same value, BCD-packed into the octet form an APDU carries.
    ///
    /// Both are the same EID, and returning them interchangeably would be a
    /// silent bug: a sequence comparing the raw `eidValue` from `GetEID` against
    /// the ASCII form would never match, and one comparing against a *truncated*
    /// conversion might match for the wrong reason. So this decodes to the octet
    /// form, and [`Self::eid_ascii`] gives the other.
    pub fn eid(&self) -> Result<Vec<u8>> {
        let ascii = self.eid_ascii()?;
        // 32 hex characters → 16 octets. SGP.22 §5.2.1 pads a 19-digit ICCID
        // with 'F'; an EID is exactly 32 digits, so any non-digit is an error
        // rather than something to pad.
        if ascii.len() != 32 {
            return Err(crate::Error::Certificate(format!(
                "EID is {} characters, expected 32",
                ascii.len()
            )));
        }
        let mut out = Vec::with_capacity(16);
        for pair in ascii.chunks(2) {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }

    /// The EID as the certificate's `serialNumber` states it: 32 ASCII digits.
    ///
    /// This is the value a reader prints; [`Self::eid`] is the octet form an
    /// APDU carries.
    pub fn eid_ascii(&self) -> Result<Vec<u8>> {
        self.euicc.subject_serial_number().ok_or_else(|| {
            crate::Error::Certificate("SGP.26 eUICC certificate has no serialNumber".into())
        })
    }
}

/// Decode one ASCII hex digit.
fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(crate::Error::Certificate(format!(
            "EID contains non-hex character {:?}",
            c as char
        ))),
    }
}

/// Decode a SEC1 or PKCS#8 PEM public key on `curve`.
fn public_key_from_pem(curve: CurveKind, pem: &[u8]) -> Result<PublicKey> {
    let der = pem_to_der(pem)?;
    // The SGP.26 `PK_*.pem` files are SubjectPublicKeyInfo (X.509), whose payload
    // is the SEC1 point. `Certificate::from_der` is not applicable, so the SPKI
    // wrapper is skipped by scanning for the uncompressed point.
    let point = extract_sec1_point(curve, &der)?;
    PublicKey::from_bytes(curve, point)
}

/// Decode a SEC1 or PKCS#8 PEM private key on `curve`.
fn private_key_from_pem(curve: CurveKind, pem: &[u8]) -> Result<KeyPair> {
    let der = pem_to_der(pem)?;
    // The SGP.26 `SK_*.pem` files are SEC1 ECPrivateKey. The RustCrypto key
    // types read PKCS#8 directly, or SEC1 through their own `from_sec1_der`
    // where the curve is unambiguous; try the direct read first and fall back
    // to wrapping the SEC1 body in a PKCS#8 PrivateKeyInfo carrying this
    // curve's OID.
    if let Ok(k) = KeyPair::from_pkcs8(curve, &der) {
        return Ok(k);
    }
    let pkcs8 = sec1_private_to_pkcs8(curve, &der)?;
    KeyPair::from_pkcs8(curve, &pkcs8)
}

/// Find the uncompressed point inside a SubjectPublicKeyInfo for `curve`.
///
/// The point is `0x04` followed by 64 bytes. Validated by `PublicKey::from_bytes`
/// afterwards, so a false positive here fails loudly rather than silently.
fn extract_sec1_point(curve: CurveKind, spki: &[u8]) -> Result<&[u8]> {
    const NEEDLE: usize = 65;
    // Inclusive of the last possible start: a point beginning at exactly
    // `len - NEEDLE` is the final valid position, and excluding it silently
    // failed on the SGP.26 keys, whose point begins immediately after the
    // BIT STRING header.
    for start in 0..=spki.len().saturating_sub(NEEDLE) {
        if spki[start] == 0x04 {
            let candidate = &spki[start..start + NEEDLE];
            if PublicKey::from_bytes(curve, candidate).is_ok() {
                return Ok(candidate);
            }
        }
    }
    Err(crate::Error::Certificate(
        "no uncompressed point found in the public key".into(),
    ))
}

/// Wrap a SEC1 `ECPrivateKey` in a PKCS#8 `PrivateKeyInfo` on `curve`.
///
/// The SEC1 body is carried verbatim as the inner OCTET STRING; only the outer
/// algorithm identifier is added. The curve OID is not optional: the RustCrypto
/// key types check it against the curve they were asked for, so emitting
/// prime256v1 here would make a brainpool key fail to load with a confusing
/// "invalid PKCS#8" message.
fn sec1_private_to_pkcs8(curve: CurveKind, sec1: &[u8]) -> Result<Vec<u8>> {
    // PrivateKeyInfo ::= SEQUENCE { version INTEGER (0),
    //   privateKeyAlgorithm AlgorithmIdentifier, privateKey OCTET STRING }
    // AlgorithmIdentifier ::= SEQUENCE { id-ecPublicKey, <namedCurve OID> }
    let mut alg_id = Vec::new();
    alg_id.push(0x06);
    alg_id.push(0x07);
    alg_id.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]); // id-ecPublicKey
    alg_id.push(0x06);
    alg_id.push(curve.oid().len() as u8);
    alg_id.extend_from_slice(curve.oid());

    let mut inner = vec![
        0x02, 0x01, 0x00, // version 0
        0x30, // AlgorithmIdentifier SEQUENCE
    ];
    inner.extend_from_slice(&der_length(alg_id.len())?);
    inner.extend_from_slice(&alg_id);
    inner.push(0x04); // OCTET STRING
    inner.extend_from_slice(&der_length(sec1.len())?);
    inner.extend_from_slice(sec1);

    let mut out = Vec::new();
    out.push(0x30);
    out.extend_from_slice(&der_length(inner.len())?);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Encode a DER definite length.
fn der_length(len: usize) -> Result<Vec<u8>> {
    if len < 0x80 {
        Ok(vec![len as u8])
    } else if len <= 0xFF {
        Ok(vec![0x81, len as u8])
    } else if len <= 0xFFFF {
        Ok(vec![0x82, (len >> 8) as u8, len as u8])
    } else {
        Err(crate::Error::Certificate("DER length too large".into()))
    }
}

/// Strip the PEM armour and base64-decode the body of the **key** block.
///
/// PEM files may hold more than one block, and the SGP.26 private keys do: an
/// `EC PARAMETERS` block naming the curve, followed by the `EC PRIVATE KEY`
/// block. Concatenating both bodies produces bytes that are not valid DER, and
/// the resulting error ("unexpected ASN.1 DER tag: expected SEQUENCE, got
/// OBJECT IDENTIFIER") points at the parser rather than at the real cause.
///
/// So this selects a single block rather than flattening the file: the last
/// block by default, which is the key in every SGP.26 file, and an explicit
/// label when the caller needs a particular one.
fn pem_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    pem_block_to_der(pem, None)
}

/// Take the body of the PEM block whose header contains `want`, or of the last
/// block when `want` is `None`.
fn pem_block_to_der(pem: &[u8], want: Option<&str>) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(pem)
        .map_err(|e| crate::Error::Certificate(format!("PEM is not UTF-8: {e}")))?;

    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = Some(rest.trim_end_matches('-').trim().to_string());
            body.clear();
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            let end_label = rest.trim_end_matches('-').trim().to_string();
            if let Some(start) = label.take() {
                // A mismatched END would silently misalign the body; refuse it.
                if start != end_label {
                    return Err(crate::Error::Certificate(format!(
                        "PEM block {start:?} closed by {end_label:?}"
                    )));
                }
                blocks.push((start, std::mem::take(&mut body)));
            }
        } else if label.is_some() {
            body.push_str(line);
        }
    }

    let chosen = match want {
        Some(w) => blocks
            .iter()
            .find(|(l, _)| l == w)
            .ok_or_else(|| crate::Error::Certificate(format!("no PEM block labelled {w:?}")))?,
        None => blocks
            .last()
            .ok_or_else(|| crate::Error::Certificate("no PEM block found".into()))?,
    };
    base64_decode(&chosen.1)
}

/// Minimal base64 decoder, standard alphabet with padding.
///
/// Hand-rolled because the workspace's dependency set is deliberately small and
/// this is the only base64 in it. Rejects rather than guesses on bad input.
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(4) {
        return Err(crate::Error::Certificate(
            "base64: length is not a multiple of 4".into(),
        ));
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                0
            } else {
                val(c).ok_or_else(|| {
                    crate::Error::Certificate(format!("base64: bad character {:?}", c as char))
                })?
            };
            acc |= (v as u32) << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixtures must load; otherwise every test below is vacuous.
    #[test]
    fn the_published_material_loads() {
        let v = Sgp26VariantO::load().expect("SGP.26 Variant O fixtures must load");
        assert!(!v.ci.as_der().is_empty());
        assert!(!v.euicc.as_der().is_empty());
    }

    /// The whole chain verifies: eUICC←EUM←CI, and the key matches its cert.
    /// Every fixture private key pairs with the certificate it is filed against.
    ///
    /// The keys were added from `SGP.26 Variant O, Valid Test Cases`, and `PROVENANCE.json`
    /// records each one's `pairs_with` and the SHA-256 prefix of its public key. Checking
    /// the pairing here — rather than trusting the copy — is what makes the manifest
    /// meaningful: a key taken from a different sub-CA still parses and still signs, and
    /// the eUICC then rejects the result for a reason that reads as a protocol bug. That
    /// is exactly the mistake the wrong-subtree search made, and it went unnoticed because
    /// nothing compared the pairs.
    ///
    /// The manifest is read with a hand-rolled scan rather than a JSON parser: this crate
    /// has no serde dependency and one small fixed-format file does not justify adding one.
    #[test]
    fn every_fixture_key_pairs_with_its_certificate() {
        let dir = std::path::Path::new(Sgp26VariantO::DIR);
        let manifest = dir.join("PROVENANCE.json");
        if !manifest.exists() {
            // A fixture shipped without the manifest is not an error for a crate
            // consumer; there is simply nothing to cross-check.
            return;
        }
        let raw = std::fs::read_to_string(&manifest).expect("PROVENANCE.json is readable");

        // Pull out each `"file"` / `"pairs_with"` pair, in order. The file is generated
        // and its shape is fixed, so a scan for the two keys is sufficient and fails
        // loudly rather than silently if the shape changes.
        let field = |key: &str, from: usize| -> Option<(String, usize)> {
            let needle = format!("\"{key}\":");
            let at = raw[from..].find(&needle)? + from + needle.len();
            let open = raw[at..].find('"')? + at + 1;
            let close = raw[open..].find('"')? + open;
            Some((raw[open..close].to_owned(), close))
        };

        let mut cursor = 0;
        let mut checked = 0;
        while let Some((file, after_file)) = field("file", cursor) {
            let Some((pairs_with, after_cert)) = field("pairs_with", after_file) else {
                break;
            };
            cursor = after_cert;

            let key_path = dir.join(&file);
            let cert_path = dir.join(&pairs_with);
            assert!(key_path.exists(), "{file} is in the manifest but missing");
            assert!(
                cert_path.exists(),
                "{pairs_with} is in the manifest but missing"
            );

            // `_BRP` names brainpool; anything else in this fixture is P-256.
            let curve = if file.contains("_BRP") {
                CurveKind::BrainpoolP256r1
            } else {
                CurveKind::P256
            };
            let pem = std::fs::read(&key_path).expect("the key file is readable");
            let key = private_key_from_pem(curve, &pem)
                .unwrap_or_else(|e| panic!("{file} must parse as a {curve:?} key: {e}"));
            let der = std::fs::read(&cert_path).expect("the certificate file is readable");
            let cert = Certificate::from_der(&der)
                .unwrap_or_else(|e| panic!("{pairs_with} must parse: {e}"));

            assert_eq!(
                key.public_key().as_ref(),
                cert.public_key().as_ref(),
                "{file} does not pair with {pairs_with} — the fixture would sign with a \
                 key the eUICC cannot verify against that certificate"
            );
            checked += 1;
        }

        assert!(
            checked >= 6,
            "expected the six added BRP and NIST key pairs to be checked, checked {checked}"
        );
    }

    /// The brainpool Variant O material carries everything a BRP sequence needs.
    ///
    /// A BRP `PrepareDownload` has to sign `smdpSigned2` under the key
    /// `CERT_S_SM_DPpb_ECDSA_BRP.der` authenticates, and authenticate the session with the
    /// EUM's. Neither half was in the fixture, so the BRP sequences were scaffolds.
    ///
    /// This asserts the whole set rather than the files' presence, because a file that is
    /// present and does not pair is worse than a missing one: it signs, and the eUICC
    /// rejects the result for a reason that reads as a protocol bug.
    #[test]
    fn the_brainpool_material_carries_the_signing_keys() {
        let brp = Sgp26VariantO::load_curve(CurveKind::BrainpoolP256r1)
            .expect("the brainpool Variant O material must load");
        brp.verify()
            .expect("the brainpool material must be internally consistent");

        assert_eq!(brp.curve, CurveKind::BrainpoolP256r1);
        assert_eq!(brp.curve.sgp26_suffix(), "BRP");

        let eum_key = brp
            .eum_private
            .as_ref()
            .expect("SK_EUM_ECDSA_BRP.pem — without it no BRP session can be authenticated");
        assert_eq!(
            eum_key.public_key().as_ref(),
            brp.eum.public_key().as_ref(),
            "the EUM private key must be the one CERT_EUM_ECDSA_BRP.der certifies"
        );

        let pb_cert = brp
            .dp_pb
            .as_ref()
            .expect("CERT_S_SM_DPpb_ECDSA_BRP.der — the certificate PrepareDownload presents");
        let pb_key = brp
            .dp_pb_private
            .as_ref()
            .expect("SK_S_SM_DPpb_ECDSA_BRP.pem — the key smdpSignature2 is signed with");
        assert_eq!(
            pb_key.public_key().as_ref(),
            pb_cert.public_key().as_ref(),
            "the binding key must match the binding certificate"
        );

        // The certificate must carry the binding role, or a sequence presenting it would
        // be refused by the §4.2.10 #08 check the suite itself asserts.
        assert_eq!(
            pb_cert.indicates_dp_pb_role(),
            Some(true),
            "CERT_S_SM_DPpb_ECDSA_BRP.der must indicate id-rspRole-dp-pb"
        );

        // And the two curves must be genuinely different material, not one set renamed —
        // the distinction the whole BRP group exists to test.
        let nist = Sgp26VariantO::load_curve(CurveKind::P256).unwrap();
        assert_ne!(
            brp.euicc.public_key().as_ref(),
            nist.euicc.public_key().as_ref(),
            "the BRP and NIST material must not be the same certificate"
        );
    }

    #[test]
    fn the_published_chain_is_internally_consistent() {
        let v = Sgp26VariantO::load().unwrap();
        v.verify().expect("SGP.26 Variant O chain must verify");
    }

    /// The EID in the certificate is `#EID1` from SGP.23 Annex A.
    ///
    /// This is the assertion the fabricated constant could not make: the value
    /// comes out of the published certificate, and SGP.23 Annex A independently
    /// gives the same octets.
    #[test]
    fn the_euicc_certificate_carries_the_spec_eid() {
        let v = Sgp26VariantO::load().unwrap();

        // The certificate states it as 32 ASCII digits.
        assert_eq!(
            v.eid_ascii().unwrap(),
            b"89049032123451234512345678901235",
            "the certificate's serialNumber is the ASCII EID"
        );

        // SGP.23 Annex A gives `#EID1` as these 16 octets.
        assert_eq!(
            v.eid().unwrap(),
            vec![
                0x89, 0x04, 0x90, 0x32, 0x12, 0x34, 0x51, 0x23, 0x45, 0x12, 0x34, 0x56, 0x78, 0x90,
                0x12, 0x35
            ],
            "SGP.23 Annex A defines #EID1 as this octet string"
        );
    }

    /// The two EID encodings are the same identifier, not two values.
    ///
    /// A sequence that compared the octet form against the ASCII one would find
    /// them unequal and report a conformance failure on a conforming eUICC, so
    /// the relationship is asserted rather than assumed.
    #[test]
    fn the_ascii_and_octet_eid_are_the_same_identifier() {
        let v = Sgp26VariantO::load().unwrap();
        let ascii = v.eid_ascii().unwrap();
        let octets = v.eid().unwrap();
        assert_eq!(octets.len() * 2, ascii.len());
        let round_tripped: Vec<u8> = octets
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        assert_eq!(round_tripped, ascii);
    }

    /// The eIM public key is a real, usable P-256 point.
    ///
    /// A zeroed or truncated key would still "load" as bytes; this checks it is
    /// a valid curve point, which is what makes it usable for verification.
    #[test]
    fn the_eim_public_key_is_a_valid_point() {
        let v = Sgp26VariantO::load().unwrap();
        assert_eq!(
            v.eim_public.as_ref().len(),
            65,
            "uncompressed P-256 point is 65 bytes"
        );
        assert_eq!(v.eim_public.as_ref()[0], 0x04, "uncompressed point prefix");
    }

    #[test]
    fn base64_round_trips_known_values() {
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert_eq!(base64_decode("TQ==").unwrap(), b"M");
        assert!(base64_decode("!!!!").is_err());
    }

    /// A missing fixture is an error, not a panic.
    ///
    /// The loopback falls back to `TestPki` on `Err`, so this path has to be
    /// reachable rather than aborting the process.
    #[test]
    fn a_missing_fixture_is_an_error_not_a_panic() {
        let r = Sgp26VariantO::load_from("/nonexistent/sgp26");
        assert!(r.is_err());
    }

    /// `der_length` covers all three encodings it claims to.
    #[test]
    fn der_length_encodes_each_width() {
        assert_eq!(der_length(0x7F).unwrap(), vec![0x7F]);
        assert_eq!(der_length(0x80).unwrap(), vec![0x81, 0x80]);
        assert_eq!(der_length(0x1234).unwrap(), vec![0x82, 0x12, 0x34]);
    }
}
