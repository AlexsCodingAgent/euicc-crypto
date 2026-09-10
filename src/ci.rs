//! The CI key set an eUICC trusts, and selection of the key to use for
//! verifying a server certificate.
//!
//! SGP.22 §5.7.5: `EUICCInfo1` advertises `euiccCiPKIdListForVerification`, a
//! list of key identifiers for the CI public keys the eUICC will accept. When a
//! server presents `euiccCiPKIdToBeUsed`, the eUICC must select the matching
//! key and verify the server certificate's signature against it.
//!
//! This module models that selection. It is deliberately explicit about the
//! failure modes: an identifier that matches nothing, an identifier that
//! matches but whose key fails verification, and an empty list are distinct
//! outcomes and must not be collapsed into one error.

use crate::ecdsa::PublicKey;
use crate::x509::Certificate;
use crate::Error;

/// A CI public key together with the identifier the eUICC advertises for it.
#[derive(Debug, Clone)]
pub struct CiKey {
    /// The key identifier, as it appears in `EUICCInfo1`.
    pub id: Vec<u8>,
    /// The public key.
    pub key: PublicKey,
}

/// The set of CI keys an eUICC trusts for verification.
#[derive(Debug, Clone, Default)]
pub struct CiKeySet {
    keys: Vec<CiKey>,
}

/// Why a server certificate could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiSelection {
    /// No CI key matched the requested identifier.
    NoMatch,
    /// A key matched the identifier but did not verify the certificate.
    SignatureInvalid,
    /// The requested identifier was empty, so the server did not name a key.
    Unspecified,
}

impl std::fmt::Display for CiSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiSelection::NoMatch => write!(f, "no CI key matches the requested identifier"),
            CiSelection::SignatureInvalid => {
                write!(f, "the matching CI key did not verify the certificate")
            }
            CiSelection::Unspecified => write!(f, "the server did not specify a CI key identifier"),
        }
    }
}

impl CiKeySet {
    /// An empty key set.
    pub fn new() -> Self {
        CiKeySet { keys: Vec::new() }
    }

    /// Add a key. Identifiers are not required to be unique; a later key with a
    /// duplicate identifier is still tried.
    pub fn add(&mut self, id: Vec<u8>, key: PublicKey) {
        self.keys.push(CiKey { id, key });
    }

    /// Number of keys in the set.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The identifiers in the set, in insertion order.
    pub fn identifiers(&self) -> Vec<&[u8]> {
        self.keys.iter().map(|k| k.id.as_slice()).collect()
    }

    /// Whether any key in the set carries `id`.
    pub fn contains(&self, id: &[u8]) -> bool {
        self.keys.iter().any(|k| k.id == id)
    }

    /// Verify `certificate` using the key named by `requested_id`.
    ///
    /// SGP.22 allows the identifier to be truncated, so a request matches a key
    /// when either is a prefix of the other. Every matching key is tried, and
    /// the certificate is accepted if any of them verifies it — a card holding
    /// two keys under one truncated identifier must not fail on the first.
    pub fn verify_server_certificate(
        &self,
        requested_id: &[u8],
        certificate: &Certificate,
    ) -> std::result::Result<&CiKey, CiSelection> {
        if requested_id.is_empty() {
            return Err(CiSelection::Unspecified);
        }
        let candidates: Vec<&CiKey> = self
            .keys
            .iter()
            .filter(|k| ids_match(&k.id, requested_id))
            .collect();
        if candidates.is_empty() {
            return Err(CiSelection::NoMatch);
        }
        for candidate in &candidates {
            if certificate.verify_signed_by_key(&candidate.key).is_ok() {
                return Ok(candidate);
            }
        }
        Err(CiSelection::SignatureInvalid)
    }
}

/// Whether a requested identifier matches a stored identifier.
///
/// SGP.22 permits the requested identifier to be the full identifier or a
/// truncation of it, and the CI key identifier to be a truncation of the full
/// hash, so either may be the shorter one.
fn ids_match(stored: &[u8], requested: &[u8]) -> bool {
    // An empty identifier on either side is not a match: there is nothing to
    // compare, and treating it as one would let an empty request select the
    // first key in the set. `verify_server_certificate` rejects an empty
    // request before reaching here, so this is defence in depth.
    if stored.is_empty() || requested.is_empty() {
        return false;
    }
    let n = stored.len().min(requested.len());
    stored[..n] == requested[..n]
}

/// Turn a selection failure into a crate error, for callers that do not need
/// to distinguish the reason.
impl From<CiSelection> for Error {
    fn from(s: CiSelection) -> Self {
        Error::Certificate(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testpki::TestPki;

    fn set_from(pki: &TestPki) -> CiKeySet {
        let mut set = CiKeySet::new();
        set.add(pki.ci_pk_id().to_vec(), pki.ci_public_key());
        set
    }

    #[test]
    fn accepts_a_certificate_signed_by_the_named_key() {
        let pki = TestPki::new();
        let set = set_from(&pki);
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let chosen = set
            .verify_server_certificate(pki.ci_pk_id(), &cert)
            .expect("the CI key must accept the certificate it issued");
        assert_eq!(chosen.id, pki.ci_pk_id());
    }

    #[test]
    fn reports_no_match_for_an_unknown_identifier() {
        let pki = TestPki::new();
        let set = set_from(&pki);
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        assert_eq!(
            set.verify_server_certificate(&[0xde, 0xad, 0xbe, 0xef], &cert)
                .unwrap_err(),
            CiSelection::NoMatch
        );
    }

    #[test]
    fn reports_unspecified_for_an_empty_identifier() {
        let pki = TestPki::new();
        let set = set_from(&pki);
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        assert_eq!(
            set.verify_server_certificate(&[], &cert).unwrap_err(),
            CiSelection::Unspecified
        );
    }

    #[test]
    fn reports_invalid_signature_when_the_key_does_not_match_the_certificate() {
        let pki = TestPki::new();
        let other = TestPki::new();
        // Advertise the RIGHT identifier but bind it to the WRONG key, which is
        // the case a naive implementation reports as "no match".
        let mut set = CiKeySet::new();
        set.add(pki.ci_pk_id().to_vec(), other.ci_public_key());
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        assert_eq!(
            set.verify_server_certificate(pki.ci_pk_id(), &cert)
                .unwrap_err(),
            CiSelection::SignatureInvalid
        );
    }

    #[test]
    fn matches_a_truncated_identifier() {
        let pki = TestPki::new();
        let set = set_from(&pki);
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        let truncated = &pki.ci_pk_id()[..8];
        set.verify_server_certificate(truncated, &cert)
            .expect("a truncated identifier must still match");
    }

    #[test]
    fn an_empty_set_matches_nothing() {
        let pki = TestPki::new();
        let set = CiKeySet::new();
        assert!(set.is_empty());
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        assert_eq!(
            set.verify_server_certificate(pki.ci_pk_id(), &cert)
                .unwrap_err(),
            CiSelection::NoMatch
        );
    }

    #[test]
    fn tries_every_key_sharing_an_identifier() {
        let pki = TestPki::new();
        let other = TestPki::new();
        let mut set = CiKeySet::new();
        // Same identifier bound to two keys; only the second issued the cert.
        set.add(pki.ci_pk_id().to_vec(), other.ci_public_key());
        set.add(pki.ci_pk_id().to_vec(), pki.ci_public_key());
        assert_eq!(set.len(), 2);
        let cert = Certificate::from_der(pki.eum_cert_der()).unwrap();
        set.verify_server_certificate(pki.ci_pk_id(), &cert)
            .expect("the second key sharing the identifier must be tried");
    }

    #[test]
    fn identifiers_are_reported_in_insertion_order() {
        let pki = TestPki::new();
        let set = set_from(&pki);
        assert_eq!(set.identifiers(), vec![pki.ci_pk_id()]);
        assert!(set.contains(pki.ci_pk_id()));
        assert!(!set.contains(&[0x00]));
    }

    #[test]
    fn prefix_matching_does_not_match_on_zero_length_overlap() {
        assert!(!ids_match(&[], &[]));
        assert!(!super::ids_match(&[1, 2], &[]));
        assert!(super::ids_match(&[1, 2, 3], &[1, 2]));
        assert!(super::ids_match(&[1, 2], &[1, 2, 3]));
        assert!(!super::ids_match(&[1, 2], &[1, 3]));
    }
}
