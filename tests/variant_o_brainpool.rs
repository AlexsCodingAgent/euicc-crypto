//! The SGP.26 Variant O brainpoolP256r1 test PKI, loaded through the real
//! loader and exercised against the published certificates.
//!
//! These are the fixtures the SGP.33-1 "BRP" test sequences need. Until the
//! curve became selectable, `fixtures/sgp26/variant-o/` held only the `_NIST`
//! files and every BRP case was blocked on capability rather than on writing.
//!
//! The point of this file is not that brainpool arithmetic works in isolation
//! (the unit tests in `src/ecdsa.rs` cover that). It is that the *GSMA-published*
//! brainpool material loads, that the private keys match the published
//! certificates, and that a signature made with a published private key
//! verifies under the published certificate's public key. A curve
//! implementation that is subtly wrong still passes self-consistent tests; it
//! does not survive agreement with an external key pair.

use euicc_crypto::ecdsa::CurveKind;
use euicc_crypto::sgp26::Sgp26VariantO;

const BRP: CurveKind = CurveKind::BrainpoolP256r1;

#[test]
fn brainpool_variant_o_loads() {
    let m = Sgp26VariantO::load_curve(BRP).expect("brainpool Variant O must load");
    assert_eq!(m.curve, BRP);
    assert_eq!(m.ci.curve(), BRP);
    assert_eq!(m.eum.curve(), BRP);
    assert_eq!(m.euicc.curve(), BRP);
    assert_eq!(m.euicc_public.curve(), BRP);
}

#[test]
fn the_brainpool_certificates_are_on_the_brainpool_curve() {
    // Parsing these at all is the assertion: the x509 reader takes the curve
    // from the certificate's namedCurve OID and rejects a mismatch, so a
    // brainpool certificate read as P-256 fails rather than silently
    // yielding a key that cannot verify anything.
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    for (name, cert) in [
        ("CERT_CI_ECDSA_BRP.der", &m.ci),
        ("CERT_EUM_ECDSA_BRP.der", &m.eum),
        ("CERT_EUICC_ECDSA_BRP.der", &m.euicc),
    ] {
        assert_eq!(cert.curve(), BRP, "{name} is not on brainpoolP256r1");
    }
}

#[test]
fn the_brainpool_nist_and_brp_sets_are_different_keys() {
    // Guards against the loader reading the same files twice under two
    // labels, which would make the BRP tests silently re-test NIST.
    let nist = Sgp26VariantO::load_curve(CurveKind::P256).unwrap();
    let brp = Sgp26VariantO::load_curve(BRP).unwrap();
    assert_ne!(
        nist.euicc_public.as_bytes(),
        brp.euicc_public.as_bytes(),
        "the NIST and BRP eUICC keys must differ"
    );
    assert_ne!(
        nist.eim_public.as_bytes(),
        brp.eim_public.as_bytes(),
        "the NIST and BRP eIM signing keys must differ"
    );
}

#[test]
fn the_brainpool_euicc_private_key_matches_its_certificate() {
    // The harness plays the eUICC's role and signs the authentication
    // response. If the private key did not match the certificate, every
    // signature would be rejected and the failure would look like a protocol
    // bug rather than a fixture bug.
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    assert_eq!(
        m.euicc_private.public_key().as_ref(),
        m.euicc.public_key().as_ref(),
        "SK_EUICC_ECDSA_BRP does not match CERT_EUICC_ECDSA_BRP"
    );
}

#[test]
fn the_brainpool_eim_private_key_matches_its_public_key() {
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    assert_eq!(
        m.eim_private.public_key().as_ref(),
        m.eim_public.as_ref(),
        "SK_S_EIMsign_ECDSA_BRP does not match PK_S_EIMsign_ECDSA_BRP"
    );
}

#[test]
fn a_brainpool_signature_under_the_published_key_verifies() {
    // The load-bearing test. Self-consistency is not enough: this signs with
    // the published GSMA private key and verifies under the published GSMA
    // public key, so an implementation that disagrees with the standard fails
    // here even though it would pass every round-trip test against itself.
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    let msg = b"SGP.33-1 BRP interop";
    let sig = m.euicc_private.sign(msg).unwrap();
    assert_eq!(sig.curve(), BRP);
    assert_eq!(sig.as_ref().len(), 64, "raw r||s on the wire");
    m.euicc.public_key().verify(msg, sig.as_ref()).unwrap();
}

#[test]
fn a_brainpool_eim_signature_verifies_under_the_published_eim_key() {
    // SGP.32 3.3.1: the eUICC verifies the eUICC Package signature against
    // EIM_PUBLIC_KEY_DATA_PK. This is that exchange, on brainpool.
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    let package = b"euiccPackage";
    let sig = m.eim_private.sign(package).unwrap();
    m.eim_public.verify(package, sig.as_ref()).unwrap();
}

#[test]
fn the_nist_set_still_loads_unchanged() {
    // The curve work must not have disturbed the existing NIST path, which
    // every other test in the suite depends on.
    let m = Sgp26VariantO::load().expect("NIST Variant O must still load");
    assert_eq!(m.curve, CurveKind::P256);
    assert_eq!(
        m.euicc_private.public_key().as_ref(),
        m.euicc.public_key().as_ref()
    );
}

#[test]
fn a_brainpool_signature_does_not_verify_under_the_nist_key() {
    // Cross-curve isolation, using the real fixtures rather than generated
    // keys. Both are 64-byte r||s and both parse; only the arithmetic differs.
    let nist = Sgp26VariantO::load_curve(CurveKind::P256).unwrap();
    let brp = Sgp26VariantO::load_curve(BRP).unwrap();
    let sig = brp.euicc_private.sign(b"message").unwrap();
    assert!(nist
        .euicc
        .public_key()
        .verify(b"message", sig.as_ref())
        .is_err());
}

#[test]
fn the_brainpool_chain_is_internally_consistent() {
    // Full material check, same as the NIST one: certificate chain, key
    // agreement, EID, and curve.
    let m = Sgp26VariantO::load_curve(BRP).unwrap();
    m.verify()
        .expect("brainpool Variant O material must be consistent");
}
