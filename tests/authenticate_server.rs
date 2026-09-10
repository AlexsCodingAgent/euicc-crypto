//! End-to-end proof that the crypto ladder supports a real SGP.22
//! `AuthenticateServer` exchange.
//!
//! This exercises the primitives together in the shape the protocol needs,
//! rather than in isolation. It exists because per-module unit tests passing
//! does not demonstrate that the modules compose into a working handshake —
//! the tag and length bugs found earlier were all in code that had passing
//! tests at the point they were written.
//!
//! The exchange modelled here:
//!
//! 1. The SM-DP+ builds `ServerSigned1` and signs it with its own key,
//!    producing `serverSignature1`.
//! 2. The eUICC receives the request, selects the CI key named by
//!    `euiccCiPKIdToBeUsed`, and verifies the server certificate against it.
//! 3. The eUICC verifies `serverSignature1` over the received `ServerSigned1`
//!    bytes, using the public key from the now-trusted server certificate.
//! 4. The eUICC builds `EuiccSigned1` and signs it with the eUICC key,
//!    producing `euiccSignature1`.
//! 5. The SM-DP+ verifies `euiccSignature1` using the eUICC certificate.
//!
//! Every step is a real cryptographic operation over real encoded bytes.

use euicc_crypto::ci::{CiKeySet, CiSelection};
use euicc_crypto::ecdsa::KeyPair;
use euicc_crypto::testpki::TestPki;
use euicc_crypto::wire::{encode_signature, parse_signature};
use euicc_crypto::x509::Certificate;

/// Minimal DER TLV helpers, standing in for the IPAd's own codec. The point is
/// that the crypto operates on bytes the protocol layer produced.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        out.push(0x81);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Multi-byte tag form, for the context tags SGP.22 uses (e.g. BF22).
fn tlv2(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = vec![(tag >> 8) as u8, (tag & 0xff) as u8];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else {
        out.push(0x81);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    out
}

/// Build the `ServerSigned1` structure and return `(encoded, bytes_signed)`.
///
/// In SGP.22 the signature is over the DER encoding of ServerSigned1.
fn server_signed1(
    transaction_id: &[u8],
    euicc_challenge: &[u8; 16],
    server_address: &str,
    server_challenge: &[u8; 16],
) -> Vec<u8> {
    let t = tlv(0x80, transaction_id); // [0] TransactionId
    let c = tlv(0x81, euicc_challenge); // [1] Octet16
    let a = tlv(0x83, server_address.as_bytes()); // [3] UTF8String
    let s = tlv(0x84, server_challenge); // [4] Octet16
    let body: Vec<u8> = [t, c, a, s].concat();
    tlv(0x30, &body) // ServerSigned1 ::= SEQUENCE
}

#[test]
fn a_full_authenticate_server_exchange_verifies() {
    // --- setup: a test PKI and a CI key set advertising the CI identifier ---
    let pki = TestPki::new();
    let mut ci_keys = CiKeySet::new();
    ci_keys.add(pki.ci_pk_id().to_vec(), pki.ci_public_key());

    // The server (SM-DP+) has its own key pair and a certificate issued by
    // the CI, which is what `serverCertificate` carries.
    let server = KeyPair::generate().unwrap();
    let server_cert_der = pki.issue_for(&server, "smdp");

    let transaction_id = [0x01u8; 16];
    let euicc_challenge = [0xAAu8; 16];
    let server_challenge = [0xBBu8; 16];
    let server_address = "smdp.example.com";

    // --- step 1: the server signs ServerSigned1 ---------------------------
    let server_signed1 = server_signed1(
        &transaction_id,
        &euicc_challenge,
        server_address,
        &server_challenge,
    );
    let server_signature1 = server.sign(&server_signed1).unwrap();
    // On the wire this is a 5F37 OCTET STRING, not bare r||s bytes.
    let server_signature1_field = encode_signature(&server_signature1);

    // --- step 2: the eUICC selects the CI key and trusts the server cert --
    let server_cert = Certificate::from_der(&server_cert_der).unwrap();
    let chosen = ci_keys
        .verify_server_certificate(pki.ci_pk_id(), &server_cert)
        .expect("the CI key must accept a certificate it issued");
    assert_eq!(chosen.id, pki.ci_pk_id());

    // --- step 3: the eUICC parses the 5F37 field and verifies it ----------
    let recovered = parse_signature(&server_signature1_field).expect("the 5F37 field must parse");
    assert_eq!(
        recovered, server_signature1,
        "the round trip must preserve it"
    );
    server_cert
        .public_key()
        .verify(&server_signed1, recovered.as_ref())
        .expect("serverSignature1 must verify under the server certificate key");

    // --- step 4: the eUICC signs EuiccSigned1 ----------------------------
    // EuiccSigned1 repeats the transaction id, address and challenges and adds
    // euiccInfo2 and ctxParams1; the signature is over its DER encoding.
    let euicc_info2 = tlv(0x30, &tlv(0x80, &[0x03, 0x00, 0x00]));
    let ctx_params1 = tlv(0xA0, &tlv(0x80, b"device-info"));
    let euicc_signed1 = tlv(
        0x30,
        &[
            tlv(0x80, &transaction_id),
            tlv(0x83, server_address.as_bytes()),
            tlv(0x84, &server_challenge),
            tlv2(0xBF22, &euicc_info2),
            ctx_params1,
        ]
        .concat(),
    );
    let euicc_signature1 = pki.euicc.sign(&euicc_signed1).unwrap();
    let euicc_signature1_field = encode_signature(&euicc_signature1);

    // --- step 5: the server verifies euiccSignature1 ---------------------
    let euicc_cert = Certificate::from_der(pki.euicc_cert_der()).unwrap();
    let recovered_euicc = parse_signature(&euicc_signature1_field)
        .expect("the euiccSignature1 5F37 field must parse");
    euicc_cert
        .public_key()
        .verify(&euicc_signed1, recovered_euicc.as_ref())
        .expect("euiccSignature1 must verify under the eUICC certificate key");

    // The signature is a raw 64-byte r||s value, which is what the 5F37 field
    // carries.
    assert_eq!(euicc_signature1.as_ref().len(), 64);
    assert_eq!(server_signature1.as_ref().len(), 64);
    // Both fields carry the APPLICATION 55 tag, so they are two bytes longer
    // than the raw signature plus one length byte.
    assert_eq!(&euicc_signature1_field[..2], &[0x5f, 0x37]);
    assert_eq!(&server_signature1_field[..2], &[0x5f, 0x37]);
    assert_eq!(euicc_signature1_field.len(), 67);
}

#[test]
fn a_tampered_5f37_field_is_rejected_after_parsing() {
    // The wrapper must not provide any protection of its own: flipping a byte
    // inside the signature still has to fail verification.
    let pki = TestPki::new();
    let signed = tlv(0x30, &tlv(0x80, &[0x07; 16]));
    let sig = pki.euicc.sign(&signed).unwrap();
    let mut field = encode_signature(&sig);
    let last = field.len() - 1;
    field[last] ^= 0x01;

    let recovered = parse_signature(&field).unwrap();
    assert_ne!(recovered, sig);
    let cert = Certificate::from_der(pki.euicc_cert_der()).unwrap();
    assert!(
        cert.public_key()
            .verify(&signed, recovered.as_ref())
            .is_err(),
        "a tampered signature must not verify merely because it parses"
    );
}

#[test]
fn a_signature_under_the_wrong_tag_does_not_parse_as_a_signature() {
    // Guards against a call site reading a universal OCTET STRING where the
    // APPLICATION 55 tag is required.
    let kp = KeyPair::generate().unwrap();
    let sig = kp.sign(b"x").unwrap();
    let mut bare = vec![0x04, 64];
    bare.extend_from_slice(sig.as_ref());
    assert!(parse_signature(&bare).is_err());
}

#[test]
fn the_exchange_fails_when_the_server_certificate_is_not_trusted() {
    let pki = TestPki::new();
    let rogue = TestPki::new();
    // The eUICC trusts the real CI, but the server presents a certificate from
    // an unrelated PKI under the real identifier.
    let mut ci_keys = CiKeySet::new();
    ci_keys.add(pki.ci_pk_id().to_vec(), pki.ci_public_key());

    let server = KeyPair::generate().unwrap();
    let rogue_cert_der = rogue.issue_for(&server, "rogue");
    let rogue_cert = Certificate::from_der(&rogue_cert_der).unwrap();

    let outcome = ci_keys.verify_server_certificate(pki.ci_pk_id(), &rogue_cert);
    assert_eq!(outcome.unwrap_err(), CiSelection::SignatureInvalid);
}

#[test]
fn a_tampered_server_signed1_does_not_verify() {
    let pki = TestPki::new();
    let server = KeyPair::generate().unwrap();
    let cert_der = pki.issue_for(&server, "smdp");
    let cert = Certificate::from_der(&cert_der).unwrap();

    let signed = server_signed1(&[0x01; 16], &[0xAA; 16], "smdp.example.com", &[0xBB; 16]);
    let sig = server.sign(&signed).unwrap();

    // Flip a byte in the transaction id inside the signed structure.
    let mut tampered = signed.clone();
    tampered[3] ^= 0x01;
    assert!(
        cert.public_key().verify(&tampered, sig.as_ref()).is_err(),
        "a modified ServerSigned1 must not verify"
    );
}

#[test]
fn an_euicc_signature_does_not_verify_under_another_cards_certificate() {
    let pki = TestPki::new();
    let other = TestPki::new();
    let signed = tlv(0x30, &tlv(0x80, &[0x01; 16]));
    let sig = pki.euicc.sign(&signed).unwrap();
    let other_cert = Certificate::from_der(other.euicc_cert_der()).unwrap();
    assert!(
        other_cert
            .public_key()
            .verify(&signed, sig.as_ref())
            .is_err(),
        "another card's certificate must not verify this signature"
    );
}
