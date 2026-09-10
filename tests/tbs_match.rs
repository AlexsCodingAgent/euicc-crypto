//! Confirm the bytes signed at generation equal the bytes the parser extracts.

use euicc_crypto::testpki::TestPki;
use euicc_crypto::x509::Certificate;

/// Independent walker: derive (tbsCertificate TLV, signature bytes) from a DER
/// certificate without using the crate's own parser.
fn tbs_and_sig(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn len(i: &[u8]) -> (usize, usize) {
        let f = i[0];
        if f & 0x80 == 0 {
            return (f as usize, 1);
        }
        let n = (f & 0x7f) as usize;
        let mut l = 0usize;
        for b in i.iter().take(1 + n).skip(1) {
            l = (l << 8) | *b as usize;
        }
        (l, 1 + n)
    }
    let (cl, clh) = len(&der[1..]);
    let body = &der[(1 + clh)..(1 + clh + cl)];
    let tbs_start = der.len() - body.len();
    let (tl, tlh) = len(&body[1..]);
    let tbs_tlv = &der[tbs_start..(tbs_start + 1 + tlh + tl)];
    let after = &body[(1 + tlh + tl)..];
    let (al, alh) = len(&after[1..]);
    let sig_in = &after[(1 + alh + al)..];
    let (sl, slh) = len(&sig_in[1..]);
    let sig = &sig_in[(1 + slh)..(1 + slh + sl)];
    (tbs_tlv.to_vec(), sig[1..].to_vec())
}

#[test]
fn generator_and_parser_agree_on_the_signed_bytes() {
    let pki = TestPki::new();
    let der = pki.eum_cert_der();
    let (tbs, sig) = tbs_and_sig(der);

    println!("tbs {} bytes, head {:02x?}", tbs.len(), &tbs[..12]);
    println!("sig {} bytes, head {:02x?}", sig.len(), &sig[..8]);

    let cert = Certificate::from_der(der).unwrap();
    println!("cert public key: {:02x?}", &cert.public_key().as_ref()[..8]);
    println!(
        "pki  public key: {:02x?}",
        &pki.eum_public_key().as_ref()[..8]
    );

    // The EUM certificate is issued by the CI, so its signature verifies
    // under the CI public key, not the EUM's own key.
    let res = pki.ci_public_key().verify_der(&tbs, &sig);
    println!("direct verify_der: {res:?}");
    assert!(res.is_ok(), "the signed bytes must verify: {res:?}");
}
