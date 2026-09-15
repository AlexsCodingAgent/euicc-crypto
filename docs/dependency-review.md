# Dependency review (second pass): adopt only what earns it

Scope: `euicc-crypto`. The bar for adopting a dependency is that it does at
least one of:

  (a) removes code that is risky to own,
  (b) fixes a known defect in the hand-rolled version, or
  (c) adds a capability the hand-rolled version lacks.

"It exists on crates.io" is not a reason. Working hand-rolled code is not
replaced for its own sake, and every candidate below was compiled and run on
this machine before being judged.

This supersedes the first pass, which was written on a false premise: it
recorded that `p256`, `ecdsa`, `elliptic-curve`, `aes-gcm` and `der_derive`
were unobtainable because "crates.io returns 403". That was wrong. Only the
`crates.io` web/API host is blocked; `index.crates.io` and
`static.crates.io` (which is where `.crate` files are actually served) both
return 200, so cargo fetches crates normally. All of those crates download,
build and pass tests here.

## Adopted

### `p256 0.13.2` + `ecdsa 0.16.9` — ADOPTED, replaces `ring` for ECC

This is not a like-for-like swap, and the reason is specific.

SGP.22 carries signatures as a **raw 64-byte `r‖s` concatenation**. `ring`
speaks ASN.1 DER and does not expose the raw form, so `src/ecdsa.rs` carries a
hand-written DER<->raw conversion in both directions: `der_to_raw`,
`raw_to_der`, and a `trim_leading_zeroes` helper. Those functions are, by the
crate's own module documentation, "the most bug-prone part of" the file, and
they exist only because of an encoding mismatch between the library and the
protocol.

`p256` emits the raw form natively. Verified:

    signature is 64 bytes (raw r||s)
    ECDSA P-256 sign/verify: ok
    no DER->raw conversion needed: true

So adopting `p256` deletes a known bug-prone conversion rather than
transliterating it. That satisfies criterion (a) squarely.

ECDH likewise works and needs no conversion:

    ECDH secrets agree: true

Replaces: `ring` for ECDSA signing/verification and ECDH.
Hand-rolled code deleted: the DER<->raw conversion path in `src/ecdsa.rs`.

### `bp256 0.14.0` (+ `p256` bumped to `0.14.0`) — ADOPTED, adds brainpoolP256r1

Criterion (c): brainpoolP256r1 is a capability the crate did not have, and it is
the blocker on the SGP.33-1 "BRP" test sequences and the brainpool half of the
SGP.26 Variant O test PKI.

**Why the version bump and not the version that matched.** `bp256` releases
before 0.14.0 do pair with the old `ecdsa 0.16` generation, which would have
made this a smaller diff. They are unusable:

  * `bp256 0.6.1` gates `AffinePoint`, `ProjectivePoint` and `Scalar` behind a
    feature named `wip-arithmetic-do-not-use`. Without it `BrainpoolP256r1`
    implements only `Curve`, `PrimeCurve` and `PointCompression`: a curve
    *identity*, with no arithmetic. It cannot sign or verify. Enabling a feature
    called `do-not-use` in a conformance suite is not defensible.
  * `bp256 0.14.0` (2026-09-10) graduates that to a stable `arithmetic` feature
    and needs `elliptic-curve 0.14.1` / `ecdsa 0.17`, the same generation as
    `p256 0.14.0`.

So both curves move together and the tree carries **one** `ecdsa` and **one**
`elliptic-curve`. That is the reason for the `p256` bump: the alternative was
two coexisting `ecdsa` versions, which means distinct types for
`p256::ecdsa::Signature` and `bp256::r1::ecdsa::Signature` and no way to write
curve-agnostic code over both. `cargo tree -p bp256` confirms a single
`ecdsa v0.17.0` and `elliptic-curve v0.14.1` shared with `p256`.

**Verified against the published GSMA material, not just round-trips.**
Self-consistent tests pass for a curve implementation that is subtly wrong. The
acceptance test signs with a published SGP.26 Variant O brainpool private key
and verifies under the published certificate's public key:

    the_brainpool_euicc_private_key_matches_its_certificate ... ok
    a_brainpool_signature_under_the_published_key_verifies   ... ok
    a_brainpool_eim_signature_verifies_under_the_published_eim_key ... ok

The `PK_*.pem` EC PARAMETERS block decodes to OID `1.3.36.3.3.2.8.1.1.7` =
brainpoolP256r1, and the key derived from the SEC1 `SK_` file matches the
certificate byte-for-byte. Signatures are **64-byte raw `r‖s` on both curves**,
so the property that justified `p256` in the first place holds for `bp256` too
and no DER conversion appears for either.

**Curve selection is explicit, and the curve comes from the certificate.**
SGP.22's wire format carries no algorithm identifier next to a signature, so the
curve is implied by whoever will verify. Rather than default it, the curve is
read from the certificate's `namedCurve` OID in `x509.rs` and carried through
`CurveKind`. A key loaded on the wrong curve fails at parse time rather than
producing a key that quietly cannot verify anything.

Added: `CurveKind`, brainpool support in `src/ecdsa.rs`, curve-aware SGP.26
loading (`Sgp26VariantO::load_curve`), `Certificate::curve()`.
Not changed: the P-256 API keeps its exact signatures, so no existing caller
needed editing beyond threading the curve where it is genuinely ambiguous.

### `x509-cert 0.2.5` — ADOPTED, replaces the hand-rolled certificate layer

Criterion (b): the hand-rolled certificate code had **four real bugs**, all
found only because tests failed, all in DER handling and parsing:

  1. the serial number INTEGER was padded after its TLV length was written, so
     the declared length was one byte short
  2. subjectPublicKeyInfo was selected by shape, which matched the issuer or
     subject Name instead; it had to be selected by field position
  3. the signed tbsCertificate slice was offset by the value length rather than
     the TLV length, so verification read the wrong bytes
  4. certificate signatures are DER while the wire helper expected raw `r‖s`

Independently checked: `x509-cert` parses the certificates this crate
generates, including the 9-byte serial with its leading zero that broke bug 1:

    parsed: 315 bytes
      serial: SerialNumber { inner: Int { ... [0, 173, 101, ...] } }
      issuer: "CN=SGP.33 TEST ONLY eum"
      tbs re-encodes to 222 bytes

Its `CertificateBuilder` also replaces the hand-written certificate issuance in
`src/testpki.rs`, which currently assembles X.509 v3 structures by hand.

Replaces: the parsing and issuance halves of `src/x509.rs` and
`src/testpki.rs`.
Not replaced: `Certificate::verify_signed_by` keeps its current meaning (see
the note on behaviour below).

### `aes-gcm 0.10.3` — ADOPTED, replaces `ring` for AES-GCM

Small, uncontroversial: same primitive, one fewer `ring` dependency, and it
removes the last reason to keep `ring` if ECC has already moved. The existing
NIST GCM test cases in `src/aead.rs` transfer unchanged and will be the
acceptance test.

### `cbc 0.1.2`, `aes 0.8.4`, `cmac 0.7.2` — ADOPTED, for BSP secure messaging

Criterion (c): BSP uses AES-CBC-128 for encryption and AES-CMAC-128 for its
C-MAC (SGP.22 Table 4c), and neither mode was available. GCM cannot stand in
for CBC, and HMAC is not a cipher-based MAC, so these are missing capabilities
rather than alternatives to working code.

The cost is smaller than it looks: `aes` and `cipher` were **already in the
tree** as `aes-gcm`'s own dependencies, at exactly the versions adopted here.
Only `cbc` and `cmac` are new, both from the same RustCrypto family and built
against the already-present `aes` and `cipher`. Verified before adoption:

    NIST SP 800-38A F.2.1 (CBC-AES128): reproduced
    FIPS-197 AES-128 single block:      reproduced
    NIST SP 800-38B D.1 (AES-128 CMAC): all three examples, incl. empty message

The single-block AES-128 vector is not incidental: BSP's ICV rule is
`AES-S-ENC(block number)`, so the raw block cipher is used directly and not only
through the CBC wrapper.

`ring` still has no CBC module in 0.17, so it could not have served here.

## Rejected

### `der 0.7.10` — REJECTED, wrong tool for this protocol

Re-tested now that it is obtainable, including with the `derive` feature and
`der_derive` in the tree. The limitation is real and unrelated to
availability: `TagNumber` wraps a `u8` with `MAX = 30`, and both the const
constructor and `TryFrom<u8>` reject anything larger. Every SGP.22/SGP.32
command tag is in the 32..56 range, which is precisely why they use the
two-byte form:

    BF2E GetEUICCChallenge   46
    BF21 PrepareDownload     33
    BF38 AuthenticateServer  56
    5F37 signature field     55

`der` therefore cannot encode or decode a single SGP.22 command tag. It is a
correct and well-built crate for X.509/PKCS structures, which is what it is
for; the SGP.22 command tag space is simply outside its model.

Note that `x509-cert` depends on `der` internally and that is fine: it uses it
for the structures `der` does model. The rejection above applies only to using
`der` to encode SGP.22 command TLVs.

### `rasn 0.28` — REJECTED for now

`rasn` does handle high tag numbers (`Tag { class: Class, value: u32 }`), so it
is the one candidate that could encode a `5F37`/`BF38` command TLV. It is
rejected on merit rather than capability:

  - the hand-rolled DER in `src/wire.rs` is ~230 lines, is covered by tests,
    and encodes and decodes the exact tags this protocol needs, verified
    against the ASN.1 and against generated reference encoders
  - `rasn` would pull a large framework and a code-generation model into a
    crate that currently has five dependencies
  - its tag model would still not remove `src/wire.rs`, because the SGP.22
    command encodings are hand-written structures rather than ASN.1-driven ones

If the DER layer later grows beyond the SGP.22 command set, revisit. Today it
does not clear the bar.

### `const-oid`, `spki`, `sec1` — REJECTED, no benefit

Available, but this crate's OIDs are a handful of fixed byte strings and its
keys are fixed-width P-256 points. Adopting them adds crates and an encoding
layer without removing complexity.

## Behaviour note

`Certificate::verify_signed_by` verifies a signature and nothing else; it does
**not** perform chain validation against a trust anchor, and its callers rely
on that narrow meaning. Nothing in this review changes that. `rustls-webpki`
0.101 -> 0.103 would enable real RFC 5280 path validation via
`verify_for_usage`, but that is a behaviour change and belongs in its own
change with its own tests, not in a dependency swap.

## Order of work

  1. `p256`/`ecdsa` for ECC, deleting the DER<->raw conversion  (criterion a)
  2. `x509-cert` for parsing and issuance                       (criterion b)
  3. `aes-gcm`, then drop `ring` entirely if nothing else needs it

Each step keeps the full test suite green, and the existing tests are the
acceptance criteria: they were written against the hand-rolled code and must
pass unchanged against the replacement.
