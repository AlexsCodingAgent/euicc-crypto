# Dependency review: what to adopt and what to keep hand-rolled

Scope: the dependency policy for `euicc-crypto`. The two sibling crates
(`tuddenham-ipad`, `euicc-simulator`) are out of scope here and keep their
zero-dependency stance unless separately decided.

Every candidate below was compiled and exercised on this machine before being
accepted or rejected. Where a swap was approved, equivalence with the code it
replaces was demonstrated against a published test vector, not asserted.

## Approved

### `hkdf 0.12.4` — APPROVED
Replaces the hand-rolled HKDF in `src/kdf.rs`.

Justification: hand-rolled and passing RFC 5869 test case 1 is not the same as
being the reference implementation. Key derivation sits on the critical path
for every session key, and there is no reason for this project to own it.

Equivalence demonstrated: `Hkdf::<Sha256>` reproduces RFC 5869 test case 1
exactly, both the extract step (`prk` =
`077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5`) and the
42-byte expand output.

### `hmac 0.12.1` — APPROVED
Replaces the hand-rolled HMAC in `src/kdf.rs`.

Justification: same reasoning as HKDF, plus `Mac::verify_slice` gives a
constant-time comparison that the hand-rolled version has to get right
manually. Removing a hand-written constant-time comparison from a crypto
crate is a strict improvement.

Equivalence demonstrated: reproduces RFC 4231 test case 1
(`b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7`) and agrees
byte-for-byte with `ring::hmac` on the same input.

### `sha2 0.10.9` — APPROVED (as a dependency of hkdf/hmac)
Already pulled in transitively by `hkdf`/`hmac`. Verified to agree with
`ring`'s SHA-256 on the same input, so having both in the tree is not a
correctness risk.

## Rejected

### `der 0.7.10` — REJECTED, cannot be used
This was the intended replacement for the hand-rolled DER in `ecdsa.rs`,
`x509.rs` and `wire.rs`, and the largest single win available on paper.

It is unusable for this protocol. `der`'s `TagNumber` caps at 30:

    const MAX: u8 = 30;
    pub const fn new(byte: u8) -> Self {
        if byte > Self::MAX { panic!("tag number out of range"); }
    }

Every tag in SGP.22 and SGP.32 is above 30 — they occupy the 32..56 range,
which is exactly why they use the two-byte form:

    BF2E GetEUICCChallenge            46
    BF21 PrepareDownload              33
    BF26 ReplaceSessionKeysRequest    38
    BF38 AuthenticateServer           56
    5F37 signature field              55

`der` therefore cannot encode or decode a single command in this protocol.
This was confirmed by running it, not by reading documentation: constructing
`Tag::Application { number: TagNumber::new(55) }` panics at compile time.

`der_derive` is also absent from the local registry, so the derive ergonomics
are unavailable regardless.

Decision: the DER code stays hand-rolled. This is not a compromise — the
SGP.22 tag space is outside what `der` models, and hand-rolled DER is what the
rest of the ecosystem does in the same position.

### `p256`, `ecdsa`, `elliptic-curve` — REJECTED, unavailable
Not present in the local registry, and crates.io returns 403 from this
machine, so they cannot be fetched. `ring` remains the only option for ECDSA
P-256 and ECDH, and it is a sound one.

### `aes-gcm` — REJECTED, unavailable
Same reason. `ring`'s AES-128-GCM stays, already verified against NIST GCM
test cases 2 and 3.

### `const-oid`, `spki`, `pkcs8` — REJECTED, no benefit
Available, but they exist to model OID and key structures. This project's OIDs
are a handful of fixed byte strings and its key handling is a fixed-width
P-256 point, so adopting them would add three crates and an encoding layer
without removing any real complexity. The hand-written constants are clearer
here because the SGP.22 tag/OID usage is unusual enough that a generic
structure adds indirection.

## Deferred

### `rustls-webpki` 0.101.7 -> 0.103.15 — DEFERRED, pending a decision
`0.103` exposes `EndEntityCert::verify_for_usage`, which performs real RFC 5280
path validation against supplied trust anchors. The current code uses 0.101
only as a structural parse check and documents "no chain validation against a
trust anchor" as a limitation.

Upgrading would close that limitation, but it is a behaviour change, not just
a version bump: the current `Certificate::verify_signed_by` deliberately
verifies a signature and nothing else, and callers rely on that meaning.
Adopting full path validation requires deciding what the trust anchor is for
the test PKI and how a validation failure surfaces to the SGP.33 sequence
layer. That is a design question, not a dependency swap.

Recommendation: take it, but as its own change with its own tests, not folded
in with the HKDF and HMAC swaps.

## Consequence for the dependency graph

After these swaps the crate carries both `ring` and the RustCrypto
`digest`/`hmac` stack. Verified this is benign:

    hkdf -> hmac -> digest 0.10.7
    hmac           digest 0.10.7
    sha2           digest 0.10.7
    ring (independent)

One shared `digest` version, no duplicate major versions, and the two SHA-256
implementations agree byte-for-byte. `ring` stays for ECC and AES because no
alternative exists offline, not by preference.

## Unrelated defect found during this review

`TAG_LOAD_BOUND_PROFILE_PACKAGE = 0xBF26` is present in both `tuddenham-ipad`
and `euicc-simulator` and is wrong. SGP.22 Annex J allocates `BF26` to
`ReplaceSessionKeysRequest`, and `LoadBoundProfilePackage` has no TLV tag at
all: SGP.22 section 5.7.6, which SGP.32 section 5.9.8 states is identical,
describes it as raw 255-byte blocks in APDU command data. This is tracked
separately from the dependency work.
