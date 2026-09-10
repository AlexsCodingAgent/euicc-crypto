//! Cryptographic primitives for GSMA SGP.22 / SGP.32 eSIM remote SIM
//! provisioning.
//!
//! This crate exists so that the sibling `tuddenham-ipad` and
//! `euicc-simulator` crates can stay dependency-free and always build offline.
//! All third-party crypto lives here, behind a small, spec-shaped API.
//!
//! # What is implemented
//!
//! | Module | Contents |
//! |---|---|
//! | [`ecdsa`] | P-256 key generation, signing, verification, DER <-> raw `r‖s` |
//! | [`ecdh`] | P-256 ephemeral key agreement |
//! | [`kdf`] | SHA-256 and HKDF-based key derivation |
//! | [`aead`] | AES-128-GCM for bound profile packages |
//! | [`x509`] | Certificate parsing and public-key extraction |
//! | [`ci`] | CI key set and selection of the key that verifies a certificate |
//! | [`testpki`] | A self-consistent P-256 test chain for the SGP.33 suites |
//!
//! # What is NOT implemented
//!
//! - **Certificate issuance.** [`testpki`] builds a self-signed test chain for
//!   exercising the code paths. It is *not* a substitute for the SGP.26 test
//!   certificates, and nothing here should be used for production provisioning.
//! - **Key storage.** Keys are plain values; there is no secure element.
//! - **Certificate path validation against a real trust anchor.** [`x509`]
//!   parses and extracts keys; chain-verification against GSMA roots is not
//!   wired up, because the roots are not available offline.
//!
//! # Signature encoding
//!
//! SGP.22 carries ECDSA signatures as a raw 64-byte `r‖s` concatenation
//! (`[APPLICATION 55] OCTET STRING`), while `ring` emits and consumes ASN.1
//! DER. [`ecdsa::der_to_raw`] and [`ecdsa::raw_to_der`] convert between them,
//! and both are round-trip tested, because getting this wrong produces
//! signatures that verify in one direction only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod ci;
pub mod ecdh;
pub mod ecdsa;
pub mod kdf;
pub mod testpki;
pub mod x509;

pub use ecdsa::{KeyPair, PublicKey, Signature};
pub use x509::Certificate;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A key, signature or certificate was malformed.
    Malformed(String),
    /// A signature did not verify.
    VerificationFailed,
    /// A cryptographic operation failed for a reason the caller cannot act on.
    Crypto(String),
    /// A certificate could not be parsed or its key could not be extracted.
    Certificate(String),
    /// The requested curve or algorithm is not supported.
    Unsupported(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(m) => write!(f, "malformed input: {m}"),
            Error::VerificationFailed => write!(f, "signature verification failed"),
            Error::Crypto(m) => write!(f, "crypto failure: {m}"),
            Error::Certificate(m) => write!(f, "certificate error: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Lowercase hex, for debug output and test vectors.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
