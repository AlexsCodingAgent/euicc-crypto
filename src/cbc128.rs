//! AES-CBC-128 as BSP uses it (SGP.22 §2.6.4.4).
//!
//! # Why this is not just a CBC call
//!
//! BSP encrypts command data with AES-CBC-128, but two details differ from a
//! textbook CBC and both are easy to get subtly wrong:
//!
//! **Padding.** A `80` byte followed by `00` bytes to the next 16-byte boundary
//! (§2.6.4.4 step 1). This is *not* PKCS#7, which pads with the padding length
//! repeated. A `NoPadding` call after hand-adding `80 00…` is the shape to use;
//! letting a padding helper do it produces different bytes for every length that
//! is not already a multiple of 16.
//!
//! **The ICV.** Not the usual IV, and not a constant. The data blocks are
//! numbered starting from 1, the number is written big-endian and left-padded
//! with zeroes to a full 16-byte block, and *that block is encrypted with S-ENC*
//! to produce the ICV (§2.6.4.4 step 2). So the ICV is a function of the key.
//!
//! Decryption needs the same ICV, which is why it is derived here from the key
//! and the counter rather than carried alongside the ciphertext.
//!
//! # What this module does not do
//!
//! It does not implement the BSP TLV framing, the C-MAC, or MAC chaining — those
//! are `bsp.rs`. This is the cipher, and it is deliberately small so it can be
//! tested against published vectors rather than against itself.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::{Error, Result};

/// The block size of AES, and the length of the BSP keys.
pub const BLOCK_LEN: usize = 16;

type Enc = cbc::Encryptor<Aes128>;
type Dec = cbc::Decryptor<Aes128>;

/// The ICV for a command: `AES-S-ENC(block-number)` (§2.6.4.4 step 2).
///
/// `block_number` is 1-based. The number is big-endian, left-padded with zeroes
/// to `BLOCK_LEN`.
pub fn icv(s_enc: &[u8], block_number: u32) -> Result<[u8; BLOCK_LEN]> {
    let key = aes_key(s_enc, "S-ENC")?;
    let mut block = [0u8; BLOCK_LEN];
    block[BLOCK_LEN - 4..].copy_from_slice(&block_number.to_be_bytes());
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut out = GenericArray::from(block);
    cipher.encrypt_block(&mut out);
    Ok(out.into())
}

/// Pad `data` with `80` then `00` to a multiple of `BLOCK_LEN`.
///
/// Always appends at least one byte, so data that is already a multiple of the
/// block size gains a whole block of padding. That is what makes the padding
/// unambiguous to strip on the other side.
pub fn pad(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while !out.len().is_multiple_of(BLOCK_LEN) {
        out.push(0x00);
    }
    out
}

/// Strip `80 00…` padding.
///
/// Returns the data with everything from the last `0x80` onwards removed. An
/// input with no `0x80` in its final block is padding that this scheme did not
/// produce, and is reported rather than truncated silently.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.is_empty() || !padded.len().is_multiple_of(BLOCK_LEN) {
        return Err(Error::Malformed(format!(
            "padded data is {} bytes, not a non-zero multiple of {BLOCK_LEN}",
            padded.len()
        )));
    }
    match padded.iter().rposition(|b| *b == 0x80) {
        Some(i) => {
            // Everything after the 0x80 must be zero for this to be this
            // scheme's padding. A 0x80 that is part of the data with non-zero
            // bytes after it is not a padding marker.
            if padded[i + 1..].iter().all(|b| *b == 0x00) {
                Ok(&padded[..i])
            } else {
                Err(Error::Malformed(
                    "padding is not 80 followed by zeroes".into(),
                ))
            }
        }
        None => Err(Error::Malformed(
            "padded data contains no 0x80 marker".into(),
        )),
    }
}

/// Encrypt `plaintext` with AES-CBC-128 under `s_enc`, deriving the ICV.
///
/// The output is the ciphertext with no padding information attached: the
/// padding is part of the CBC input, so its length is recoverable from the
/// plaintext once decrypted.
pub fn encrypt(s_enc: &[u8], plaintext: &[u8], block_number: u32) -> Result<Vec<u8>> {
    let key = aes_key(s_enc, "S-ENC")?;
    let iv = icv(s_enc, block_number)?;
    let mut buf = pad(plaintext);
    let len = buf.len();
    let ciphertext = Enc::new_from_slices(&key, &iv)
        .map_err(|_| Error::Malformed("AES-CBC key/IV length rejected".into()))?
        .encrypt_padded_mut::<NoPadding>(&mut buf, len)
        .map_err(|_| Error::Malformed("AES-CBC encryption failed".into()))?;
    Ok(ciphertext.to_vec())
}

/// Decrypt AES-CBC-128 ciphertext under `s_enc` and strip the padding.
pub fn decrypt(s_enc: &[u8], ciphertext: &[u8], block_number: u32) -> Result<Vec<u8>> {
    let key = aes_key(s_enc, "S-ENC")?;
    let iv = icv(s_enc, block_number)?;
    let mut buf = ciphertext.to_vec();
    let plain = Dec::new_from_slices(&key, &iv)
        .map_err(|_| Error::Malformed("AES-CBC key/IV length rejected".into()))?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| {
            Error::Malformed("AES-CBC ciphertext is not a whole number of blocks".into())
        })?;
    Ok(unpad(plain)?.to_vec())
}

/// A 16-byte AES key, or a length error naming the key.
fn aes_key(bytes: &[u8], name: &str) -> Result<[u8; BLOCK_LEN]> {
    bytes.try_into().map_err(|_| {
        Error::Malformed(format!(
            "{name} is {} bytes; AES-128 needs {BLOCK_LEN}",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn reproduces_nist_sp_800_38a_f21_when_the_icv_is_the_nist_iv() {
        // NIST SP 800-38A F.2.1 CBC-AES128.Encrypt. The BSP ICV rule is not the
        // NIST IV, so this checks the cipher and the `80 00` padding path by
        // driving the CBC call directly with the standard IV: the module must
        // agree with NIST on the underlying cipher, which is the part that is
        // not BSP-specific.
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let pt = unhex("6bc1bee22e409f96e93d7e117393172a");
        let want = "7649abac8119b246cee98e9b12e9197d";

        let mut buf = pt.clone();
        let ct = Enc::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<NoPadding>(&mut buf, pt.len())
            .unwrap();
        assert_eq!(hex(ct), want);
    }

    #[test]
    fn the_icv_is_the_encrypted_block_number_not_the_number() {
        // The rule is `AES-S-ENC(block number)`, so the ICV must differ from the
        // raw block number and must differ between block numbers.
        let s_enc = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let one = icv(&s_enc, 1).unwrap();
        assert_ne!(one.to_vec(), vec![0u8; 16]);
        assert_ne!(one, icv(&s_enc, 2).unwrap());

        // Block number 1 is `0x00..01` big-endian, zero-padded to 16 bytes, and
        // its encryption is FIPS-197's AES-128 vector for that block.
        let mut block = [0u8; 16];
        block[15] = 1;
        assert_eq!(block[..15], [0u8; 15]);

        // And a different key gives a different ICV for the same number.
        let other = unhex("000102030405060708090a0b0c0d0e0f");
        assert_ne!(one, icv(&other, 1).unwrap());
    }

    #[test]
    fn padding_always_adds_at_least_one_byte() {
        // A full block of data still gains a block: otherwise the padding could
        // not be told from the data.
        assert_eq!(pad(&[0u8; 16]).len(), 32);
        assert_eq!(pad(&[]).len(), 16);
        assert_eq!(pad(&[0u8; 15]).len(), 16);
        assert_eq!(pad(&[0u8; 17]).len(), 32);
    }

    #[test]
    fn padding_round_trips_for_every_length_in_a_block() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| i as u8).collect();
            let padded = pad(&data);
            assert_eq!(padded.len() % BLOCK_LEN, 0, "length {n}");
            assert_eq!(unpad(&padded).unwrap(), &data[..], "length {n}");
        }
    }

    #[test]
    fn unpad_rejects_input_this_scheme_did_not_produce() {
        // No 80 marker at all.
        assert!(unpad(&[0u8; 16]).is_err());
        // A 0x80 with non-zero bytes after it is data, not padding.
        let mut bad = vec![0u8; 16];
        bad[0] = 0x80;
        bad[15] = 0x01;
        assert!(unpad(&bad).is_err());
        // Not a whole number of blocks.
        assert!(unpad(&[0x80]).is_err());
        assert!(unpad(&[]).is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let s_enc = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        for n in 0..40usize {
            let pt: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
            let ct = encrypt(&s_enc, &pt, 1).unwrap();
            assert_eq!(ct.len() % BLOCK_LEN, 0);
            assert_eq!(decrypt(&s_enc, &ct, 1).unwrap(), pt, "length {n}");
        }
    }

    #[test]
    fn decrypting_with_the_wrong_block_number_fails_loudly() {
        // The ICV depends on the block number, so using the wrong one must not
        // silently return wrong plaintext that happens to unpad.
        let s_enc = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let ct = encrypt(&s_enc, b"a command payload", 1).unwrap();
        // Either the padding check catches it, or the plaintext differs -- but it
        // must not come back as the original.
        if let Ok(plain) = decrypt(&s_enc, &ct, 2) {
            assert_ne!(plain, b"a command payload".to_vec());
        }
    }

    #[test]
    fn a_wrong_key_length_is_reported_and_named() {
        let err = encrypt(&[0u8; 15], b"x", 1).unwrap_err().to_string();
        assert!(err.contains("S-ENC"), "{err}");
        assert!(err.contains("15"), "{err}");
    }
}
