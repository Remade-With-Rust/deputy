use crate::error::{CryptoError, Result};
use crate::key::SubKey;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Seal `plaintext` under `key` with AES-256-GCM, authenticating `aad` (additional
/// authenticated data, e.g. the artifact's content address). The output layout is
/// `nonce(12) ‖ ciphertext ‖ tag(16)`, with a fresh random nonce per call.
pub fn seal(key: &SubKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Random)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Seal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob produced by [`seal`] with the same `key` and `aad`. Returns
/// [`CryptoError::Open`] on any authentication failure (wrong key, tampered bytes, or wrong
/// AAD) and [`CryptoError::Malformed`] if the blob is too short to contain a nonce + tag.
pub fn open(key: &SubKey, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Open)
}
