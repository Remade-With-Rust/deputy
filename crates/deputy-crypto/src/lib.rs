//! # deputy-crypto
//!
//! Deputy's encryption-at-rest primitives, implementing the design in `docs/STORAGE.md` §2.
//!
//! The key hierarchy:
//!
//! ```text
//! passphrase ──Argon2id(salt, params)──▶ MasterKey            (memory only, zeroized on drop)
//!                                            │ HKDF-SHA256(domain)
//!                       ┌────────────────────┼────────────────────┐
//!                       ▼                     ▼                    ▼
//!                 SubKey(Store)         SubKey(Meta)         SubKey(Audit)
//!                       │ HKDF(content_hash)
//!                       ▼
//!               per-artifact SubKey ──▶ AES-256-GCM seal/open
//! ```
//!
//! No key material is ever serialized, logged, or written to disk: [`MasterKey`] and
//! [`SubKey`] zeroize on drop, and only the non-secret [`KdfParams`] (+ a [`make_verifier`]
//! blob) are persisted so a wrong passphrase is detectable without storing the key.
#![forbid(unsafe_code)]

mod aead;
mod derive;
mod error;
mod kdf;
mod key;
mod verify;

#[cfg(test)]
mod tests;

pub use aead::{open, seal};
pub use derive::{derive_artifact_subkey, derive_subkey, derive_sync_key, KeyDomain};
pub use error::{CryptoError, Result};
pub use kdf::{derive_master, KdfParams};
pub use key::{MasterKey, SubKey};
pub use verify::{check_verifier, make_verifier};
