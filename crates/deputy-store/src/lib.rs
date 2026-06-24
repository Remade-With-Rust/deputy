//! # deputy-store
//!
//! Deputy's encrypted-at-rest storage layer, implementing `docs/STORAGE.md`:
//!
//! - [`Vault`] — the unlocked context. [`Vault::create`] initializes a new store (deriving
//!   Argon2id params + a key verifier); [`Vault::unlock`] re-derives the key hierarchy from a
//!   passphrase and rejects the wrong one. Subkeys live in memory only and zeroize on drop.
//! - **Content-addressed artifact stores** (dirty + prod). Every artifact is sealed with
//!   AES-256-GCM under a per-artifact subkey, addressed by the SHA-256 of its bytes, with the
//!   content address bound in as AEAD additional data.
//! - **Encrypted metadata** (SpaceDB Layer 0 KV): scan verdicts and other records, each sealed
//!   under the metadata subkey.
//! - **Hash-chained audit log**: append-only, tamper-evident provenance.
//!
//! Everything lives under one Deputy home directory (default `~/.deputy`); see
//! [`Vault::create`] for the on-disk layout.
#![forbid(unsafe_code)]

mod artifacts;
mod audit;
mod error;
mod meta;
mod snapshot;
mod sync;
mod vault;

#[cfg(test)]
mod tests;

pub use audit::AuditEntry;
pub use error::{Result, StoreError};
pub use snapshot::{restore, snapshot, RestoreInfo, SnapshotInfo};
pub use sync::{export_metadata, import_metadata, SyncReport};
pub use vault::Vault;

// Re-export the storage-relevant core vocabulary so callers need only depend on this crate.
pub use deputy_core::{ArtifactRef, ContentHash, ScanVerdict, StoreKind};
