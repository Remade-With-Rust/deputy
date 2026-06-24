//! Conflict-free multi-device metadata sync (SpaceDB Layers 1 + 3).
//!
//! Deputy's metadata (scan verdicts + the prod crate index) is modelled as a set of **LWW
//! registers** in a Y-CRDT [`CrdtDoc`] — one register per metadata key. Two devices that
//! acquired / promoted *different* crates converge cleanly on import (union); a key edited on
//! both converges by last-writer-wins. The delta primitive (`state_vector` /
//! `encode_update_since`) underlies a future live replica (Layer 2 hot).
//!
//! The exported update is a portable CRDT blob, **not** encrypted: per-device salts mean two
//! devices with the same passphrase derive different at-rest keys, so the vault key can't seal a
//! cross-device blob. Transfer it over a secure channel between your own devices; a future
//! revision derives a shared sync key from the user's mID (shared across their devices).

use sha2::{Digest, Sha256};
use spacedb_crdt::CrdtDoc;

use crate::error::{Result, StoreError};
use crate::vault::Vault;

/// Summary of a sync import.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Metadata entries present after the merge.
    pub merged_entries: usize,
}

fn crdt_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Sync(e.to_string())
}

/// A stable per-vault CRDT actor id (so a device's edits attribute consistently).
fn actor_id(vault: &Vault) -> u64 {
    let digest = Sha256::digest(vault.root().to_string_lossy().as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn doc_from_metadata(vault: &Vault) -> Result<CrdtDoc> {
    let doc = CrdtDoc::new(actor_id(vault));
    for (key, value) in vault.metadata_entries()? {
        doc.set_register(&key, &value).map_err(crdt_err)?;
    }
    Ok(doc)
}

/// Export this vault's metadata as a portable CRDT update, mergeable into another device's vault.
pub fn export_metadata(vault: &Vault) -> Result<Vec<u8>> {
    Ok(doc_from_metadata(vault)?.encode_full())
}

/// Merge a CRDT update (from [`export_metadata`] on another device) into this vault. Convergent:
/// new entries are added, and a key written on both devices is resolved by the CRDT.
pub fn import_metadata(vault: &Vault, update: &[u8]) -> Result<SyncReport> {
    // Merge the remote update into a doc seeded with our current metadata.
    let doc = doc_from_metadata(vault)?;
    doc.apply_update(update).map_err(crdt_err)?;

    // Write the converged registers back into the encrypted metadata store.
    let mut merged = 0;
    for key in doc.register_keys() {
        if let Some(value) = doc.get_register::<Vec<u8>>(&key).map_err(crdt_err)? {
            vault.put_metadata(&key, &value)?;
            merged += 1;
        }
    }
    Ok(SyncReport {
        merged_entries: merged,
    })
}
