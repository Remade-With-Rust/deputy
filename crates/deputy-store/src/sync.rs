//! Conflict-free, end-to-end-encrypted multi-device metadata sync (SpaceDB Layers 1 + 3).
//!
//! Deputy's metadata (scan verdicts + the prod crate index) is modelled as a set of **LWW
//! registers** in a Y-CRDT [`CrdtDoc`] — one register per metadata key. Two devices that
//! acquired / promoted *different* crates converge cleanly on import (union); a key edited on
//! both converges by last-writer-wins. The delta primitive (`state_vector` /
//! `encode_update_since`) underlies a future live replica (Layer 2 hot).
//!
//! The exported blob is sealed under the **mID-bound sync key** ([`derive_sync_key`]): the same
//! on every device of one user (same passphrase + same mID), so they can read each other's
//! exports, while it is opaque to anyone else. The user's mID is the shared identity that binds
//! the key; the passphrase supplies confidentiality (mID exports no secret). See
//! `docs/STORAGE.md` §7.

use deputy_crypto::{derive_sync_key as crypto_derive_sync_key, open, seal, SubKey};
use sha2::{Digest, Sha256};
use spacedb_crdt::CrdtDoc;

use crate::error::{Result, StoreError};
use crate::vault::Vault;

/// The symmetric key that seals a sync blob — shared across a user's devices, derived by
/// [`derive_sync_key`]. (A [`deputy_crypto::SubKey`] under the hood.)
pub type SyncKey = SubKey;

const SYNC_AAD: &[u8] = b"deputy:sync:v1";

/// Summary of a sync import.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// Metadata entries present after the merge.
    pub merged_entries: usize,
}

/// Derive the mID-bound sync key for `mid_did` from the vault `passphrase`. Every device of the
/// same user (same passphrase + same mID DID) derives the same key; a different identity or
/// passphrase derives a different one, so a sync blob is readable only within one user's fleet.
pub fn derive_sync_key(passphrase: &[u8], mid_did: &str) -> Result<SyncKey> {
    crypto_derive_sync_key(passphrase, mid_did).map_err(StoreError::from)
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

/// Export this vault's metadata as a **sealed** CRDT update, mergeable into another of the
/// user's devices via [`import_metadata`] under the same [`SyncKey`].
pub fn export_metadata(vault: &Vault, sync: &SyncKey) -> Result<Vec<u8>> {
    let update = doc_from_metadata(vault)?.encode_full();
    seal(sync, &update, SYNC_AAD).map_err(StoreError::from)
}

/// Merge a sealed CRDT update (from [`export_metadata`] on another device) into this vault.
/// Opening fails unless `sync` matches the exporting device's key — i.e. the same user's
/// passphrase + mID. Convergent: new entries are added, a key written on both is resolved by
/// the CRDT.
pub fn import_metadata(vault: &Vault, sealed_update: &[u8], sync: &SyncKey) -> Result<SyncReport> {
    let update = open(sync, sealed_update, SYNC_AAD)?;

    // Merge the remote update into a doc seeded with our current metadata.
    let doc = doc_from_metadata(vault)?;
    doc.apply_update(&update).map_err(crdt_err)?;

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
