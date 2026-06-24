use deputy_core::{ArtifactRef, ContentHash, MetadataStore, ScanVerdict, StoreKind};
use spacedb_store::{Durability, KvEngine, WriteTx};

use crate::error::{Result, StoreError};
use crate::vault::Vault;

// Keys are namespaced strings (e.g. `verdict:<eco>:<hash>`); values are plaintext bytes, which
// SpaceDB's collection AES-256-GCM-encrypts under the per-collection DEK before writing. The DB
// therefore leaks nothing in the clear, and Deputy no longer seals metadata itself.

fn verdict_key(artifact: &ArtifactRef) -> String {
    format!("verdict:{}:{}", artifact.ecosystem, artifact.hash)
}

fn store_tag(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::Dirty => "dirty",
        StoreKind::Prod => "prod",
    }
}

fn crate_index_key(kind: StoreKind, name: &str, version: &str) -> String {
    format!("crate:{}:{name}:{version}", store_tag(kind))
}

fn db_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Db(e.to_string())
}

impl Vault {
    fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        // The collection encrypts `value` under its DEK; Immediate durability fsyncs the commit.
        let mut txn = self
            .db()
            .begin_write(Durability::Immediate)
            .map_err(db_err)?;
        self.meta()
            .put(&mut txn, &key.to_owned(), &value.to_vec())
            .map_err(db_err)?;
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // The collection decrypts the row; a missing key returns `None` without touching the KEK.
        let txn = self.db().begin_read().map_err(db_err)?;
        self.meta().get(&txn, &key.to_owned()).map_err(db_err)
    }

    /// All metadata entries `(key, plaintext value)`, decrypted — the input to CRDT sync.
    pub(crate) fn metadata_entries(&self) -> Result<Vec<(String, Vec<u8>)>> {
        let txn = self.db().begin_read().map_err(db_err)?;
        // The string codec is order-preserving, so `["", high)` spans every key.
        let high = "\u{10FFFF}".to_owned();
        self.meta()
            .range(&txn, &String::new(), &high)
            .map_err(db_err)
    }

    /// Write a metadata entry (used by the sync merge); encrypted by the collection.
    pub(crate) fn put_metadata(&self, key: &str, value: &[u8]) -> Result<()> {
        self.put_meta(key, value)
    }

    /// Record a scan verdict for an artifact, sealed under the metadata subkey.
    pub fn put_verdict(&self, artifact: &ArtifactRef, verdict: &ScanVerdict) -> Result<()> {
        let key = verdict_key(artifact);
        let plain = serde_json::to_vec(verdict)?;
        self.put_meta(&key, &plain)
    }

    /// Fetch a previously recorded scan verdict, if any.
    pub fn get_verdict(&self, artifact: &ArtifactRef) -> Result<Option<ScanVerdict>> {
        let key = verdict_key(artifact);
        let Some(plain) = self.get_meta(&key)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(&plain)?))
    }

    /// Record the content hash a crate `name@version` resolves to within a store. The prod
    /// index is what lets a later scan detect **substitution** — the same name+version mapping
    /// to a different hash than what was promoted (`docs/PIPELINE.md` §4).
    pub fn put_crate_hash(
        &self,
        kind: StoreKind,
        name: &str,
        version: &str,
        hash: &ContentHash,
    ) -> Result<()> {
        let key = crate_index_key(kind, name, version);
        self.put_meta(&key, hash.to_hex().as_bytes())
    }

    /// The content hash recorded for `name@version` in a store, if any.
    pub fn crate_hash(
        &self,
        kind: StoreKind,
        name: &str,
        version: &str,
    ) -> Result<Option<ContentHash>> {
        let key = crate_index_key(kind, name, version);
        let Some(plain) = self.get_meta(&key)? else {
            return Ok(None);
        };
        let hex = std::str::from_utf8(&plain)
            .map_err(|_| StoreError::Malformed("crate-index value is not UTF-8".to_owned()))?;
        let hash = ContentHash::from_sha256_hex(hex)
            .map_err(|e| StoreError::Malformed(format!("crate-index hash: {e}")))?;
        Ok(Some(hash))
    }
}

/// The API-first [`MetadataStore`] contract, satisfied by the encrypted SpaceDB-backed store.
impl MetadataStore for Vault {
    fn record_verdict(
        &self,
        artifact: &ArtifactRef,
        verdict: &ScanVerdict,
    ) -> deputy_core::Result<()> {
        Ok(self.put_verdict(artifact, verdict)?)
    }

    fn verdict(&self, artifact: &ArtifactRef) -> deputy_core::Result<Option<ScanVerdict>> {
        Ok(self.get_verdict(artifact)?)
    }
}
