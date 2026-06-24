use deputy_core::{ArtifactRef, ContentHash, MetadataStore, ScanVerdict, StoreKind};
use deputy_crypto::{open, seal};
use redb::TableDefinition;

use crate::error::{Result, StoreError};
use crate::vault::Vault;

/// Single key/value table. Keys are namespaced strings (e.g. `verdict:<eco>:<hash>`); values
/// are AEAD-sealed under the metadata subkey, so the database file leaks nothing in the clear.
const META_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("deputy_meta");

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
    fn put_meta(&self, key: &str, sealed: &[u8]) -> Result<()> {
        let txn = self.db().begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(META_TABLE).map_err(db_err)?;
            table.insert(key, sealed).map_err(db_err)?;
        }
        txn.commit().map_err(db_err)?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db().begin_read().map_err(db_err)?;
        let table = match txn.open_table(META_TABLE) {
            Ok(table) => table,
            // No writes have happened yet, so the table doesn't exist: treat as empty.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(db_err(e)),
        };
        match table.get(key).map_err(db_err)? {
            Some(guard) => Ok(Some(guard.value().to_vec())),
            None => Ok(None),
        }
    }

    /// Record a scan verdict for an artifact, sealed under the metadata subkey.
    pub fn put_verdict(&self, artifact: &ArtifactRef, verdict: &ScanVerdict) -> Result<()> {
        let key = verdict_key(artifact);
        let plain = serde_json::to_vec(verdict)?;
        let sealed = seal(self.meta_key(), &plain, key.as_bytes())?;
        self.put_meta(&key, &sealed)
    }

    /// Fetch a previously recorded scan verdict, if any.
    pub fn get_verdict(&self, artifact: &ArtifactRef) -> Result<Option<ScanVerdict>> {
        let key = verdict_key(artifact);
        let Some(sealed) = self.get_meta(&key)? else {
            return Ok(None);
        };
        let plain = open(self.meta_key(), &sealed, key.as_bytes())?;
        let verdict = serde_json::from_slice(&plain)?;
        Ok(Some(verdict))
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
        let sealed = seal(self.meta_key(), hash.to_hex().as_bytes(), key.as_bytes())?;
        self.put_meta(&key, &sealed)
    }

    /// The content hash recorded for `name@version` in a store, if any.
    pub fn crate_hash(
        &self,
        kind: StoreKind,
        name: &str,
        version: &str,
    ) -> Result<Option<ContentHash>> {
        let key = crate_index_key(kind, name, version);
        let Some(sealed) = self.get_meta(&key)? else {
            return Ok(None);
        };
        let plain = open(self.meta_key(), &sealed, key.as_bytes())?;
        let hex = std::str::from_utf8(&plain)
            .map_err(|_| StoreError::Malformed("crate-index value is not UTF-8".to_owned()))?;
        let hash = ContentHash::from_sha256_hex(hex)
            .map_err(|e| StoreError::Malformed(format!("crate-index hash: {e}")))?;
        Ok(Some(hash))
    }
}

/// The API-first [`MetadataStore`] contract, satisfied by the encrypted redb store.
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
