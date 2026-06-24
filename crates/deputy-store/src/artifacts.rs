use std::path::PathBuf;

use deputy_core::{ArtifactStore, ContentHash, StoreKind};
use deputy_crypto::{derive_artifact_subkey, open, seal};
use sha2::{Digest, Sha256};

use crate::error::{Result, StoreError};
use crate::vault::{write_atomic, Vault};

fn kind_dir(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::Dirty => "dirty",
        StoreKind::Prod => "prod",
    }
}

/// SHA-256 content address of `bytes`.
fn content_address(bytes: &[u8]) -> ContentHash {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    ContentHash::sha256(out)
}

impl Vault {
    fn artifact_path(&self, kind: StoreKind, hash: &ContentHash) -> PathBuf {
        let hex = hash.to_hex();
        let shard = &hex[..2];
        self.root()
            .join("store")
            .join(kind_dir(kind))
            .join(hash.algo().as_str())
            .join(shard)
            .join(format!("{hex}.sealed"))
    }

    /// Seal raw artifact bytes into `kind`, addressed by their SHA-256. The content address is
    /// bound into the AEAD as additional data, so a sealed blob cannot be relocated to a
    /// different address. Idempotent: identical bytes already stored is a no-op.
    pub fn put_artifact(&self, kind: StoreKind, raw: &[u8]) -> Result<ContentHash> {
        let hash = content_address(raw);
        let path = self.artifact_path(kind, &hash);
        if path.exists() {
            return Ok(hash);
        }
        let subkey = derive_artifact_subkey(self.store_key(), hash.bytes());
        let sealed = seal(&subkey, raw, hash.to_string().as_bytes())?;
        write_atomic(&path, &sealed)?;
        Ok(hash)
    }

    /// Retrieve and decrypt a stored artifact, re-verifying the decrypted bytes against the
    /// content address they were looked up by (defense in depth).
    pub fn get_artifact(&self, kind: StoreKind, hash: &ContentHash) -> Result<Vec<u8>> {
        let path = self.artifact_path(kind, hash);
        let sealed = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(format!("artifact {hash}")));
            }
            Err(e) => return Err(e.into()),
        };
        let subkey = derive_artifact_subkey(self.store_key(), hash.bytes());
        let raw = open(&subkey, &sealed, hash.to_string().as_bytes())?;
        if content_address(&raw) != *hash {
            return Err(StoreError::Integrity);
        }
        Ok(raw)
    }

    /// Whether `kind` holds an artifact with this content address.
    pub fn has_artifact(&self, kind: StoreKind, hash: &ContentHash) -> Result<bool> {
        Ok(self.artifact_path(kind, hash).exists())
    }
}

/// The API-first [`ArtifactStore`] contract, satisfied by the on-disk sealed store. Errors
/// convert into [`deputy_core::Error`] at this boundary.
impl ArtifactStore for Vault {
    fn put(&self, kind: StoreKind, raw: &[u8]) -> deputy_core::Result<ContentHash> {
        Ok(self.put_artifact(kind, raw)?)
    }

    fn get(&self, kind: StoreKind, hash: &ContentHash) -> deputy_core::Result<Vec<u8>> {
        Ok(self.get_artifact(kind, hash)?)
    }

    fn contains(&self, kind: StoreKind, hash: &ContentHash) -> deputy_core::Result<bool> {
        Ok(self.has_artifact(kind, hash)?)
    }
}
