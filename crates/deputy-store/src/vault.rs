use std::fs;
use std::path::{Path, PathBuf};

use deputy_crypto::{
    check_verifier, derive_master_bound, derive_subkey, make_verifier, KdfParams, KeyDomain,
    MasterKey, SubKey,
};
use serde::{Deserialize, Serialize};
use spacedb_store::{Collection, KeyProvider, RedbEngine, StaticKeyProvider};
use std::sync::Arc;

use crate::error::{Result, StoreError};

/// Persisted, non-secret key material: the Argon2id parameters/salt and a verifier blob. The
/// master key is **not** here — it is re-derived from the passphrase on every unlock.
#[derive(Serialize, Deserialize)]
struct MasterKdfFile {
    params: KdfParams,
    verifier: Vec<u8>,
}

/// An unlocked Deputy store: the derived key hierarchy plus handles to the on-disk state.
///
/// The subkeys ([`SubKey`]) zeroize on drop, so dropping a `Vault` clears the live key
/// material; the on-disk store is opaque without re-deriving the master key from the
/// passphrase.
pub struct Vault {
    root: PathBuf,
    store_key: SubKey,
    audit_key: SubKey,
    db: RedbEngine,
    /// Encrypted metadata: a SpaceDB collection whose per-collection DEK is wrapped under the
    /// metadata-domain subkey (the KEK). SpaceDB AES-256-GCM-encrypts every row.
    meta: Collection<String, Vec<u8>>,
}

/// The SpaceDB collection holding all of Deputy's metadata, and the schema version bound into
/// each row's AEAD (bump only with a migration).
pub(crate) const META_COLLECTION: &str = "deputy_meta";
pub(crate) const META_SCHEMA: u32 = 1;

impl Vault {
    /// Initialize a brand-new vault rooted at `root`, protected by `passphrase`. Fails with
    /// [`StoreError::AlreadyInitialized`] if a vault already exists there.
    ///
    /// On-disk layout created under `root` (see `docs/STORAGE.md` §1):
    ///
    /// ```text
    /// keys/master.kdf      Argon2id params + verifier (no key)
    /// store/dirty/         sealed staging artifacts (content-addressed)
    /// store/prod/          sealed promoted artifacts (content-addressed, append-only)
    /// store/meta.db        encrypted metadata (SpaceDB Layer 0 KV)
    /// logs/audit.log       hash-chained append-only provenance
    /// ```
    pub fn create(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self> {
        Self::create_bound(root, passphrase, &[])
    }

    /// Like [`Self::create`], but additionally binds the vault to `binding` (e.g. an mID DID) — the
    /// vault can then only be unlocked with the same binding. An empty `binding` equals [`create`].
    pub fn create_bound(root: impl AsRef<Path>, passphrase: &[u8], binding: &[u8]) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let kdf_path = Self::kdf_path(&root);
        if kdf_path.exists() {
            return Err(StoreError::AlreadyInitialized);
        }

        let params = KdfParams::recommended()?;
        let master = derive_master_bound(passphrase, &params, binding)?;
        let verifier = make_verifier(&master)?;

        for dir in [
            root.join("keys"),
            root.join("store").join("dirty"),
            root.join("store").join("prod"),
            root.join("logs"),
        ] {
            fs::create_dir_all(dir)?;
        }

        let file = MasterKdfFile { params, verifier };
        write_atomic(&kdf_path, &serde_json::to_vec_pretty(&file)?)?;

        Self::from_master(root, &master)
    }

    /// Unlock an existing vault at `root` with `passphrase`. Fails with
    /// [`StoreError::WrongPassphrase`] if the passphrase does not match the stored verifier,
    /// and [`StoreError::NotInitialized`] if no vault exists there.
    pub fn unlock(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self> {
        Self::unlock_bound(root, passphrase, &[])
    }

    /// Like [`Self::unlock`], but requires the same `binding` the vault was created with. A wrong
    /// binding fails with [`StoreError::WrongPassphrase`] (the derived key won't match the verifier)
    /// — so a vault sealed under one mID identity cannot be opened under another. Empty = [`unlock`].
    pub fn unlock_bound(root: impl AsRef<Path>, passphrase: &[u8], binding: &[u8]) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let kdf_path = Self::kdf_path(&root);
        if !kdf_path.exists() {
            return Err(StoreError::NotInitialized);
        }

        let raw = fs::read(&kdf_path)?;
        let file: MasterKdfFile = serde_json::from_slice(&raw)?;
        let master = derive_master_bound(passphrase, &file.params, binding)?;
        if !check_verifier(&master, &file.verifier) {
            return Err(StoreError::WrongPassphrase);
        }

        Self::from_master(root, &master)
    }

    fn from_master(root: PathBuf, master: &MasterKey) -> Result<Self> {
        let store_key = derive_subkey(master, KeyDomain::Store);
        let audit_key = derive_subkey(master, KeyDomain::Audit);

        let db = RedbEngine::open(root.join("store").join("meta.db"))
            .map_err(|e| StoreError::Db(e.to_string()))?;

        // The metadata-domain subkey is the SpaceDB vault key (KEK); SpaceDB wraps a fresh
        // per-collection DEK under it and encrypts every metadata row with that DEK.
        let kek = derive_subkey(master, KeyDomain::Meta);
        let provider: Arc<dyn KeyProvider> = Arc::new(StaticKeyProvider::new(kek.expose_bytes()));
        let meta = Collection::open_or_create(&db, provider, META_COLLECTION, META_SCHEMA)
            .map_err(|e| StoreError::Db(e.to_string()))?;

        Ok(Self {
            root,
            store_key,
            audit_key,
            db,
            meta,
        })
    }

    fn kdf_path(root: &Path) -> PathBuf {
        root.join("keys").join("master.kdf")
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn store_key(&self) -> &SubKey {
        &self.store_key
    }

    pub(crate) fn audit_key(&self) -> &SubKey {
        &self.audit_key
    }

    pub(crate) fn db(&self) -> &RedbEngine {
        &self.db
    }

    pub(crate) fn meta(&self) -> &Collection<String, Vec<u8>> {
        &self.meta
    }
}

/// Write `bytes` to `path` atomically: write a sibling temp file, then rename over the target.
/// Creates parent directories as needed.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("path has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
