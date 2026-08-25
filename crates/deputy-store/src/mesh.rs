//! Disco-ready seams: SpaceDB's Transport, ShardStore, and Settlement, plus the
//! composed `spacedb-sdk` replica. Deputy builds against these locally so `disco`
//! can fill them on launch day (`building-the-new-internet` deploy.md).

use std::fs;
use std::path::{Path, PathBuf};

use spacedb_durability::{DurabilityResult, ShardStore};
use spacedb_meter::{LocalSettlement, RateCard, Settlement, Usage, UsageClaim};

/// A content-addressed shard store on the local disk. Disco fills the same
/// [`ShardStore`] trait with erasure shards across the mesh.
pub struct DiskShardStore {
    root: PathBuf,
}

impl DiskShardStore {
    /// Store shards as `<root>/<hex hash>` files.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self, hash: &[u8; 32]) -> PathBuf {
        let mut name = String::with_capacity(64);
        for b in hash {
            use std::fmt::Write;
            let _ = write!(name, "{b:02x}");
        }
        self.root.join(name)
    }
}

impl ShardStore for DiskShardStore {
    fn put(&self, hash: &[u8; 32], bytes: &[u8]) -> DurabilityResult<()> {
        fs::write(self.path(hash), bytes)
            .map_err(|e| spacedb_durability::DurabilityError::Store(e.to_string()))
    }

    fn get(&self, hash: &[u8; 32]) -> DurabilityResult<Option<Vec<u8>>> {
        let path = self.path(hash);
        if !path.exists() {
            return Ok(None);
        }
        fs::read(path)
            .map(Some)
            .map_err(|e| spacedb_durability::DurabilityError::Store(e.to_string()))
    }

    fn delete(&self, hash: &[u8; 32]) -> DurabilityResult<()> {
        let path = self.path(hash);
        if path.exists() {
            fs::remove_file(path)
                .map_err(|e| spacedb_durability::DurabilityError::Store(e.to_string()))?;
        }
        Ok(())
    }
}

/// Self-hosted settlement: price claims against a rate card, mint no `$MATA`.
/// Disco fills the same [`Settlement`] trait with Iron Bank.
pub fn local_settlement() -> LocalSettlement {
    LocalSettlement::new(RateCard {
        storage_per_gib_month: 1,
        compute_per_megafuel: 1,
        compute_per_invocation: 1,
        transit_per_gib: 1,
    })
}

/// Record a local-use claim so the settlement seam is exercised on every snapshot.
pub fn settle_local_use(
    settlement: &mut LocalSettlement,
    did: &str,
    byte_seconds: u128,
) -> Result<spacedb_meter::Settled, spacedb_meter::MeterError> {
    let claim = UsageClaim::new(did, did, Usage::Storage { byte_seconds }, 0, 1);
    settlement.settle(&claim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spacedb_replica::{connected_pair, Transport};
    use spacedb_sdk::{CrdtType, Database, Identity, Schema, Tier};
    use tempfile::TempDir;

    #[test]
    fn disk_shard_store_roundtrips() {
        let dir = TempDir::new().unwrap();
        let store = DiskShardStore::open(dir.path()).unwrap();
        let hash = [0x11u8; 32];
        store.put(&hash, b"shard-bytes").unwrap();
        assert_eq!(
            store.get(&hash).unwrap().as_deref(),
            Some(&b"shard-bytes"[..])
        );
        store.delete(&hash).unwrap();
        assert!(store.get(&hash).unwrap().is_none());
    }

    #[test]
    fn in_process_transport_delivers_frames() {
        let (a, b, _link) = connected_pair();
        a.send(b"hello").unwrap();
        assert_eq!(b.drain(), vec![b"hello".to_vec()]);
    }

    #[test]
    fn local_settlement_prices_a_claim() {
        let mut settlement = local_settlement();
        let receipt =
            settle_local_use(&mut settlement, "did:mata:owner", (1u128 << 30) * 2_592_000).unwrap();
        assert_eq!(receipt.settles_to_did, "did:mata:owner");
        // 1 GiB held for a 30-day month at 1 micro-$MATA / GiB-month prices to 1.
        assert_eq!(settlement.tallied("did:mata:owner"), 1);
    }

    #[test]
    fn spacedb_sdk_opens_an_offline_replica() {
        let owner = Identity::generate("did:mata:deputy-test").unwrap();
        let mut db = Database::open(Identity::generate("did:mata:home-1").unwrap());
        db.register_identity(&owner).unwrap();
        db.define(
            Schema::new("deputy_meta")
                .field("verdict", CrdtType::Register, Tier::Convergent)
                .field("crate_index", CrdtType::Register, Tier::Causal),
        );
        assert!(!spacedb_sdk::rusty_alloc_enabled());
    }
}
