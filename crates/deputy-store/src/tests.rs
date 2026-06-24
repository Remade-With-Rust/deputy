//! Integration tests for the storage layer: vault lock/unlock, content-addressed sealed
//! artifacts, persistence across re-derivation, encrypted metadata, and audit-chain integrity.

use std::fs;

use deputy_core::{
    ArtifactRef, ArtifactStore, EcosystemId, Finding, MetadataStore, ScanVerdict, Severity,
    StoreKind,
};
use serde_json::json;
use tempfile::TempDir;

use crate::{StoreError, Vault};

const PW: &[u8] = b"correct horse battery staple";

fn fresh() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    (dir, vault)
}

#[test]
fn create_then_unlock_roundtrips_an_artifact() {
    let (dir, vault) = fresh();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"hello deputy")
        .unwrap();
    drop(vault); // zeroizes keys

    let reopened = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(
        reopened.get_artifact(StoreKind::Dirty, &hash).unwrap(),
        b"hello deputy"
    );
}

#[test]
fn wrong_passphrase_is_rejected() {
    let dir = TempDir::new().unwrap();
    Vault::create(dir.path(), PW).unwrap();
    assert!(matches!(
        Vault::unlock(dir.path(), b"not the passphrase"),
        Err(StoreError::WrongPassphrase)
    ));
}

#[test]
fn create_twice_and_unlock_uninitialized_fail() {
    let dir = TempDir::new().unwrap();
    Vault::create(dir.path(), PW).unwrap();
    assert!(matches!(
        Vault::create(dir.path(), PW),
        Err(StoreError::AlreadyInitialized)
    ));

    let empty = TempDir::new().unwrap();
    assert!(matches!(
        Vault::unlock(empty.path(), PW),
        Err(StoreError::NotInitialized)
    ));
}

#[test]
fn put_is_idempotent_and_content_addressed() {
    let (_dir, vault) = fresh();
    let a = vault.put_artifact(StoreKind::Dirty, b"data").unwrap();
    let a_again = vault.put_artifact(StoreKind::Dirty, b"data").unwrap();
    assert_eq!(a, a_again, "same bytes => same address");

    let b = vault.put_artifact(StoreKind::Dirty, b"other").unwrap();
    assert_ne!(a, b, "different bytes => different address");
    assert!(vault.has_artifact(StoreKind::Dirty, &a).unwrap());
}

#[test]
fn dirty_and_prod_stores_are_isolated() {
    let (_dir, vault) = fresh();
    let hash = vault.put_artifact(StoreKind::Dirty, b"x").unwrap();
    assert!(vault.has_artifact(StoreKind::Dirty, &hash).unwrap());
    assert!(!vault.has_artifact(StoreKind::Prod, &hash).unwrap());
    assert!(matches!(
        vault.get_artifact(StoreKind::Prod, &hash),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn tampering_a_sealed_artifact_is_detected() {
    let (dir, vault) = fresh();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"secret payload")
        .unwrap();

    let hex = hash.to_hex();
    let path = dir
        .path()
        .join("store")
        .join("dirty")
        .join("sha256")
        .join(&hex[..2])
        .join(format!("{hex}.sealed"));
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&path, &bytes).unwrap();

    assert!(vault.get_artifact(StoreKind::Dirty, &hash).is_err());
}

#[test]
fn verdicts_roundtrip_and_persist() {
    let (dir, vault) = fresh();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"crate bytes")
        .unwrap();
    let artifact = ArtifactRef {
        ecosystem: EcosystemId::Cargo,
        hash,
    };

    assert_eq!(vault.get_verdict(&artifact).unwrap(), None);

    let verdict = ScanVerdict::Findings(vec![Finding {
        id: "RUSTSEC-2024-0001".into(),
        severity: Severity::High,
        summary: "example advisory".into(),
    }]);
    vault.put_verdict(&artifact, &verdict).unwrap();
    assert_eq!(vault.get_verdict(&artifact).unwrap(), Some(verdict.clone()));

    drop(vault);
    let reopened = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(reopened.get_verdict(&artifact).unwrap(), Some(verdict));
}

#[test]
fn audit_chain_links_and_verifies() {
    let (_dir, vault) = fresh();
    let e0 = vault.audit_append("promote", json!({"hash": "a"})).unwrap();
    assert_eq!(e0.seq, 0);
    assert_eq!(e0.prev_hex, "0".repeat(64), "first entry chains to genesis");

    let e1 = vault.audit_append("promote", json!({"hash": "b"})).unwrap();
    assert_eq!(e1.seq, 1);
    assert_eq!(
        e1.prev_hex, e0.this_hex,
        "each entry back-links to the previous"
    );

    assert_eq!(vault.audit_verify().unwrap(), 2);
    let entries = vault.audit_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].payload, json!({"hash": "b"}));
}

#[test]
fn audit_tampering_breaks_the_chain() {
    let (dir, vault) = fresh();
    vault.audit_append("event", json!({"n": 1})).unwrap();
    vault.audit_append("event", json!({"n": 2})).unwrap();

    let path = dir.path().join("logs").join("audit.log");
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&path, &bytes).unwrap();

    assert!(matches!(
        vault.audit_verify(),
        Err(StoreError::AuditChain { .. })
    ));
}

#[test]
fn core_trait_objects_drive_the_store() {
    let (_dir, vault) = fresh();

    let store: &dyn ArtifactStore = &vault;
    let hash = store.put(StoreKind::Dirty, b"via trait").unwrap();
    assert!(store.contains(StoreKind::Dirty, &hash).unwrap());
    assert_eq!(store.get(StoreKind::Dirty, &hash).unwrap(), b"via trait");

    let meta: &dyn MetadataStore = &vault;
    let artifact = ArtifactRef {
        ecosystem: EcosystemId::Cargo,
        hash,
    };
    meta.record_verdict(&artifact, &ScanVerdict::Clean).unwrap();
    assert_eq!(meta.verdict(&artifact).unwrap(), Some(ScanVerdict::Clean));
}

#[test]
fn crate_index_roundtrips_per_store_and_persists() {
    let (dir, vault) = fresh();
    let hash = vault
        .put_artifact(StoreKind::Prod, b"promoted bytes")
        .unwrap();

    assert_eq!(
        vault.crate_hash(StoreKind::Prod, "foo", "1.0.0").unwrap(),
        None
    );
    vault
        .put_crate_hash(StoreKind::Prod, "foo", "1.0.0", &hash)
        .unwrap();
    assert_eq!(
        vault.crate_hash(StoreKind::Prod, "foo", "1.0.0").unwrap(),
        Some(hash.clone())
    );
    // The index is per-store: prod entry does not leak into dirty.
    assert_eq!(
        vault.crate_hash(StoreKind::Dirty, "foo", "1.0.0").unwrap(),
        None
    );

    drop(vault);
    let reopened = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(
        reopened
            .crate_hash(StoreKind::Prod, "foo", "1.0.0")
            .unwrap(),
        Some(hash)
    );
}

#[test]
fn snapshot_survives_lost_shards_and_restores_a_working_vault() {
    // Build a vault with some artifact + metadata state.
    let (src_dir, vault) = fresh();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"important crate bytes")
        .unwrap();
    let artifact = ArtifactRef {
        ecosystem: EcosystemId::Cargo,
        hash: hash.clone(),
    };
    vault.put_verdict(&artifact, &ScanVerdict::Clean).unwrap();
    drop(vault); // flush + release the meta.db

    // Snapshot it: 4 data + 2 parity shards (tolerates 2 losses).
    let snap_dir = TempDir::new().unwrap();
    let info = crate::snapshot(src_dir.path(), snap_dir.path(), 4, 2).unwrap();
    assert_eq!(info.total_shards, 6);

    // Lose 2 shards (the parity budget).
    let mut removed = 0;
    for entry in std::fs::read_dir(snap_dir.path()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("shard-") && removed < 2 {
            std::fs::remove_file(&path).unwrap();
            removed += 1;
        }
    }
    assert_eq!(removed, 2);

    // Restore into a fresh location and confirm it's a working vault.
    let restore_dir = TempDir::new().unwrap();
    let target = restore_dir.path().join("vault");
    let restore_info = crate::restore(snap_dir.path(), &target).unwrap();
    assert_eq!(
        restore_info.shards_used, 4,
        "reconstructed from the 4 surviving shards"
    );

    let restored = Vault::unlock(&target, PW).unwrap();
    assert_eq!(
        restored.get_artifact(StoreKind::Dirty, &hash).unwrap(),
        b"important crate bytes"
    );
    assert_eq!(
        restored.get_verdict(&artifact).unwrap(),
        Some(ScanVerdict::Clean)
    );
}

#[test]
fn metadata_converges_across_two_vaults_via_crdt_sync() {
    // Two devices (same passphrase, so they share the sync key) with distinct metadata.
    let dir_a = TempDir::new().unwrap();
    let vault_a = Vault::create(dir_a.path(), PW).unwrap();
    let dir_b = TempDir::new().unwrap();
    let vault_b = Vault::create(dir_b.path(), PW).unwrap();

    let ha = vault_a
        .put_artifact(StoreKind::Prod, b"alpha bytes")
        .unwrap();
    vault_a
        .put_crate_hash(StoreKind::Prod, "alpha", "1.0.0", &ha)
        .unwrap();
    let hb = vault_b
        .put_artifact(StoreKind::Prod, b"beta bytes")
        .unwrap();
    vault_b
        .put_crate_hash(StoreKind::Prod, "beta", "2.0.0", &hb)
        .unwrap();

    // Bidirectional CRDT sync.
    let from_a = crate::export_metadata(&vault_a).unwrap();
    let from_b = crate::export_metadata(&vault_b).unwrap();
    crate::import_metadata(&vault_b, &from_a).unwrap();
    crate::import_metadata(&vault_a, &from_b).unwrap();

    // Both vaults converge on the union of the two crate-index entries.
    assert_eq!(
        vault_a
            .crate_hash(StoreKind::Prod, "alpha", "1.0.0")
            .unwrap(),
        Some(ha.clone())
    );
    assert_eq!(
        vault_a
            .crate_hash(StoreKind::Prod, "beta", "2.0.0")
            .unwrap(),
        Some(hb.clone())
    );
    assert_eq!(
        vault_b
            .crate_hash(StoreKind::Prod, "alpha", "1.0.0")
            .unwrap(),
        Some(ha)
    );
    assert_eq!(
        vault_b
            .crate_hash(StoreKind::Prod, "beta", "2.0.0")
            .unwrap(),
        Some(hb)
    );
}

#[test]
fn metadata_values_are_encrypted_at_rest_by_spacedb() {
    let (dir, vault) = fresh();
    let hash = vault.put_artifact(StoreKind::Dirty, b"x").unwrap();
    let artifact = ArtifactRef {
        ecosystem: EcosystemId::Cargo,
        hash,
    };

    // A distinctive marker placed in a metadata *value* (not the key).
    let marker = "TOP-SECRET-FINDING-MARKER-9f3a7c";
    vault
        .put_verdict(
            &artifact,
            &ScanVerdict::Findings(vec![Finding {
                id: marker.into(),
                severity: Severity::High,
                summary: "leak probe".into(),
            }]),
        )
        .unwrap();

    // The on-disk SpaceDB file must contain only ciphertext for the value — the marker, which
    // lives inside the encrypted row, must not appear in plaintext.
    let db_bytes = fs::read(dir.path().join("store").join("meta.db")).unwrap();
    assert!(
        !db_bytes
            .windows(marker.len())
            .any(|w| w == marker.as_bytes()),
        "metadata value leaked in plaintext — SpaceDB encryption is not active"
    );
    // Sanity: it still round-trips through decryption.
    assert!(!vault.get_verdict(&artifact).unwrap().unwrap().is_clean());
}
