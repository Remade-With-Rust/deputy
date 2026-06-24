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
