use std::collections::HashMap;

use deputy_core::{
    ContentHash, DepEcosystem, DepName, DepRef, EcosystemId, Error, Pin, Result, SourceId,
    StoreKind, Version,
};
use deputy_store::Vault;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::acquire;

fn sha256(bytes: &[u8]) -> ContentHash {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(Sha256::digest(bytes).as_slice());
    ContentHash::sha256(digest)
}

fn pin(name: &str, version: &str, expected: ContentHash) -> Pin {
    Pin {
        dep: DepRef {
            ecosystem: EcosystemId::Cargo,
            name: DepName::new(name),
            version: Version::new(version),
        },
        expected,
    }
}

/// A network-free [`DepEcosystem`]: `fetch` returns canned bytes keyed by crate name, and
/// `verify_integrity` runs the real SHA-256 check (so the integrity gate is genuinely tested).
struct FakeEcosystem {
    pins: Vec<Pin>,
    blobs: HashMap<String, Vec<u8>>,
}

impl DepEcosystem for FakeEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Cargo
    }

    fn discover(&self, _source: &SourceId) -> Result<Vec<Pin>> {
        Ok(self.pins.clone())
    }

    fn fetch(&self, pin: &Pin) -> Result<Vec<u8>> {
        self.blobs
            .get(pin.dep.name.as_str())
            .cloned()
            .ok_or_else(|| Error::NotFound {
                what: pin.dep.name.as_str().to_owned(),
            })
    }

    fn verify_integrity(&self, pin: &Pin, raw: &[u8]) -> Result<()> {
        let actual = sha256(raw);
        if actual == pin.expected {
            Ok(())
        } else {
            Err(Error::Integrity {
                expected: pin.expected.to_string(),
                actual: actual.to_string(),
            })
        }
    }
}

#[test]
fn acquires_verifies_and_records_provenance() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), b"pw").unwrap();

    let good = b"good crate bytes".to_vec();
    let good_hash = sha256(&good);
    // The pin expects one thing, but the "CDN" serves different bytes => integrity mismatch.
    let tampered_expected = sha256(b"what the lockfile pinned");

    let mut blobs = HashMap::new();
    blobs.insert("good".to_string(), good.clone());
    blobs.insert("tampered".to_string(), b"but the CDN served this".to_vec());

    let eco = FakeEcosystem {
        pins: vec![
            pin("good", "1.0.0", good_hash.clone()),
            pin("tampered", "2.0.0", tampered_expected.clone()),
        ],
        blobs,
    };

    let report = acquire(&vault, &eco, &SourceId::new("unused")).unwrap();

    assert_eq!(report.acquired.len(), 1);
    assert_eq!(report.acquired[0].name, "good");
    assert_eq!(report.acquired[0].hash, good_hash);
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].name, "tampered");
    assert!(!report.is_clean());

    // The good crate is sealed in the dirty store; the tampered one never reached it.
    assert!(vault.has_artifact(StoreKind::Dirty, &good_hash).unwrap());
    assert!(!vault
        .has_artifact(StoreKind::Dirty, &tampered_expected)
        .unwrap());
    // Exactly one provenance record (only the successful acquisition).
    assert_eq!(vault.audit_entries().unwrap().len(), 1);
}

#[test]
fn acquisition_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), b"pw").unwrap();

    let bytes = b"reproducible crate".to_vec();
    let hash = sha256(&bytes);
    let mut blobs = HashMap::new();
    blobs.insert("c".to_string(), bytes);
    let eco = FakeEcosystem {
        pins: vec![pin("c", "1.0.0", hash)],
        blobs,
    };

    let first = acquire(&vault, &eco, &SourceId::new("x")).unwrap();
    assert_eq!(first.acquired.len(), 1);

    let second = acquire(&vault, &eco, &SourceId::new("x")).unwrap();
    assert_eq!(second.acquired.len(), 0);
    assert_eq!(second.already_present, 1);
    // No duplicate provenance entry on the idempotent re-run.
    assert_eq!(vault.audit_entries().unwrap().len(), 1);
}
