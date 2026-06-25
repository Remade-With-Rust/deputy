use std::fs;

use deputy_core::{
    ArtifactRef, ContentHash, DepName, DepRef, EcosystemId, Pin, ScanVerdict, Severity, StoreKind,
    Version as CoreVersion,
};
use deputy_store::Vault;
use semver::VersionReq;
use tempfile::TempDir;

use crate::{scan, Advisory, AdvisoryDb, VulnMatch};

const PW: &[u8] = b"scan passphrase";

fn pin(name: &str, version: &str, hash: ContentHash) -> Pin {
    Pin {
        dep: DepRef {
            ecosystem: EcosystemId::Cargo,
            name: DepName::new(name),
            version: CoreVersion::new(version),
        },
        expected: hash,
    }
}

fn findings(verdict: &ScanVerdict) -> &[deputy_core::Finding] {
    match verdict {
        ScanVerdict::Findings(f) => f,
        ScanVerdict::Clean => &[],
    }
}

#[test]
fn clean_scan_records_a_clean_verdict() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"crate bytes")
        .unwrap();

    let report = scan(
        &vault,
        &pin("foo", "1.0.0", hash.clone()),
        &AdvisoryDb::new(),
    )
    .unwrap();
    assert!(report.is_clean());

    let artifact = ArtifactRef {
        ecosystem: EcosystemId::Cargo,
        hash,
    };
    assert_eq!(
        vault.get_verdict(&artifact).unwrap(),
        Some(ScanVerdict::Clean)
    );
}

#[test]
fn matching_advisory_blocks_but_non_matching_version_is_clean() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();

    let mut db = AdvisoryDb::new();
    db.add(Advisory {
        id: "RUSTSEC-2024-9999".into(),
        package: "vuln".into(),
        matcher: VulnMatch::Vulnerable(VersionReq::parse("<2.0.0").unwrap()),
        severity: Severity::High,
        title: "demo advisory".into(),
    });

    let vuln_hash = vault.put_artifact(StoreKind::Dirty, b"vulnerable").unwrap();
    let report = scan(&vault, &pin("vuln", "1.5.0", vuln_hash), &db).unwrap();
    assert!(!report.is_clean());
    assert!(findings(&report.verdict)
        .iter()
        .any(|f| f.id == "RUSTSEC-2024-9999" && f.severity == Severity::High));

    let safe_hash = vault.put_artifact(StoreKind::Dirty, b"patched").unwrap();
    let safe = scan(&vault, &pin("vuln", "2.0.1", safe_hash), &db).unwrap();
    assert!(safe.is_clean());
}

#[test]
fn substitution_against_prod_is_detected() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();

    // prod records a different hash for foo@1.0.0 than the dirty pin presents.
    let dirty_hash = vault
        .put_artifact(StoreKind::Dirty, b"the dirty artifact")
        .unwrap();
    let prod_hash = vault
        .put_artifact(StoreKind::Prod, b"a DIFFERENT prod artifact")
        .unwrap();
    vault
        .put_crate_hash(StoreKind::Prod, "foo", "1.0.0", &prod_hash)
        .unwrap();

    let report = scan(&vault, &pin("foo", "1.0.0", dirty_hash), &AdvisoryDb::new()).unwrap();
    assert!(!report.is_clean());
    assert!(findings(&report.verdict)
        .iter()
        .any(|f| f.id == "DEPUTY-SUBSTITUTION"));
}

#[test]
fn tampered_artifact_fails_integrity() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"to be tampered with")
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

    let report = scan(&vault, &pin("foo", "1.0.0", hash), &AdvisoryDb::new()).unwrap();
    assert!(!report.is_clean());
    assert!(findings(&report.verdict)
        .iter()
        .any(|f| f.id == "DEPUTY-INTEGRITY"));
}

#[test]
fn unacquired_artifact_is_noted_not_failed() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let ghost = ContentHash::sha256([9u8; 32]);

    let report = scan(&vault, &pin("ghost", "1.0.0", ghost), &AdvisoryDb::new()).unwrap();
    assert!(report.is_clean());
    assert!(report.notes.iter().any(|n| n.contains("not acquired")));
}

#[test]
fn advisory_db_loads_from_toml_and_matches_by_version() {
    let toml = r#"
[[advisory]]
id = "RUSTSEC-2024-0001"
package = "foo"
vulnerable = "<1.2.3"
severity = "critical"
title = "Use-after-free in foo"
"#;
    let db = AdvisoryDb::from_toml(toml).unwrap();
    assert_eq!(db.len(), 1);
    assert_eq!(
        db.check("foo", &semver::Version::parse("1.0.0").unwrap())
            .len(),
        1
    );
    assert!(db
        .check("foo", &semver::Version::parse("1.2.3").unwrap())
        .is_empty());
    assert!(db
        .check("other", &semver::Version::parse("0.1.0").unwrap())
        .is_empty());
}
