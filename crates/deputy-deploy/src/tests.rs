use std::fs;

use deputy_core::{
    ArtifactRef, ContentHash, DepName, DepRef, EcosystemId, Finding, Pin, ScanVerdict, Severity,
    StoreKind, Version as CoreVersion,
};
use deputy_store::Vault;
use flate2::write::GzEncoder;
use flate2::Compression;
use tempfile::TempDir;

use crate::{gate, materialize, promote, GateDecision, Promotion};

const PW: &[u8] = b"deploy passphrase";

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

/// Scan-clean and promote a crate into prod, returning its pin.
fn promote_clean(vault: &Vault, name: &str, version: &str, bytes: &[u8]) -> Pin {
    let hash = vault.put_artifact(StoreKind::Dirty, bytes).unwrap();
    vault
        .put_verdict(
            &ArtifactRef {
                ecosystem: EcosystemId::Cargo,
                hash: hash.clone(),
            },
            &ScanVerdict::Clean,
        )
        .unwrap();
    let outcome = promote(vault, EcosystemId::Cargo, name, version, &hash, None).unwrap();
    assert!(matches!(outcome, Promotion::Promoted(_)));
    pin(name, version, hash)
}

/// Build a synthetic `.crate` tarball from `(path, content)` pairs.
fn make_crate(files: &[(&str, &str)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, content.as_bytes())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

#[test]
fn clean_verdict_promotes_with_a_chained_receipt() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();

    let hash = vault
        .put_artifact(StoreKind::Dirty, b"a good crate")
        .unwrap();
    // Simulate a completed clean scan.
    vault
        .put_verdict(
            &ArtifactRef {
                ecosystem: EcosystemId::Cargo,
                hash: hash.clone(),
            },
            &ScanVerdict::Clean,
        )
        .unwrap();

    let outcome = promote(
        &vault,
        EcosystemId::Cargo,
        "foo",
        "1.0.0",
        &hash,
        Some("did:mata:abc"),
    )
    .unwrap();
    let Promotion::Promoted(receipt) = outcome else {
        panic!("expected promotion");
    };
    assert_eq!(receipt.name, "foo");
    assert_eq!(receipt.hash, hash);
    assert_eq!(receipt.actor.as_deref(), Some("did:mata:abc"));
    assert_eq!(receipt.chain_hash.len(), 64);

    // Prod now holds the artifact and the crate index.
    assert!(vault.has_artifact(StoreKind::Prod, &hash).unwrap());
    assert_eq!(
        vault.crate_hash(StoreKind::Prod, "foo", "1.0.0").unwrap(),
        Some(hash)
    );

    // The receipt is the latest entry in a valid audit chain.
    let entries = vault.audit_entries().unwrap();
    assert_eq!(entries.last().unwrap().kind, "promote");
    assert_eq!(vault.audit_verify().unwrap(), entries.len() as u64);
}

#[test]
fn findings_quarantine_and_never_reach_prod() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();

    let hash = vault
        .put_artifact(StoreKind::Dirty, b"a risky crate")
        .unwrap();
    let verdict = ScanVerdict::Findings(vec![Finding {
        id: "RUSTSEC-2024-0001".into(),
        severity: Severity::High,
        summary: "demo".into(),
    }]);
    vault
        .put_verdict(
            &ArtifactRef {
                ecosystem: EcosystemId::Cargo,
                hash: hash.clone(),
            },
            &verdict,
        )
        .unwrap();

    let outcome = promote(&vault, EcosystemId::Cargo, "foo", "1.0.0", &hash, None).unwrap();
    let Promotion::Quarantined { findings } = outcome else {
        panic!("expected quarantine");
    };
    assert_eq!(findings.len(), 1);

    // Nothing reached prod.
    assert!(!vault.has_artifact(StoreKind::Prod, &hash).unwrap());
    assert_eq!(
        vault.crate_hash(StoreKind::Prod, "foo", "1.0.0").unwrap(),
        None
    );
}

#[test]
fn promoting_an_unscanned_artifact_is_refused() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let hash = vault
        .put_artifact(StoreKind::Dirty, b"never scanned")
        .unwrap();

    // No verdict recorded => promotion must error rather than promote.
    assert!(promote(&vault, EcosystemId::Cargo, "foo", "1.0.0", &hash, None).is_err());
    assert!(!vault.has_artifact(StoreKind::Prod, &hash).unwrap());
}

#[test]
fn gate_allows_a_fully_promoted_clean_set() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let a = promote_clean(&vault, "alpha", "1.0.0", b"alpha bytes");
    let b = promote_clean(&vault, "beta", "2.0.0", b"beta bytes");

    let decision = gate(&vault, &[a, b]).unwrap();
    assert!(matches!(decision, GateDecision::Allowed { cleared: 2 }));
}

#[test]
fn gate_blocks_a_dependency_without_a_promotion_receipt() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let promoted = promote_clean(&vault, "alpha", "1.0.0", b"alpha bytes");

    // A second crate that was acquired + scanned clean but NEVER promoted (dirty-only).
    let dirty_hash = vault.put_artifact(StoreKind::Dirty, b"unpromoted").unwrap();
    vault
        .put_verdict(
            &ArtifactRef {
                ecosystem: EcosystemId::Cargo,
                hash: dirty_hash.clone(),
            },
            &ScanVerdict::Clean,
        )
        .unwrap();
    let dirty_only = pin("beta", "2.0.0", dirty_hash);

    let decision = gate(&vault, &[promoted, dirty_only]).unwrap();
    let GateDecision::Blocked { violations } = decision else {
        panic!("expected block");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].name, "beta");
    assert!(violations[0].reason.contains("no promotion receipt"));
}

#[test]
fn gate_blocks_an_unknown_hash() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let promoted = promote_clean(&vault, "alpha", "1.0.0", b"alpha bytes");
    let ghost = pin("ghost", "9.9.9", ContentHash::sha256([7u8; 32]));

    let decision = gate(&vault, &[promoted, ghost]).unwrap();
    assert!(!decision.is_allowed());
}

#[test]
fn gate_blocks_when_prod_index_was_substituted() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let p = promote_clean(&vault, "alpha", "1.0.0", b"alpha bytes");

    // Corrupt the prod crate index so it points at a different hash than the promoted one.
    vault
        .put_crate_hash(
            StoreKind::Prod,
            "alpha",
            "1.0.0",
            &ContentHash::sha256([0u8; 32]),
        )
        .unwrap();

    let GateDecision::Blocked { violations } = gate(&vault, &[p]).unwrap() else {
        panic!("expected block");
    };
    assert!(violations[0].reason.contains("substitution"));
}

#[test]
fn gate_blocks_when_the_audit_chain_is_broken() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let p = promote_clean(&vault, "alpha", "1.0.0", b"alpha bytes");

    let audit = dir.path().join("logs").join("audit.log");
    let mut bytes = fs::read(&audit).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    fs::write(&audit, &bytes).unwrap();

    let GateDecision::Blocked { violations } = gate(&vault, &[p]).unwrap() else {
        panic!("expected block");
    };
    assert!(violations[0].reason.contains("audit log integrity"));
}

#[test]
fn materialize_writes_a_vendor_tree_and_config() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();

    let lib_rs = "pub fn demo() {}\n";
    let crate_bytes = make_crate(&[
        (
            "demo-1.0.0/Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        ),
        ("demo-1.0.0/src/lib.rs", lib_rs),
    ]);
    let hash = vault.put_artifact(StoreKind::Prod, &crate_bytes).unwrap();

    let out = TempDir::new().unwrap();
    let plan = materialize(&vault, &[pin("demo", "1.0.0", hash.clone())], out.path()).unwrap();
    assert_eq!(plan.materialized.len(), 1);
    assert!(plan.missing.is_empty());

    let crate_dir = out.path().join("vendor").join("demo");
    assert!(crate_dir.join("Cargo.toml").is_file());
    assert!(crate_dir.join("src").join("lib.rs").is_file());

    // The checksum file records the crate package hash and each file's sha256.
    let checksum: serde_json::Value =
        serde_json::from_slice(&fs::read(crate_dir.join(".cargo-checksum.json")).unwrap()).unwrap();
    assert_eq!(checksum["package"], serde_json::json!(hash.to_hex()));
    let expected_lib = {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(lib_rs.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    assert_eq!(
        checksum["files"]["src/lib.rs"],
        serde_json::json!(expected_lib)
    );

    // The source-replacement config redirects crates-io to the vendor dir.
    let config = fs::read_to_string(out.path().join(".cargo").join("config.toml")).unwrap();
    assert!(config.contains("replace-with = \"deputy-prod\""));
    assert!(config.contains("directory = \"vendor\""));
}

#[test]
fn materialize_reports_unpromoted_pins_as_missing() {
    let dir = TempDir::new().unwrap();
    let vault = Vault::create(dir.path(), PW).unwrap();
    let out = TempDir::new().unwrap();

    let plan = materialize(
        &vault,
        &[pin("ghost", "1.0.0", ContentHash::sha256([3u8; 32]))],
        out.path(),
    )
    .unwrap();
    assert!(plan.materialized.is_empty());
    assert_eq!(plan.missing, vec![("ghost".to_owned(), "1.0.0".to_owned())]);
}
