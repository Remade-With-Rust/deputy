use deputy_core::{ContentHash, DepEcosystem, DepName, DepRef, EcosystemId, Pin, Version};
use sha2::{Digest, Sha256};

use crate::{parse_pins, CargoEcosystem};

const LOCK: &str = r#"
version = 4

[[package]]
name = "deputy-core"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"
dependencies = ["serde_derive"]

[[package]]
name = "sparse-crate"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
checksum = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

[[package]]
name = "no-checksum"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "from-git"
version = "0.1.0"
source = "git+https://github.com/example/from-git#abc123"
checksum = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
"#;

#[test]
fn parse_pins_keeps_only_crates_io_with_checksums() {
    let pins = parse_pins(LOCK).unwrap();
    // serde + sparse-crate; deputy-core (no source), no-checksum, and from-git are skipped.
    assert_eq!(pins.len(), 2);

    let serde = pins
        .iter()
        .find(|p| p.dep.name.as_str() == "serde")
        .unwrap();
    assert_eq!(serde.dep.version.as_str(), "1.0.228");
    assert_eq!(serde.dep.ecosystem, EcosystemId::Cargo);
    assert_eq!(serde.expected, ContentHash::sha256([0xab; 32]));

    assert!(pins.iter().any(|p| p.dep.name.as_str() == "sparse-crate"));
    assert!(!pins.iter().any(|p| p.dep.name.as_str() == "from-git"));
    assert!(!pins.iter().any(|p| p.dep.name.as_str() == "no-checksum"));
}

#[test]
fn malformed_lockfile_is_rejected() {
    assert!(parse_pins("this is not = valid = toml").is_err());
}

#[test]
fn verify_integrity_accepts_matching_bytes_and_rejects_tampering() {
    let eco = CargoEcosystem::new();
    let raw = b"the real .crate bytes";

    let mut digest = [0u8; 32];
    digest.copy_from_slice(Sha256::digest(raw).as_slice());
    let good = Pin {
        dep: DepRef {
            ecosystem: EcosystemId::Cargo,
            name: DepName::new("demo"),
            version: Version::new("1.0.0"),
        },
        expected: ContentHash::sha256(digest),
    };
    assert!(eco.verify_integrity(&good, raw).is_ok());

    let bad = Pin {
        expected: ContentHash::sha256([0x00; 32]),
        ..good.clone()
    };
    assert!(eco.verify_integrity(&bad, raw).is_err());
    // A tampered byte must also fail against the genuine pin.
    assert!(eco
        .verify_integrity(&good, b"the real .crate bytez")
        .is_err());
}
