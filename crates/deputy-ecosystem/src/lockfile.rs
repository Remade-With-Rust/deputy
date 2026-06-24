use deputy_core::{ContentHash, DepName, DepRef, EcosystemId, Error, Pin, Result, Version};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LockFile {
    #[serde(default)]
    package: Vec<LockPackage>,
}

#[derive(Debug, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

/// Parse the fetchable pins from the text of a `Cargo.lock`.
///
/// Returns one [`Pin`] per crates.io dependency that carries a `checksum`. Dependencies with
/// no `source` (workspace/path members) or no checksum, and non-crates.io registries / git
/// deps, are skipped — Deputy only acquires what it can content-verify (`docs/PIPELINE.md` §1).
pub fn parse_pins(lock_toml: &str) -> Result<Vec<Pin>> {
    let lock: LockFile = toml::from_str(lock_toml).map_err(|e| Error::Malformed {
        what: format!("Cargo.lock: {e}"),
    })?;

    let mut pins = Vec::new();
    for pkg in lock.package {
        let (Some(source), Some(checksum)) = (pkg.source.as_deref(), pkg.checksum.as_deref())
        else {
            continue;
        };
        if !is_crates_io(source) {
            continue;
        }
        pins.push(Pin {
            dep: DepRef {
                ecosystem: EcosystemId::Cargo,
                name: DepName::new(pkg.name),
                version: Version::new(pkg.version),
            },
            expected: ContentHash::from_sha256_hex(checksum)?,
        });
    }
    Ok(pins)
}

/// Both the git index (`registry+https://github.com/rust-lang/crates.io-index`) and the sparse
/// index (`sparse+https://index.crates.io/`) name crates.io.
fn is_crates_io(source: &str) -> bool {
    source.contains("crates.io")
}
