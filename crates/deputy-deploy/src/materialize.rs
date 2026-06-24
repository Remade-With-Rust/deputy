use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use deputy_core::{ContentHash, Error, Pin, Result, StoreKind};
use deputy_store::{StoreError, Vault};
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::Archive;

/// One crate written into the vendor tree.
#[derive(Debug, Clone, Serialize)]
pub struct MaterializedCrate {
    pub name: String,
    pub version: String,
    pub hash: ContentHash,
    /// The vendor subdirectory name (relative to the vendor dir).
    pub dir: String,
}

/// The outcome of materializing prod into a source tree.
#[derive(Debug, Clone, Serialize)]
pub struct MaterializePlan {
    pub vendor_dir: PathBuf,
    pub config_path: PathBuf,
    pub materialized: Vec<MaterializedCrate>,
    /// Pins not present in prod (not promoted) — skipped.
    pub missing: Vec<(String, String)>,
}

/// Vendor the prod copies of `pins` into `out_dir`, then write a Cargo source-replacement config
/// so builds in `out_dir` consume Deputy's owned, verified artifacts instead of crates.io
/// (`docs/PIPELINE.md` §6).
///
/// Produces `out_dir/vendor/<dir>/` (extracted crate + `.cargo-checksum.json`) for each promoted
/// pin, and `out_dir/.cargo/config.toml` redirecting `crates-io` to the vendor directory. Pins
/// that are not in prod are reported in [`MaterializePlan::missing`] and skipped.
pub fn materialize(vault: &Vault, pins: &[Pin], out_dir: &Path) -> Result<MaterializePlan> {
    let vendor_dir = out_dir.join("vendor");

    // Crate names that appear at more than one version need version-qualified dir names.
    let mut name_counts: HashMap<&str, usize> = HashMap::new();
    for pin in pins {
        *name_counts.entry(pin.dep.name.as_str()).or_default() += 1;
    }

    let mut materialized = Vec::new();
    let mut missing = Vec::new();

    for pin in pins {
        let name = pin.dep.name.as_str();
        let version = pin.dep.version.as_str();

        let raw = match vault.get_artifact(StoreKind::Prod, &pin.expected) {
            Ok(bytes) => bytes,
            Err(StoreError::NotFound(_)) => {
                missing.push((name.to_owned(), version.to_owned()));
                continue;
            }
            Err(e) => return Err(e.into()),
        };

        let dir = if name_counts.get(name).copied().unwrap_or(0) > 1 {
            format!("{name}-{version}")
        } else {
            name.to_owned()
        };
        let crate_dir = vendor_dir.join(&dir);

        let files = extract_crate(&raw, &crate_dir)?;
        write_checksum_json(&crate_dir, &files, &pin.expected)?;

        materialized.push(MaterializedCrate {
            name: name.to_owned(),
            version: version.to_owned(),
            hash: pin.expected.clone(),
            dir,
        });
    }

    let config_path = write_cargo_config(out_dir)?;

    Ok(MaterializePlan {
        vendor_dir,
        config_path,
        materialized,
        missing,
    })
}

/// Extract a `.crate` tarball into `dest`, returning the relative-path → sha256-hex map cargo's
/// `.cargo-checksum.json` requires. Rejects unsafe (non-relative / `..`) archive paths.
fn extract_crate(crate_tar_gz: &[u8], dest: &Path) -> Result<BTreeMap<String, String>> {
    let mut archive = Archive::new(GzDecoder::new(crate_tar_gz));
    let mut files = BTreeMap::new();

    let entries = archive.entries().map_err(|e| Error::Malformed {
        what: format!("not a .crate tarball: {e}"),
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|e| Error::Malformed {
            what: format!("tar entry: {e}"),
        })?;
        let path = entry
            .path()
            .map_err(|e| Error::Malformed {
                what: format!("tar path: {e}"),
            })?
            .into_owned();

        // Strip the leading `<name>-<version>/` component.
        let mut components = path.components();
        components.next();
        let relative = components.as_path().to_path_buf();
        if relative.as_os_str().is_empty() {
            continue;
        }
        // Defense in depth: never let an archive escape the vendor dir.
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(Error::Malformed {
                what: format!("unsafe path in crate archive: {}", path.display()),
            });
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let mut content = Vec::new();
        entry
            .read_to_end(&mut content)
            .map_err(|e| Error::Malformed {
                what: format!("read tar entry: {e}"),
            })?;

        let out_path = dest.join(&relative);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(io_backend)?;
        }
        fs::write(&out_path, &content).map_err(io_backend)?;

        files.insert(to_unix(&relative), sha256_hex(&content));
    }

    Ok(files)
}

fn write_checksum_json(
    crate_dir: &Path,
    files: &BTreeMap<String, String>,
    package: &ContentHash,
) -> Result<()> {
    let doc = serde_json::json!({ "files": files, "package": package.to_hex() });
    let bytes = serde_json::to_vec(&doc).map_err(|e| Error::Backend {
        detail: format!("checksum json: {e}"),
    })?;
    fs::write(crate_dir.join(".cargo-checksum.json"), bytes).map_err(io_backend)?;
    Ok(())
}

fn write_cargo_config(out_dir: &Path) -> Result<PathBuf> {
    let cargo_dir = out_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).map_err(io_backend)?;
    let config = "\
# Generated by Deputy: build against owned, verified prod copies instead of crates.io.
[source.crates-io]
replace-with = \"deputy-prod\"

[source.deputy-prod]
directory = \"vendor\"
";
    let config_path = cargo_dir.join("config.toml");
    fs::write(&config_path, config).map_err(io_backend)?;
    Ok(config_path)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest.as_slice() {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn to_unix(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn io_backend(e: std::io::Error) -> Error {
    Error::Backend {
        detail: format!("vendor i/o: {e}"),
    }
}
