use std::io::Read as _;
use std::path::{Path, PathBuf};

use deputy_core::{ContentHash, DepEcosystem, EcosystemId, Error, Pin, Result, SourceId};
use sha2::{Digest, Sha256};

use crate::lockfile::parse_pins;

/// The Cargo / crates.io ecosystem.
///
/// - `discover` reads a `Cargo.lock` (the `SourceId` is a path to a repo dir or directly to a
///   lockfile) and returns the pinned crates.io dependencies.
/// - `fetch` downloads the immutable `.crate` tarball from the crates.io CDN over TLS.
/// - `verify_integrity` checks the bytes' SHA-256 against the lockfile checksum.
#[derive(Debug, Default, Clone)]
pub struct CargoEcosystem;

impl CargoEcosystem {
    pub fn new() -> Self {
        Self
    }

    fn lock_path(source: &SourceId) -> PathBuf {
        let path = Path::new(source.as_str());
        if path.is_dir() {
            path.join("Cargo.lock")
        } else {
            path.to_path_buf()
        }
    }

    /// The immutable CDN URL for a crate version's `.crate` tarball.
    fn download_url(pin: &Pin) -> String {
        let name = pin.dep.name.as_str();
        let version = pin.dep.version.as_str();
        format!("https://static.crates.io/crates/{name}/{name}-{version}.crate")
    }
}

fn sha256(bytes: &[u8]) -> ContentHash {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    ContentHash::sha256(out)
}

impl DepEcosystem for CargoEcosystem {
    fn id(&self) -> EcosystemId {
        EcosystemId::Cargo
    }

    fn discover(&self, source: &SourceId) -> Result<Vec<Pin>> {
        let path = Self::lock_path(source);
        let text = std::fs::read_to_string(&path).map_err(|e| Error::Backend {
            detail: format!("read {}: {e}", path.display()),
        })?;
        parse_pins(&text)
    }

    fn fetch(&self, pin: &Pin) -> Result<Vec<u8>> {
        let url = Self::download_url(pin);
        let response = ureq::get(&url).call().map_err(|e| Error::Backend {
            detail: format!("fetch {url}: {e}"),
        })?;
        let mut buf = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| Error::Backend {
                detail: format!("read body {url}: {e}"),
            })?;
        Ok(buf)
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
