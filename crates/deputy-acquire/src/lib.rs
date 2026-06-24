//! # deputy-acquire
//!
//! Orchestrates acquisition: discover a source's pinned dependencies, fetch each, verify its
//! content hash, and seal it into the **dirty** store with a provenance record
//! (`docs/PIPELINE.md` §1–§2). It is generic over [`deputy_core::DepEcosystem`], so it works
//! for Cargo today and any future ecosystem without change.
//!
//! Each crate is handled independently and fail-closed: a fetch or integrity failure is
//! recorded in the report and the artifact is **not** sealed, but the run continues for the
//! rest. Only bytes whose SHA-256 matches the pinned checksum ever reach the store.
#![forbid(unsafe_code)]

use deputy_core::{ContentHash, DepEcosystem, Result, SourceId, StoreKind};
use deputy_store::Vault;
use serde::Serialize;
use serde_json::json;

/// A successfully acquired crate.
#[derive(Debug, Clone, Serialize)]
pub struct AcquiredCrate {
    pub name: String,
    pub version: String,
    pub hash: ContentHash,
}

/// A crate that could not be acquired (fetch error or integrity mismatch).
#[derive(Debug, Clone, Serialize)]
pub struct AcquireFailure {
    pub name: String,
    pub version: String,
    pub error: String,
}

/// The outcome of an acquisition run.
#[derive(Debug, Default, Serialize)]
pub struct AcquireReport {
    pub acquired: Vec<AcquiredCrate>,
    pub already_present: usize,
    pub failed: Vec<AcquireFailure>,
}

impl AcquireReport {
    /// Total dependencies considered (newly acquired + already present + failed).
    pub fn total(&self) -> usize {
        self.acquired.len() + self.already_present + self.failed.len()
    }

    /// Whether every considered dependency was acquired or already present.
    pub fn is_clean(&self) -> bool {
        self.failed.is_empty()
    }
}

enum Outcome {
    Acquired(ContentHash),
    AlreadyPresent,
}

/// Discover the source's pinned dependencies and acquire each into the dirty store of `vault`.
///
/// `discover` failing aborts the run (we cannot proceed without the pin set); per-crate
/// failures are collected into [`AcquireReport::failed`].
pub fn acquire(
    vault: &Vault,
    ecosystem: &dyn DepEcosystem,
    source: &SourceId,
) -> Result<AcquireReport> {
    let pins = ecosystem.discover(source)?;
    let mut report = AcquireReport::default();

    for pin in &pins {
        let name = pin.dep.name.as_str().to_owned();
        let version = pin.dep.version.as_str().to_owned();
        match acquire_one(vault, ecosystem, pin) {
            Ok(Outcome::Acquired(hash)) => report.acquired.push(AcquiredCrate {
                name,
                version,
                hash,
            }),
            Ok(Outcome::AlreadyPresent) => report.already_present += 1,
            Err(e) => report.failed.push(AcquireFailure {
                name,
                version,
                error: e.to_string(),
            }),
        }
    }

    Ok(report)
}

fn acquire_one(
    vault: &Vault,
    ecosystem: &dyn DepEcosystem,
    pin: &deputy_core::Pin,
) -> Result<Outcome> {
    // Content-addressed + idempotent: if the exact pinned hash is already staged, skip the
    // network entirely.
    if vault.has_artifact(StoreKind::Dirty, &pin.expected)? {
        return Ok(Outcome::AlreadyPresent);
    }

    let raw = ecosystem.fetch(pin)?;
    ecosystem.verify_integrity(pin, &raw)?; // fail-closed: nothing is sealed until this passes
    let hash = vault.put_artifact(StoreKind::Dirty, &raw)?;

    vault.audit_append(
        "acquire",
        json!({
            "ecosystem": ecosystem.id().as_str(),
            "name": pin.dep.name.as_str(),
            "version": pin.dep.version.as_str(),
            "hash": hash.to_string(),
        }),
    )?;

    Ok(Outcome::Acquired(hash))
}

#[cfg(test)]
mod tests;
