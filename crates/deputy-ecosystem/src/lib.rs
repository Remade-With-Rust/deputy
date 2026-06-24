//! # deputy-ecosystem
//!
//! Dependency-ecosystem implementations behind the `deputy_core::DepEcosystem` trait. Cargo is
//! the first (and currently only) implementor; npm/PyPI/Go follow without pipeline-core
//! changes (`docs/PIPELINE.md` §0, §8).
//!
//! [`CargoEcosystem`] reads a `Cargo.lock` for pinned crates.io dependencies, fetches each
//! immutable `.crate` tarball from the CDN, and verifies its SHA-256 against the lockfile
//! checksum — acquisition is driven by the *resolved* graph, never free-text names, which is
//! what makes it tamper-evident and typosquat-resistant (`docs/THREAT_MODEL.md` ADV-3).
#![forbid(unsafe_code)]

mod cargo;
mod lockfile;

#[cfg(test)]
mod tests;

pub use cargo::CargoEcosystem;
pub use lockfile::parse_pins;
