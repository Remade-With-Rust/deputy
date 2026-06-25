//! # deputy-scan
//!
//! Scanners that decide whether a dirty artifact is safe to promote (`docs/PIPELINE.md` §4).
//! [`scan`] runs, fail-closed, against one pinned dependency and records a `ScanVerdict`:
//!
//! **Blocking findings** (make the verdict non-clean → not promotable):
//! - integrity failure — the sealed artifact does not decrypt / hash to its address,
//! - substitution — prod holds a *different* hash for the same `name@version`,
//! - advisory match — the pinned version is hit by a known advisory ([`AdvisoryDb`]).
//!
//! **Notes** (informational, non-blocking): build scripts, proc-macros, `unsafe` / native code.
#![forbid(unsafe_code)]

mod advisory;
mod scan;

#[cfg(test)]
mod tests;

pub use advisory::{Advisory, AdvisoryDb, VulnMatch};
pub use scan::{scan, ScanReport};
