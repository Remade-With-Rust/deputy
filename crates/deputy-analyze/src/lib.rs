//! # deputy-analyze
//!
//! Language analytics and **critical-point-of-failure** scoring for a dependency tree
//! (`docs/PIPELINE.md` §3).
//!
//! Two signals are combined per dependency:
//! - **Blast radius** — how many crates transitively depend on it, from the `Cargo.lock` graph
//!   (computable offline, no acquisition needed). This dominates the score.
//! - **Capability surface** — from inspecting the acquired `.crate`: build scripts, proc-macros,
//!   `unsafe`, native FFI, and the language mix (memory-unsafe C/C++/asm raise risk).
//!
//! [`analyze`] takes a `Cargo.lock` plus a callback that returns a crate's `.crate` bytes when
//! available (e.g. from the dirty store), so it is decoupled from storage and easy to test.
#![forbid(unsafe_code)]

mod graph;
mod inspect;
mod language;
mod risk;

#[cfg(test)]
mod tests;

use std::cmp::Ordering;

use deputy_core::Result;

pub use graph::{parse_lockfile, DepGraph, LockedCrate};
pub use inspect::{inspect, CrateFacts};
pub use language::Language;
pub use risk::{AnalysisReport, LanguageReport, RiskScore};

/// Analyze a dependency tree from its `Cargo.lock`.
///
/// `fetch_crate(name, version)` returns the crate's `.crate` tarball bytes if it has been
/// acquired, or `None` (in which case the crate is scored on blast radius alone). The returned
/// risks are sorted most-critical first.
pub fn analyze(
    lockfile_toml: &str,
    mut fetch_crate: impl FnMut(&str, &str) -> Option<Vec<u8>>,
) -> Result<AnalysisReport> {
    let crates = parse_lockfile(lockfile_toml)?;
    let graph = DepGraph::from_locked(&crates);

    let mut risks = Vec::with_capacity(crates.len());
    let mut by_language: std::collections::BTreeMap<Language, usize> = Default::default();
    let mut inspected = 0usize;

    for c in &crates {
        let blast_radius = graph.blast_radius(&c.name, &c.version);
        let facts = fetch_crate(&c.name, &c.version).and_then(|bytes| inspect(&bytes).ok());

        if let Some(facts) = &facts {
            inspected += 1;
            for (lang, lines) in &facts.languages {
                *by_language.entry(*lang).or_default() += lines;
            }
        }

        risks.push(risk::score(
            &c.name,
            &c.version,
            blast_radius,
            graph.len(),
            facts.as_ref(),
        ));
    }

    risks.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| b.blast_radius.cmp(&a.blast_radius))
            .then_with(|| a.name.cmp(&b.name))
    });

    Ok(AnalysisReport {
        language_report: LanguageReport {
            by_language,
            crates_analyzed: inspected,
        },
        risks,
        total_crates: crates.len(),
        inspected,
    })
}
