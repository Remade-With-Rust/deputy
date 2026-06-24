use std::collections::BTreeMap;

use crate::inspect::CrateFacts;
use crate::language::Language;

/// A critical-point-of-failure score for one dependency, with the human-readable reasons that
/// produced it. Higher = more damage if this crate is compromised (`docs/PIPELINE.md` §3).
#[derive(Debug, Clone)]
pub struct RiskScore {
    pub name: String,
    pub version: String,
    /// Crates that transitively depend on this one.
    pub blast_radius: usize,
    /// Whether the crate's source was inspected (acquired) — capability fields are only
    /// meaningful when true.
    pub inspected: bool,
    pub has_build_script: bool,
    pub is_proc_macro: bool,
    pub unsafe_occurrences: usize,
    pub native_unsafe_lines: usize,
    pub links_native: Option<String>,
    /// Composite score in [0, ~100].
    pub score: f64,
    pub reasons: Vec<String>,
}

/// Aggregate language line counts across all inspected crates.
#[derive(Debug, Clone, Default)]
pub struct LanguageReport {
    pub by_language: BTreeMap<Language, usize>,
    pub crates_analyzed: usize,
}

impl LanguageReport {
    pub fn total_lines(&self) -> usize {
        self.by_language.values().sum()
    }
}

/// The full output of an analysis run.
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub language_report: LanguageReport,
    /// Risk scores, sorted descending (most critical first).
    pub risks: Vec<RiskScore>,
    pub total_crates: usize,
    pub inspected: usize,
}

/// Score one crate from its blast radius and (optional) inspected facts.
pub(crate) fn score(
    name: &str,
    version: &str,
    blast_radius: usize,
    graph_size: usize,
    facts: Option<&CrateFacts>,
) -> RiskScore {
    let mut score = 0.0;
    let mut reasons = Vec::new();

    // Blast radius dominates: up to 60 points, scaled by the fraction of the tree affected.
    let fraction = blast_radius as f64 / graph_size.max(1) as f64;
    score += fraction * 60.0;
    reasons.push(format!(
        "depended on by {blast_radius} crate(s) ({:.0}% of the tree)",
        fraction * 100.0
    ));

    let mut risk = RiskScore {
        name: name.to_owned(),
        version: version.to_owned(),
        blast_radius,
        inspected: facts.is_some(),
        has_build_script: false,
        is_proc_macro: false,
        unsafe_occurrences: 0,
        native_unsafe_lines: 0,
        links_native: None,
        score: 0.0,
        reasons: Vec::new(),
    };

    if let Some(facts) = facts {
        risk.has_build_script = facts.has_build_script;
        risk.is_proc_macro = facts.is_proc_macro;
        risk.unsafe_occurrences = facts.unsafe_occurrences;
        risk.native_unsafe_lines = facts.native_unsafe_lines();
        risk.links_native = facts.links_native.clone();

        if facts.has_build_script {
            score += 15.0;
            reasons.push("runs a build script (arbitrary code at build time)".to_owned());
        }
        if facts.is_proc_macro {
            score += 10.0;
            reasons.push("proc-macro: executes inside the compiler".to_owned());
        }
        if let Some(links) = &facts.links_native {
            score += 8.0;
            reasons.push(format!("links native library `{links}` (FFI boundary)"));
        }
        let native = facts.native_unsafe_lines();
        if native > 0 {
            score += 10.0;
            reasons.push(format!(
                "{native} line(s) of memory-unsafe native code (C/C++/asm)"
            ));
        }
        if facts.unsafe_occurrences > 0 {
            // Diminishing returns, capped.
            let contribution = ((facts.unsafe_occurrences as f64).ln_1p() * 3.0).min(12.0);
            score += contribution;
            reasons.push(format!(
                "{} `unsafe` occurrence(s)",
                facts.unsafe_occurrences
            ));
        }
    } else {
        reasons.push("not yet acquired — capability surface unknown".to_owned());
    }

    risk.score = score;
    risk.reasons = reasons;
    risk
}
