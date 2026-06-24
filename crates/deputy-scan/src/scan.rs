use deputy_analyze::inspect;
use deputy_core::{ArtifactRef, Finding, Pin, Result, ScanVerdict, Severity, StoreKind};
use deputy_store::{StoreError, Vault};
use semver::Version;
use serde::Serialize;

use crate::advisory::AdvisoryDb;

/// The result of scanning a dirty artifact: the blocking [`ScanVerdict`] plus non-blocking
/// informational notes (capability surface, skipped checks).
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub verdict: ScanVerdict,
    pub notes: Vec<String>,
}

impl ScanReport {
    pub fn is_clean(&self) -> bool {
        self.verdict.is_clean()
    }
}

/// Scan one pinned dependency in the dirty store and record the verdict in metadata
/// (`Analyzed → Scanned`). Fail-closed: any blocking finding makes the artifact non-promotable.
pub fn scan(vault: &Vault, pin: &Pin, advisories: &AdvisoryDb) -> Result<ScanReport> {
    let name = pin.dep.name.as_str();
    let version = pin.dep.version.as_str();
    let mut findings = Vec::new();
    let mut notes = Vec::new();

    // 1. Integrity — the dirty artifact must decrypt and hash to its address.
    let raw = match vault.get_artifact(StoreKind::Dirty, &pin.expected) {
        Ok(bytes) => Some(bytes),
        Err(StoreError::NotFound(_)) => {
            notes.push("not acquired — integrity & capability checks skipped".to_owned());
            None
        }
        Err(e) => {
            findings.push(finding(
                "DEPUTY-INTEGRITY",
                Severity::Critical,
                format!("integrity check failed: {e}"),
            ));
            None
        }
    };

    // 2. Substitution — prod must not hold a different hash for this name@version.
    if let Some(prod_hash) = vault.crate_hash(StoreKind::Prod, name, version)? {
        if prod_hash != pin.expected {
            findings.push(finding(
                "DEPUTY-SUBSTITUTION",
                Severity::Critical,
                format!(
                    "prod holds a different artifact for {name} {version}: {prod_hash} vs pinned {}",
                    pin.expected
                ),
            ));
        }
    }

    // 3. Advisories — match the pinned version against known advisories.
    match version.parse::<Version>() {
        Ok(semver) => {
            for advisory in advisories.check(name, &semver) {
                findings.push(finding(
                    &advisory.id,
                    advisory.severity,
                    advisory.title.clone(),
                ));
            }
        }
        Err(_) => notes.push(format!(
            "version `{version}` is not semver — advisory check skipped"
        )),
    }

    // 4. Static capability review (informational, surfaced but non-blocking).
    if let Some(raw) = &raw {
        if let Ok(facts) = inspect(raw) {
            if facts.has_build_script {
                notes.push("runs a build script (arbitrary code at build time)".to_owned());
            }
            if facts.is_proc_macro {
                notes.push("proc-macro (executes inside the compiler)".to_owned());
            }
            let native = facts.native_unsafe_lines();
            if native > 0 {
                notes.push(format!("{native} line(s) of native C/C++/asm"));
            }
            if facts.unsafe_occurrences > 0 {
                notes.push(format!(
                    "{} `unsafe` occurrence(s)",
                    facts.unsafe_occurrences
                ));
            }
        }
    }

    let verdict = if findings.is_empty() {
        ScanVerdict::Clean
    } else {
        ScanVerdict::Findings(findings)
    };

    vault.put_verdict(
        &ArtifactRef {
            ecosystem: pin.dep.ecosystem,
            hash: pin.expected.clone(),
        },
        &verdict,
    )?;

    Ok(ScanReport { verdict, notes })
}

fn finding(id: &str, severity: Severity, summary: String) -> Finding {
    Finding {
        id: id.to_owned(),
        severity,
        summary,
    }
}
