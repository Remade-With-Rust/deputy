use std::collections::HashSet;

use deputy_core::{ArtifactRef, Pin, Result, ScanVerdict, StoreKind};
use deputy_store::Vault;

/// A single reason a dependency failed the gate.
#[derive(Debug, Clone)]
pub struct GateViolation {
    pub name: String,
    pub version: String,
    pub reason: String,
}

/// The decision of the fail-closed deploy gate.
#[derive(Debug, Clone)]
pub enum GateDecision {
    /// Every dependency is promoted, clean, and receipted. Carries the count cleared.
    Allowed { cleared: usize },
    /// At least one dependency failed; deployment must not proceed.
    Blocked { violations: Vec<GateViolation> },
}

impl GateDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateDecision::Allowed { .. })
    }
}

/// The fail-closed deploy gate (`docs/PIPELINE.md` §6, `docs/THREAT_MODEL.md` ADV-5).
///
/// Allows a deployment only if **every** pin clears all of:
/// 1. the audit chain is intact (so receipts can be trusted),
/// 2. a promotion **receipt** exists for the pinned content hash,
/// 3. the artifact is present in the **prod** store,
/// 4. its recorded scan **verdict is clean**,
/// 5. the **prod crate index** maps `name@version` to exactly this hash (no substitution).
///
/// Checks are on content hashes, so there is no name/version TOCTOU. Any failure → `Blocked`.
pub fn gate(vault: &Vault, pins: &[Pin]) -> Result<GateDecision> {
    // (1) The audit chain must verify; a broken chain blocks everything.
    let entries = match vault.audit_entries() {
        Ok(entries) => entries,
        Err(_) => {
            return Ok(GateDecision::Blocked {
                violations: vec![GateViolation {
                    name: "*".to_owned(),
                    version: "*".to_owned(),
                    reason: "audit log integrity check failed".to_owned(),
                }],
            });
        }
    };

    // (2) Collect the content hashes that carry a promotion receipt.
    let promoted: HashSet<String> = entries
        .iter()
        .filter(|e| e.kind == "promote")
        .filter_map(|e| {
            e.payload
                .get("hash")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .collect();

    let mut violations = Vec::new();
    for pin in pins {
        let name = pin.dep.name.as_str();
        let version = pin.dep.version.as_str();
        let hash_str = pin.expected.to_string();
        let mut block = |reason: &str| {
            violations.push(GateViolation {
                name: name.to_owned(),
                version: version.to_owned(),
                reason: reason.to_owned(),
            });
        };

        if !promoted.contains(&hash_str) {
            block("no promotion receipt for the pinned hash");
            continue;
        }
        if !vault.has_artifact(StoreKind::Prod, &pin.expected)? {
            block("not present in the prod store");
            continue;
        }
        match vault.get_verdict(&ArtifactRef {
            ecosystem: pin.dep.ecosystem,
            hash: pin.expected.clone(),
        })? {
            Some(ScanVerdict::Clean) => {}
            Some(ScanVerdict::Findings(_)) => {
                block("scan verdict has findings");
                continue;
            }
            None => {
                block("no scan verdict recorded");
                continue;
            }
        }
        match vault.crate_hash(StoreKind::Prod, name, version)? {
            Some(h) if h == pin.expected => {}
            Some(_) => block("prod crate index points to a different hash (substitution)"),
            None => block("missing prod crate-index entry"),
        }
    }

    if violations.is_empty() {
        Ok(GateDecision::Allowed {
            cleared: pins.len(),
        })
    } else {
        Ok(GateDecision::Blocked { violations })
    }
}
