use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// The lifecycle state of a single dependency artifact as it moves through the pipeline.
/// The allowed transitions encode `docs/PIPELINE.md` §7 and are enforced by
/// [`ArtifactState::transition`]. Every edge is, additionally, mID-gated at the API layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactState {
    /// Found in a source's resolved dependency graph.
    Discovered,
    /// Downloaded and integrity-verified into the dirty store.
    Acquired,
    /// Language analytics + critical-point-of-failure scoring complete.
    Analyzed,
    /// Scanners have run and produced a verdict.
    Scanned,
    /// Clean verdict; promoted into the prod store with a signed receipt.
    Promoted,
    /// Scan found issues; held out of prod pending review / re-scan.
    Quarantined,
    /// Materialized back into source and cleared by the deploy gate.
    Deployed,
}

impl ArtifactState {
    pub const fn name(self) -> &'static str {
        match self {
            ArtifactState::Discovered => "Discovered",
            ArtifactState::Acquired => "Acquired",
            ArtifactState::Analyzed => "Analyzed",
            ArtifactState::Scanned => "Scanned",
            ArtifactState::Promoted => "Promoted",
            ArtifactState::Quarantined => "Quarantined",
            ArtifactState::Deployed => "Deployed",
        }
    }

    /// Whether `self -> next` is a permitted edge in the pipeline state machine.
    pub const fn can_transition_to(self, next: ArtifactState) -> bool {
        use ArtifactState::*;
        matches!(
            (self, next),
            (Discovered, Acquired)
                | (Acquired, Analyzed)
                | (Analyzed, Scanned)
                | (Scanned, Promoted)
                | (Scanned, Quarantined)
                | (Quarantined, Scanned)
                | (Promoted, Deployed)
        )
    }

    /// Advance to `next`, or return [`Error::IllegalTransition`] if the edge is not allowed.
    pub fn transition(self, next: ArtifactState) -> Result<ArtifactState> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(Error::IllegalTransition {
                from: self.name(),
                to: next.name(),
            })
        }
    }
}

/// Severity of a scanner finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single issue raised by a scanner against an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub summary: String,
}

/// The outcome of scanning an artifact. Only [`ScanVerdict::Clean`] is promotable
/// (`docs/PIPELINE.md` §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanVerdict {
    Clean,
    Findings(Vec<Finding>),
}

impl ScanVerdict {
    pub fn is_clean(&self) -> bool {
        matches!(self, ScanVerdict::Clean)
    }
}

#[cfg(test)]
mod tests {
    use super::ArtifactState::*;
    use super::*;

    #[test]
    fn happy_path_is_permitted() {
        let path = [Discovered, Acquired, Analyzed, Scanned, Promoted, Deployed];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn quarantine_and_rescan_loop_is_permitted() {
        assert!(Scanned.can_transition_to(Quarantined));
        assert!(Quarantined.can_transition_to(Scanned));
    }

    #[test]
    fn skipping_states_is_rejected() {
        let err = Discovered.transition(Promoted).unwrap_err();
        assert_eq!(
            err,
            Error::IllegalTransition {
                from: "Discovered",
                to: "Promoted"
            }
        );
    }

    #[test]
    fn quarantined_cannot_deploy() {
        assert!(!Quarantined.can_transition_to(Deployed));
        assert!(!Quarantined.can_transition_to(Promoted));
    }

    #[test]
    fn only_clean_verdict_is_clean() {
        assert!(ScanVerdict::Clean.is_clean());
        assert!(!ScanVerdict::Findings(vec![Finding {
            id: "RUSTSEC-0000-0000".into(),
            severity: Severity::High,
            summary: "example".into(),
        }])
        .is_clean());
    }
}
