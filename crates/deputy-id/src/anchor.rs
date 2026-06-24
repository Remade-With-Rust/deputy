use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::IdError;

/// A per-DID anchor store enforcing two cross-sign-in invariants (`docs/AUTH.md` §5, §9):
///
/// 1. **Genesis immutability** — a known DID must always present the same genesis-roster hash;
///    a different one signals identity spoofing.
/// 2. **Version monotonicity** — the head-roster version must never decrease; a lower version
///    signals a stolen-device rollback.
///
/// The verifier cannot enforce these (it is stateless and makes no network calls), so the
/// relying party persists `(did → genesis_hash, last_seen_version)` and checks here.
pub trait AnchorStore: Send + Sync {
    /// Check a freshly-verified identity against its anchor and record the new high-water
    /// version. On first sight, records the anchor and returns `Ok`.
    fn check_and_update(
        &self,
        did: &str,
        genesis_roster_hash: &[u8; 32],
        current_version: u64,
    ) -> Result<(), IdError>;
}

struct Anchor {
    genesis_roster_hash: [u8; 32],
    last_seen_version: u64,
}

/// Process-local [`AnchorStore`]. A persistent implementation arrives with the API layer.
#[derive(Default)]
pub struct InMemoryAnchorStore {
    anchors: Mutex<HashMap<String, Anchor>>,
}

impl InMemoryAnchorStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AnchorStore for InMemoryAnchorStore {
    fn check_and_update(
        &self,
        did: &str,
        genesis_roster_hash: &[u8; 32],
        current_version: u64,
    ) -> Result<(), IdError> {
        let mut anchors = self.anchors.lock().expect("anchor mutex poisoned");
        match anchors.get_mut(did) {
            Some(anchor) => {
                if &anchor.genesis_roster_hash != genesis_roster_hash {
                    return Err(IdError::GenesisMismatch {
                        did: did.to_owned(),
                    });
                }
                if current_version < anchor.last_seen_version {
                    return Err(IdError::Rollback {
                        did: did.to_owned(),
                        presented: current_version,
                        last_seen: anchor.last_seen_version,
                    });
                }
                anchor.last_seen_version = current_version;
                Ok(())
            }
            None => {
                anchors.insert(
                    did.to_owned(),
                    Anchor {
                        genesis_roster_hash: *genesis_roster_hash,
                        last_seen_version: current_version,
                    },
                );
                Ok(())
            }
        }
    }
}
