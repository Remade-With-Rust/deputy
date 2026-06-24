use deputy_core::{
    ArtifactRef, ContentHash, EcosystemId, Error, Finding, Result, ScanVerdict, StoreKind,
};
use deputy_store::Vault;
use serde::Serialize;
use serde_json::json;

/// A promotion receipt: the append-only, hash-chained record that a specific artifact was
/// promoted into prod, by whom, and where it sits in the audit chain.
#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub name: String,
    pub version: String,
    pub hash: ContentHash,
    /// The promoting actor (e.g. an mID DID), if supplied.
    pub actor: Option<String>,
    /// Sequence number of the receipt in the audit chain.
    pub audit_seq: u64,
    /// The receipt's own hash within the chain.
    pub chain_hash: String,
}

/// The outcome of a promotion attempt.
#[derive(Debug, Clone, Serialize)]
pub enum Promotion {
    /// Promoted into prod; carries the receipt.
    Promoted(Receipt),
    /// Held out of prod because the scan verdict had findings.
    Quarantined { findings: Vec<Finding> },
}

/// Promote a scanned, clean dependency from dirty into prod, or quarantine it.
///
/// Fails (rather than promoting) if the artifact was never scanned, or if its dirty bytes no
/// longer pass integrity at promotion time (a tamper after scanning is caught here).
pub fn promote(
    vault: &Vault,
    ecosystem: EcosystemId,
    name: &str,
    version: &str,
    hash: &ContentHash,
    actor: Option<&str>,
) -> Result<Promotion> {
    let artifact = ArtifactRef {
        ecosystem,
        hash: hash.clone(),
    };
    let verdict = vault
        .get_verdict(&artifact)?
        .ok_or_else(|| Error::NotFound {
            what: format!("scan verdict for {name} {version} — scan before promoting"),
        })?;

    match verdict {
        ScanVerdict::Clean => {
            // Copy the verified bytes dirty -> prod. `get_artifact` re-verifies the content
            // address, so a post-scan tamper aborts the promotion here (fail-closed).
            let raw = vault.get_artifact(StoreKind::Dirty, hash)?;
            let prod_hash = vault.put_artifact(StoreKind::Prod, &raw)?;
            vault.put_crate_hash(StoreKind::Prod, name, version, &prod_hash)?;

            let entry = vault.audit_append(
                "promote",
                json!({
                    "name": name,
                    "version": version,
                    "hash": prod_hash.to_string(),
                    "actor": actor,
                }),
            )?;

            Ok(Promotion::Promoted(Receipt {
                name: name.to_owned(),
                version: version.to_owned(),
                hash: prod_hash,
                actor: actor.map(str::to_owned),
                audit_seq: entry.seq,
                chain_hash: entry.this_hex,
            }))
        }
        ScanVerdict::Findings(findings) => {
            vault.audit_append(
                "quarantine",
                json!({
                    "name": name,
                    "version": version,
                    "hash": hash.to_string(),
                    "finding_count": findings.len(),
                    "actor": actor,
                }),
            )?;
            Ok(Promotion::Quarantined { findings })
        }
    }
}
