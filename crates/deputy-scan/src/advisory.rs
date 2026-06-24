//! A small advisory model + matching engine. Advisories are keyed by package; a version is
//! affected if it satisfies the advisory's `vulnerable` semver requirement.
//!
//! The TOML schema accepted by [`AdvisoryDb::from_toml`]:
//!
//! ```toml
//! [[advisory]]
//! id = "RUSTSEC-2024-0001"
//! package = "foo"
//! vulnerable = "<1.2.3"     # a semver VersionReq matching affected versions
//! severity = "high"          # low | medium | high | critical
//! title = "Use-after-free in foo"
//! ```
//!
//! This keeps the engine self-contained and offline-testable; importing the full RUSTSEC
//! advisory-db is a future enrichment.

use std::collections::HashMap;

use deputy_core::{Error, Result, Severity};
use semver::{Version, VersionReq};
use serde::Deserialize;

/// A single security advisory affecting a package's versions.
#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub package: String,
    pub vulnerable: VersionReq,
    pub severity: Severity,
    pub title: String,
}

/// A queryable set of advisories, indexed by package name.
#[derive(Debug, Clone, Default)]
pub struct AdvisoryDb {
    by_package: HashMap<String, Vec<Advisory>>,
}

impl AdvisoryDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, advisory: Advisory) {
        self.by_package
            .entry(advisory.package.clone())
            .or_default()
            .push(advisory);
    }

    pub fn len(&self) -> usize {
        self.by_package.values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_package.is_empty()
    }

    /// Advisories affecting `name` at `version`.
    pub fn check(&self, name: &str, version: &Version) -> Vec<&Advisory> {
        self.by_package
            .get(name)
            .into_iter()
            .flatten()
            .filter(|advisory| advisory.vulnerable.matches(version))
            .collect()
    }

    /// Load advisories from a TOML document (see the module docs for the schema).
    pub fn from_toml(text: &str) -> Result<Self> {
        let doc: AdvisoryDoc = toml::from_str(text).map_err(|e| Error::Malformed {
            what: format!("advisory db: {e}"),
        })?;
        let mut db = Self::new();
        for raw in doc.advisory {
            let vulnerable = VersionReq::parse(&raw.vulnerable).map_err(|e| Error::Malformed {
                what: format!(
                    "advisory {}: invalid version requirement `{}`: {e}",
                    raw.id, raw.vulnerable
                ),
            })?;
            let severity = parse_severity(&raw.severity).ok_or_else(|| Error::Malformed {
                what: format!("advisory {}: unknown severity `{}`", raw.id, raw.severity),
            })?;
            db.add(Advisory {
                id: raw.id,
                package: raw.package,
                vulnerable,
                severity,
                title: raw.title,
            });
        }
        Ok(db)
    }
}

#[derive(Debug, Deserialize)]
struct AdvisoryDoc {
    #[serde(default)]
    advisory: Vec<RawAdvisory>,
}

#[derive(Debug, Deserialize)]
struct RawAdvisory {
    id: String,
    package: String,
    vulnerable: String,
    severity: String,
    #[serde(default)]
    title: String,
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Some(Severity::Low),
        "medium" | "moderate" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}
