//! RUSTSEC advisory-db importer.
//!
//! Downloads the [RustSec advisory database](https://github.com/rustsec/advisory-db) tarball,
//! parses each advisory's TOML frontmatter, and converts it into the [`AdvisoryDb`] the scanner
//! queries. The `patched` version ranges are converted to a `vulnerable` requirement
//! (everything below the lowest patched version); advisories with no fix flag every version, and
//! informational-only advisories (unmaintained / notices) are skipped.

use deputy_core::Severity;
use deputy_scan::{Advisory, AdvisoryDb, VulnMatch};
use semver::VersionReq;
use serde::Deserialize;
use std::io::Read;

const ADVISORY_DB_TARBALL: &str =
    "https://github.com/rustsec/advisory-db/archive/refs/heads/main.tar.gz";

#[derive(Deserialize)]
struct RawAdvisory {
    advisory: RawMeta,
    versions: Option<RawVersions>,
}

#[derive(Deserialize)]
struct RawMeta {
    id: String,
    package: String,
    #[serde(default)]
    informational: Option<String>,
    #[serde(default)]
    cvss: Option<String>,
}

#[derive(Deserialize)]
struct RawVersions {
    #[serde(default)]
    patched: Vec<String>,
    #[serde(default)]
    unaffected: Vec<String>,
}

/// Download + parse the RUSTSEC advisory database into an [`AdvisoryDb`].
pub async fn fetch_rustsec() -> Result<AdvisoryDb, String> {
    let bytes = reqwest::Client::new()
        .get(ADVISORY_DB_TARBALL)
        .header("User-Agent", "deputy")
        .send()
        .await
        .map_err(|e| format!("download advisory-db: {e}"))?
        .error_for_status()
        .map_err(|e| format!("advisory-db: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("read advisory-db: {e}"))?;

    tokio::task::spawn_blocking(move || parse_tarball(&bytes))
        .await
        .map_err(|e| format!("advisory parse task: {e}"))?
}

fn parse_tarball(gz: &[u8]) -> Result<AdvisoryDb, String> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(gz));
    let mut db = AdvisoryDb::new();
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let Ok(mut entry) = entry else { continue };
        let Ok(path) = entry.path().map(|p| p.to_path_buf()) else {
            continue;
        };
        let path = path.to_string_lossy();
        // Only the per-crate advisory files: advisory-db-main/crates/<name>/RUSTSEC-*.md
        if !path.contains("/crates/") || !path.contains("RUSTSEC-") {
            continue;
        }
        let mut content = String::new();
        if entry.read_to_string(&mut content).is_err() {
            continue;
        }
        if let Some(advisory) = parse_advisory(&content) {
            db.add(advisory);
        }
    }
    Ok(db)
}

fn parse_advisory(content: &str) -> Option<Advisory> {
    let toml_block = extract_toml(content)?;
    let raw: RawAdvisory = toml::from_str(&toml_block).ok()?;
    // Skip informational-only advisories (unmaintained, notice, etc.) — not version-specific CVEs.
    if raw.advisory.informational.is_some() {
        return None;
    }
    let (patched, unaffected) = match raw.versions {
        Some(v) => (parse_reqs(&v.patched), parse_reqs(&v.unaffected)),
        None => (vec![], vec![]),
    };
    let severity = raw
        .advisory
        .cvss
        .as_deref()
        .and_then(severity_from_cvss)
        .unwrap_or(Severity::High);
    Some(Advisory {
        title: extract_title(content).unwrap_or_else(|| raw.advisory.id.clone()),
        id: raw.advisory.id,
        package: raw.advisory.package,
        matcher: VulnMatch::NotPatched {
            patched,
            unaffected,
        },
        severity,
    })
}

/// Map a CVSS v3.x vector to Deputy's qualitative severity via the computed base score.
fn severity_from_cvss(vector: &str) -> Option<Severity> {
    let score = cvss_base_score(vector)?;
    Some(if score < 4.0 {
        Severity::Low
    } else if score < 7.0 {
        Severity::Medium
    } else if score < 9.0 {
        Severity::High
    } else {
        Severity::Critical
    })
}

/// Compute the CVSS v3.1 base score from a vector string
/// (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Returns `None` if a required metric is
/// missing or unrecognized.
fn cvss_base_score(vector: &str) -> Option<f64> {
    let (mut av, mut ac, mut pr, mut ui, mut scope, mut c, mut i, mut a) =
        (None, None, None, None, None, None, None, None);
    for part in vector.split('/') {
        let (k, v) = part.split_once(':')?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => scope = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {}
        }
    }
    let changed = scope? == "C";
    let av = match av? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match ac? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match pr? {
        "N" => 0.85,
        "L" if changed => 0.68,
        "L" => 0.62,
        "H" if changed => 0.5,
        "H" => 0.27,
        _ => return None,
    };
    let ui = match ui? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |m: &str| -> f64 {
        match m {
            "H" => 0.56,
            "L" => 0.22,
            _ => 0.0,
        }
    };
    let iss = 1.0 - ((1.0 - cia(c?)) * (1.0 - cia(i?)) * (1.0 - cia(a?)));
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = (impact + exploitability) * if changed { 1.08 } else { 1.0 };
    Some(roundup(raw.min(10.0)))
}

/// CVSS v3.1 roundup: ceil to one decimal place (integer math to avoid float drift).
fn roundup(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        scaled as f64 / 100_000.0
    } else {
        ((scaled / 10_000) + 1) as f64 / 10.0
    }
}

/// Extract the leading ```toml … ``` fenced block that RUSTSEC advisories begin with.
fn extract_toml(content: &str) -> Option<String> {
    let after_fence = content.find("```toml")? + "```toml".len();
    let rest = &content[after_fence..];
    let end = rest.find("```")?;
    Some(rest[..end].to_string())
}

fn extract_title(content: &str) -> Option<String> {
    content
        .lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").trim().to_owned())
}

/// Parse a list of semver requirement strings (e.g. `">= 0.6.3, < 0.7.0"`), dropping any that
/// don't parse. A comma-separated requirement is an AND of comparators.
fn parse_reqs(specs: &[String]) -> Vec<VersionReq> {
    specs
        .iter()
        .filter_map(|s| VersionReq::parse(s).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_scores_map_to_severity() {
        // Classic 9.8 (network, no privs, full impact) → Critical.
        assert_eq!(
            severity_from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(Severity::Critical)
        );
        // 1.8 (local, high complexity, low confidentiality only) → Low.
        assert_eq!(
            severity_from_cvss("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
            Some(Severity::Low)
        );
        // 7.5 (network, confidentiality only) → High.
        assert_eq!(
            severity_from_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            Some(Severity::High)
        );
        assert_eq!(severity_from_cvss("not-a-vector"), None);
    }
}
