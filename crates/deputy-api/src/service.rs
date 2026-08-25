use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use deputy_acquire::{acquire, acquire_pins, AcquireReport};
use deputy_analyze::{analyze, inspect, AnalysisReport};
use deputy_core::{
    ContentHash, DepEcosystem, DepName, DepRef, EcosystemId, Pin, ScanVerdict, SourceId, StoreKind,
    Version,
};
use deputy_deploy::{gate, materialize, promote, GateDecision, MaterializePlan, Promotion};
use deputy_ecosystem::{parse_pins, CargoEcosystem};
use deputy_id::{Authenticator, Session, VerifyParams};
use deputy_scan::{scan, AdvisoryDb, ScanReport};
use deputy_store::Vault;
use mata_cap::{
    authorize as mata_authorize, ApiRequest, Caller as MataCaller, Capability as MataCapability,
};
use spacedb_access::{
    authorize, AccessRequest, Capability, Did, Identity, MemKeyDirectory, Ops, RevocationSet,
    Scope, SignedCapability,
};

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// The capability scope covering Deputy's whole vault.
const DEPUTY_SCOPE: &str = "deputy";

/// A typed mata-cap request: every Deputy op declares `deputy:<action>`.
struct DeputyOp {
    action: &'static str,
}

impl ApiRequest for DeputyOp {
    fn required_capability(&self) -> MataCapability {
        MataCapability::new("deputy", self.action)
    }
}

/// Folder name that means "union every workspace in the vault". Reserved; cannot be a real group.
const ALL_WORKSPACES: &str = "*";

fn is_all_workspaces(name: &str) -> bool {
    name.trim() == ALL_WORKSPACES
}

/// `owner/repo` as GitHub shows it — two path segments, no drive letter or backslash.
/// Local ingest names (a folder name, or a nested relative path) are skipped on refresh.
pub(crate) fn is_github_full_name(name: &str) -> bool {
    if name.contains('\\') || name.contains(':') {
        return false;
    }
    let mut parts = name.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(owner), Some(repo), None)
            if !owner.is_empty() && !repo.is_empty() && owner != "." && repo != "."
    )
}

/// Optional repo filter on a folder-scoped request. Empty / missing = the whole group.
fn scope_repo(repo: &Option<String>) -> Option<&str> {
    repo.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Cache key so a group's analytics and a single-repo slice of that group never share a result.
fn scope_key(name: &str, repo: Option<&str>) -> String {
    match repo {
        Some(r) => format!("{name}::{r}"),
        None => name.to_owned(),
    }
}

/// Display label: the repo full_name when scoped, otherwise the group/folder name.
fn scope_label(name: &str, repo: Option<&str>) -> String {
    if is_all_workspaces(name) && repo.is_none() {
        return "All workspaces".to_owned();
    }
    repo.unwrap_or(name).to_owned()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mata_action(op: Ops) -> &'static str {
    if op.contains(Ops::WRITE) {
        "write"
    } else if op.contains(Ops::COMPUTE) {
        "compute"
    } else {
        "read"
    }
}

fn mata_caller(did: &Did, ops: Ops) -> MataCaller {
    let mut grants = Vec::new();
    if ops.contains(Ops::READ) {
        grants.push(MataCapability::new("deputy", "read"));
    }
    if ops.contains(Ops::WRITE) {
        grants.push(MataCapability::new("deputy", "write"));
    }
    if ops.contains(Ops::COMPUTE) {
        grants.push(MataCapability::new("deputy", "compute"));
    }
    MataCaller::new(did.to_string(), grants)
}

/// The synthetic owner DID used when mID is deactivated ([`DeputyService::open_local`], and the
/// `deputy sync --no-mid` key binding). It is deliberately *not* a `did:mata:` identity, so it
/// is obvious in logs that no mID backs it.
pub const LOCAL_DID: &str = "did:deputy:local";

/// One repository's download + acquisition result within a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct RepoSummary {
    pub full_name: String,
    /// Total pinned dependencies in the lockfile (the full transitive closure).
    pub deps: usize,
    /// Dependencies now sealed in the vault (newly acquired + already present).
    pub acquired: usize,
    pub lockfile_found: bool,
    /// GitHub source tarball (or equivalent) sealed in the vault — kept even when there is no lockfile.
    #[serde(default)]
    pub source_archived: bool,
    pub error: Option<String>,
}

/// A named folder grouping the repositories allocated to it.
#[derive(Serialize, Deserialize, Clone)]
pub struct FolderSummary {
    pub name: String,
    pub repos: Vec<RepoSummary>,
}

/// A GitHub repository's source tarball, sealed in the dirty store so the tree survives GitHub
/// or crates.io going away.
#[derive(Serialize, Deserialize, Clone)]
pub struct RepoArchive {
    pub full_name: String,
    pub hash: String,
    pub bytes: usize,
}

/// A single advisory/integrity finding for a dependency.
#[derive(Serialize, Deserialize, Clone)]
pub struct FindingView {
    pub dep: String,
    pub id: String,
    pub severity: String,
    pub summary: String,
}

/// The scan result for one repository in a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct RepoScanResult {
    pub full_name: String,
    pub deps: usize,
    pub lockfile_found: bool,
    pub findings: Vec<FindingView>,
    pub error: Option<String>,
}

/// The result of scanning every repository in a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct FolderScanReport {
    pub name: String,
    pub repos: Vec<RepoScanResult>,
}

/// One dependency's "social heartbeat": is a newer version out, and does the pinned version have
/// a known advisory (an issue that has landed publicly)?
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HeartbeatEntry {
    pub name: String,
    pub current: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub advisories: Vec<String>,
    /// Unix seconds when `latest` was published on crates.io. `None` on reports persisted before
    /// this field existed (those caches are refreshed once). `Some(0)` means we looked and crates.io
    /// did not give a date.
    #[serde(default)]
    pub latest_updated: Option<u64>,
}

/// The heartbeat for every dependency in a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct HeartbeatReport {
    pub name: String,
    pub entries: Vec<HeartbeatEntry>,
}

/// Live heartbeat snapshot, polled while `/folders/heartbeat` is in flight so the UI can paint
/// rows as each crates.io lookup finishes.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatProgress {
    pub name: String,
    pub done: usize,
    pub total: usize,
    pub entries: Vec<HeartbeatEntry>,
}

/// A connected GitHub account: an OAuth or PAT token plus a human label (its login by default).
/// Persisted (PAT included) into the AES-256-GCM-encrypted vault metadata so connections survive
/// restarts; the token is only ever recoverable with the vault passphrase.
#[derive(Clone, Serialize, Deserialize)]
pub struct GhConnection {
    pub label: String,
    pub token: String,
    /// Optional org/user to scope the repo listing to. Empty = list by the token user's
    /// affiliations (GitHub's `/user/repos`), which spans every org the user belongs to.
    pub owner: String,
}

/// A validated (promoted) dependency in the production store.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProdDep {
    pub name: String,
    pub version: String,
    pub hash: String,
}

/// A dependency that has a newer release than the pinned version. The current version may already
/// be in production; the new version is staged (downloaded) pending review.
#[derive(Serialize, Deserialize, Clone)]
pub struct NewVersionEntry {
    pub name: String,
    pub production: String,
    pub in_production: bool,
    pub staged: String,
    pub staged_ok: bool,
}

/// The result of a new-version scan over a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct NewVersionReport {
    pub name: String,
    pub entries: Vec<NewVersionEntry>,
}

/// A dependency that is NOT safely held in the offline vault, and why.
#[derive(Serialize, Deserialize, Clone)]
pub struct CoverageGap {
    pub name: String,
    pub version: String,
    /// `not acquired` (crates.io but missing/failed), `git dependency`, or `other registry`.
    pub reason: String,
}

/// Offline-archive coverage for a folder: how much of its dependency *source* is actually stored.
#[derive(Serialize, Deserialize, Clone)]
pub struct CoverageReport {
    pub name: String,
    /// crates.io deps that CAN be archived (unique name@version across the folder's lockfiles).
    pub registry_total: usize,
    /// Of those, how many are sealed in the vault right now.
    pub archived: usize,
    /// Everything not covered: missing crates.io deps + git/path/other-registry deps.
    pub gaps: Vec<CoverageGap>,
}

/// Live progress for a combined workspace scan (advisories → lockfiles → crates.io → coverage).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    pub stage: String,
    pub label: String,
    pub done: usize,
    pub total: usize,
}

/// One-button scan: lockfile verdicts, staged newer releases, and offline-archive coverage.
#[derive(Serialize, Deserialize, Clone)]
pub struct CombinedScanReport {
    pub advisories: usize,
    pub scan: FolderScanReport,
    pub updates: NewVersionReport,
    /// Set when the crates.io / staging stage failed; `updates` is then empty.
    #[serde(default)]
    pub updates_error: Option<String>,
    pub coverage: CoverageReport,
    /// Unix seconds when this report was produced. `0` means unknown (older payloads).
    #[serde(default)]
    pub scanned_at: u64,
}

/// Fast local snapshot for a workspace landing page (no crates.io round-trips).
#[derive(Serialize, Deserialize, Clone)]
pub struct WorkspaceOverview {
    pub name: String,
    pub repos: usize,
    pub lockfiles: usize,
    pub unique_deps: usize,
    pub acquired: usize,
    pub in_production: usize,
    pub advisory_hits: usize,
    pub rustsec_loaded: usize,
    pub archived: usize,
    pub registry_total: usize,
    pub gaps: usize,
}

/// Aggregate line counts for one language across a folder's dependency crates.
#[derive(Serialize, Deserialize, Clone)]
pub struct LangStat {
    pub language: String,
    pub lines: usize,
    pub crates: usize,
}

/// One dependency crate: the languages its `.crate` contains plus the supply-chain risk signals
/// that bear on a security review (`docs/PIPELINE.md` §3).
#[derive(Serialize, Deserialize, Clone)]
pub struct DepLang {
    pub name: String,
    pub version: String,
    pub languages: Vec<String>,
    pub lines: usize,
    /// Runs a `build.rs` — arbitrary code at build time.
    pub has_build_script: bool,
    /// A proc-macro crate — code runs inside the compiler.
    pub is_proc_macro: bool,
    /// Heuristic count of `unsafe` in the Rust sources.
    pub unsafe_occurrences: usize,
    /// `links = "…"` native library (FFI / sys crate), if any.
    pub links_native: Option<String>,
    /// Lines written in memory-unsafe native languages (C / C++ / asm).
    pub native_unsafe_lines: usize,
    /// True if this exact `name@version` is already promoted to the production store; false means
    /// it's still in staging (the dirty store).
    pub in_production: bool,
}

/// Dependency-language + security analytics for a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct DepAnalytics {
    pub name: String,
    pub total_deps: usize,
    pub analyzed: usize,
    pub by_language: Vec<LangStat>,
    pub deps: Vec<DepLang>,
    // Aggregate risk counts across the analyzed crates.
    pub build_scripts: usize,
    pub proc_macros: usize,
    pub native_crates: usize,
    pub unsafe_crates: usize,
}

struct AnalyticsBody {
    analyzed: usize,
    by_language: Vec<LangStat>,
    deps: Vec<DepLang>,
    build_scripts: usize,
    proc_macros: usize,
    native_crates: usize,
    unsafe_crates: usize,
}

/// Live analytics snapshot, polled while `/folders/analytics` inspects crates.
#[derive(Serialize, Deserialize, Clone)]
pub struct AnalyticsProgress {
    pub name: String,
    pub done: usize,
    pub total: usize,
    pub analyzed: usize,
    pub by_language: Vec<LangStat>,
    pub deps: Vec<DepLang>,
    pub build_scripts: usize,
    pub proc_macros: usize,
    pub native_crates: usize,
    pub unsafe_crates: usize,
}

fn lang_stats(
    lines: &std::collections::BTreeMap<String, usize>,
    crate_counts: &std::collections::BTreeMap<String, usize>,
) -> Vec<LangStat> {
    let mut by_language: Vec<LangStat> = lines
        .iter()
        .map(|(language, lines)| LangStat {
            crates: crate_counts.get(language).copied().unwrap_or(0),
            language: language.clone(),
            lines: *lines,
        })
        .collect();
    by_language.sort_by_key(|s| std::cmp::Reverse(s.lines));
    by_language
}

/// Download + inspect each unique dependency crate, aggregating language line counts and the
/// supply-chain risk signals. Blocking (network + tar inspection) — run under `spawn_blocking`.
/// `tick` is invoked after each crate so the UI can paint rows as they land.
fn compute_dep_analytics(
    vault: &Vault,
    pins: Vec<Pin>,
    mut tick: impl FnMut(&AnalyticsBody, usize, usize),
) -> AnalyticsBody {
    let eco = CargoEcosystem::new();
    let mut lines: std::collections::BTreeMap<String, usize> = Default::default();
    let mut crate_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut deps = Vec::with_capacity(pins.len());
    let (mut analyzed, mut build_scripts, mut proc_macros, mut native_crates, mut unsafe_crates) =
        (0, 0, 0, 0, 0);
    let total = pins.len();

    for (i, pin) in pins.iter().enumerate() {
        let name = pin.dep.name.as_str().to_owned();
        let version = pin.dep.version.as_str().to_owned();
        // Which area is this dep in — production (promoted) or staging (dirty only)?
        let in_production = vault
            .crate_hash(StoreKind::Prod, &name, &version)
            .ok()
            .flatten()
            .is_some();
        // Prefer the already-acquired crate from the vault; only download what isn't staged.
        let bytes = vault
            .get_artifact(StoreKind::Dirty, &pin.expected)
            .ok()
            .or_else(|| eco.fetch(pin).ok());
        match bytes.and_then(|b| inspect(&b).ok()) {
            Some(facts) => {
                analyzed += 1;
                let mut langs = Vec::new();
                for (lang, count) in &facts.languages {
                    let l = lang.as_str().to_owned();
                    *lines.entry(l.clone()).or_default() += count;
                    *crate_counts.entry(l.clone()).or_default() += 1;
                    langs.push(l);
                }
                let native_unsafe_lines = facts.native_unsafe_lines();
                let is_native = facts.links_native.is_some() || native_unsafe_lines > 0;
                if facts.has_build_script {
                    build_scripts += 1;
                }
                if facts.is_proc_macro {
                    proc_macros += 1;
                }
                if is_native {
                    native_crates += 1;
                }
                if facts.unsafe_occurrences > 0 {
                    unsafe_crates += 1;
                }
                deps.push(DepLang {
                    name,
                    version,
                    languages: langs,
                    lines: facts.total_lines,
                    has_build_script: facts.has_build_script,
                    is_proc_macro: facts.is_proc_macro,
                    unsafe_occurrences: facts.unsafe_occurrences,
                    links_native: facts.links_native.clone(),
                    native_unsafe_lines,
                    in_production,
                });
            }
            None => deps.push(DepLang {
                name,
                version,
                languages: vec![],
                lines: 0,
                has_build_script: false,
                is_proc_macro: false,
                unsafe_occurrences: 0,
                links_native: None,
                native_unsafe_lines: 0,
                in_production,
            }),
        }
        tick(
            &AnalyticsBody {
                analyzed,
                by_language: lang_stats(&lines, &crate_counts),
                deps: deps.clone(),
                build_scripts,
                proc_macros,
                native_crates,
                unsafe_crates,
            },
            i + 1,
            total,
        );
    }

    AnalyticsBody {
        analyzed,
        by_language: lang_stats(&lines, &crate_counts),
        deps,
        build_scripts,
        proc_macros,
        native_crates,
        unsafe_crates,
    }
}

/// Fetch a repo's `Cargo.lock` over the GitHub API. `Ok(Some)` if present, `Ok(None)` if absent.
async fn fetch_lockfile(
    client: &reqwest::Client,
    token: &str,
    full_name: &str,
) -> Result<Option<String>, String> {
    let url = format!("https://api.github.com/repos/{full_name}/contents/Cargo.lock");
    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header("User-Agent", "deputy")
        .header("Accept", "application/vnd.github.raw")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(
            "403 — the PAT needs 'Contents: Read' permission (Administration/Metadata is not enough)"
                .to_owned(),
        );
    }
    if !resp.status().is_success() {
        return Err(format!("GitHub {}", resp.status()));
    }
    resp.text().await.map(Some).map_err(|e| e.to_string())
}

/// Fetch a repo's `Cargo.lock` trying each connected PAT until one can read it — repos may live
/// under different GitHub accounts. `Ok(None)` if no token finds it (absent or inaccessible);
/// `Err` only if every token errored without a definitive 404.
async fn fetch_lockfile_any(
    client: &reqwest::Client,
    tokens: &[String],
    full_name: &str,
) -> Result<Option<String>, String> {
    let mut saw_none = false;
    let mut last_err = None;
    for token in tokens {
        match fetch_lockfile(client, token, full_name).await {
            Ok(Some(text)) => return Ok(Some(text)),
            Ok(None) => saw_none = true,
            Err(e) => last_err = Some(e),
        }
    }
    if saw_none {
        Ok(None)
    } else if let Some(e) = last_err {
        Err(e)
    } else {
        Ok(None)
    }
}

fn github_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .user_agent("deputy")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// GitHub source tarball for `owner/repo` (default branch). Follows the codeload redirect.
async fn fetch_repo_tarball(
    client: &reqwest::Client,
    tokens: &[String],
    full_name: &str,
) -> Result<Vec<u8>, String> {
    let url = format!("https://api.github.com/repos/{full_name}/tarball");
    let mut last_err = None;
    for token in tokens {
        let resp = client
            .get(&url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| e.to_string());
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            last_err = Some("repository not found".to_owned());
            continue;
        }
        if !resp.status().is_success() {
            last_err = Some(format!("GitHub {}", resp.status()));
            continue;
        }
        return resp
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| e.to_string());
    }
    Err(last_err.unwrap_or_else(|| "no GitHub token could fetch the source tarball".to_owned()))
}

async fn fetch_crate_bytes(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Option<Vec<u8>> {
    let url = format!("https://static.crates.io/crates/{name}/{name}-{version}.crate");
    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.bytes().await.ok().map(|b| b.to_vec())
}

fn seal_crate_tarball(vault: &Vault, name: &str, version: &str, raw: &[u8]) -> bool {
    if vault
        .crate_hash(StoreKind::Dirty, name, version)
        .ok()
        .flatten()
        .is_some()
    {
        return true;
    }
    let Ok(hash) = vault.put_artifact(StoreKind::Dirty, raw) else {
        return false;
    };
    vault
        .put_crate_hash(StoreKind::Dirty, name, version, &hash)
        .is_ok()
}

/// Every `Cargo.toml` in a GitHub-style gzip tarball (skip `target/` and `.git`).
pub(crate) fn cargo_tomls_from_github_tarball(gz: &[u8]) -> Vec<String> {
    let dec = flate2::read::GzDecoder::new(gz);
    let mut archive = tar::Archive::new(dec);
    let Ok(entries) = archive.entries() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let mut entry = entry;
        let Ok(path) = entry.path() else {
            continue;
        };
        let path = path.to_string_lossy().replace('\\', "/");
        if !path.ends_with("Cargo.toml") {
            continue;
        }
        if path.split('/').any(|p| p == "target" || p == ".git") {
            continue;
        }
        let mut buf = String::new();
        if entry.read_to_string(&mut buf).is_ok() && !buf.is_empty() {
            out.push(buf);
        }
    }
    out
}

/// Package name@version plus crates.io direct dependencies (skip path/git).
pub(crate) fn crates_from_manifest(toml_text: &str) -> Vec<(String, String)> {
    let Ok(value) = toml_text.parse::<toml::Value>() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(pkg) = value.get("package").and_then(|p| p.as_table()) {
        if let (Some(name), Some(ver)) = (
            pkg.get("name").and_then(|n| n.as_str()),
            pkg.get("version").and_then(|v| v.as_str()),
        ) {
            if !name.is_empty() && !ver.is_empty() {
                out.push((name.to_owned(), ver.to_owned()));
            }
        }
    }
    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = value.get(table_name).and_then(|t| t.as_table()) else {
            continue;
        };
        for (name, spec) in table {
            if spec.get("path").is_some() || spec.get("git").is_some() {
                continue;
            }
            let ver = spec
                .as_str()
                .or_else(|| spec.get("version").and_then(|v| v.as_str()))
                .unwrap_or("")
                .trim();
            if ver.is_empty() {
                continue;
            }
            out.push((name.clone(), ver.to_owned()));
        }
    }
    out
}

async fn resolve_and_seal_unlocked_crates(
    client: &reqwest::Client,
    vault: &Vault,
    manifests: &[String],
) -> Vec<(String, String)> {
    let mut want: HashSet<(String, String)> = HashSet::new();
    for text in manifests {
        for (name, spec) in crates_from_manifest(text) {
            let version = if semver::Version::parse(&spec).is_ok() {
                spec
            } else if let Some((latest, _)) = crates_io_latest(client, &name).await {
                latest
            } else {
                continue;
            };
            want.insert((name, version));
        }
    }
    let mut sealed = Vec::new();
    for (name, version) in want {
        if vault
            .crate_hash(StoreKind::Dirty, &name, &version)
            .ok()
            .flatten()
            .is_some()
        {
            sealed.push((name, version));
            continue;
        }
        let Some(bytes) = fetch_crate_bytes(client, &name, &version).await else {
            continue;
        };
        if seal_crate_tarball(vault, &name, &version, &bytes) {
            sealed.push((name, version));
        }
    }
    sealed
}

/// One project staged for acquisition (from a GitHub repo or a local folder): its display name,
/// whether a lockfile was found, any fetch/read error, the pins parsed from its `Cargo.lock`, and
/// the raw lockfile text (kept so folder ops can re-parse it offline instead of re-fetching).
struct StagedRepo {
    repo: String,
    lockfile_found: bool,
    fetch_error: Option<String>,
    pins: Vec<Pin>,
    lockfile_text: Option<String>,
    source_archived: bool,
    /// crates.io crates sealed because this repo had no lockfile (the package + direct deps).
    unlocked_crates: Vec<(String, String)>,
}

/// Recursively collect every `Cargo.lock` under `root` (skipping `target/` and dotdirs) so a local
/// folder of projects can be ingested the same way as a set of GitHub repos.
fn find_lockfiles(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let skip = path
                    .file_name()
                    .map(|n| {
                        let n = n.to_string_lossy();
                        n == "target" || n.starts_with('.')
                    })
                    .unwrap_or(false);
                if !skip {
                    stack.push(path);
                }
            } else if path.file_name().is_some_and(|n| n == "Cargo.lock") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Minimal `Cargo.lock` view used by the coverage check — we need *every* package, including the
/// git/path ones [`parse_pins`] deliberately drops.
#[derive(Deserialize)]
struct RawLock {
    #[serde(default)]
    package: Vec<RawPkg>,
}

#[derive(Deserialize)]
struct RawPkg {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Both the git index and the sparse index identify crates.io — the only source we can archive.
fn is_cratesio(source: &str) -> bool {
    source.starts_with("registry+https://github.com/rust-lang/crates.io-index")
        || source.starts_with("sparse+https://index.crates.io/")
}

/// The latest stable version of a crate on crates.io, if reachable, plus when that version
/// was published (Unix seconds).
async fn crates_io_latest(client: &reqwest::Client, name: &str) -> Option<(String, Option<u64>)> {
    let resp = client
        .get(format!("https://crates.io/api/v1/crates/{name}"))
        .header("User-Agent", "deputy")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    crates_io_latest_from_json(&v)
}

pub(crate) fn crates_io_latest_from_json(v: &serde_json::Value) -> Option<(String, Option<u64>)> {
    let krate = v.get("crate")?;
    let latest = krate
        .get("max_stable_version")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| krate.get("newest_version").and_then(|s| s.as_str()))?
        .to_owned();
    let from_version = v.get("versions").and_then(|x| x.as_array()).and_then(|arr| {
        arr.iter()
            .find(|ver| ver.get("num").and_then(|n| n.as_str()) == Some(latest.as_str()))
            .and_then(|ver| {
                ver.get("created_at")
                    .and_then(|s| s.as_str())
                    .or_else(|| ver.get("updated_at").and_then(|s| s.as_str()))
            })
            .and_then(rfc3339_to_unix)
    });
    let updated = from_version.or_else(|| {
        krate
            .get("updated_at")
            .and_then(|s| s.as_str())
            .and_then(rfc3339_to_unix)
    });
    Some((latest, updated))
}

/// UTC `YYYY-MM-DDTHH:MM:SS[.frac]Z` (crates.io) → Unix seconds. No `chrono`.
pub(crate) fn rfc3339_to_unix(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i32 = dp.next()?.parse().ok()?;
    let m: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let time = rest
        .split_once(['Z', '+', '-'])
        .map(|(t, _)| t)
        .unwrap_or(rest);
    let time = time.split('.').next()?;
    let mut tp = time.split(':');
    let hour: u64 = tp.next()?.parse().ok()?;
    let min: u64 = tp.next()?.parse().ok()?;
    let sec: u64 = tp.next().unwrap_or("0").parse().ok().unwrap_or(0);
    if hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = unix_days_from_ymd(y, m, d)?;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + hour * 3_600 + min * 60 + sec)
}

/// Inverse of Howard Hinnant's civil-from-days (Unix epoch day count).
fn unix_days_from_ymd(y: i32, m: u32, d: u32) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era as i64 * 146_097 + doe as i64 - 719_468)
}

/// The latest stable version of a crate **and its `.crate` checksum**, so the new version can be
/// staged (downloaded + integrity-verified) without a lockfile.
async fn crates_io_latest_versioned(
    client: &reqwest::Client,
    name: &str,
) -> Option<(String, String)> {
    let resp = client
        .get(format!("https://crates.io/api/v1/crates/{name}"))
        .header("User-Agent", "deputy")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    let krate = v.get("crate")?;
    let latest = krate
        .get("max_stable_version")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| krate.get("newest_version").and_then(|s| s.as_str()))?
        .to_owned();
    let checksum = v
        .get("versions")?
        .as_array()?
        .iter()
        .find(|ver| ver.get("num").and_then(|n| n.as_str()) == Some(latest.as_str()))
        .and_then(|ver| ver.get("checksum").and_then(|c| c.as_str()))?
        .to_owned();
    Some((latest, checksum))
}

/// Checksum for a specific crates.io version, used when promoting a selected new release.
async fn crates_io_checksum(
    client: &reqwest::Client,
    name: &str,
    version: &str,
) -> Option<String> {
    let resp = client
        .get(format!("https://crates.io/api/v1/crates/{name}/{version}"))
        .header("User-Agent", "deputy")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.ok()?;
    v.get("version")?
        .get("checksum")?
        .as_str()
        .map(str::to_owned)
}

fn pin_for_named_version(vault: &Vault, pins: &[Pin], name: &str, version: &str) -> Option<Pin> {
    if let Some(pin) = pins.iter().find(|p| {
        p.dep.name.as_str() == name && p.dep.version.as_str() == version
    }) {
        return Some(pin.clone());
    }
    let hash = vault.crate_hash(StoreKind::Dirty, name, version).ok().flatten()?;
    Some(Pin {
        dep: DepRef {
            ecosystem: EcosystemId::Cargo,
            name: DepName::new(name),
            version: Version::new(version),
        },
        expected: hash,
    })
}

/// The in-process capability surface — the canonical API the CLI, the HTTP server, and the UI
/// all drive. Holds an unlocked [`Vault`], the mID [`Session`] that authorized the unlock, and a
/// SpaceDB **capability** (Layer 5) that gates every operation for the acting principal — a
/// human or an AI agent.
pub struct DeputyService {
    /// The unlocked vault, or `None` until an mID sign-in unlocks it (the *gated* default). The
    /// vault key is bound to the verified mID DID, so a different identity cannot open it — and in
    /// gated mode no vault data is reachable before sign-in. Embed/local mode unlocks it up front.
    vault: std::sync::Mutex<Option<std::sync::Arc<Vault>>>,
    /// Held so the vault can be unlocked later (gated mode) and re-bound to the signed-in DID.
    root: std::path::PathBuf,
    passphrase: Vec<u8>,
    /// The acting principal. Swappable at runtime: a browser mID sign-in ([`Self::sign_in`])
    /// replaces it with the verified wallet identity. The capability layer below gates ops
    /// independently; this is who the principal *is* (DID shown, used in promotion receipts).
    session: std::sync::Mutex<Session>,
    ecosystem: CargoEcosystem,
    advisories: std::sync::RwLock<AdvisoryDb>,

    // SpaceDB Layer 5 — signed, scoped, revocable capability gating.
    owner: Identity,
    directory: MemKeyDirectory,
    revocations: RevocationSet,
    capability: SignedCapability,

    /// RP-side sign-in: issues single-use nonces and verifies wallet tokens (`deputy-id`).
    authenticator: Authenticator,
    /// The bare origin a wallet token's `aud` must equal — what the challenge advertises.
    mid_audience: String,

    /// Whether a verified mID session authorized this service. `false` when opened in local mode
    /// ([`Self::open_local`]) — capabilities still gate ops, but the owner is a local identity.
    mid_active: std::sync::atomic::AtomicBool,

    /// Connected GitHub accounts (OAuth or PAT). Tokens live in memory and in the encrypted vault.
    github_connections: std::sync::Mutex<Vec<GhConnection>>,
    /// In-flight browser GitHub approval (device flow or `gh auth login --web`).
    github_oauth: std::sync::Mutex<Option<crate::github_oauth::PendingGithubOauth>>,

    /// Named folders grouping downloaded repositories. Persisted to the encrypted vault.
    folders: std::sync::Mutex<HashMap<String, FolderSummary>>,

    /// Each folder's raw `Cargo.lock` texts as `(project, text)`, captured at download. Lets folder
    /// ops (analytics/scan/coverage/heartbeat) re-parse offline instead of re-fetching from GitHub
    /// — which is what made them fail for local folders. Persisted to the encrypted vault.
    folder_lockfiles: std::sync::Mutex<HashMap<String, Vec<(String, String)>>>,

    /// Cached dependency-language analytics per folder — downloading + inspecting every crate is
    /// expensive, so it's computed lazily and invalidated on re-download / delete.
    analytics_cache: std::sync::Mutex<HashMap<String, DepAnalytics>>,

    /// Last combined scan per workspace scope, persisted so Scan Dependencies isn't empty on return.
    last_scans: std::sync::Mutex<HashMap<String, CombinedScanReport>>,

    /// Last crates.io heartbeat per workspace scope — skip the network on relogin when present.
    last_heartbeats: std::sync::Mutex<HashMap<String, HeartbeatReport>>,

    /// GitHub source tarballs sealed in the vault, keyed by `owner/name`.
    repo_archives: std::sync::Mutex<HashMap<String, RepoArchive>>,

    /// Live `(done, total)` acquisition progress for the in-flight download, polled by the UI.
    download_progress: std::sync::Mutex<Option<(usize, usize)>>,

    /// Live combined-scan progress, polled by the UI while `/folders/scan-all` runs.
    scan_progress: std::sync::Mutex<Option<ScanProgress>>,

    /// Epoch so a superseded heartbeat POST cannot publish into the current snapshot.
    heartbeat_epoch: std::sync::atomic::AtomicU64,
    /// Live heartbeat snapshot, polled by the UI while `/folders/heartbeat` runs.
    heartbeat_progress: std::sync::Mutex<Option<(u64, HeartbeatProgress)>>,

    /// Epoch so a superseded analytics POST cannot publish into the current snapshot.
    analytics_epoch: std::sync::atomic::AtomicU64,
    /// Live analytics snapshot, polled by the UI while `/folders/analytics` runs.
    analytics_progress: std::sync::Mutex<Option<(u64, AnalyticsProgress)>>,
}

impl DeputyService {
    /// Open the service with **mID active** (the default): the verified mID `session` gates the
    /// unlock, and the opener becomes the **owner** with a self-granted full capability over the
    /// vault (the owner DID is the mID DID). The `passphrase` derives the at-rest key. Scoped
    /// capabilities for agents come from [`Self::grant`].
    pub fn open(
        root: impl AsRef<Path>,
        passphrase: &[u8],
        session: Session,
        now_unix_secs: u64,
    ) -> Result<Self, ApiError> {
        session.ensure_valid(now_unix_secs)?;
        let did = session.did.clone();
        let svc = Self::assemble(root, passphrase, session, true)?;
        // mID active: bind the vault to the verified DID and unlock immediately.
        svc.unlock_vault(did.as_bytes())?;
        Ok(svc)
    }

    /// Open with **mID deactivated** (the embed / off toggle): no mID token required, owner is a
    /// synthetic local identity ([`LOCAL_DID`]), and the vault is unlocked up front with **no DID
    /// binding**. For embedding Deputy in software that already owns its auth + encryption, and for
    /// local development / the CLI. Access is then gated only by passphrase possession.
    pub fn open_local(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, ApiError> {
        let svc = Self::assemble(root, passphrase, Self::local_session(), false)?;
        svc.unlock_vault(&[])?; // embed: unbound, unlocked now
        Ok(svc)
    }

    /// Open **gated and locked** — the secure default. The vault stays sealed until an mID sign-in
    /// ([`Self::sign_in`]) supplies a verified DID, at which point it is unlocked **bound to that
    /// DID**. Until then every vault-backed op returns `vault locked`, and a different identity can
    /// never open it. For the desktop app, which signs in interactively after the window opens.
    pub fn open_gated_locked(root: impl AsRef<Path>, passphrase: &[u8]) -> Result<Self, ApiError> {
        Self::assemble(root, passphrase, Self::local_session(), false)
    }

    fn local_session() -> Session {
        Session {
            did: LOCAL_DID.to_owned(),
            claims: std::collections::BTreeMap::new(),
            current_version: 0,
            genesis_roster_hash: [0u8; 32],
            iat: 0,
            exp: u64::MAX,
            aud: LOCAL_DID.to_owned(),
        }
    }

    /// Build the service shell (owner/capability/auth) with the vault **locked** (`None`). The
    /// caller unlocks via [`Self::unlock_vault`] — now (embed/open) or at sign-in (gated).
    fn assemble(
        root: impl AsRef<Path>,
        passphrase: &[u8],
        session: Session,
        mid_active: bool,
    ) -> Result<Self, ApiError> {
        let owner = Identity::generate(session.did.clone())?;
        let directory = MemKeyDirectory::new();
        directory.publish(&owner)?;
        let cap = Capability::grant(
            owner.did().clone(),
            owner.did().clone(),
            Scope::Collection(DEPUTY_SCOPE.to_owned()),
            Ops::READ | Ops::WRITE | Ops::COMPUTE,
        )?;
        let capability = SignedCapability::sign(cap, &owner)?;

        let mid_audience = std::env::var("DEPUTY_MID_AUDIENCE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:8080".to_owned());

        Ok(Self {
            vault: std::sync::Mutex::new(None),
            root: root.as_ref().to_path_buf(),
            passphrase: passphrase.to_vec(),
            session: std::sync::Mutex::new(session),
            ecosystem: CargoEcosystem::new(),
            advisories: std::sync::RwLock::new(AdvisoryDb::new()),
            owner,
            directory,
            revocations: RevocationSet::new(),
            capability,
            authenticator: Authenticator::in_memory(),
            mid_audience,
            mid_active: std::sync::atomic::AtomicBool::new(mid_active),
            github_connections: std::sync::Mutex::new(Vec::new()),
            github_oauth: std::sync::Mutex::new(None),
            folders: std::sync::Mutex::new(HashMap::new()),
            folder_lockfiles: std::sync::Mutex::new(HashMap::new()),
            analytics_cache: std::sync::Mutex::new(HashMap::new()),
            last_scans: std::sync::Mutex::new(HashMap::new()),
            last_heartbeats: std::sync::Mutex::new(HashMap::new()),
            repo_archives: std::sync::Mutex::new(HashMap::new()),
            download_progress: std::sync::Mutex::new(None),
            scan_progress: std::sync::Mutex::new(None),
            heartbeat_epoch: std::sync::atomic::AtomicU64::new(0),
            heartbeat_progress: std::sync::Mutex::new(None),
            analytics_epoch: std::sync::atomic::AtomicU64::new(0),
            analytics_progress: std::sync::Mutex::new(None),
        })
    }

    /// The unlocked vault, or a `vault locked` error if no sign-in has unlocked it yet (gated mode).
    fn vault(&self) -> Result<std::sync::Arc<Vault>, ApiError> {
        self.vault
            .lock()
            .expect("vault mutex")
            .clone()
            .ok_or_else(|| ApiError::unauthorized("vault locked — sign in with mID to unlock"))
    }

    /// Whether the vault is currently unlocked.
    fn vault_unlocked(&self) -> bool {
        self.vault.lock().expect("vault mutex").is_some()
    }

    /// Unlock (or first-time create) the vault bound to `binding` (an mID DID, or empty for embed
    /// mode), then load the GitHub connections + folders persisted in it. A wrong binding means the
    /// vault was sealed under a different identity (or passphrase) → refused.
    fn unlock_vault(&self, binding: &[u8]) -> Result<(), ApiError> {
        let vault = match Vault::unlock_bound(&self.root, &self.passphrase, binding) {
            Ok(v) => v,
            Err(deputy_store::StoreError::NotInitialized) => {
                Vault::create_bound(&self.root, &self.passphrase, binding)?
            }
            Err(e) => return Err(e.into()),
        };
        *self
            .github_connections
            .lock()
            .expect("github connections mutex") = Self::load_github_connections(&vault);
        *self.folders.lock().expect("folders mutex") = Self::load_folders(&vault);
        *self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex") = Self::load_folder_lockfiles(&vault);
        *self.last_scans.lock().expect("last scans mutex") = Self::load_last_scans(&vault);
        *self
            .analytics_cache
            .lock()
            .expect("analytics mutex") = Self::load_analytics_cache(&vault);
        *self
            .last_heartbeats
            .lock()
            .expect("last heartbeats mutex") = Self::load_last_heartbeats(&vault);
        *self
            .repo_archives
            .lock()
            .expect("repo archives mutex") = Self::load_repo_archives(&vault);
        *self.vault.lock().expect("vault mutex") = Some(std::sync::Arc::new(vault));
        Ok(())
    }

    // ── Persisted GitHub state ────────────────────────────────────────────────
    // Connections + folders live in the encrypted vault metadata so they survive restarts.

    fn load_github_connections(vault: &Vault) -> Vec<GhConnection> {
        vault
            .get_app_state("github_connections")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn load_folders(vault: &Vault) -> HashMap<String, FolderSummary> {
        let list: Vec<FolderSummary> = vault
            .get_app_state("folders")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        list.into_iter().map(|f| (f.name.clone(), f)).collect()
    }

    /// Write the current GitHub connections back to the encrypted vault (best-effort; a write
    /// failure must not fail the user-facing operation that triggered it).
    fn persist_github_connections(&self) {
        let snapshot = self
            .github_connections
            .lock()
            .expect("github connections mutex")
            .clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("github_connections", &json);
        }
    }

    /// Write the current folder groupings back to the encrypted vault (best-effort).
    fn persist_folders(&self) {
        let snapshot: Vec<FolderSummary> = self
            .folders
            .lock()
            .expect("folders mutex")
            .values()
            .cloned()
            .collect();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("folders", &json);
        }
    }

    fn load_folder_lockfiles(vault: &Vault) -> HashMap<String, Vec<(String, String)>> {
        vault
            .get_app_state("folder_lockfiles")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Write the current per-folder lockfiles back to the encrypted vault (best-effort).
    fn persist_folder_lockfiles(&self) {
        let snapshot = self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("folder_lockfiles", &json);
        }
    }

    fn load_last_scans(vault: &Vault) -> HashMap<String, CombinedScanReport> {
        vault
            .get_app_state("last_scans")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn persist_last_scans(&self) {
        let snapshot = self.last_scans.lock().expect("last scans mutex").clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("last_scans", &json);
        }
    }

    fn load_analytics_cache(vault: &Vault) -> HashMap<String, DepAnalytics> {
        vault
            .get_app_state("analytics_cache")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn persist_analytics_cache(&self) {
        let snapshot = self
            .analytics_cache
            .lock()
            .expect("analytics mutex")
            .clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("analytics_cache", &json);
        }
    }

    fn load_last_heartbeats(vault: &Vault) -> HashMap<String, HeartbeatReport> {
        vault
            .get_app_state("last_heartbeats")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn persist_last_heartbeats(&self) {
        let snapshot = self
            .last_heartbeats
            .lock()
            .expect("last heartbeats mutex")
            .clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("last_heartbeats", &json);
        }
    }

    fn load_repo_archives(vault: &Vault) -> HashMap<String, RepoArchive> {
        vault
            .get_app_state("repo_archives")
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn persist_repo_archives(&self) {
        let snapshot = self
            .repo_archives
            .lock()
            .expect("repo archives mutex")
            .clone();
        if let (Ok(json), Ok(vault)) = (serde_json::to_vec(&snapshot), self.vault()) {
            let _ = vault.put_app_state("repo_archives", &json);
        }
    }

    fn remember_repo_archive(&self, full_name: &str, hash: &ContentHash, bytes: usize) {
        self.repo_archives.lock().expect("repo archives mutex").insert(
            full_name.to_owned(),
            RepoArchive {
                full_name: full_name.to_owned(),
                hash: hash.to_hex(),
                bytes,
            },
        );
        self.persist_repo_archives();
    }

    fn source_is_archived(&self, full_name: &str) -> bool {
        self.repo_archives
            .lock()
            .expect("repo archives mutex")
            .contains_key(full_name)
    }

    async fn archive_github_source(
        &self,
        client: &reqwest::Client,
        tokens: &[String],
        full_name: &str,
        has_lockfile: bool,
    ) -> (bool, Vec<(String, String)>, Option<String>) {
        let vault = match self.vault() {
            Ok(v) => v,
            Err(e) => return (false, Vec::new(), Some(e.message)),
        };
        match fetch_repo_tarball(client, tokens, full_name).await {
            Ok(bytes) => {
                let archived = match vault.put_artifact(StoreKind::Dirty, &bytes) {
                    Ok(hash) => {
                        self.remember_repo_archive(full_name, &hash, bytes.len());
                        true
                    }
                    Err(e) => return (false, Vec::new(), Some(e.to_string())),
                };
                let unlocked = if has_lockfile {
                    Vec::new()
                } else {
                    let tomls = cargo_tomls_from_github_tarball(&bytes);
                    resolve_and_seal_unlocked_crates(client, &vault, &tomls).await
                };
                (archived, unlocked, None)
            }
            Err(e) => (false, Vec::new(), Some(e)),
        }
    }

    pub(crate) fn remember_heartbeat(
        &self,
        name: &str,
        repo: Option<&str>,
        report: HeartbeatReport,
    ) {
        self.last_heartbeats
            .lock()
            .expect("last heartbeats mutex")
            .insert(scope_key(name, repo), report);
        self.persist_last_heartbeats();
    }

    pub(crate) fn remember_scan(&self, name: &str, repo: Option<&str>, mut report: CombinedScanReport) {
        if report.scanned_at == 0 {
            report.scanned_at = unix_now();
        }
        self.last_scans
            .lock()
            .expect("last scans mutex")
            .insert(scope_key(name, repo), report);
        self.persist_last_scans();
    }

    /// The last combined scan for this workspace, if one has been stored.
    pub fn last_scan(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<Option<CombinedScanReport>, ApiError> {
        self.authorize_op(Ops::READ)?;
        let repo = scope_repo(&repo);
        Ok(self
            .last_scans
            .lock()
            .expect("last scans mutex")
            .get(&scope_key(&name, repo))
            .cloned())
    }

    /// The stored `(project, lockfile text)` pairs for a folder, optionally filtered to one repo.
    /// Errors if the folder is unknown, the repo isn't in it, or — for folders downloaded before
    /// lockfile capture — asks the user to re-pull it.
    ///
    /// `name == "*"` unions every folder in the vault (the all-workspaces overview). A repo
    /// filter is not allowed on that view.
    fn stored_lockfiles(
        &self,
        name: &str,
        repo: Option<&str>,
    ) -> Result<Vec<(String, String)>, ApiError> {
        if is_all_workspaces(name) {
            if repo.is_some() {
                return Err(ApiError::bad_request(
                    "cannot scope a repository on the all-workspaces view",
                ));
            }
            let map = self
                .folder_lockfiles
                .lock()
                .expect("folder lockfiles mutex");
            let mut all = Vec::new();
            for files in map.values() {
                all.extend(files.iter().cloned());
            }
            return Ok(all);
        }
        let lockfiles = if let Some(lockfiles) = self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .get(name)
            .cloned()
        {
            lockfiles
        } else if self
            .folders
            .lock()
            .expect("folders mutex")
            .contains_key(name)
        {
            return Err(ApiError::bad_request(format!(
                "folder '{name}' was downloaded before lockfile capture — re-pull it to enable analytics/scan/coverage"
            )));
        } else {
            return Err(ApiError::bad_request(format!("no such folder: {name}")));
        };
        let Some(repo) = repo else {
            return Ok(lockfiles);
        };
        let filtered: Vec<_> = lockfiles
            .into_iter()
            .filter(|(full_name, _)| full_name == repo)
            .collect();
        if !filtered.is_empty() {
            return Ok(filtered);
        }
        // Listed in the folder but no Cargo.lock was captured (missing on GitHub, or fetch failed).
        // Treat as an empty workspace — not an error — so Overview/Scan/Analytics can load.
        let known = self
            .folders
            .lock()
            .expect("folders mutex")
            .get(name)
            .is_some_and(|f| f.repos.iter().any(|r| r.full_name == repo));
        if known {
            Ok(Vec::new())
        } else {
            Err(ApiError::bad_request(format!(
                "no such repository '{repo}' in '{name}'"
            )))
        }
    }

    /// Drop cached analytics for a folder and any per-repo slices of it.
    fn invalidate_analytics(&self, folder: &str) {
        let prefix = format!("{folder}::");
        self.analytics_cache
            .lock()
            .expect("analytics mutex")
            .retain(|k, _| k != folder && !k.starts_with(&prefix));
        self.persist_analytics_cache();
    }

    fn invalidate_last_scans(&self, folder: &str) {
        let prefix = format!("{folder}::");
        self.last_scans
            .lock()
            .expect("last scans mutex")
            .retain(|k, _| k != folder && !k.starts_with(&prefix));
    }

    fn invalidate_heartbeats(&self, folder: &str) {
        let prefix = format!("{folder}::");
        self.last_heartbeats
            .lock()
            .expect("last heartbeats mutex")
            .retain(|k, _| k != folder && !k.starts_with(&prefix));
        self.persist_last_heartbeats();
    }

    /// Attach an advisory database used by [`DeputyService::scan`].
    pub fn with_advisories(mut self, advisories: AdvisoryDb) -> Self {
        self.advisories = std::sync::RwLock::new(advisories);
        self
    }

    /// Replace the advisory database with a freshly-downloaded RUSTSEC one (capability: WRITE).
    /// Returns the number of advisories loaded. Skips the download when a set is already in memory.
    pub async fn load_rustsec_advisories(&self) -> Result<usize, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let n = self.advisory_count();
        if n > 0 {
            return Ok(n);
        }
        let db = crate::rustsec::fetch_rustsec()
            .await
            .map_err(ApiError::bad_request)?;
        let count = db.len();
        *self.advisories.write().expect("advisories lock") = db;
        Ok(count)
    }

    /// How many advisories are currently loaded.
    pub fn advisory_count(&self) -> usize {
        self.advisories.read().expect("advisories lock").len()
    }

    /// Prepare a browser GitHub sign-in (capability: WRITE). The vault must already be unlocked.
    pub fn begin_github_oauth(&self) -> Result<(), ApiError> {
        self.authorize_op(Ops::WRITE)?;
        self.vault()?;
        Ok(())
    }

    pub(crate) fn set_github_oauth_pending(
        &self,
        pending: crate::github_oauth::PendingGithubOauth,
    ) {
        *self.github_oauth.lock().expect("github oauth mutex") = Some(pending);
    }

    pub(crate) fn github_oauth_pending(&self) -> Option<crate::github_oauth::PendingGithubOauth> {
        self.github_oauth
            .lock()
            .expect("github oauth mutex")
            .clone()
    }

    pub(crate) fn clear_github_oauth_pending(&self) {
        *self.github_oauth.lock().expect("github oauth mutex") = None;
    }

    /// Connect (or replace) a GitHub token under a label (capability: WRITE). Multiple
    /// accounts can be connected; each keeps its own token.
    pub fn connect_github(
        &self,
        label: String,
        token: String,
        owner: String,
    ) -> Result<(), ApiError> {
        self.authorize_op(Ops::WRITE)?;
        if token.trim().is_empty() {
            return Err(ApiError::bad_request("empty GitHub token"));
        }
        let label = match label.trim() {
            "" => "GitHub".to_owned(),
            l => l.to_owned(),
        };
        let owner = owner.trim().to_owned();
        let mut conns = self
            .github_connections
            .lock()
            .expect("github connections mutex");
        // Replace the token/owner if this label is already connected; otherwise add a new account.
        match conns.iter_mut().find(|c| c.label == label) {
            Some(existing) => {
                existing.token = token;
                existing.owner = owner;
            }
            None => conns.push(GhConnection {
                label,
                token,
                owner,
            }),
        }
        drop(conns);
        self.persist_github_connections();
        Ok(())
    }

    /// Remove a connected GitHub account by label (capability: WRITE). No-op if absent.
    pub fn disconnect_github(&self, label: &str) -> Result<(), ApiError> {
        self.authorize_op(Ops::WRITE)?;
        self.github_connections
            .lock()
            .expect("github connections mutex")
            .retain(|c| c.label != label);
        self.persist_github_connections();
        Ok(())
    }

    /// The labels of all connected GitHub accounts (capability: READ) — never the tokens.
    pub fn github_connection_labels(&self) -> Result<Vec<String>, ApiError> {
        self.authorize_op(Ops::READ)?;
        self.vault()?; // gated: no account info before the vault is unlocked by sign-in
        Ok(self
            .github_connections
            .lock()
            .expect("github connections mutex")
            .iter()
            .map(|c| c.label.clone())
            .collect())
    }

    /// All connected accounts (label + token) (capability: READ), or a 400 if none are connected.
    pub(crate) fn github_connections(&self) -> Result<Vec<GhConnection>, ApiError> {
        self.authorize_op(Ops::READ)?;
        self.vault()?; // gated
        let conns = self
            .github_connections
            .lock()
            .expect("github connections mutex")
            .clone();
        if conns.is_empty() {
            return Err(ApiError::bad_request(
                "GitHub not connected — add an account on the GitHub tab first",
            ));
        }
        Ok(conns)
    }

    /// The tokens of all connected accounts (capability: READ), for trying lockfile fetches.
    pub(crate) fn github_tokens(&self) -> Result<Vec<String>, ApiError> {
        Ok(self
            .github_connections()?
            .into_iter()
            .map(|c| c.token)
            .collect())
    }

    /// Download + analyze the selected repos' lockfiles (capability: WRITE).
    ///
    /// `split = false` stores them as one named group (`folder`). `split = true` stores each repo
    /// as its own workspace named after `owner/name` — same vault acquisition, no extra fetches.
    pub async fn download_repos(
        &self,
        folder: String,
        repos: Vec<String>,
        split: bool,
    ) -> Result<FolderSummary, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let tokens = self.github_tokens()?;
        let client = github_http_client();

        // Fetch each lockfile (when present) and always archive the unique GitHub source tree.
        let mut staged = Vec::with_capacity(repos.len());
        let n_repos = repos.len().max(1);
        for (i, repo) in repos.into_iter().enumerate() {
            *self.download_progress.lock().expect("progress mutex") = Some((i, n_repos));
            let (lockfile_found, fetch_error, pins, lockfile_text) =
                match fetch_lockfile_any(&client, &tokens, &repo).await {
                    Ok(Some(text)) => {
                        let pins = parse_pins(&text).unwrap_or_default();
                        (true, None, pins, Some(text))
                    }
                    Ok(None) => (false, None, vec![], None),
                    Err(e) => (false, Some(e), vec![], None),
                };
            let (source_archived, unlocked_crates, source_err) = self
                .archive_github_source(&client, &tokens, &repo, lockfile_found)
                .await;
            let fetch_error = fetch_error.or(source_err.filter(|_| !source_archived && !lockfile_found));
            staged.push(StagedRepo {
                repo,
                lockfile_found,
                fetch_error,
                pins,
                lockfile_text,
                source_archived,
                unlocked_crates,
            });
        }
        *self.download_progress.lock().expect("progress mutex") = None;
        self.finish_download(folder, staged, split)
    }

    /// Acquire every dependency in the `Cargo.lock` files under a **local** folder path (no GitHub
    /// needed). Each `Cargo.lock` is treated as a project; its name is its directory relative to
    /// `path`. Useful when the source is already on disk and not pushed to GitHub.
    /// `split` persists each lockfile as its own workspace, same as [`Self::download_repos`].
    pub fn download_local(
        &self,
        folder: String,
        path: String,
        split: bool,
    ) -> Result<FolderSummary, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let root = std::path::Path::new(path.trim());
        if !root.is_dir() {
            return Err(ApiError::bad_request(format!(
                "not a folder: {}",
                root.display()
            )));
        }
        let lockfiles = find_lockfiles(root);
        if lockfiles.is_empty() {
            return Err(ApiError::bad_request(
                "no Cargo.lock found anywhere under that folder".to_owned(),
            ));
        }
        let mut staged = Vec::with_capacity(lockfiles.len());
        for lf in lockfiles {
            // Name a project by its directory relative to the chosen folder (root itself → its name).
            let name = lf
                .parent()
                .and_then(|p| p.strip_prefix(root).ok())
                .map(|rel| {
                    if rel.as_os_str().is_empty() {
                        root.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| ".".to_owned())
                    } else {
                        rel.to_string_lossy().into_owned()
                    }
                })
                .unwrap_or_else(|| lf.display().to_string());
            match std::fs::read_to_string(&lf) {
                Ok(text) => {
                    let pins = parse_pins(&text).unwrap_or_default();
                    staged.push(StagedRepo {
                        repo: name,
                        lockfile_found: true,
                        fetch_error: None,
                        pins,
                        lockfile_text: Some(text),
                        source_archived: false,
                        unlocked_crates: Vec::new(),
                    });
                }
                Err(e) => staged.push(StagedRepo {
                    repo: name,
                    lockfile_found: false,
                    fetch_error: Some(e.to_string()),
                    pins: vec![],
                    lockfile_text: None,
                    source_archived: false,
                    unlocked_crates: Vec::new(),
                }),
            }
        }
        self.finish_download(folder, staged, split)
    }

    /// Shared tail of [`Self::download_repos`] / [`Self::download_local`]: deduplicate pins across
    /// all projects (content-addressed, so a crate shared by several is fetched at most once),
    /// acquire the unique set once with progress, summarize per project, and persist as one group
    /// or as one workspace per repo.
    fn finish_download(
        &self,
        folder: String,
        staged: Vec<StagedRepo>,
        split: bool,
    ) -> Result<FolderSummary, ApiError> {
        let vault = self.vault()?;
        // Keep each project's raw lockfile so folder ops (analytics/scan/coverage/heartbeat) can
        // re-parse it offline — they no longer re-fetch from GitHub, which never worked for local
        // folders and defeated the offline-vault purpose anyway.
        let lockfiles: Vec<(String, String)> = staged
            .iter()
            .filter_map(|s| s.lockfile_text.clone().map(|t| (s.repo.clone(), t)))
            .collect();

        let mut seen: HashSet<String> = HashSet::new();
        let mut unique_pins: Vec<Pin> = Vec::new();
        for s in &staged {
            for p in &s.pins {
                if seen.insert(p.expected.to_hex()) {
                    unique_pins.push(p.clone());
                }
            }
        }
        let total = unique_pins.len();
        *self.download_progress.lock().expect("progress mutex") = Some((0, total));

        // Acquire the unique set once, reporting progress. `acquire_one` skips anything already
        // sealed from a previous session, so nothing is ever fetched twice.
        let progress = &self.download_progress;
        acquire_pins(&vault, &self.ecosystem, &unique_pins, |i, _| {
            *progress.lock().expect("progress mutex") = Some((i, total));
        });
        *self.download_progress.lock().expect("progress mutex") = None;

        // Per-project summary: `deps` is its lockfile pin count; `acquired` is how many of its pins
        // are now sealed (a crate shared with another project counts as acquired for both).
        let mut summaries = Vec::with_capacity(staged.len());
        for s in staged {
            let acquired = s
                .pins
                .iter()
                .filter(|p| {
                    vault
                        .has_artifact(StoreKind::Dirty, &p.expected)
                        .unwrap_or(false)
                })
                .count()
                + s.unlocked_crates.len();
            let deps = s.pins.len() + s.unlocked_crates.len();
            let error = if s.fetch_error.is_some() {
                s.fetch_error
            } else if s.lockfile_found && acquired < deps {
                Some(format!(
                    "{} of {} deps failed to acquire",
                    deps - acquired,
                    deps
                ))
            } else {
                None
            };
            summaries.push(RepoSummary {
                full_name: s.repo,
                deps,
                acquired,
                lockfile_found: s.lockfile_found,
                source_archived: s.source_archived,
                error,
            });
        }

        let summary = if split {
            // One workspace per repo, named after owner/name (or the local project path).
            for r in &summaries {
                let name = r.full_name.clone();
                let lf: Vec<(String, String)> = lockfiles
                    .iter()
                    .filter(|(n, _)| n == &name)
                    .cloned()
                    .collect();
                self.invalidate_analytics(&name);
                self.invalidate_heartbeats(&name);
                self.folder_lockfiles
                    .lock()
                    .expect("folder lockfiles mutex")
                    .insert(name.clone(), lf);
                self.folders.lock().expect("folders mutex").insert(
                    name.clone(),
                    FolderSummary {
                        name,
                        repos: vec![r.clone()],
                    },
                );
            }
            let name = if summaries.len() == 1 {
                summaries[0].full_name.clone()
            } else {
                format!("{} repositories", summaries.len())
            };
            FolderSummary {
                name,
                repos: summaries,
            }
        } else {
            let name = folder.trim();
            if name.is_empty() {
                return Err(ApiError::bad_request(
                    "a group name is required (e.g. Remade-With-Rust)".to_owned(),
                ));
            }
            if is_all_workspaces(name) {
                return Err(ApiError::bad_request(
                    "'*' is reserved for the all-workspaces overview".to_owned(),
                ));
            }
            self.invalidate_analytics(name);
            self.invalidate_heartbeats(name);
            self.folder_lockfiles
                .lock()
                .expect("folder lockfiles mutex")
                .insert(name.to_owned(), lockfiles);
            let summary = FolderSummary {
                name: name.to_owned(),
                repos: summaries,
            };
            self.folders
                .lock()
                .expect("folders mutex")
                .insert(name.to_owned(), summary.clone());
            summary
        };
        self.persist_folders();
        self.persist_folder_lockfiles();
        Ok(summary)
    }

    /// Re-fetch `Cargo.lock` from GitHub for the workspaces in `name` / `repo` and acquire any
    /// newly pinned crates. Existing folders are merged, not replaced — a failed fetch keeps the
    /// last lockfile. Local-only workspaces cannot be re-read from disk (no path is stored).
    pub async fn refresh_workspace(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<FolderSummary, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let repo = scope_repo(&repo).map(str::to_owned);
        if is_all_workspaces(&name) && repo.is_some() {
            return Err(ApiError::bad_request(
                "cannot scope a repository on the all-workspaces view",
            ));
        }

        let folders_snapshot: Vec<FolderSummary> = {
            let map = self.folders.lock().expect("folders mutex");
            if is_all_workspaces(&name) {
                map.values().cloned().collect()
            } else {
                match map.get(&name) {
                    Some(f) => vec![f.clone()],
                    None => {
                        return Err(ApiError::bad_request(format!("no such folder: {name}")));
                    }
                }
            }
        };

        if folders_snapshot.is_empty() {
            return Ok(FolderSummary {
                name: scope_label(&name, repo.as_deref()),
                repos: Vec::new(),
            });
        }

        if let Some(ref want) = repo {
            let folder = &folders_snapshot[0];
            if !folder.repos.iter().any(|r| &r.full_name == want) {
                return Err(ApiError::bad_request(format!(
                    "no such repository '{want}' in '{name}'"
                )));
            }
        }

        let mut jobs: Vec<(String, String)> = Vec::new();
        for folder in &folders_snapshot {
            for r in &folder.repos {
                if repo.as_ref().is_some_and(|want| &r.full_name != want) {
                    continue;
                }
                if is_github_full_name(&r.full_name) {
                    jobs.push((folder.name.clone(), r.full_name.clone()));
                }
            }
        }

        if jobs.is_empty() {
            return Err(ApiError::bad_request(
                "no GitHub repositories in this selection to refresh — local folders must be re-added from the GitHub or Local folder tab",
            ));
        }

        let tokens = self.github_tokens()?;
        let client = github_http_client();
        let mut updates: HashMap<String, Vec<StagedRepo>> = HashMap::new();
        let n_jobs = jobs.len().max(1);
        for (i, (folder, repo_name)) in jobs.into_iter().enumerate() {
            *self.download_progress.lock().expect("progress mutex") = Some((i, n_jobs));
            let (lockfile_found, mut fetch_error, pins, lockfile_text) =
                match fetch_lockfile_any(&client, &tokens, &repo_name).await {
                    Ok(Some(text)) => {
                        let pins = parse_pins(&text).unwrap_or_default();
                        (true, None, pins, Some(text))
                    }
                    Ok(None) => (false, None, Vec::new(), None),
                    Err(e) => (false, Some(e), Vec::new(), None),
                };
            let (source_archived, unlocked_crates, source_err) = self
                .archive_github_source(&client, &tokens, &repo_name, lockfile_found)
                .await;
            if fetch_error.is_none() && !source_archived {
                fetch_error = source_err;
            }
            updates.entry(folder).or_default().push(StagedRepo {
                repo: repo_name,
                lockfile_found,
                fetch_error,
                pins,
                lockfile_text,
                source_archived,
                unlocked_crates,
            });
        }
        *self.download_progress.lock().expect("progress mutex") = None;

        self.apply_refresh_updates(name, repo.as_deref(), updates)
    }

    fn apply_refresh_updates(
        &self,
        request_name: String,
        request_repo: Option<&str>,
        updates: HashMap<String, Vec<StagedRepo>>,
    ) -> Result<FolderSummary, ApiError> {
        let vault = self.vault()?;
        let mut unique_pins: Vec<Pin> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut merged: HashMap<String, Vec<(String, String)>> = HashMap::new();

        {
            let mut lockfiles = self
                .folder_lockfiles
                .lock()
                .expect("folder lockfiles mutex");
            for (folder, staged) in &updates {
                let mut files = lockfiles.get(folder).cloned().unwrap_or_default();
                for s in staged {
                    if let Some(text) = &s.lockfile_text {
                        if let Some(slot) = files.iter_mut().find(|(n, _)| n == &s.repo) {
                            slot.1 = text.clone();
                        } else {
                            files.push((s.repo.clone(), text.clone()));
                        }
                        for p in &s.pins {
                            if seen.insert(p.expected.to_hex()) {
                                unique_pins.push(p.clone());
                            }
                        }
                    }
                }
                lockfiles.insert(folder.clone(), files.clone());
                merged.insert(folder.clone(), files);
            }
        }

        for folder in updates.keys() {
            self.invalidate_analytics(folder);
            self.invalidate_heartbeats(folder);
        }

        let total = unique_pins.len();
        *self.download_progress.lock().expect("progress mutex") = Some((0, total));
        if !unique_pins.is_empty() {
            let progress = &self.download_progress;
            acquire_pins(&vault, &self.ecosystem, &unique_pins, |i, _| {
                *progress.lock().expect("progress mutex") = Some((i, total));
            });
        }
        *self.download_progress.lock().expect("progress mutex") = None;

        let mut combined = Vec::new();
        {
            let mut folders = self.folders.lock().expect("folders mutex");
            for (folder, staged) in &updates {
                let files = merged.get(folder).cloned().unwrap_or_default();
                let err_by_repo: HashMap<String, String> = staged
                    .iter()
                    .filter_map(|s| s.fetch_error.clone().map(|e| (s.repo.clone(), e)))
                    .collect();
                let existing_order: Vec<String> = folders
                    .get(folder)
                    .map(|f| f.repos.iter().map(|r| r.full_name.clone()).collect())
                    .unwrap_or_else(|| files.iter().map(|(n, _)| n.clone()).collect());

                let staged_by_repo: HashMap<&str, &StagedRepo> =
                    staged.iter().map(|s| (s.repo.as_str(), s)).collect();
                let mut summaries = Vec::with_capacity(existing_order.len());
                for repo_name in existing_order {
                    let extra = staged_by_repo.get(repo_name.as_str());
                    let unlocked = extra.map(|s| s.unlocked_crates.len()).unwrap_or(0);
                    let source_archived = extra
                        .map(|s| s.source_archived)
                        .unwrap_or_else(|| self.source_is_archived(&repo_name));
                    let text = files
                        .iter()
                        .find(|(n, _)| n == &repo_name)
                        .map(|(_, t)| t.as_str());
                    let pins = text
                        .map(parse_pins)
                        .and_then(Result::ok)
                        .unwrap_or_default();
                    let pin_acquired = pins
                        .iter()
                        .filter(|p| {
                            vault
                                .has_artifact(StoreKind::Dirty, &p.expected)
                                .unwrap_or(false)
                        })
                        .count();
                    let acquired = pin_acquired + unlocked;
                    let deps = pins.len() + unlocked;
                    let error = match err_by_repo.get(&repo_name) {
                        Some(e) => Some(e.clone()),
                        None if !pins.is_empty() && pin_acquired < pins.len() => Some(format!(
                            "{} of {} deps failed to acquire",
                            pins.len() - pin_acquired,
                            pins.len()
                        )),
                        None => None,
                    };
                    summaries.push(RepoSummary {
                        full_name: repo_name,
                        deps,
                        acquired,
                        lockfile_found: text.is_some(),
                        source_archived,
                        error,
                    });
                }
                if let Some(want) = request_repo {
                    combined.extend(
                        summaries
                            .iter()
                            .filter(|r| r.full_name == want)
                            .cloned(),
                    );
                } else {
                    combined.extend(summaries.iter().cloned());
                }
                folders.insert(
                    folder.clone(),
                    FolderSummary {
                        name: folder.clone(),
                        repos: summaries,
                    },
                );
            }
        }

        self.persist_folders();
        self.persist_folder_lockfiles();
        Ok(FolderSummary {
            name: scope_label(&request_name, request_repo),
            repos: combined,
        })
    }

    /// The live acquisition progress `(done, total)` for the in-flight download, if any.
    pub fn download_progress(&self) -> Option<(usize, usize)> {
        *self.download_progress.lock().expect("progress mutex")
    }

    fn set_scan_progress(&self, stage: &str, label: &str, done: usize, total: usize) {
        *self.scan_progress.lock().expect("scan progress mutex") = Some(ScanProgress {
            stage: stage.to_owned(),
            label: label.to_owned(),
            done,
            total,
        });
    }

    fn clear_scan_progress(&self) {
        *self.scan_progress.lock().expect("scan progress mutex") = None;
    }

    /// Live combined-scan progress, if a scan is in flight.
    pub fn scan_progress(&self) -> Option<ScanProgress> {
        self.scan_progress
            .lock()
            .expect("scan progress mutex")
            .clone()
    }

    fn begin_heartbeat_progress(&self, name: String, total: usize) -> u64 {
        let epoch = self
            .heartbeat_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        *self
            .heartbeat_progress
            .lock()
            .expect("heartbeat progress mutex") = Some((
            epoch,
            HeartbeatProgress {
                name,
                done: 0,
                total,
                entries: Vec::with_capacity(total),
            },
        ));
        epoch
    }

    fn publish_heartbeat(&self, epoch: u64, entry: Option<HeartbeatEntry>) {
        let mut guard = self
            .heartbeat_progress
            .lock()
            .expect("heartbeat progress mutex");
        let Some((current, progress)) = guard.as_mut() else {
            return;
        };
        if *current != epoch {
            return;
        }
        if let Some(entry) = entry {
            progress.entries.push(entry);
        }
        progress.done = progress.done.saturating_add(1).min(progress.total);
    }

    fn clear_heartbeat_progress(&self, epoch: u64) {
        let mut guard = self
            .heartbeat_progress
            .lock()
            .expect("heartbeat progress mutex");
        if guard.as_ref().is_some_and(|(current, _)| *current == epoch) {
            *guard = None;
        }
    }

    /// Live heartbeat snapshot, if a heartbeat is in flight.
    pub fn heartbeat_progress(&self) -> Option<HeartbeatProgress> {
        self.heartbeat_progress
            .lock()
            .expect("heartbeat progress mutex")
            .as_ref()
            .map(|(_, progress)| progress.clone())
    }

    fn pin_advisories(&self, name: &str, version: &str) -> Vec<String> {
        semver::Version::parse(version)
            .ok()
            .map(|v| {
                self.advisories
                    .read()
                    .expect("advisories lock")
                    .check(name, &v)
                    .iter()
                    .map(|a| a.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn begin_analytics_progress(&self, name: String, total: usize) -> u64 {
        let epoch = self
            .analytics_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        *self
            .analytics_progress
            .lock()
            .expect("analytics progress mutex") = Some((
            epoch,
            AnalyticsProgress {
                name,
                done: 0,
                total,
                analyzed: 0,
                by_language: Vec::new(),
                deps: Vec::new(),
                build_scripts: 0,
                proc_macros: 0,
                native_crates: 0,
                unsafe_crates: 0,
            },
        ));
        epoch
    }

    fn publish_analytics(
        &self,
        epoch: u64,
        name: &str,
        body: &AnalyticsBody,
        done: usize,
        total: usize,
    ) {
        let mut guard = self
            .analytics_progress
            .lock()
            .expect("analytics progress mutex");
        let Some((current, progress)) = guard.as_mut() else {
            return;
        };
        if *current != epoch {
            return;
        }
        progress.name = name.to_owned();
        progress.done = done;
        progress.total = total;
        progress.analyzed = body.analyzed;
        progress.by_language = body.by_language.clone();
        progress.deps = body.deps.clone();
        progress.build_scripts = body.build_scripts;
        progress.proc_macros = body.proc_macros;
        progress.native_crates = body.native_crates;
        progress.unsafe_crates = body.unsafe_crates;
    }

    fn clear_analytics_progress(&self, epoch: u64) {
        let mut guard = self
            .analytics_progress
            .lock()
            .expect("analytics progress mutex");
        if guard.as_ref().is_some_and(|(current, _)| *current == epoch) {
            *guard = None;
        }
    }

    /// Live analytics snapshot, if an inspect is in flight.
    pub fn analytics_progress(&self) -> Option<AnalyticsProgress> {
        self.analytics_progress
            .lock()
            .expect("analytics progress mutex")
            .as_ref()
            .map(|(_, progress)| progress.clone())
    }

    /// All named folders and their repositories (capability: READ).
    pub fn folders(&self) -> Result<Vec<FolderSummary>, ApiError> {
        self.authorize_op(Ops::READ)?;
        let vault = self.vault()?;
        let files = self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .clone();
        let archived = self
            .repo_archives
            .lock()
            .expect("repo archives mutex")
            .clone();
        let mut list: Vec<FolderSummary> = self
            .folders
            .lock()
            .expect("folders mutex")
            .values()
            .cloned()
            .collect();
        for folder in &mut list {
            let stored = files.get(&folder.name).cloned().unwrap_or_default();
            for repo in &mut folder.repos {
                if archived.contains_key(&repo.full_name) {
                    repo.source_archived = true;
                }
                let Some((_, text)) = stored.iter().find(|(n, _)| n == &repo.full_name) else {
                    continue;
                };
                let Ok(pins) = parse_pins(text) else {
                    continue;
                };
                if pins.is_empty() {
                    continue;
                }
                repo.lockfile_found = true;
                if repo.deps == 0 {
                    repo.deps = pins.len();
                    repo.acquired = pins
                        .iter()
                        .filter(|p| {
                            vault
                                .has_artifact(StoreKind::Dirty, &p.expected)
                                .unwrap_or(false)
                        })
                        .count();
                }
            }
        }
        Ok(list)
    }

    #[cfg(test)]
    pub(crate) fn test_put_folder(
        &self,
        folder: FolderSummary,
        lockfiles: Vec<(String, String)>,
    ) {
        let name = folder.name.clone();
        self.folders
            .lock()
            .expect("folders mutex")
            .insert(name.clone(), folder);
        self.folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .insert(name, lockfiles);
    }

    /// Remove a named folder (capability: WRITE). No-op if it doesn't exist.
    pub fn delete_folder(&self, name: &str) -> Result<(), ApiError> {
        self.authorize_op(Ops::WRITE)?;
        self.folders.lock().expect("folders mutex").remove(name);
        self.folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .remove(name);
        self.invalidate_analytics(name);
        self.invalidate_last_scans(name);
        self.invalidate_heartbeats(name);
        self.persist_folders();
        self.persist_folder_lockfiles();
        self.persist_last_scans();
        Ok(())
    }

    /// Dependency-language analytics for a folder (capability: READ). Downloads + inspects each
    /// unique dependency crate the first time (slow); subsequent calls are served from the
    /// persisted cache. Progress (including completed crates) is published via
    /// [`Self::analytics_progress`].
    pub async fn folder_analytics(
        self: std::sync::Arc<Self>,
        name: String,
        repo: Option<String>,
    ) -> Result<DepAnalytics, ApiError> {
        self.authorize_op(Ops::READ)?;
        let repo = scope_repo(&repo);
        let cache_key = scope_key(&name, repo);
        if let Some(cached) = self
            .analytics_cache
            .lock()
            .expect("analytics mutex")
            .get(&cache_key)
            .cloned()
        {
            return Ok(cached);
        }
        // Unique pins across the folder's stored lockfiles (offline; GitHub or local).
        let pins = self.folder_unique_pins(&name, repo)?;
        let total_deps = pins.len();
        let label = scope_label(&name, repo);
        let epoch = self.begin_analytics_progress(label.clone(), total_deps);
        tokio::task::yield_now().await;

        let vault = self.vault()?;
        let svc = self.clone();
        let tick_label = label.clone();
        let body = tokio::task::spawn_blocking(move || {
            compute_dep_analytics(&vault, pins, |body, done, total| {
                svc.publish_analytics(epoch, &tick_label, body, done, total);
            })
        })
        .await
        .map_err(|e| ApiError::bad_request(format!("analytics task failed: {e}")))?;
        self.clear_analytics_progress(epoch);

        let analytics = DepAnalytics {
            name: label,
            total_deps,
            analyzed: body.analyzed,
            by_language: body.by_language,
            deps: body.deps,
            build_scripts: body.build_scripts,
            proc_macros: body.proc_macros,
            native_crates: body.native_crates,
            unsafe_crates: body.unsafe_crates,
        };
        self.analytics_cache
            .lock()
            .expect("analytics mutex")
            .insert(cache_key, analytics.clone());
        self.persist_analytics_cache();
        Ok(analytics)
    }

    /// The unique pins across a folder's stored lockfiles (works offline, GitHub or local),
    /// optionally limited to one repository.
    fn folder_unique_pins(&self, name: &str, repo: Option<&str>) -> Result<Vec<Pin>, ApiError> {
        let mut unique: std::collections::BTreeMap<(String, String), Pin> = Default::default();
        for (_repo, text) in self.stored_lockfiles(name, repo)? {
            if let Ok(pins) = parse_pins(&text) {
                for p in pins {
                    let key = (
                        p.dep.name.as_str().to_owned(),
                        p.dep.version.as_str().to_owned(),
                    );
                    unique.insert(key, p);
                }
            }
        }
        Ok(unique.into_values().collect())
    }

    fn pin_cache_key(pin: &Pin) -> (String, String) {
        (
            pin.dep.name.as_str().to_owned(),
            pin.dep.version.as_str().to_owned(),
        )
    }

    /// `(folder, repo full_name)` pairs that have a stored lockfile in this scope.
    fn lockfile_repo_scopes(&self, name: &str) -> Vec<(String, String)> {
        let map = self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex");
        if is_all_workspaces(name) {
            map.iter()
                .flat_map(|(folder, files)| {
                    files
                        .iter()
                        .map(|(repo, _)| (folder.clone(), repo.clone()))
                })
                .collect()
        } else {
            map.get(name)
                .into_iter()
                .flat_map(|files| {
                    files
                        .iter()
                        .map(|(repo, _)| (name.to_owned(), repo.clone()))
                })
                .collect()
        }
    }

    /// Cache keys to read for a heartbeat. Per-repo keys come first so a group/all view
    /// prefers child-repo results over a stale group snapshot.
    fn heartbeat_cache_keys(&self, name: &str, repo: Option<&str>) -> Vec<String> {
        if let Some(r) = repo {
            let mut keys = vec![scope_key(name, Some(r))];
            if name != r {
                keys.push(scope_key(r, None));
            }
            return keys;
        }
        // Per-repo caches only — never the group/`*` aggregate. That snapshot is often older
        // than child-repo checks and would hide their updates.
        let mut keys = Vec::new();
        let mut seen = HashSet::new();
        for (folder, repo_name) in self.lockfile_repo_scopes(name) {
            for key in [
                scope_key(&folder, Some(&repo_name)),
                scope_key(&repo_name, None),
                scope_key(&folder, None),
            ] {
                if folder != repo_name && key == scope_key(&folder, None) {
                    continue;
                }
                if seen.insert(key.clone()) {
                    keys.push(key);
                }
            }
        }
        keys
    }

    fn cached_heartbeat_pins(
        &self,
        name: &str,
        repo: Option<&str>,
    ) -> HashMap<(String, String), HeartbeatEntry> {
        let keys = self.heartbeat_cache_keys(name, repo);
        let cache = self
            .last_heartbeats
            .lock()
            .expect("last heartbeats mutex");
        let mut by_pin = HashMap::new();
        for key in keys {
            let Some(report) = cache.get(&key) else {
                continue;
            };
            for e in &report.entries {
                if e.latest_updated.is_none() {
                    continue;
                }
                by_pin
                    .entry((e.name.clone(), e.current.clone()))
                    .and_modify(|cur: &mut HeartbeatEntry| {
                        if e.update_available && !cur.update_available {
                            *cur = e.clone();
                        }
                    })
                    .or_insert_with(|| e.clone());
            }
        }
        by_pin
    }

    /// The social heartbeat for a folder's dependencies (capability: READ): for each unique dep,
    /// fetch the latest crates.io version and surface advisories on the pinned version.
    /// Progress (including completed entries) is published via [`Self::heartbeat_progress`].
    ///
    /// A group or all-workspaces view is composed from each child repo's cached heartbeat so
    /// visiting a repo never leaves the parent Overview missing that repo's updates.
    pub async fn folder_heartbeat(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<HeartbeatReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let repo = scope_repo(&repo);
        let pins = self.folder_unique_pins(&name, repo)?;
        let label = scope_label(&name, repo);
        let mut by_pin = self.cached_heartbeat_pins(&name, repo);
        let missing: Vec<Pin> = pins
            .iter()
            .filter(|p| !by_pin.contains_key(&Self::pin_cache_key(p)))
            .cloned()
            .collect();
        if missing.is_empty() {
            let entries = pins
                .iter()
                .filter_map(|p| by_pin.get(&Self::pin_cache_key(p)).cloned())
                .collect();
            let report = HeartbeatReport {
                name: label,
                entries,
            };
            self.remember_heartbeat(&name, repo, report.clone());
            return Ok(report);
        }
        let epoch = self.begin_heartbeat_progress(label.clone(), pins.len());
        tokio::task::yield_now().await;
        for p in &pins {
            if let Some(e) = by_pin.get(&Self::pin_cache_key(p)) {
                self.publish_heartbeat(epoch, Some(e.clone()));
            }
        }
        let fetched = self.folder_heartbeat_inner(epoch, missing).await;
        self.clear_heartbeat_progress(epoch);
        for e in fetched? {
            by_pin.insert((e.name.clone(), e.current.clone()), e);
        }
        let entries = pins
            .iter()
            .filter_map(|p| by_pin.get(&Self::pin_cache_key(p)).cloned())
            .collect();
        let report = HeartbeatReport {
            name: label,
            entries,
        };
        self.remember_heartbeat(&name, repo, report.clone());
        Ok(report)
    }

    async fn folder_heartbeat_inner(
        &self,
        epoch: u64,
        pins: Vec<Pin>,
    ) -> Result<Vec<HeartbeatEntry>, ApiError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("deputy")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut handles = Vec::with_capacity(pins.len());
        for pin in pins {
            let client = client.clone();
            let sem = sem.clone();
            let dep_name = pin.dep.name.as_str().to_owned();
            let current = pin.dep.version.as_str().to_owned();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                let latest = crates_io_latest(&client, &dep_name).await;
                (dep_name, current, latest)
            }));
        }

        let mut entries = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok((dep_name, current, latest)) => {
                    let (latest, latest_updated) = match latest {
                        Some((ver, ts)) => (Some(ver), Some(ts.unwrap_or(0))),
                        None => (None, Some(0)),
                    };
                    let update_available = match (
                        semver::Version::parse(&current),
                        latest
                            .as_deref()
                            .and_then(|l| semver::Version::parse(l).ok()),
                    ) {
                        (Ok(cur), Some(lat)) => lat > cur,
                        _ => false,
                    };
                    let advisories = self.pin_advisories(&dep_name, &current);
                    let entry = HeartbeatEntry {
                        name: dep_name,
                        current,
                        latest,
                        update_available,
                        advisories,
                        latest_updated,
                    };
                    entries.push(entry.clone());
                    self.publish_heartbeat(epoch, Some(entry));
                }
                Err(_) => self.publish_heartbeat(epoch, None),
            }
            tokio::task::yield_now().await;
        }
        Ok(entries)
    }

    /// Scan a folder's dependencies for newer published releases and **stage** each new version
    /// (download + SHA-256 verify into the dirty store) alongside the current one — which may
    /// already be in production (capability: WRITE).
    pub async fn scan_new_versions(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<NewVersionReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let repo = scope_repo(&repo);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("deputy")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let pins = self.folder_unique_pins(&name, repo)?;

        // crates.io, concurrently (a sequential ping per unique crate looks hung on a full vault).
        let total = pins.len().max(1);
        self.set_scan_progress("updates", "Checking crates.io (network)", 0, total);
        tokio::task::yield_now().await;
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        let mut handles = Vec::with_capacity(pins.len());
        for pin in &pins {
            let client = client.clone();
            let sem = sem.clone();
            let dep_name = pin.dep.name.as_str().to_owned();
            let current = pin.dep.version.as_str().to_owned();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.ok();
                let latest = crates_io_latest_versioned(&client, &dep_name).await;
                (dep_name, current, latest)
            }));
        }
        let mut updates: Vec<(String, String, String, String)> = Vec::new();
        for (i, handle) in handles.into_iter().enumerate() {
            self.set_scan_progress("updates", "Checking crates.io (network)", i, total);
            let Ok((dep_name, current, latest)) = handle.await else {
                continue;
            };
            if let Some((latest, checksum)) = latest {
                let newer = matches!(
                    (
                        semver::Version::parse(&current),
                        semver::Version::parse(&latest)
                    ),
                    (Ok(c), Ok(l)) if l > c
                );
                if newer {
                    updates.push((dep_name, current, latest, checksum));
                }
            }
        }
        self.set_scan_progress("updates", "Checking crates.io (network)", pins.len(), total);

        // Stage the new versions into the dirty store via a synthetic lockfile (reuses the
        // fetch -> verify -> seal pipeline).
        let mut lockfile = String::from("version = 4\n");
        for (dep, _cur, new, sum) in &updates {
            lockfile.push_str(&format!(
                "\n[[package]]\nname = \"{dep}\"\nversion = \"{new}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sum}\"\n"
            ));
        }
        let new_pins = parse_pins(&lockfile).unwrap_or_default();
        let vault = self.vault()?;
        let stage_total = new_pins.len().max(1);
        acquire_pins(&vault, &self.ecosystem, &new_pins, |i, _| {
            self.set_scan_progress("updates", "Staging new versions", i, stage_total);
        });

        let entries = updates
            .into_iter()
            .map(|(dep, cur, new, _)| {
                let in_production = vault
                    .crate_hash(StoreKind::Prod, &dep, &cur)
                    .ok()
                    .flatten()
                    .is_some();
                let staged_ok = new_pins
                    .iter()
                    .find(|p| p.dep.name.as_str() == dep && p.dep.version.as_str() == new)
                    .map(|p| {
                        vault
                            .has_artifact(StoreKind::Dirty, &p.expected)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                NewVersionEntry {
                    name: dep,
                    production: cur,
                    in_production,
                    staged: new,
                    staged_ok,
                }
            })
            .collect();
        Ok(NewVersionReport {
            name: scope_label(&name, repo),
            entries,
        })
    }

    /// Offline-archive coverage for a folder (capability: READ): walk every repo's `Cargo.lock`,
    /// classify each dependency, and report which ones are safely sealed in the vault vs. which are
    /// gaps — missing crates.io deps (failed/never acquired), git deps, or other registries that
    /// Deputy can't content-verify. Path/workspace members (your own code) are ignored.
    pub fn folder_coverage(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<CoverageReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let repo = scope_repo(&repo);
        let vault = self.vault()?;

        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut registry_total = 0usize;
        let mut archived = 0usize;
        let mut gaps: Vec<CoverageGap> = Vec::new();

        for (_repo, text) in self.stored_lockfiles(&name, repo)? {
            let Ok(lock) = toml::from_str::<RawLock>(&text) else {
                continue;
            };
            for pkg in lock.package {
                if !seen.insert((pkg.name.clone(), pkg.version.clone())) {
                    continue;
                }
                // No source = workspace/path member (your own code), not a dependency to archive.
                let Some(source) = pkg.source.as_deref() else {
                    continue;
                };
                if source.starts_with("git+") {
                    gaps.push(CoverageGap {
                        name: pkg.name,
                        version: pkg.version,
                        reason: "git dependency".to_owned(),
                    });
                } else if is_cratesio(source) {
                    registry_total += 1;
                    let staged = pkg
                        .checksum
                        .as_deref()
                        .and_then(|c| ContentHash::from_sha256_hex(c).ok())
                        .map(|h| {
                            vault.has_artifact(StoreKind::Dirty, &h).unwrap_or(false)
                                || vault.has_artifact(StoreKind::Prod, &h).unwrap_or(false)
                        })
                        .unwrap_or(false);
                    if staged {
                        archived += 1;
                    } else {
                        gaps.push(CoverageGap {
                            name: pkg.name,
                            version: pkg.version,
                            reason: "not acquired".to_owned(),
                        });
                    }
                } else {
                    gaps.push(CoverageGap {
                        name: pkg.name,
                        version: pkg.version,
                        reason: "other registry".to_owned(),
                    });
                }
            }
        }
        // Surface the actionable gaps first (not acquired), then the structural ones.
        gaps.sort_by(|a, b| a.reason.cmp(&b.reason).then(a.name.cmp(&b.name)));
        Ok(CoverageReport {
            name: scope_label(&name, repo),
            registry_total,
            archived,
            gaps,
        })
    }

    /// Local vault + advisory snapshot for a workspace landing page (capability: READ).
    /// Outdated counts stay on the heartbeat path — this call does not hit crates.io.
    pub fn folder_overview(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<WorkspaceOverview, ApiError> {
        self.authorize_op(Ops::READ)?;
        let repo = scope_repo(&repo);
        let lockfiles = self.stored_lockfiles(&name, repo)?;
        let pins = self.folder_unique_pins(&name, repo)?;
        let vault = self.vault()?;
        let mut acquired = 0usize;
        let mut in_production = 0usize;
        for pin in &pins {
            let prod = vault
                .has_artifact(StoreKind::Prod, &pin.expected)
                .unwrap_or(false);
            let dirty = vault
                .has_artifact(StoreKind::Dirty, &pin.expected)
                .unwrap_or(false);
            if prod {
                in_production += 1;
            }
            if prod || dirty {
                acquired += 1;
            }
        }
        let mut advisory_hits = 0usize;
        {
            let advisories = self.advisories.read().expect("advisories lock");
            for pin in &pins {
                let Ok(ver) = semver::Version::parse(pin.dep.version.as_str()) else {
                    continue;
                };
                if !advisories.check(pin.dep.name.as_str(), &ver).is_empty() {
                    advisory_hits += 1;
                }
            }
        }
        let coverage = self.folder_coverage(name.clone(), repo.map(str::to_owned))?;
        let repos = if is_all_workspaces(&name) {
            let folders = self.folders.lock().expect("folders mutex");
            let mut seen = HashSet::new();
            for f in folders.values() {
                for r in &f.repos {
                    seen.insert(r.full_name.as_str());
                }
            }
            if seen.is_empty() {
                lockfiles
                    .iter()
                    .map(|(n, _)| n.as_str())
                    .collect::<HashSet<_>>()
                    .len()
            } else {
                seen.len()
            }
        } else {
            let folders = self.folders.lock().expect("folders mutex");
            match folders.get(&name) {
                Some(f) => match repo {
                    Some(r) => f.repos.iter().filter(|x| x.full_name == r).count(),
                    None => f.repos.len(),
                },
                None => lockfiles.len(),
            }
        };
        Ok(WorkspaceOverview {
            name: scope_label(&name, repo),
            repos,
            lockfiles: lockfiles.len(),
            unique_deps: pins.len(),
            acquired,
            in_production,
            advisory_hits,
            rustsec_loaded: self.advisory_count(),
            archived: coverage.archived,
            registry_total: coverage.registry_total,
            gaps: coverage.gaps.len(),
        })
    }

    /// Promote a folder's scanned-clean, acquired dependencies into the production store
    /// (capability: WRITE), each with a hash-chained receipt. Returns the count promoted.
    ///
    /// `only` (when non-empty) is the opt-in list from New Versions: those name@version crates
    /// are staged if needed, then promoted. Otherwise every clean pin not in `hold` is promoted.
    pub async fn promote_folder(
        &self,
        name: String,
        repo: Option<String>,
        hold: Vec<(String, String)>,
        only: Vec<(String, String)>,
    ) -> Result<usize, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let pins = self.folder_unique_pins(&name, scope_repo(&repo))?;
        let hold: HashSet<(String, String)> = hold.into_iter().collect();
        let did = self.session().did;

        if !only.is_empty() {
            self.stage_named_versions(&only).await?;
        }

        let targets: Vec<Pin> = if !only.is_empty() {
            only.iter()
                .filter_map(|(n, v)| pin_for_named_version(&vault, &pins, n, v))
                .collect()
        } else {
            pins.iter()
                .filter(|pin| {
                    !hold.contains(&(
                        pin.dep.name.as_str().to_owned(),
                        pin.dep.version.as_str().to_owned(),
                    ))
                })
                .cloned()
                .collect()
        };

        // Scan each dep first so its verdict is recorded — `promote` refuses anything un-scanned.
        {
            let advisories = self.advisories.read().expect("advisories lock");
            for pin in &targets {
                let _ = scan(&vault, pin, &advisories);
            }
        }

        // `promote` quarantines anything with scan findings, so flagged deps stay in staging.
        let promoted = targets
            .iter()
            .filter(|pin| {
                promote(
                    &vault,
                    pin.dep.ecosystem,
                    pin.dep.name.as_str(),
                    pin.dep.version.as_str(),
                    &pin.expected,
                    Some(&did),
                )
                .is_ok()
            })
            .count();
        Ok(promoted)
    }

    /// Download + seal any `only` versions that are not already in the dirty store.
    async fn stage_named_versions(&self, only: &[(String, String)]) -> Result<(), ApiError> {
        let vault = self.vault()?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("deputy")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let mut lockfile = String::from("version = 4\n");
        let mut any = false;
        for (name, version) in only {
            if vault
                .crate_hash(StoreKind::Dirty, name, version)
                .ok()
                .flatten()
                .is_some()
            {
                continue;
            }
            let Some(sum) = crates_io_checksum(&client, name, version).await else {
                continue;
            };
            lockfile.push_str(&format!(
                "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sum}\"\n"
            ));
            any = true;
        }
        if any {
            let new_pins = parse_pins(&lockfile).unwrap_or_default();
            acquire_pins(&vault, &self.ecosystem, &new_pins, |_, _| {});
        }
        Ok(())
    }

    /// The validated dependencies in the production store (capability: READ).
    /// When `name` is set, only deps that appear in that folder (and optional repo) are returned.
    pub fn production_deps(
        &self,
        name: Option<&str>,
        repo: Option<&str>,
    ) -> Result<Vec<ProdDep>, ApiError> {
        self.authorize_op(Ops::READ)?;
        let mut deps: Vec<ProdDep> = self
            .vault()?
            .list_store_crates(StoreKind::Prod)?
            .into_iter()
            .map(|(name, version, hash)| ProdDep {
                name,
                version,
                hash: hash.to_hex(),
            })
            .collect();
        if let Some(folder) = name.filter(|s| !s.is_empty()) {
            let pins = self.folder_unique_pins(folder, repo.filter(|s| !s.is_empty()))?;
            let wanted: HashSet<(String, String)> = pins
                .iter()
                .map(|p| {
                    (
                        p.dep.name.as_str().to_owned(),
                        p.dep.version.as_str().to_owned(),
                    )
                })
                .collect();
            deps.retain(|d| wanted.contains(&(d.name.clone(), d.version.clone())));
        }
        deps.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
        Ok(deps)
    }

    /// One-button workspace scan (capability: WRITE): load RUSTSEC if needed, scan lockfiles,
    /// check crates.io for newer releases (and stage them), then report offline-archive coverage.
    /// Progress is published via [`Self::scan_progress`] for the UI to poll.
    pub async fn scan_workspace(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<CombinedScanReport, ApiError> {
        let result = self.scan_workspace_inner(name, repo).await;
        self.clear_scan_progress();
        result
    }

    async fn scan_workspace_inner(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<CombinedScanReport, ApiError> {
        let advisories = if self.advisory_count() > 0 {
            self.advisory_count()
        } else {
            self.set_scan_progress("advisories", "Loading RUSTSEC advisories", 0, 1);
            tokio::task::yield_now().await;
            match self.load_rustsec_advisories().await {
                Ok(n) => n,
                Err(_) => self.advisory_count(),
            }
        };

        self.set_scan_progress("scan", "Scanning lockfiles", 0, 1);
        tokio::task::yield_now().await;
        let scan = tokio::task::block_in_place(|| self.scan_folder(name.clone(), repo.clone()))?;

        let (updates, updates_error) =
            match self.scan_new_versions(name.clone(), repo.clone()).await {
                Ok(u) => (u, None),
                Err(e) => (
                    NewVersionReport {
                        name: scope_label(&name, scope_repo(&repo)),
                        entries: Vec::new(),
                    },
                    Some(e.message),
                ),
            };

        self.set_scan_progress("coverage", "Checking offline coverage", 0, 1);
        tokio::task::yield_now().await;
        let coverage = tokio::task::block_in_place(|| self.folder_coverage(name.clone(), repo.clone()))?;
        self.set_scan_progress("coverage", "Checking offline coverage", 1, 1);

        let report = CombinedScanReport {
            advisories,
            scan,
            updates,
            updates_error,
            coverage,
            scanned_at: unix_now(),
        };
        self.remember_scan(&name, scope_repo(&repo), report.clone());
        self.invalidate_heartbeats(&name);
        Ok(report)
    }

    /// Scan every repository in a folder (capability: WRITE), reading each project's stored
    /// `Cargo.lock` and running the dependency scanner over its pins (advisory + substitution
    /// checks; integrity is skipped for not-yet-acquired deps and noted as such).
    pub fn scan_folder(
        &self,
        name: String,
        repo: Option<String>,
    ) -> Result<FolderScanReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let repo = scope_repo(&repo);
        let lockfiles = self.stored_lockfiles(&name, repo)?;
        let total = lockfiles.len().max(1);
        let mut repos = Vec::with_capacity(lockfiles.len());
        for (i, (full_name, text)) in lockfiles.into_iter().enumerate() {
            self.set_scan_progress("scan", "Scanning lockfiles", i, total);
            repos.push(self.scan_repo(&vault, full_name, &text));
        }
        self.set_scan_progress("scan", "Scanning lockfiles", repos.len(), total);
        Ok(FolderScanReport {
            name: scope_label(&name, repo),
            repos,
        })
    }

    fn scan_repo(&self, vault: &Vault, full_name: String, text: &str) -> RepoScanResult {
        let pins = match parse_pins(text) {
            Ok(p) => p,
            Err(e) => {
                return RepoScanResult {
                    full_name,
                    deps: 0,
                    lockfile_found: true,
                    findings: vec![],
                    error: Some(format!("parse: {e}")),
                }
            }
        };

        let mut findings = Vec::new();
        for pin in &pins {
            if let Ok(report) = scan(
                vault,
                pin,
                &self.advisories.read().expect("advisories lock"),
            ) {
                if let ScanVerdict::Findings(fs) = report.verdict {
                    for f in fs {
                        findings.push(FindingView {
                            dep: format!("{} {}", pin.dep.name.as_str(), pin.dep.version.as_str()),
                            id: f.id,
                            severity: format!("{:?}", f.severity),
                            summary: f.summary,
                        });
                    }
                }
            }
        }
        RepoScanResult {
            full_name,
            deps: pins.len(),
            lockfile_found: true,
            findings,
            error: None,
        }
    }

    /// A snapshot of the current acting principal.
    pub fn session(&self) -> Session {
        self.session.lock().expect("session mutex").clone()
    }

    /// Whether a verified mID session backs this service (`false` in local mode).
    pub fn mid_active(&self) -> bool {
        self.mid_active.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Issue a single-use challenge for a browser/extension sign-in: the nonce the wallet must
    /// embed and the audience (bare origin) its token's `aud` must equal.
    pub fn issue_challenge(&self) -> (String, String) {
        (self.authenticator.issue_nonce(), self.mid_audience.clone())
    }

    /// Verify a wallet token from the MATA extension and, on success, make its identity the acting
    /// principal (flips `mid_active` on). The vault stays unlocked by the passphrase — mID
    /// authenticates *who is driving*, not the at-rest key (`docs/AUTH.md` §1).
    pub fn sign_in(
        &self,
        token: &str,
        nonce: &str,
        audience: &str,
        now_unix_secs: u64,
    ) -> Result<Session, ApiError> {
        // The RP origin the wallet bound the token's `aud` to. The page reports its own
        // `window.location.origin` so the wallet's origin check passes whether the user browses via
        // localhost or 127.0.0.1; fall back to the configured audience if none was sent.
        let aud = if audience.trim().is_empty() {
            self.mid_audience.clone()
        } else {
            audience.to_owned()
        };
        let params = VerifyParams::new(aud, nonce.to_owned(), now_unix_secs);
        let session = self
            .authenticator
            .authenticate(token, &params)
            .map_err(|e| ApiError::unauthorized(format!("mID sign-in failed: {e}")))?;
        // Gated mode: the vault is still locked, so unlock it bound to this verified DID. (In embed
        // mode it's already unlocked unbound, so we keep that vault and just record the session.)
        if !self.vault_unlocked() {
            self.unlock_vault(session.did.as_bytes())?;
        }
        *self.session.lock().expect("session mutex") = session.clone();
        self.mid_active
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(session)
    }

    /// The vault owner's DID — the capability issuer.
    pub fn owner_did(&self) -> &Did {
        self.owner.did()
    }

    /// The owner grants `bearer` (a human or an AI agent) a scoped, optionally-expiring capability
    /// over the vault, signed under the owner's key.
    pub fn grant(
        &self,
        bearer: impl Into<Did>,
        ops: Ops,
        expiry: Option<u64>,
    ) -> Result<SignedCapability, ApiError> {
        let mut cap = Capability::grant(
            self.owner.did().clone(),
            bearer,
            Scope::Collection(DEPUTY_SCOPE.to_owned()),
            ops,
        )?;
        if let Some(exp) = expiry {
            cap = cap.with_expiry(exp);
        }
        Ok(SignedCapability::sign(cap, &self.owner)?)
    }

    /// Act under a different capability (e.g. an agent's grant) for subsequent operations.
    pub fn act_as(&mut self, capability: SignedCapability) {
        self.capability = capability;
    }

    /// Revoke a capability by id; subsequent checks under it are denied.
    pub fn revoke(&mut self, capability_id: [u8; 16]) {
        self.revocations.revoke(capability_id);
    }

    /// Check that the acting capability authorizes `op` over the vault scope (signature, scope,
    /// ops, expiry, and revocation are all enforced).
    pub(crate) fn authorize_op(&self, op: Ops) -> Result<(), ApiError> {
        let scope = Scope::Collection(DEPUTY_SCOPE.to_owned());
        let request = AccessRequest {
            bearer: &self.capability.capability.bearer,
            scope: &scope,
            op,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let decision = authorize(
            &self.capability,
            &request,
            &self.directory,
            now,
            &self.revocations,
        )?;
        if !decision.is_allowed() {
            return Err(ApiError::forbidden(decision));
        }
        mata_authorize(
            &mata_caller(
                &self.capability.capability.bearer,
                self.capability.capability.ops,
            ),
            &DeputyOp {
                action: mata_action(op),
            },
        )
        .map_err(|e| ApiError::unauthorized(e.to_string()))?;
        Ok(())
    }

    fn pins(&self, source: &str) -> Result<Vec<Pin>, ApiError> {
        Ok(self.ecosystem.discover(&SourceId::new(source))?)
    }

    fn lock_text(&self, source: &str) -> Result<String, ApiError> {
        let path = Path::new(source);
        let lock = if path.is_dir() {
            path.join("Cargo.lock")
        } else {
            path.to_path_buf()
        };
        std::fs::read_to_string(&lock)
            .map_err(|e| ApiError::bad_request(format!("read {}: {e}", lock.display())))
    }

    /// List the source's pinned crates.io dependencies. (capability: READ)
    pub fn discover(&self, source: &str) -> Result<Vec<Pin>, ApiError> {
        self.authorize_op(Ops::READ)?;
        self.pins(source)
    }

    /// Fetch, verify, and seal the source's dependencies into the dirty store. (capability: WRITE)
    pub fn acquire(&self, source: &str) -> Result<AcquireReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        Ok(acquire(&vault, &self.ecosystem, &SourceId::new(source))?)
    }

    /// Language analytics + critical-point-of-failure scoring. (capability: READ)
    pub fn analyze(&self, source: &str) -> Result<AnalysisReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let lock = self.lock_text(source)?;
        let hashes: HashMap<(String, String), ContentHash> = parse_pins(&lock)?
            .into_iter()
            .map(|p| {
                (
                    (
                        p.dep.name.as_str().to_owned(),
                        p.dep.version.as_str().to_owned(),
                    ),
                    p.expected,
                )
            })
            .collect();
        let vault = self.vault()?;
        Ok(analyze(&lock, |name, version| {
            let hash = hashes.get(&(name.to_owned(), version.to_owned()))?;
            vault.get_artifact(StoreKind::Dirty, hash).ok()
        })?)
    }

    /// Scan every dependency, recording verdicts. (capability: WRITE)
    pub fn scan(&self, source: &str) -> Result<Vec<ScanReport>, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        self.pins(source)?
            .iter()
            .map(|pin| {
                scan(
                    &vault,
                    pin,
                    &self.advisories.read().expect("advisories lock"),
                )
                .map_err(ApiError::from)
            })
            .collect()
    }

    /// Promote scanned-clean dependencies into prod. (capability: WRITE)
    pub fn promote(&self, source: &str) -> Result<Vec<Promotion>, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let did = self.session().did;
        let outcomes = self
            .pins(source)?
            .iter()
            .filter_map(|pin| {
                promote(
                    &vault,
                    pin.dep.ecosystem,
                    pin.dep.name.as_str(),
                    pin.dep.version.as_str(),
                    &pin.expected,
                    Some(&did),
                )
                .ok()
            })
            .collect();
        Ok(outcomes)
    }

    /// Run the fail-closed deploy gate over the source's dependencies. (capability: READ)
    pub fn gate(&self, source: &str) -> Result<GateDecision, ApiError> {
        self.authorize_op(Ops::READ)?;
        let vault = self.vault()?;
        Ok(gate(&vault, &self.pins(source)?)?)
    }

    /// Gate, then vendor prod copies into `into`. (capability: WRITE)
    pub fn deploy(&self, source: &str, into: &str) -> Result<MaterializePlan, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let pins = self.pins(source)?;
        match gate(&vault, &pins)? {
            GateDecision::Blocked { violations } => Err(ApiError::gate_blocked(violations)),
            GateDecision::Allowed { .. } => Ok(materialize(&vault, &pins, Path::new(into))?),
        }
    }
}
