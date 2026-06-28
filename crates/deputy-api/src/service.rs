use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use deputy_acquire::{acquire, acquire_pins, AcquireReport};
use deputy_analyze::{analyze, inspect, AnalysisReport};
use deputy_core::{ContentHash, DepEcosystem, Pin, ScanVerdict, SourceId, StoreKind};
use deputy_deploy::{gate, materialize, promote, GateDecision, MaterializePlan, Promotion};
use deputy_ecosystem::{parse_pins, CargoEcosystem};
use deputy_id::{Authenticator, Session, VerifyParams};
use deputy_scan::{scan, AdvisoryDb, ScanReport};
use deputy_store::Vault;
use spacedb_access::{
    authorize, AccessRequest, Capability, Did, Identity, MemKeyDirectory, Ops, RevocationSet,
    Scope, SignedCapability,
};

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// The capability scope covering Deputy's whole vault.
const DEPUTY_SCOPE: &str = "deputy";

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
    pub error: Option<String>,
}

/// A named folder grouping the repositories allocated to it.
#[derive(Serialize, Deserialize, Clone)]
pub struct FolderSummary {
    pub name: String,
    pub repos: Vec<RepoSummary>,
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
#[derive(Serialize, Deserialize, Clone)]
pub struct HeartbeatEntry {
    pub name: String,
    pub current: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub advisories: Vec<String>,
}

/// The heartbeat for every dependency in a folder.
#[derive(Serialize, Deserialize, Clone)]
pub struct HeartbeatReport {
    pub name: String,
    pub entries: Vec<HeartbeatEntry>,
}

/// A connected GitHub account: a fine-grained PAT plus a human label (its login by default).
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

/// Download + inspect each unique dependency crate, aggregating language line counts and the
/// supply-chain risk signals. Blocking (network + tar inspection) — run under `spawn_blocking`.
fn compute_dep_analytics(vault: &Vault, pins: Vec<Pin>) -> AnalyticsBody {
    let eco = CargoEcosystem::new();
    let mut lines: std::collections::BTreeMap<String, usize> = Default::default();
    let mut crate_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut deps = Vec::with_capacity(pins.len());
    let (mut analyzed, mut build_scripts, mut proc_macros, mut native_crates, mut unsafe_crates) =
        (0, 0, 0, 0, 0);

    for pin in &pins {
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
    }

    let mut by_language: Vec<LangStat> = lines
        .into_iter()
        .map(|(language, lines)| LangStat {
            crates: crate_counts.get(&language).copied().unwrap_or(0),
            language,
            lines,
        })
        .collect();
    by_language.sort_by_key(|s| std::cmp::Reverse(s.lines));
    AnalyticsBody {
        analyzed,
        by_language,
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

/// One project staged for acquisition (from a GitHub repo or a local folder): its display name,
/// whether a lockfile was found, any fetch/read error, the pins parsed from its `Cargo.lock`, and
/// the raw lockfile text (kept so folder ops can re-parse it offline instead of re-fetching).
struct StagedRepo {
    repo: String,
    lockfile_found: bool,
    fetch_error: Option<String>,
    pins: Vec<Pin>,
    lockfile_text: Option<String>,
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

/// The latest stable version of a crate on crates.io, if reachable.
async fn crates_io_latest(client: &reqwest::Client, name: &str) -> Option<String> {
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
    krate
        .get("max_stable_version")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| krate.get("newest_version").and_then(|s| s.as_str()))
        .map(String::from)
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

    /// A connected GitHub fine-grained PAT used to list/acquire the user's repos. Held in memory
    /// only — never written to the vault or logged.
    github_connections: std::sync::Mutex<Vec<GhConnection>>,

    /// Named folders grouping downloaded repositories. Persisted to the encrypted vault.
    folders: std::sync::Mutex<HashMap<String, FolderSummary>>,

    /// Each folder's raw `Cargo.lock` texts as `(project, text)`, captured at download. Lets folder
    /// ops (analytics/scan/coverage/heartbeat) re-parse offline instead of re-fetching from GitHub
    /// — which is what made them fail for local folders. Persisted to the encrypted vault.
    folder_lockfiles: std::sync::Mutex<HashMap<String, Vec<(String, String)>>>,

    /// Cached dependency-language analytics per folder — downloading + inspecting every crate is
    /// expensive, so it's computed lazily and invalidated on re-download / delete.
    analytics_cache: std::sync::Mutex<HashMap<String, DepAnalytics>>,

    /// Live `(done, total)` acquisition progress for the in-flight download, polled by the UI.
    download_progress: std::sync::Mutex<Option<(usize, usize)>>,
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
            folders: std::sync::Mutex::new(HashMap::new()),
            folder_lockfiles: std::sync::Mutex::new(HashMap::new()),
            analytics_cache: std::sync::Mutex::new(HashMap::new()),
            download_progress: std::sync::Mutex::new(None),
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

    /// The stored `(project, lockfile text)` pairs for a folder. Errors if the folder is unknown,
    /// or — for folders downloaded before lockfile capture — asks the user to re-pull it.
    fn stored_lockfiles(&self, name: &str) -> Result<Vec<(String, String)>, ApiError> {
        if let Some(lockfiles) = self
            .folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .get(name)
            .cloned()
        {
            return Ok(lockfiles);
        }
        if self.folders.lock().expect("folders mutex").contains_key(name) {
            Err(ApiError::bad_request(format!(
                "folder '{name}' was downloaded before lockfile capture — re-pull it to enable analytics/scan/coverage"
            )))
        } else {
            Err(ApiError::bad_request(format!("no such folder: {name}")))
        }
    }

    /// Attach an advisory database used by [`DeputyService::scan`].
    pub fn with_advisories(mut self, advisories: AdvisoryDb) -> Self {
        self.advisories = std::sync::RwLock::new(advisories);
        self
    }

    /// Replace the advisory database with a freshly-downloaded RUSTSEC one (capability: WRITE).
    /// Returns the number of advisories loaded.
    pub async fn load_rustsec_advisories(&self) -> Result<usize, ApiError> {
        self.authorize_op(Ops::WRITE)?;
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

    /// Connect (or replace) a GitHub fine-grained PAT under a label (capability: WRITE). Multiple
    /// accounts can be connected; each keeps its own token. Stored in memory for this session only.
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

    /// Download + analyze the selected repos' lockfiles and allocate them to `folder`
    /// (capability: WRITE). Each repo's `Cargo.lock` is fetched over the GitHub API and its
    /// pinned dependencies counted; the folder grouping is stored for the Infrastructure view.
    pub async fn download_repos(
        &self,
        folder: String,
        repos: Vec<String>,
    ) -> Result<FolderSummary, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let tokens = self.github_tokens()?;
        let client = reqwest::Client::new();

        // Pre-pass: fetch each lockfile and parse its pins (the full transitive tree per repo).
        let mut staged = Vec::with_capacity(repos.len());
        for repo in repos {
            match fetch_lockfile_any(&client, &tokens, &repo).await {
                Ok(Some(text)) => {
                    let pins = parse_pins(&text).unwrap_or_default();
                    staged.push(StagedRepo {
                        repo,
                        lockfile_found: true,
                        fetch_error: None,
                        pins,
                        lockfile_text: Some(text),
                    });
                }
                Ok(None) => staged.push(StagedRepo {
                    repo,
                    lockfile_found: false,
                    fetch_error: None,
                    pins: vec![],
                    lockfile_text: None,
                }),
                Err(e) => staged.push(StagedRepo {
                    repo,
                    lockfile_found: false,
                    fetch_error: Some(e),
                    pins: vec![],
                    lockfile_text: None,
                }),
            }
        }
        self.finish_download(folder, staged)
    }

    /// Acquire every dependency in the `Cargo.lock` files under a **local** folder path (no GitHub
    /// needed). Each `Cargo.lock` is treated as a project; its name is its directory relative to
    /// `path`. Useful when the source is already on disk and not pushed to GitHub.
    pub fn download_local(&self, folder: String, path: String) -> Result<FolderSummary, ApiError> {
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
                    });
                }
                Err(e) => staged.push(StagedRepo {
                    repo: name,
                    lockfile_found: false,
                    fetch_error: Some(e.to_string()),
                    pins: vec![],
                    lockfile_text: None,
                }),
            }
        }
        self.finish_download(folder, staged)
    }

    /// Shared tail of [`Self::download_repos`] / [`Self::download_local`]: deduplicate pins across
    /// all projects (content-addressed, so a crate shared by several is fetched at most once),
    /// acquire the unique set once with progress, summarize per project, and persist the folder.
    fn finish_download(
        &self,
        folder: String,
        staged: Vec<StagedRepo>,
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
                .count();
            let error = if s.fetch_error.is_some() {
                s.fetch_error
            } else if s.lockfile_found && acquired < s.pins.len() {
                Some(format!(
                    "{} of {} deps failed to acquire",
                    s.pins.len() - acquired,
                    s.pins.len()
                ))
            } else {
                None
            };
            summaries.push(RepoSummary {
                full_name: s.repo,
                deps: s.pins.len(),
                acquired,
                lockfile_found: s.lockfile_found,
                error,
            });
        }

        let summary = FolderSummary {
            name: folder.clone(),
            repos: summaries,
        };
        self.analytics_cache
            .lock()
            .expect("analytics mutex")
            .remove(&folder);
        self.folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .insert(folder.clone(), lockfiles);
        self.folders
            .lock()
            .expect("folders mutex")
            .insert(folder, summary.clone());
        self.persist_folders();
        self.persist_folder_lockfiles();
        Ok(summary)
    }

    /// The live acquisition progress `(done, total)` for the in-flight download, if any.
    pub fn download_progress(&self) -> Option<(usize, usize)> {
        *self.download_progress.lock().expect("progress mutex")
    }

    /// All named folders and their repositories (capability: READ).
    pub fn folders(&self) -> Result<Vec<FolderSummary>, ApiError> {
        self.authorize_op(Ops::READ)?;
        self.vault()?; // gated: no folder listing before the vault is unlocked by sign-in
        Ok(self
            .folders
            .lock()
            .expect("folders mutex")
            .values()
            .cloned()
            .collect())
    }

    /// Remove a named folder (capability: WRITE). No-op if it doesn't exist.
    pub fn delete_folder(&self, name: &str) -> Result<(), ApiError> {
        self.authorize_op(Ops::WRITE)?;
        self.folders.lock().expect("folders mutex").remove(name);
        self.folder_lockfiles
            .lock()
            .expect("folder lockfiles mutex")
            .remove(name);
        self.analytics_cache
            .lock()
            .expect("analytics mutex")
            .remove(name);
        self.persist_folders();
        self.persist_folder_lockfiles();
        Ok(())
    }

    /// Dependency-language analytics for a folder (capability: READ). Downloads + inspects each
    /// unique dependency crate the first time (slow); subsequent calls are served from cache.
    pub async fn folder_analytics(
        self: std::sync::Arc<Self>,
        name: String,
    ) -> Result<DepAnalytics, ApiError> {
        self.authorize_op(Ops::READ)?;
        if let Some(cached) = self
            .analytics_cache
            .lock()
            .expect("analytics mutex")
            .get(&name)
            .cloned()
        {
            return Ok(cached);
        }
        // Unique pins across the folder's stored lockfiles (offline; GitHub or local).
        let pins = self.folder_unique_pins(&name)?;
        let total_deps = pins.len();

        let vault = self.vault()?;
        let body = tokio::task::spawn_blocking(move || compute_dep_analytics(&vault, pins))
            .await
            .map_err(|e| ApiError::bad_request(format!("analytics task failed: {e}")))?;

        let analytics = DepAnalytics {
            name: name.clone(),
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
            .insert(name, analytics.clone());
        Ok(analytics)
    }

    /// The unique pins across a folder's stored lockfiles (works offline, GitHub or local).
    fn folder_unique_pins(&self, name: &str) -> Result<Vec<Pin>, ApiError> {
        let mut unique: std::collections::BTreeMap<(String, String), Pin> = Default::default();
        for (_repo, text) in self.stored_lockfiles(name)? {
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

    /// The social heartbeat for a folder's dependencies (capability: READ): for each unique dep,
    /// fetch the latest crates.io version and surface advisories on the pinned version.
    pub async fn folder_heartbeat(&self, name: String) -> Result<HeartbeatReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let client = reqwest::Client::new();
        let pins = self.folder_unique_pins(&name)?;

        let mut entries = Vec::with_capacity(pins.len());
        for pin in pins {
            let dep_name = pin.dep.name.as_str().to_owned();
            let current = pin.dep.version.as_str().to_owned();
            let latest = crates_io_latest(&client, &dep_name).await;
            let update_available = match (
                semver::Version::parse(&current),
                latest
                    .as_deref()
                    .and_then(|l| semver::Version::parse(l).ok()),
            ) {
                (Ok(cur), Some(lat)) => lat > cur,
                _ => false,
            };
            let advisories = semver::Version::parse(&current)
                .ok()
                .map(|v| {
                    self.advisories
                        .read()
                        .expect("advisories lock")
                        .check(&dep_name, &v)
                        .iter()
                        .map(|a| a.id.clone())
                        .collect()
                })
                .unwrap_or_default();
            entries.push(HeartbeatEntry {
                name: dep_name,
                current,
                latest,
                update_available,
                advisories,
            });
        }
        Ok(HeartbeatReport { name, entries })
    }

    /// Scan a folder's dependencies for newer published releases and **stage** each new version
    /// (download + SHA-256 verify into the dirty store) alongside the current one — which may
    /// already be in production (capability: WRITE).
    pub async fn scan_new_versions(&self, name: String) -> Result<NewVersionReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let client = reqwest::Client::new();
        let pins = self.folder_unique_pins(&name)?;

        // Which deps have a newer published version (with its checksum, so we can stage it)?
        let mut updates: Vec<(String, String, String, String)> = Vec::new();
        for pin in &pins {
            let dep_name = pin.dep.name.as_str();
            let current = pin.dep.version.as_str();
            if let Some((latest, checksum)) = crates_io_latest_versioned(&client, dep_name).await {
                let newer = matches!(
                    (
                        semver::Version::parse(current),
                        semver::Version::parse(&latest)
                    ),
                    (Ok(c), Ok(l)) if l > c
                );
                if newer {
                    updates.push((dep_name.to_owned(), current.to_owned(), latest, checksum));
                }
            }
        }

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
        acquire_pins(&vault, &self.ecosystem, &new_pins, |_, _| {});

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
        Ok(NewVersionReport { name, entries })
    }

    /// Offline-archive coverage for a folder (capability: READ): walk every repo's `Cargo.lock`,
    /// classify each dependency, and report which ones are safely sealed in the vault vs. which are
    /// gaps — missing crates.io deps (failed/never acquired), git deps, or other registries that
    /// Deputy can't content-verify. Path/workspace members (your own code) are ignored.
    pub fn folder_coverage(&self, name: String) -> Result<CoverageReport, ApiError> {
        self.authorize_op(Ops::READ)?;
        let vault = self.vault()?;

        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut registry_total = 0usize;
        let mut archived = 0usize;
        let mut gaps: Vec<CoverageGap> = Vec::new();

        for (_repo, text) in self.stored_lockfiles(&name)? {
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
            name,
            registry_total,
            archived,
            gaps,
        })
    }

    /// Promote a folder's scanned-clean, acquired dependencies into the production store
    /// (capability: WRITE), each with a hash-chained receipt. Returns the count promoted.
    pub async fn promote_folder(
        &self,
        name: String,
        hold: Vec<(String, String)>,
    ) -> Result<usize, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let pins = self.folder_unique_pins(&name)?;
        let hold: HashSet<(String, String)> = hold.into_iter().collect();
        let did = self.session().did;
        // Promote every clean, acquired dependency that the caller did NOT hold back in staging.
        let promoted = pins
            .iter()
            .filter(|pin| {
                let key = (
                    pin.dep.name.as_str().to_owned(),
                    pin.dep.version.as_str().to_owned(),
                );
                !hold.contains(&key)
                    && promote(
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

    /// The validated dependencies in the production store (capability: READ).
    pub fn production_deps(&self) -> Result<Vec<ProdDep>, ApiError> {
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
        deps.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
        Ok(deps)
    }

    /// Scan every repository in a folder (capability: WRITE), reading each project's stored
    /// `Cargo.lock` and running the dependency scanner over its pins (advisory + substitution
    /// checks; integrity is skipped for not-yet-acquired deps and noted as such).
    pub fn scan_folder(&self, name: String) -> Result<FolderScanReport, ApiError> {
        self.authorize_op(Ops::WRITE)?;
        let vault = self.vault()?;
        let repos = self
            .stored_lockfiles(&name)?
            .into_iter()
            .map(|(full_name, text)| self.scan_repo(&vault, full_name, &text))
            .collect();
        Ok(FolderScanReport { name, repos })
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
        if decision.is_allowed() {
            Ok(())
        } else {
            Err(ApiError::forbidden(decision))
        }
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
