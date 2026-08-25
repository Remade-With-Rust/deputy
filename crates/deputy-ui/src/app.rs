//! The Dioxus single-page app (web + desktop). A thin client of the Deputy API.
//!
//! Flow: an **mID login landing page** gates the app; once signed in, a left **sidebar** selects
//! a **workspace** (one GitHub/local repo, a group such as an org, or **all workspaces** via the
//! Deputy logo) and a tab. Selecting a workspace opens **Overview** — dependency counts, outdated
//! crates, and vault/advisory status. The **GitHub** tab opens a browser for you to approve access
//! (no PAT required), lists repositories, and adds them as individual workspaces or as a named
//! group. Scan / Analytics / New Versions / Production then show only that workspace's requirements.

use std::collections::HashSet;
use std::sync::OnceLock;

use dioxus::prelude::*;
use serde::Deserialize;

const API_BASE: &str = "http://127.0.0.1:7878";

fn chrome_css() -> &'static str {
    static SHEET: OnceLock<String> = OnceLock::new();
    SHEET.get_or_init(|| {
        let mut sheet = rusty_tokens::css::root_sheet();
        sheet.push_str(DEPUTY_THEME);
        sheet.push_str(CSS);
        sheet
    })
}

#[cfg(target_arch = "wasm32")]
pub fn launch() {
    dioxus::launch(App);
}

/// Desktop launch — a normal window (NOT always-on-top), plus a runtime `deputy://` deep-link
/// handler so the mID sign-in callback returns straight into the app with no browser hop.
#[cfg(not(target_arch = "wasm32"))]
pub fn launch() {
    use dioxus::desktop::tao::window::Theme;
    use dioxus::desktop::{Config, WindowBuilder};
    let icon = crate::chrome::window_icon();
    let taskbar_icon = icon.clone();
    let window = WindowBuilder::new()
        .with_title("Deputy")
        .with_always_on_top(false)
        .with_theme(Some(Theme::Dark));
    let cfg = Config::new()
        .with_window(window)
        .with_icon(icon)
        .with_background_color((0x15, 0x1e, 0x18, 0xff))
        .with_menu(None)
        .with_on_window(move |w, _vdom| {
            #[cfg(target_os = "windows")]
            crate::chrome::apply_windows_chrome(&w, &taskbar_icon);
            #[cfg(not(target_os = "windows"))]
            let _ = &taskbar_icon;
            let _ = w;
        })
        .with_custom_event_handler(|event, _target| {
            if let dioxus::desktop::tao::event::Event::Opened { urls } = event {
                for url in urls {
                    let s = url.as_str();
                    if s.starts_with("deputy://") {
                        eprintln!("[Deputy mID] runtime deep-link: {s}");
                        handle_mid_callback(s);
                    }
                }
            }
        });
    dioxus::LaunchBuilder::desktop().with_cfg(cfg).launch(App);
}

/// Parse a `deputy://mid-callback#mid_response=<base64url>` deep link, pull the wallet token out,
/// and POST it to the embedded API's `/auth/verify` — completing sign-in with **no browser**.
/// Shared by the runtime `Event::Opened` handler and the cold-start argv path in `main.rs`.
#[cfg(not(target_arch = "wasm32"))]
pub fn handle_mid_callback(url: &str) {
    use base64::Engine;
    let dec = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Some(frag) = url.split('#').nth(1) else {
        return;
    };
    let Some(enc) = frag
        .split('&')
        .find_map(|kv| kv.strip_prefix("mid_response="))
    else {
        return;
    };
    let Ok(json_bytes) = dec.decode(enc) else {
        eprintln!("[Deputy mID] callback: malformed mid_response");
        return;
    };
    let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&json_bytes) else {
        return;
    };
    let result = resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if result.get("outcome").and_then(|o| o.as_str()) != Some("ok") {
        eprintln!("[Deputy mID] callback outcome not ok");
        return;
    }
    let Some(jwt) = result.get("jwt").and_then(|j| j.as_str()).map(String::from) else {
        return;
    };
    // Pull nonce + aud out of the JWT payload so /auth/verify consumes the matching nonce.
    let (nonce, aud) = jwt
        .split('.')
        .nth(1)
        .and_then(|p| dec.decode(p).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .map(|p| {
            (
                p.get("nonce")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default()
                    .to_string(),
                p.get("aud")
                    .and_then(|a| a.as_str())
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .unwrap_or_default();
    let body = serde_json::json!({ "token": jwt, "nonce": nonce, "audience": aud });
    // Run the verify POST on a dedicated OS thread. reqwest::blocking spins up and then *drops* its
    // own tokio runtime, which panics ("Cannot drop a runtime … from within an asynchronous
    // context") when called on the desktop event-loop thread — dx drives that loop inside a tokio
    // runtime. A freshly-spawned thread has no ambient runtime, so the drop is legal. We join so the
    // argv cold-start path (main.rs) waits for completion before exiting; the localhost round-trip is
    // sub-millisecond, so the brief block on the event-loop thread is negligible.
    let _ = std::thread::spawn(move || {
        match reqwest::blocking::Client::new()
            .post(format!("{API_BASE}/auth/verify"))
            .json(&body)
            .send()
        {
            Ok(r) => eprintln!("[Deputy mID] callback verify → HTTP {}", r.status()),
            Err(e) => eprintln!("[Deputy mID] callback verify error: {e}"),
        }
    })
    .join();
}

// ── API response types (mirror the deputy-api JSON) ──────────────────────────

#[derive(Deserialize, Clone, PartialEq)]
struct Session {
    status: String,
    did: String,
    #[serde(default)]
    mid_active: bool,
}

/// A single-use sign-in challenge from `/auth/challenge`.
#[derive(Deserialize, Clone, PartialEq)]
struct Challenge {
    nonce: String,
    audience: String,
}

#[derive(Deserialize, Clone, PartialEq)]
struct Repo {
    full_name: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    fork: bool,
    #[serde(default)]
    connection: String,
}

/// The result of downloading + acquiring one repo into a folder.
#[derive(Deserialize, Clone, PartialEq)]
struct RepoSummary {
    full_name: String,
    #[serde(default)]
    deps: usize,
    #[serde(default)]
    acquired: usize,
    #[serde(default)]
    lockfile_found: bool,
    #[serde(default)]
    source_archived: bool,
    #[serde(default)]
    error: Option<String>,
}

/// A named folder grouping the repositories allocated to it.
#[derive(Deserialize, Clone, PartialEq)]
struct FolderSummary {
    name: String,
    repos: Vec<RepoSummary>,
}

/// The selected working set: a whole group, or one repo inside a group / a solo-repo folder.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Workspace {
    folder: String,
    repo: Option<String>,
}

const WS_SEP: char = '\u{1f}';
const WS_ALL: &str = "a";
const ALL_WORKSPACES: &str = "*";

impl Workspace {
    fn all() -> Self {
        Self {
            folder: ALL_WORKSPACES.into(),
            repo: None,
        }
    }

    fn is_all(&self) -> bool {
        self.folder == ALL_WORKSPACES && self.repo.is_none()
    }

    fn group(folder: impl Into<String>) -> Self {
        Self {
            folder: folder.into(),
            repo: None,
        }
    }

    fn repo(folder: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            folder: folder.into(),
            repo: Some(repo.into()),
        }
    }

    fn label(&self) -> String {
        if self.is_all() {
            "All workspaces".into()
        } else {
            self.repo.clone().unwrap_or_else(|| self.folder.clone())
        }
    }

    fn encode(&self) -> String {
        if self.is_all() {
            return WS_ALL.into();
        }
        match &self.repo {
            Some(r) => format!("r{WS_SEP}{}{WS_SEP}{r}", self.folder),
            None => format!("g{WS_SEP}{}", self.folder),
        }
    }

    fn decode(s: &str) -> Option<Self> {
        if s == WS_ALL {
            return Some(Self::all());
        }
        let mut parts = s.split(WS_SEP);
        match (parts.next(), parts.next(), parts.next()) {
            (Some("g"), Some(f), None) if !f.is_empty() => Some(Self::group(f)),
            (Some("r"), Some(f), Some(r)) if !f.is_empty() && !r.is_empty() => {
                Some(Self::repo(f, r))
            }
            _ => None,
        }
    }

    fn api_body(&self) -> serde_json::Value {
        match &self.repo {
            Some(r) => serde_json::json!({ "name": self.folder, "repo": r }),
            None => serde_json::json!({ "name": self.folder }),
        }
    }
}

fn repo_short(full_name: &str) -> (&str, &str) {
    full_name.split_once('/').unwrap_or(("", full_name))
}

fn workspace_from_api_body(body: &serde_json::Value) -> Option<Workspace> {
    let name = body.get("name")?.as_str()?;
    let repo = body
        .get("repo")
        .and_then(|r| r.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    if name == ALL_WORKSPACES {
        Some(Workspace::all())
    } else if let Some(r) = repo {
        Some(Workspace::repo(name, r))
    } else {
        Some(Workspace::group(name))
    }
}

/// Dashboard jobs tag in-flight work with `encode` or `encode#gen[#pull]`.
/// Compare only the encode prefix so a leftover result is never painted under a new title.
fn job_scope_matches(scope: &str, ws: &Workspace) -> bool {
    scope.split('#').next() == Some(ws.encode().as_str())
}

fn report_is_for(ws: &Workspace, name: &str) -> bool {
    ws.label() == name
}

/// Old vault JSON omitted `lockfile_found`; a positive dep count means a lockfile was parsed.
fn lockfile_present(found: bool, deps: usize) -> bool {
    found || deps > 0
}

fn repo_vault_line(r: &RepoSummary) -> String {
    if lockfile_present(r.lockfile_found, r.deps) {
        format!("{}/{} acquired", r.acquired, r.deps)
    } else if r.source_archived {
        "source archived · no Cargo.lock".into()
    } else {
        "no Cargo.lock".into()
    }
}

/// Keep the current tab when changing workspace, except GitHub (the add-flow), which lands on Overview.
fn select_workspace(mut ctx: WorkspaceCtx, ws: Workspace) {
    let from_github = matches!((ctx.tab)(), Tab::GitHub);
    ctx.current.set(Some(ws));
    if from_github {
        ctx.tab.set(Tab::Overview);
    }
}

/// UTC calendar date + hour:minute from a Unix timestamp. Empty when `secs` is 0.
fn format_scanned_at(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let (year, month, day) = unix_days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02} UTC")
}

/// UTC calendar date from a Unix timestamp. Empty when `secs` is 0.
fn format_updated_at(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let (year, month, day) = unix_days_to_ymd((secs / 86_400) as i64);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Howard Hinnant's civil-from-days (proleptic Gregorian).
fn unix_days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn picker_trigger(current: &Option<Workspace>, folders: &[FolderSummary]) -> (String, String) {
    match current {
        None => ("Select a workspace…".into(), String::new()),
        Some(ws) if ws.is_all() => ("All workspaces".into(), "everything in the vault".into()),
        Some(ws) => {
            if let Some(repo) = &ws.repo {
                let (owner, name) = repo_short(repo);
                if owner.is_empty() {
                    (name.into(), ws.folder.clone())
                } else {
                    (name.into(), owner.into())
                }
            } else if let Some(f) = folders.iter().find(|f| f.name == ws.folder) {
                if is_solo_repo(f) {
                    let (owner, name) = repo_short(&f.name);
                    if owner.is_empty() {
                        (f.name.clone(), String::new())
                    } else {
                        (name.into(), owner.into())
                    }
                } else {
                    let n = f.repos.len();
                    (f.name.clone(), format!("{n} repos"))
                }
            } else {
                (ws.folder.clone(), String::new())
            }
        }
    }
}

fn folder_matches(f: &FolderSummary, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    f.name.to_lowercase().contains(q)
        || f.repos
            .iter()
            .any(|r| r.full_name.to_lowercase().contains(q))
}

fn is_solo_repo(f: &FolderSummary) -> bool {
    f.repos.len() == 1 && f.repos[0].full_name == f.name
}

fn common_owner(repos: &HashSet<String>) -> Option<String> {
    let mut owners = repos.iter().filter_map(|r| r.split('/').next());
    let first = owners.next()?.to_owned();
    if owners.all(|o| o == first) {
        Some(first)
    } else {
        None
    }
}

fn pick_workspace(summary: &FolderSummary) -> Option<Workspace> {
    let first = summary.repos.first()?;
    if summary.repos.len() == 1 || summary.name.ends_with(" repositories") {
        Some(Workspace::group(first.full_name.clone()))
    } else {
        Some(Workspace::group(summary.name.clone()))
    }
}

/// Shared workspace + folder list, owned by [`Dashboard`] so every tab sees the same selection.
#[derive(Clone, Copy)]
struct WorkspaceCtx {
    current: Signal<Option<Workspace>>,
    folders: Signal<Vec<FolderSummary>>,
    rev: Signal<u32>,
    tab: Signal<Tab>,
}

/// Live acquisition progress, polled during a download.
#[derive(Deserialize, Clone, PartialEq)]
struct ProgressView {
    done: usize,
    total: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct FindingView {
    dep: String,
    id: String,
    severity: String,
    summary: String,
}

#[derive(Deserialize, Clone, PartialEq)]
struct RepoScanResult {
    full_name: String,
    #[serde(default)]
    deps: usize,
    #[serde(default)]
    lockfile_found: bool,
    #[serde(default)]
    findings: Vec<FindingView>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct FolderScanReport {
    name: String,
    repos: Vec<RepoScanResult>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct HeartbeatEntry {
    name: String,
    current: String,
    #[serde(default)]
    latest: Option<String>,
    #[serde(default)]
    update_available: bool,
    #[serde(default)]
    advisories: Vec<String>,
    /// Unix seconds when `latest` was published. Missing/0 → no date shown.
    #[serde(default)]
    latest_updated: Option<u64>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct HeartbeatReport {
    name: String,
    entries: Vec<HeartbeatEntry>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct HeartbeatProgressView {
    #[serde(default)]
    name: String,
    done: usize,
    total: usize,
    #[serde(default)]
    entries: Vec<HeartbeatEntry>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct ProdDep {
    name: String,
    version: String,
    #[serde(default)]
    hash: String,
}

#[derive(Deserialize, Clone, PartialEq)]
struct NewVersionEntry {
    name: String,
    production: String,
    #[serde(default)]
    in_production: bool,
    staged: String,
    #[serde(default)]
    staged_ok: bool,
}

#[derive(Deserialize, Clone, PartialEq)]
struct NewVersionReport {
    name: String,
    entries: Vec<NewVersionEntry>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct CoverageGap {
    name: String,
    version: String,
    #[serde(default)]
    reason: String,
}

#[derive(Deserialize, Clone, PartialEq)]
struct CoverageReport {
    name: String,
    #[serde(default)]
    registry_total: usize,
    #[serde(default)]
    archived: usize,
    #[serde(default)]
    gaps: Vec<CoverageGap>,
}

#[derive(Deserialize, Clone, PartialEq)]
struct ScanProgressView {
    #[serde(default)]
    stage: String,
    #[serde(default)]
    label: String,
    done: usize,
    total: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct CombinedScanReport {
    #[serde(default)]
    advisories: usize,
    scan: FolderScanReport,
    updates: NewVersionReport,
    #[serde(default)]
    updates_error: Option<String>,
    coverage: CoverageReport,
    #[serde(default)]
    scanned_at: u64,
}

#[derive(Deserialize, Clone, PartialEq)]
struct WorkspaceOverview {
    name: String,
    #[serde(default)]
    repos: usize,
    #[serde(default)]
    lockfiles: usize,
    #[serde(default)]
    unique_deps: usize,
    #[serde(default)]
    acquired: usize,
    #[serde(default)]
    in_production: usize,
    #[serde(default)]
    advisory_hits: usize,
    #[serde(default)]
    rustsec_loaded: usize,
    #[serde(default)]
    archived: usize,
    #[serde(default)]
    registry_total: usize,
    #[serde(default)]
    gaps: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct HealthView {
    #[serde(default)]
    did: String,
    #[serde(default)]
    mid_active: bool,
}

#[derive(Deserialize, Clone, PartialEq)]
struct LangStat {
    language: String,
    lines: usize,
    crates: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct DepLang {
    name: String,
    version: String,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    lines: usize,
    #[serde(default)]
    has_build_script: bool,
    #[serde(default)]
    is_proc_macro: bool,
    #[serde(default)]
    unsafe_occurrences: usize,
    #[serde(default)]
    links_native: Option<String>,
    #[serde(default)]
    native_unsafe_lines: usize,
    #[serde(default)]
    in_production: bool,
}

#[derive(Deserialize, Clone, PartialEq)]
struct DepAnalytics {
    name: String,
    total_deps: usize,
    analyzed: usize,
    by_language: Vec<LangStat>,
    deps: Vec<DepLang>,
    #[serde(default)]
    build_scripts: usize,
    #[serde(default)]
    proc_macros: usize,
    #[serde(default)]
    native_crates: usize,
    #[serde(default)]
    unsafe_crates: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct AnalyticsProgressView {
    #[serde(default)]
    name: String,
    done: usize,
    total: usize,
    #[serde(default)]
    analyzed: usize,
    #[serde(default)]
    by_language: Vec<LangStat>,
    #[serde(default)]
    deps: Vec<DepLang>,
    #[serde(default)]
    build_scripts: usize,
    #[serde(default)]
    proc_macros: usize,
    #[serde(default)]
    native_crates: usize,
    #[serde(default)]
    unsafe_crates: usize,
}

fn analytics_from_progress(p: AnalyticsProgressView) -> DepAnalytics {
    DepAnalytics {
        name: p.name,
        total_deps: p.total,
        analyzed: p.analyzed,
        by_language: p.by_language,
        deps: p.deps,
        build_scripts: p.build_scripts,
        proc_macros: p.proc_macros,
        native_crates: p.native_crates,
        unsafe_crates: p.unsafe_crates,
    }
}

// ── API client ───────────────────────────────────────────────────────────────
//
// Same `get_json`/`post_json` surface on both platforms; the transport differs because desktop
// is native (no browser fetch): web uses gloo-net (the browser's fetch), desktop uses reqwest.

/// Pull `{"error": "..."}` out of a non-2xx JSON body, else a generic status string.
fn err_from_body(status: u16, body: Option<serde_json::Value>) -> String {
    body.and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
        .unwrap_or_else(|| format!("HTTP {status}"))
}

#[cfg(target_arch = "wasm32")]
async fn read_json<T: for<'de> Deserialize<'de>>(
    resp: gloo_net::http::Response,
) -> Result<T, String> {
    if !resp.ok() {
        let status = resp.status();
        return Err(err_from_body(
            status,
            resp.json::<serde_json::Value>().await.ok(),
        ));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
async fn get_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let resp = gloo_net::http::Request::get(&format!("{API_BASE}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    read_json(resp).await
}

#[cfg(target_arch = "wasm32")]
async fn post_json<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: &serde_json::Value,
) -> Result<T, String> {
    let resp = gloo_net::http::Request::post(&format!("{API_BASE}{path}"))
        .json(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    read_json(resp).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn read_json<T: for<'de> Deserialize<'de>>(resp: reqwest::Response) -> Result<T, String> {
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        return Err(err_from_body(
            status,
            resp.json::<serde_json::Value>().await.ok(),
        ));
    }
    resp.json::<T>().await.map_err(|e| e.to_string())
}

#[cfg(not(target_arch = "wasm32"))]
async fn get_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    let resp = reqwest::Client::new()
        .get(format!("{API_BASE}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    read_json(resp).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn post_json<T: for<'de> Deserialize<'de>>(
    path: &str,
    body: &serde_json::Value,
) -> Result<T, String> {
    let resp = reqwest::Client::new()
        .post(format!("{API_BASE}{path}"))
        .json(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    read_json(resp).await
}

/// Cross-platform async sleep — browser timers on web, tokio on desktop.
async fn sleep_ms(ms: u32) {
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(ms).await;
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(std::time::Duration::from_millis(ms as u64)).await;
}

/// Open a URL in the system browser (desktop) or a new tab (web).
fn open_url(url: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        let url = url.to_owned();
        spawn(async move {
            let js = format!("window.open({}, '_blank')", serde_json::Value::String(url));
            let _ = dioxus::document::eval(&js).await;
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = if cfg!(target_os = "macos") {
            std::process::Command::new("open").arg(url).spawn()
        } else if cfg!(target_os = "windows") {
            std::process::Command::new("cmd")
                .args(["/C", "start", "", url])
                .spawn()
        } else {
            std::process::Command::new("xdg-open").arg(url).spawn()
        };
    }
}

/// Ask the **MATA Sovereign ID browser extension** to sign the challenge and return a wallet
/// token, speaking the exact wire protocol of `@matanetwork/sovereign-id` (ADR 0005, v1):
///
/// - detect: `window.__mata_mid__` is an object with `.version === 1`
/// - request: `postMessage({ __mata_mid_v1: true, kind: "sign_in_request", request_id, rp_origin,
///   nonce, claims }, "*")`
/// - response: `{ __mata_mid_v1: true, kind: "sign_in_response", request_id, result }` where
///   `result.outcome` is `"ok"` (carrying `result.jwt`), `"denied"`, or `"error"`.
///
/// `rp_origin` is the audience Deputy will verify the token's `aud` against (so the wallet binds
/// the token to this relying party). It must equal Deputy's served origin (`DEPUTY_MID_AUDIENCE`).
///
/// Web-only: desktop has no browser extension and uses [`launch_mata_deeplink`] instead.
#[cfg(target_arch = "wasm32")]
async fn request_mid_token(rp_origin: &str, nonce: &str) -> Result<String, String> {
    // JSON-encode so the values land in the script as safely-quoted string literals.
    let origin = serde_json::to_string(rp_origin).unwrap_or_else(|_| "\"\"".to_owned());
    let non = serde_json::to_string(nonce).unwrap_or_else(|_| "\"\"".to_owned());
    let script = format!(
        r#"
        const DISC = "__mata_mid_v1";
        const ext = window["__mata_mid__"];
        if (!ext || typeof ext !== "object" || ext.version !== 1) {{
          console.warn("[Deputy mID] window.__mata_mid__ absent — extension not injected on this origin");
          return {{ ok: false, error: "MATA extension not detected on this page. It must be installed, unlocked, and permitted on this origin (localhost). Or use Dev access below." }};
        }}
        const rpOrigin = {origin};
        const nonce = {non};
        const requestId = (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : String(Math.random());
        console.log("[Deputy mID] sign_in_request", {{ rpOrigin, nonce, requestId }});
        return await new Promise((resolve) => {{
          let done = false;
          function onMsg(ev) {{
            const d = ev.data;
            if (!d || d[DISC] !== true || d.kind !== "sign_in_response" || d.request_id !== requestId) return;
            done = true;
            window.removeEventListener("message", onMsg);
            const r = d.result || {{}};
            console.log("[Deputy mID] sign_in_response", JSON.stringify(r));
            if (r.outcome === "ok") resolve({{ ok: true, token: r.jwt }});
            else if (r.outcome === "denied") resolve({{ ok: false, error: "You denied the sign-in request in the MATA extension." }});
            else resolve({{ ok: false, error: r.message || ("sign-in error: " + (r.error_code || "unknown")) }});
          }}
          window.addEventListener("message", onMsg);
          window.postMessage({{
            [DISC]: true,
            kind: "sign_in_request",
            request_id: requestId,
            rp_origin: rpOrigin,
            nonce: nonce,
            claims: {{ required: ["did"], optional: [], custom: {{}} }}
          }}, "*");
          setTimeout(() => {{
            if (done) return;
            window.removeEventListener("message", onMsg);
            resolve({{ ok: false, error: "Timed out waiting for the MATA extension consent screen." }});
          }}, 120000);
        }});
        "#
    );
    let value = dioxus::document::eval(&script)
        .await
        .map_err(|e| format!("extension bridge error: {e:?}"))?;
    if value.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        value
            .get("token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| "extension returned no token".to_owned())
    } else {
        Err(value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("sign-in declined")
            .to_owned())
    }
}

/// The page's real origin (`window.location.origin`) — what the wallet binds the token's `aud`
/// to, and what Deputy must verify against (so localhost vs 127.0.0.1 stays consistent).
async fn page_origin() -> String {
    dioxus::document::eval("return window.location.origin;")
        .await
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Run an mID sign-in and return the resulting session. **Web** asks the MATA browser extension to
/// sign and verifies the token; **desktop** has no extension, so it deep-links the MATA *native*
/// app and waits for the embedded API's `/auth/callback` to complete the verify.
#[cfg(target_arch = "wasm32")]
async fn run_mid_signin(origin: String, nonce: String) -> Result<Session, String> {
    let token = request_mid_token(&origin, &nonce).await?;
    let body = serde_json::json!({ "token": token, "nonce": nonce, "audience": origin });
    post_json::<Session>("/auth/verify", &body).await
}

#[cfg(not(target_arch = "wasm32"))]
async fn run_mid_signin(_origin: String, nonce: String) -> Result<Session, String> {
    // Launch the MATA native app via `mata-mid://`; its response returns to the embedded API's
    // /auth/callback page, which POSTs the token to /auth/verify and flips `mid_active`.
    eprintln!(
        "[Deputy mID] native sign-in start (nonce {})",
        &nonce[..nonce.len().min(8)]
    );
    launch_mata_deeplink(&nonce);
    eprintln!("[Deputy mID] waiting for MATA to sign + call back (polling /health)…");
    // Give up after ~20s if MATA never responds (e.g. not installed / not the default handler).
    for i in 0..20 {
        sleep_ms(1000).await;
        match get_json::<Session>("/health").await {
            Ok(s) if s.mid_active => {
                eprintln!("[Deputy mID] ✓ signed in as {}", s.did);
                return Ok(s);
            }
            Ok(_) => {
                if i % 5 == 0 {
                    eprintln!("[Deputy mID] …still waiting ({i}s)");
                }
            }
            Err(e) => eprintln!("[Deputy mID] poll error: {e}"),
        }
    }
    Err("Timed out waiting for MATA sign-in — is the MATA app installed + registered for mata-mid://?".to_owned())
}

/// Build the `mata-mid://request` deep link (ADR 0005 native surface) and hand it to the OS URL
/// handler, which launches the registered MATA native app. The app reads the base64url payload,
/// signs, and returns the result via our `deputy://mid-callback` scheme (handled natively by
/// `handle_mid_callback` — no browser). Logs to the terminal so the whole hop is watchable.
#[cfg(not(target_arch = "wasm32"))]
fn launch_mata_deeplink(nonce: &str) {
    use base64::Engine;
    let payload = serde_json::json!({
        "version": 1,
        "request_id": format!("deputy-{nonce}"),
        "rp_origin": API_BASE,
        "nonce": nonce,
        "claims": { "required": ["did"], "optional": [], "custom": {} },
        // Return via the embedded API's /auth/callback page: the wallet opens it in the
        // default browser, the page reads the #mid_response fragment and POSTs the token to
        // /auth/verify, and our /health poll flips. One browser hop, but it needs NO custom
        // URL scheme — a bare (non-bundled) binary cannot register `deputy://` with macOS
        // LaunchServices, so the schemeless path is the one that works everywhere.
        // (`deputy://` stays handled in handle_mid_callback for OS-bundled installs.)
        "callback": format!("{API_BASE}/auth/callback"),
    });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
    let url = format!("mata-mid://request?payload={b64}");
    eprintln!("[Deputy mID] launching deep-link → {url}");
    let spawn = if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(&url).spawn()
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("cmd")
            .args(["/C", "start", "", &url])
            .spawn()
    } else {
        std::process::Command::new("xdg-open").arg(&url).spawn()
    };
    match spawn {
        Ok(_) => eprintln!("[Deputy mID] OS launcher invoked — the MATA app should open now"),
        Err(e) => eprintln!("[Deputy mID] FAILED to launch deep-link: {e}"),
    }
}

// ── Root: the mID auth gate ───────────────────────────────────────────────────

#[component]
fn App() -> Element {
    let session = use_signal(|| None::<Session>);
    rsx! {
        style { {chrome_css()} }
        {match session.read().clone() {
            Some(s) => rsx! { Dashboard { session: s, sess: session } },
            None => rsx! { Landing { sess: session } },
        }}
    }
}

// ── Landing page: sign in with mID (+ dev access) ─────────────────────────────

#[component]
fn Landing(sess: Signal<Option<Session>>) -> Element {
    let mut sess = sess;
    let mut error = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| None::<String>);

    let sign_in_label = if busy() {
        "Signing in…".to_string()
    } else {
        format!("{} Sign in with mID", rusty_symbols::status::OK)
    };

    rsx! {
        div { class: "landing",
            div { class: "login-card",
                div { class: "brand", "Deputy" }
                p { class: "tag", "There is a new dependency in town" }
                button {
                    class: "primary big",
                    disabled: busy(),
                    onclick: move |_| {
                        busy.set(true);
                        error.set(None);
                        spawn(async move {
                            // Get a single-use challenge, then sign in via the platform's mID surface
                            // (browser extension on web, native deep-link on desktop).
                            status.set(Some("Requesting a sign-in challenge…".to_string()));
                            let challenge = match get_json::<Challenge>("/auth/challenge").await {
                                Ok(c) => c,
                                Err(e) => { status.set(None); error.set(Some(format!("couldn't start sign-in — {e}"))); busy.set(false); return; }
                            };
                            let origin = page_origin().await;
                            status.set(Some("Waiting for MATA…".to_string()));
                            match run_mid_signin(origin, challenge.nonce).await {
                                Ok(s) => sess.set(Some(s)),
                                Err(e) => error.set(Some(e)),
                            }
                            status.set(None);
                            busy.set(false);
                        });
                    },
                    "{sign_in_label}"
                }
                {match &*status.read() {
                    Some(s) => rsx! { p { class: "muted login-hint", "{s}" } },
                    None => rsx! {},
                }}
                div { class: "divider", span { "dev" } }
                button {
                    class: "dev big",
                    disabled: busy(),
                    onclick: move |_| {
                        busy.set(true);
                        error.set(None);
                        spawn(async move {
                            match get_json::<Session>("/health").await {
                                Ok(s) => sess.set(Some(s)),
                                Err(e) => error.set(Some(e)),
                            }
                            busy.set(false);
                        });
                    },
                    "⚙ Dev access — skip mID"
                }
                {match &*error.read() {
                    Some(e) => rsx! { p { class: "err", "{e}" } },
                    None => rsx! {},
                }}
            }
        }
    }
}

// ── Authenticated shell: sidebar + tabbed content ─────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Overview,
    GitHub,
    Infrastructure,
    Scan,
    Heartbeat,
    Analytics,
    Production,
}

/// Shared download-job state, owned by [`Dashboard`] (which stays mounted across tab switches)
/// and read by `GitHubTab` via context. Because the driving spawns live in Dashboard's scope —
/// not a tab's — navigating away no longer cancels the in-flight POST (so the embedded API keeps
/// acquiring in the background) or loses the progress. A tab kicks off a download by writing
/// `request`; the runner in Dashboard picks it up.
#[derive(Clone, Copy)]
struct DownloadJob {
    active: Signal<bool>,
    progress: Signal<Option<ProgressView>>,
    result: Signal<Option<Result<FolderSummary, String>>>,
    request: Signal<Option<DownloadReq>>,
}

/// A queued acquisition: which endpoint to POST (`/github/download`, `/local/download`, or
/// `/folders/refresh`) and its JSON body. The runner reports progress + result the same way.
/// `stay` keeps the current tab after success (Infrastructure refresh); GitHub pulls land on Overview.
#[derive(Clone, PartialEq)]
struct DownloadReq {
    url: &'static str,
    body: serde_json::Value,
    stay: bool,
}

/// Combined workspace scan, owned by [`Dashboard`] so navigating away from Scan Dependencies
/// does not cancel the in-flight POST or lose progress. ScanTab queues work via `request`.
#[derive(Clone, Copy)]
struct ScanJob {
    active: Signal<bool>,
    progress: Signal<Option<ScanProgressView>>,
    report: Signal<Option<Result<CombinedScanReport, String>>>,
    request: Signal<Option<serde_json::Value>>,
    advisories: Signal<Option<usize>>,
    /// `Workspace::encode` of the scan currently held or in flight.
    req_key: Signal<String>,
}

/// Overview snapshot + crates.io heartbeat. Lives on [`Dashboard`] so leaving Overview
/// does not cancel Version Control's network check.
#[derive(Clone, Copy)]
struct OverviewJob {
    snapshot: Signal<Option<Result<WorkspaceOverview, String>>>,
    heartbeat: Signal<Option<Result<HeartbeatReport, String>>>,
    health: Signal<Option<HealthView>>,
    /// `Workspace::encode` of the snapshot/heartbeat currently held (or being fetched).
    scope: Signal<String>,
    loading: Signal<bool>,
    done: Signal<usize>,
    total: Signal<usize>,
    vc_filter: Signal<String>,
    vc_scoped: Signal<Option<Result<HeartbeatReport, String>>>,
    vc_loading: Signal<bool>,
    vc_done: Signal<usize>,
    vc_total: Signal<usize>,
}

/// Dep Analytics fetch owned by [`Dashboard`].
#[derive(Clone, Copy)]
struct AnalyticsJob {
    loading: Signal<bool>,
    result: Signal<Option<Result<DepAnalytics, String>>>,
    done: Signal<usize>,
    total: Signal<usize>,
    /// `{encode}#{pull_rev}` of the result currently held (or being fetched).
    scope: Signal<String>,
}

/// Production-deps fetch owned by [`Dashboard`]. `gen` bumps after a promote to reload.
#[derive(Clone, Copy)]
struct ProductionJob {
    loading: Signal<bool>,
    result: Signal<Option<Result<Vec<ProdDep>, String>>>,
    gen: Signal<u32>,
    /// `{encode}#{gen}#{pull_rev}` of the result currently held (or being fetched).
    scope: Signal<String>,
}

#[component]
fn Dashboard(session: Session, sess: Signal<Option<Session>>) -> Element {
    let mut sess = sess;
    let mut tab = use_signal(|| Tab::Overview);
    let mut current = use_signal(|| Some(Workspace::all()));

    // ── Background download job (persists across tab switches) ────────────────
    // These signals + the runner below live in Dashboard's scope, so the work keeps going and
    // the progress keeps updating even when GitHubTab is unmounted by navigating to another tab.
    let mut active = use_signal(|| false);
    let mut progress = use_signal(|| None::<ProgressView>);
    let mut result = use_signal(|| None::<Result<FolderSummary, String>>);
    let mut request = use_signal(|| None::<DownloadReq>);

    let mut folders = use_signal(Vec::<FolderSummary>::new);
    let mut ws_rev = use_signal(|| 0u32);
    let mut pull_rev = use_signal(|| 0u32);
    let mut folders_ready = use_signal(|| false);

    use_effect(move || {
        let _ = ws_rev();
        spawn(async move {
            if let Ok(list) = get_json::<Vec<FolderSummary>>("/folders").await {
                folders.set(list);
            }
            folders_ready.set(true);
        });
    });

    use_effect(move || {
        // Fires when a tab dispatches a new download via `request`.
        if let Some(req) = request() {
            request.set(None);
            active.set(true);
            progress.set(None);
            result.set(None);
            // Poll server-side acquisition progress until the download finishes.
            spawn(async move {
                while active() {
                    if let Ok(p) =
                        get_json::<Option<ProgressView>>("/github/download/progress").await
                    {
                        progress.set(p);
                    }
                    sleep_ms(400).await;
                }
                progress.set(None);
            });
            // The download itself — kept alive here, so it survives tab navigation.
            spawn(async move {
                let r = post_json::<FolderSummary>(req.url, &req.body).await;
                if let Ok(ref summary) = r {
                    if !req.stay {
                        current.set(pick_workspace(summary));
                        tab.set(Tab::Overview);
                    }
                    ws_rev.set(ws_rev() + 1);
                    pull_rev.set(pull_rev() + 1);
                }
                result.set(Some(r));
                active.set(false);
            });
        }
    });
    use_context_provider(|| DownloadJob {
        active,
        progress,
        result,
        request,
    });

    // ── Combined scan job (persists across tab switches) ──────────────────────
    let mut scan_active = use_signal(|| false);
    let mut scan_progress = use_signal(|| None::<ScanProgressView>);
    let mut scan_report = use_signal(|| None::<Result<CombinedScanReport, String>>);
    let mut scan_request = use_signal(|| None::<serde_json::Value>);
    let mut scan_req_key = use_signal(String::new);
    let mut advisories = use_signal(|| None::<usize>);

    use_effect(move || {
        spawn(async move {
            match post_json::<serde_json::Value>("/advisories/rustsec", &serde_json::json!({}))
                .await
            {
                Ok(v) => advisories.set(
                    v.get("advisories")
                        .and_then(|a| a.as_u64())
                        .map(|n| n as usize),
                ),
                Err(_) => {
                    if let Ok(v) = get_json::<serde_json::Value>("/advisories").await {
                        advisories.set(
                            v.get("advisories")
                                .and_then(|a| a.as_u64())
                                .map(|n| n as usize),
                        );
                    } else {
                        advisories.set(Some(0));
                    }
                }
            }
        });
    });

    use_effect(move || {
        if let Some(body) = scan_request() {
            scan_request.set(None);
            scan_req_key.set(
                workspace_from_api_body(&body)
                    .map(|w| w.encode())
                    .unwrap_or_default(),
            );
            scan_active.set(true);
            scan_progress.set(Some(ScanProgressView {
                stage: "start".into(),
                label: "Scanning lockfiles…".into(),
                done: 0,
                total: 1,
            }));
            spawn(async move {
                while scan_active() {
                    if let Ok(Some(p)) =
                        get_json::<Option<ScanProgressView>>("/folders/scan/progress").await
                    {
                        scan_progress.set(Some(p));
                    }
                    sleep_ms(300).await;
                }
                scan_progress.set(None);
            });
            spawn(async move {
                let r = post_json::<CombinedScanReport>("/folders/scan-all", &body).await;
                if let Ok(ref report) = r {
                    advisories.set(Some(report.advisories));
                }
                let done_key = scan_req_key();
                let cur = current
                    .read()
                    .as_ref()
                    .map(Workspace::encode)
                    .unwrap_or_default();
                if cur == done_key {
                    scan_report.set(Some(r));
                }
                scan_active.set(false);
            });
        }
    });

    use_effect(move || {
        let ws = current.read().clone();
        let key = ws.as_ref().map(Workspace::encode).unwrap_or_default();
        if scan_active() && scan_req_key() == key {
            return;
        }
        let Some(ws) = ws else {
            scan_report.set(None);
            return;
        };
        scan_report.set(None);
        let body = ws.api_body();
        spawn(async move {
            if scan_active() && scan_req_key() == key {
                return;
            }
            match post_json::<Option<CombinedScanReport>>("/folders/scan/last", &body).await {
                Ok(Some(r)) => {
                    if current.read().as_ref().map(Workspace::encode).as_deref()
                        == Some(key.as_str())
                        && !(scan_active() && scan_req_key() == key)
                    {
                        scan_report.set(Some(Ok(r)));
                    }
                }
                Ok(None) | Err(_) => {
                    if current.read().as_ref().map(Workspace::encode).as_deref()
                        == Some(key.as_str())
                        && !(scan_active() && scan_req_key() == key)
                    {
                        scan_report.set(None);
                    }
                }
            }
        });
    });
    use_context_provider(|| ScanJob {
        active: scan_active,
        progress: scan_progress,
        report: scan_report,
        request: scan_request,
        advisories,
        req_key: scan_req_key,
    });

    let mut ov_snapshot = use_signal(|| None::<Result<WorkspaceOverview, String>>);
    let mut ov_heartbeat = use_signal(|| None::<Result<HeartbeatReport, String>>);
    let mut ov_health = use_signal(|| {
        Some(HealthView {
            did: session.did.clone(),
            mid_active: session.mid_active,
        })
    });
    // Match the default workspace so the first Overview paint is not treated as a stale scope.
    let mut ov_scope = use_signal(|| WS_ALL.to_string());
    let mut ov_loading = use_signal(|| true);
    let mut ov_done = use_signal(|| 0usize);
    let mut ov_total = use_signal(|| 0usize);
    let mut vc_filter = use_signal(String::new);
    let mut vc_scoped = use_signal(|| None::<Result<HeartbeatReport, String>>);
    let mut vc_loading = use_signal(|| false);
    let mut vc_done = use_signal(|| 0usize);
    let mut vc_total = use_signal(|| 0usize);

    use_effect(move || {
        let _ = pull_rev();
        let ready = folders_ready();
        let ws = current.read().clone();
        let key = ws.as_ref().map(Workspace::encode).unwrap_or_default();
        ov_scope.set(key.clone());
        vc_filter.set(String::new());
        vc_scoped.set(None);
        vc_loading.set(false);
        vc_done.set(0);
        vc_total.set(0);
        ov_snapshot.set(None);
        ov_heartbeat.set(None);
        ov_done.set(0);
        ov_total.set(0);
        if !ready {
            ov_loading.set(true);
            return;
        }
        let Some(ws) = ws else {
            ov_loading.set(false);
            return;
        };
        ov_loading.set(true);
        let body = ws.api_body();
        let snap_key = key.clone();
        let snap_body = body.clone();
        spawn(async move {
            if let Ok(h) = get_json::<HealthView>("/health").await {
                ov_health.set(Some(h));
            }
            let snap = post_json::<WorkspaceOverview>("/folders/overview", &snap_body).await;
            if ov_scope() == snap_key {
                ov_snapshot.set(Some(snap));
            }
        });
        let poll_key = key.clone();
        spawn(async move {
            while ov_loading() && ov_scope() == poll_key {
                if vc_filter().is_empty() {
                    if let Ok(Some(p)) =
                        get_json::<Option<HeartbeatProgressView>>("/folders/heartbeat/progress")
                            .await
                    {
                        if ov_scope() == poll_key
                            && vc_filter().is_empty()
                            && Workspace::decode(&poll_key)
                                .is_some_and(|w| report_is_for(&w, &p.name))
                        {
                            ov_done.set(p.done);
                            ov_total.set(p.total);
                            ov_heartbeat.set(Some(Ok(HeartbeatReport {
                                name: p.name,
                                entries: p.entries,
                            })));
                        }
                    }
                }
                sleep_ms(250).await;
            }
        });
        spawn(async move {
            let beat = post_json::<HeartbeatReport>("/folders/heartbeat", &body).await;
            if ov_scope() == key {
                if let Ok(ref r) = beat {
                    ov_done.set(r.entries.len());
                    ov_total.set(r.entries.len());
                }
                ov_heartbeat.set(Some(beat));
                ov_loading.set(false);
            }
        });
    });

    use_effect(move || {
        let v = vc_filter();
        if v.is_empty() {
            vc_scoped.set(None);
            vc_loading.set(false);
            vc_done.set(0);
            vc_total.set(0);
            return;
        }
        let Some(ws) = Workspace::decode(&v) else {
            return;
        };
        let key = v.clone();
        vc_loading.set(true);
        vc_scoped.set(None);
        vc_done.set(0);
        vc_total.set(0);
        let body = ws.api_body();
        let poll_key = key.clone();
        spawn(async move {
            while vc_loading() && vc_filter() == poll_key {
                if let Ok(Some(p)) =
                    get_json::<Option<HeartbeatProgressView>>("/folders/heartbeat/progress").await
                {
                    if vc_filter() == poll_key
                        && Workspace::decode(&poll_key).is_some_and(|w| report_is_for(&w, &p.name))
                    {
                        vc_done.set(p.done);
                        vc_total.set(p.total);
                        vc_scoped.set(Some(Ok(HeartbeatReport {
                            name: p.name,
                            entries: p.entries,
                        })));
                    }
                }
                sleep_ms(250).await;
            }
        });
        spawn(async move {
            let beat = post_json::<HeartbeatReport>("/folders/heartbeat", &body).await;
            if vc_filter() == key {
                if let Ok(ref r) = beat {
                    vc_done.set(r.entries.len());
                    vc_total.set(r.entries.len());
                }
                vc_scoped.set(Some(beat));
                vc_loading.set(false);
            }
        });
    });
    use_context_provider(|| OverviewJob {
        snapshot: ov_snapshot,
        heartbeat: ov_heartbeat,
        health: ov_health,
        scope: ov_scope,
        loading: ov_loading,
        done: ov_done,
        total: ov_total,
        vc_filter,
        vc_scoped,
        vc_loading,
        vc_done,
        vc_total,
    });

    let mut an_loading = use_signal(|| false);
    let mut an_result = use_signal(|| None::<Result<DepAnalytics, String>>);
    let mut an_scope = use_signal(String::new);
    let mut an_request = use_signal(|| None::<(Workspace, u32)>);
    let mut an_done = use_signal(|| 0usize);
    let mut an_total = use_signal(|| 0usize);
    use_effect(move || {
        let gen = pull_rev();
        let ws = current.read().clone();
        let stale = match &ws {
            Some(w) => !an_scope().is_empty() && !job_scope_matches(&an_scope(), w),
            None => !an_scope().is_empty(),
        };
        if stale {
            an_result.set(None);
            an_loading.set(false);
            an_scope.set(String::new());
            an_done.set(0);
            an_total.set(0);
        }
        if tab() != Tab::Analytics {
            return;
        }
        let Some(ws) = ws else {
            an_result.set(None);
            an_loading.set(false);
            an_scope.set(String::new());
            return;
        };
        let key = format!("{}#{gen}", ws.encode());
        if an_scope() == key && (an_loading() || an_result.read().is_some()) {
            return;
        }
        an_request.set(Some((ws, gen)));
    });
    use_effect(move || {
        let Some((ws, gen)) = an_request() else {
            return;
        };
        an_request.set(None);
        let key = format!("{}#{gen}", ws.encode());
        an_scope.set(key.clone());
        an_loading.set(true);
        an_result.set(None);
        an_done.set(0);
        an_total.set(0);
        let body = ws.api_body();
        let poll_key = key.clone();
        spawn(async move {
            while an_loading() && an_scope() == poll_key {
                if let Ok(Some(p)) =
                    get_json::<Option<AnalyticsProgressView>>("/folders/analytics/progress").await
                {
                    if an_scope() == poll_key {
                        an_done.set(p.done);
                        an_total.set(p.total);
                        an_result.set(Some(Ok(analytics_from_progress(p))));
                    }
                }
                sleep_ms(250).await;
            }
        });
        spawn(async move {
            let r = post_json::<DepAnalytics>("/folders/analytics", &body).await;
            if an_scope() == key {
                if let Ok(ref a) = r {
                    an_done.set(a.total_deps);
                    an_total.set(a.total_deps);
                }
                an_result.set(Some(r));
                an_loading.set(false);
            }
        });
    });
    use_context_provider(|| AnalyticsJob {
        loading: an_loading,
        result: an_result,
        done: an_done,
        total: an_total,
        scope: an_scope,
    });

    let mut prod_loading = use_signal(|| false);
    let mut prod_result = use_signal(|| None::<Result<Vec<ProdDep>, String>>);
    let mut prod_scope = use_signal(String::new);
    let prod_gen = use_signal(|| 0u32);
    let mut prod_request = use_signal(|| None::<(Workspace, u32, u32)>);
    use_effect(move || {
        let gen = prod_gen();
        let pull = pull_rev();
        let ws = current.read().clone();
        let stale = match &ws {
            Some(w) => !prod_scope().is_empty() && !job_scope_matches(&prod_scope(), w),
            None => !prod_scope().is_empty(),
        };
        if stale {
            prod_result.set(None);
            prod_loading.set(false);
            prod_scope.set(String::new());
        }
        if tab() != Tab::Production {
            return;
        }
        let Some(ws) = ws else {
            prod_result.set(None);
            prod_loading.set(false);
            prod_scope.set(String::new());
            return;
        };
        let key = format!("{}#{gen}#{pull}", ws.encode());
        if prod_scope() == key && (prod_loading() || prod_result.read().is_some()) {
            return;
        }
        prod_request.set(Some((ws, gen, pull)));
    });
    use_effect(move || {
        let Some((ws, gen, pull)) = prod_request() else {
            return;
        };
        prod_request.set(None);
        let key = format!("{}#{gen}#{pull}", ws.encode());
        prod_scope.set(key.clone());
        prod_loading.set(true);
        prod_result.set(None);
        let body = ws.api_body();
        spawn(async move {
            let r = post_json::<Vec<ProdDep>>("/folders/production", &body).await;
            if prod_scope() == key {
                prod_result.set(Some(r));
                prod_loading.set(false);
            }
        });
    });
    use_context_provider(|| ProductionJob {
        loading: prod_loading,
        result: prod_result,
        gen: prod_gen,
        scope: prod_scope,
    });

    use_context_provider(|| WorkspaceCtx {
        current,
        folders,
        rev: ws_rev,
        tab,
    });

    let did_line = format!("{} {}", rusty_symbols::status::LIVE, session.did);

    rsx! {
        div { class: "shell",
            nav { class: "sidebar",
                button {
                    class: "brand sb-logo",
                    r#type: "button",
                    title: "Overview of all workspaces",
                    onclick: move |_| {
                        current.set(Some(Workspace::all()));
                        tab.set(Tab::Overview);
                    },
                    "Deputy"
                }
                WorkspacePicker {}
                div { class: "nav",
                    NavItem { tab, this: Tab::Overview, label: "Overview" }
                    NavItem { tab, this: Tab::GitHub, label: "GitHub" }
                    NavItem { tab, this: Tab::Infrastructure, label: "Infrastructure" }
                    NavItem { tab, this: Tab::Scan, label: "Scan Dependencies" }
                    NavItem { tab, this: Tab::Analytics, label: "Dep Analytics" }
                    NavItem { tab, this: Tab::Heartbeat, label: "New Versions" }
                    NavItem { tab, this: Tab::Production, label: "Production Dependencies" }
                }
                {if active() {
                    let p = progress.read().clone();
                    let label = match p {
                        Some(ref p) if p.total > 0 => format!("downloading {}/{}…", p.done, p.total),
                        _ => "downloading…".to_string(),
                    };
                    let live = rusty_a11y::live::polite(&label);
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "{label}"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else if scan_active() {
                    let p = scan_progress.read().clone();
                    let label = match p {
                        Some(ref p) if p.total > 0 => {
                            format!("{} — {}/{}", p.label, p.done, p.total)
                        }
                        Some(ref p) if !p.label.is_empty() => p.label.clone(),
                        _ => "scanning…".to_string(),
                    };
                    let live = rusty_a11y::live::polite(&label);
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "{label}"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else if an_loading() {
                    let n = an_done();
                    let t = an_total();
                    let label = if t > 0 {
                        format!("inspecting crates — {n}/{t}")
                    } else {
                        "inspecting crates…".to_string()
                    };
                    let live = rusty_a11y::live::polite(&label);
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "{label}"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else if prod_loading() {
                    let live = rusty_a11y::live::polite("loading production");
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "loading production…"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else if ov_loading() {
                    let n = ov_done();
                    let t = ov_total();
                    let label = if t > 0 {
                        format!("checking crates.io — {n}/{t}")
                    } else {
                        "checking crates.io…".to_string()
                    };
                    let live = rusty_a11y::live::polite(&label);
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "{label}"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else if vc_loading() {
                    let n = vc_done();
                    let t = vc_total();
                    let label = if t > 0 {
                        format!("checking versions — {n}/{t}")
                    } else {
                        "checking versions…".to_string()
                    };
                    let live = rusty_a11y::live::polite(&label);
                    rsx! { div { class: "sb-busy",
                        span { class: "sb-spinner" }
                        "{label}"
                        div { class: "sr-only", dangerous_inner_html: "{live}" }
                    } }
                } else {
                    rsx! {}
                }}
                div { class: "sb-footer",
                    span { class: "did", "{did_line}" }
                    {if !session.mid_active {
                        rsx! { span { class: "badge", "local mode" } }
                    } else {
                        rsx! { span { class: "badge mid", "mID" } }
                    }}
                    button { class: "ghost", onclick: move |_| sess.set(None), "Sign out" }
                }
            }
            main { class: "content",
                {match tab() {
                    Tab::Overview => rsx! { OverviewTab {} },
                    Tab::GitHub => rsx! { GitHubTab {} },
                    Tab::Infrastructure => rsx! { InfrastructureTab {} },
                    Tab::Scan => rsx! { ScanTab {} },
                    Tab::Analytics => rsx! { AnalyticsTab {} },
                    Tab::Heartbeat => rsx! { HeartbeatTab {} },
                    Tab::Production => rsx! { ProductionTab {} },
                }}
            }
        }
    }
}

#[component]
fn WorkspacePicker() -> Element {
    let mut ctx = use_context::<WorkspaceCtx>();
    let mut open = use_signal(|| false);
    let mut filter = use_signal(String::new);
    let folders = ctx.folders.read().clone();
    let current = ctx.current.read().clone();
    let q = filter().trim().to_lowercase();
    let (main, sub) = picker_trigger(&current, &folders);
    let show_all = q.is_empty() || "all workspaces".contains(&q);
    let all_on = current.as_ref().is_some_and(Workspace::is_all);
    let all_cls = if all_on { "ws-opt selected" } else { "ws-opt" };
    rsx! {
        div {
            class: "ws-picker",
            onkeydown: move |evt| {
                if evt.key().to_string() == "Escape" {
                    open.set(false);
                }
            },
            label { class: "ws-label", "Workspace" }
            button {
                class: "ws-trigger",
                r#type: "button",
                aria_haspopup: "listbox",
                aria_expanded: "{open()}",
                onclick: move |_| open.set(!open()),
                div { class: "ws-trigger-text",
                    span { class: "ws-trigger-main", "{main}" }
                    {if !sub.is_empty() {
                        rsx! { span { class: "ws-trigger-sub", "{sub}" } }
                    } else {
                        rsx! {}
                    }}
                }
                span { class: "ws-caret", "▾" }
            }
            {if open() {
                rsx! {
                    div {
                        class: "ws-menu-backdrop",
                        onclick: move |_| open.set(false),
                    }
                    div { class: "ws-menu", role: "listbox",
                        input {
                            class: "ws-filter",
                            r#type: "search",
                            placeholder: "Filter repos…",
                            value: "{filter}",
                            oninput: move |e| filter.set(e.value()),
                        }
                        {if show_all {
                            rsx! {
                                button {
                                    class: "{all_cls}",
                                    r#type: "button",
                                    key: "{WS_ALL}",
                                    onclick: move |_| {
                                        open.set(false);
                                        filter.set(String::new());
                                        select_workspace(ctx, Workspace::all());
                                    },
                                    span { class: "ws-repo-name", "All workspaces" }
                                    span { class: "ws-repo-owner", "everything in the vault" }
                                }
                            }
                        } else {
                            rsx! {}
                        }}
                        for f in folders.iter().filter(|f| folder_matches(f, &q)) {
                            {if is_solo_repo(f) {
                                let ws = Workspace::group(f.name.clone());
                                let on = current.as_ref() == Some(&ws);
                                let cls = if on { "ws-opt ws-repo selected" } else { "ws-opt ws-repo" };
                                let (owner, name) = repo_short(&f.name);
                                let key = ws.encode();
                                rsx! {
                                    button {
                                        class: "{cls}",
                                        r#type: "button",
                                        key: "{key}",
                                        onclick: {
                                            let ws = ws.clone();
                                            move |_| {
                                                open.set(false);
                                                filter.set(String::new());
                                                select_workspace(ctx, ws.clone());
                                            }
                                        },
                                        span { class: "ws-repo-name", "{name}" }
                                        {if !owner.is_empty() {
                                            rsx! { span { class: "ws-repo-owner", "{owner}" } }
                                        } else {
                                            rsx! {}
                                        }}
                                    }
                                }
                            } else {
                                let group_ws = Workspace::group(f.name.clone());
                                let group_on = current.as_ref() == Some(&group_ws);
                                let group_cls = if group_on {
                                    "ws-opt ws-group selected"
                                } else {
                                    "ws-opt ws-group"
                                };
                                let n = f.repos.len();
                                let show_all_repos = q.is_empty() || f.name.to_lowercase().contains(&q);
                                let group_key = group_ws.encode();
                                rsx! {
                                    button {
                                        class: "{group_cls}",
                                        r#type: "button",
                                        key: "{group_key}",
                                        onclick: {
                                            let ws = group_ws.clone();
                                            move |_| {
                                                open.set(false);
                                                filter.set(String::new());
                                                select_workspace(ctx, ws.clone());
                                            }
                                        },
                                        span { class: "ws-repo-name", "{f.name}" }
                                        span { class: "ws-repo-owner", "{n} repos" }
                                    }
                                    for r in f.repos.iter().filter(|r| {
                                        show_all_repos || r.full_name.to_lowercase().contains(&q)
                                    }) {
                                        {
                                            let row_ws = Workspace::repo(f.name.clone(), r.full_name.clone());
                                            let on = current.as_ref() == Some(&row_ws);
                                            let cls = if on {
                                                "ws-opt ws-repo selected"
                                            } else {
                                                "ws-opt ws-repo"
                                            };
                                            let (owner, name) = repo_short(&r.full_name);
                                            let key = row_ws.encode();
                                            rsx! {
                                                button {
                                                    class: "{cls}",
                                                    r#type: "button",
                                                    key: "{key}",
                                                    onclick: {
                                                        let ws = row_ws.clone();
                                                        move |_| {
                                                            open.set(false);
                                                            filter.set(String::new());
                                                            select_workspace(ctx, ws.clone());
                                                        }
                                                    },
                                                    span { class: "ws-repo-name", "{name}" }
                                                    {if !owner.is_empty() {
                                                        rsx! { span { class: "ws-repo-owner", "{owner}" } }
                                                    } else {
                                                        rsx! {}
                                                    }}
                                                }
                                            }
                                        }
                                    }
                                }
                            }}
                        }
                        button {
                            class: "ws-opt ws-add",
                            r#type: "button",
                            onclick: move |_| {
                                open.set(false);
                                filter.set(String::new());
                                ctx.tab.set(Tab::GitHub);
                            },
                            "+ Add workspace…"
                        }
                    }
                }
            } else {
                rsx! {}
            }}
        }
    }
}

#[component]
fn NavItem(tab: Signal<Tab>, this: Tab, label: String) -> Element {
    let mut tab = tab;
    let cls = if tab() == this {
        "nav-item active"
    } else {
        "nav-item"
    };
    rsx! {
        button { class: "{cls}", onclick: move |_| tab.set(this), "{label}" }
    }
}

fn scoped_repos(folders: &[FolderSummary], ws: &Workspace) -> Vec<RepoSummary> {
    scoped_repo_refs(folders, ws)
        .into_iter()
        .map(|(_, r)| r)
        .collect()
}

fn scoped_repo_refs(folders: &[FolderSummary], ws: &Workspace) -> Vec<(String, RepoSummary)> {
    if ws.is_all() {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for f in folders {
            for r in &f.repos {
                if seen.insert(r.full_name.clone()) {
                    out.push((f.name.clone(), r.clone()));
                }
            }
        }
        return out;
    }
    folders
        .iter()
        .find(|f| f.name == ws.folder)
        .map(|f| match &ws.repo {
            Some(r) => f
                .repos
                .iter()
                .filter(|x| x.full_name == *r)
                .cloned()
                .map(|repo| (f.name.clone(), repo))
                .collect(),
            None => f
                .repos
                .iter()
                .cloned()
                .map(|repo| (f.name.clone(), repo))
                .collect(),
        })
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum UpdatePriority {
    High,
    Medium,
    Low,
}

impl UpdatePriority {
    fn label(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::High => "x.0.0",
            Self::Medium => "0.x.0",
            Self::Low => "0.0.x",
        }
    }

    fn class(self) -> &'static str {
        match self {
            Self::High => "vc-pri high",
            Self::Medium => "vc-pri medium",
            Self::Low => "vc-pri low",
        }
    }
}

fn parse_semver_core(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let patch = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor, patch))
}

fn update_priority(current: &str, latest: &str) -> Option<UpdatePriority> {
    let (cm, ci, cp) = parse_semver_core(current)?;
    let (lm, li, lp) = parse_semver_core(latest)?;
    if lm > cm {
        Some(UpdatePriority::High)
    } else if lm == cm && li > ci {
        Some(UpdatePriority::Medium)
    } else if lm == cm && li == ci && lp > cp {
        Some(UpdatePriority::Low)
    } else {
        None
    }
}

// ── Overview: landing page for the selected workspace ─────────────────────────

#[component]
fn OverviewTab() -> Element {
    let mut ctx = use_context::<WorkspaceCtx>();
    let job = use_context::<OverviewJob>();

    let current = ctx.current.read().clone();
    let folders = ctx.folders.read().clone();
    let title = current
        .as_ref()
        .map(Workspace::label)
        .unwrap_or_else(|| "Overview".to_string());
    let is_all = current.as_ref().is_some_and(Workspace::is_all);
    let is_group = !is_all
        && current.as_ref().is_some_and(|w| w.repo.is_none())
        && current.as_ref().is_some_and(|w| {
            folders
                .iter()
                .find(|f| f.name == w.folder)
                .is_some_and(|f| !is_solo_repo(f))
        });
    let kind = if is_all {
        "all workspaces"
    } else if is_group {
        "group"
    } else {
        "repository"
    };
    let repos = current
        .as_ref()
        .map(|w| scoped_repos(&folders, w))
        .unwrap_or_default();
    let repo_refs = current
        .as_ref()
        .map(|w| scoped_repo_refs(&folders, w))
        .unwrap_or_default();

    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                div {
                    h2 { "{title}" }
                    {if current.is_some() {
                        rsx! { p { class: "muted ov-kicker", "{kind}" } }
                    } else {
                        rsx! {}
                    }}
                }
            }
            {match current.clone() {
                None => rsx! {
                    p { class: "muted",
                        "Select a repository or group in the sidebar, click Deputy for a vault-wide "
                        "overview, or add one from the GitHub tab."
                    }
                },
                Some(ws) => {
                    let scoped = job_scope_matches(&(job.scope)(), &ws);
                    let heartbeat = if scoped {
                        match &*job.heartbeat.read() {
                            Some(Ok(r)) if report_is_for(&ws, &r.name) => Some(Ok(r.clone())),
                            Some(Err(e)) => Some(Err(e.clone())),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    rsx! {
                        {match (scoped, &*job.snapshot.read()) {
                            (false, _) | (_, None) => rsx! { p { class: "muted", "Reading this workspace's lockfiles…" } },
                            (_, Some(Err(e))) => rsx! { p { class: "err", "Couldn't load overview — {e}" } },
                            (_, Some(Ok(ov))) if report_is_for(&ws, &ov.name) => rsx! { OverviewStats {
                                ov: ov.clone(),
                                heartbeat,
                                health: job.health.read().clone(),
                            } },
                            _ => rsx! { p { class: "muted", "Reading this workspace's lockfiles…" } },
                        }}
                    }
                },
            }}
        }
        {if current.is_some() {
            rsx! { VersionControlPanel { repo_refs: repo_refs.clone() } }
        } else {
            rsx! {}
        }}
        {if current.is_some() && !repos.is_empty() {
            rsx! {
                section { class: "panel",
                    h3 { "Repositories" }
                    ul { class: "repolist",
                        for r in repos.iter() {
                            li { class: "repo-row",
                                span { class: "repo-name", "{r.full_name}" }
                                span { class: "muted", "{repo_vault_line(r)}" }
                            }
                        }
                    }
                }
            }
        } else {
            rsx! {}
        }}
        {if current.is_some() {
            rsx! {
                section { class: "panel",
                    h3 { "Open" }
                    div { class: "ov-actions",
                        button { class: "ghost", onclick: move |_| ctx.tab.set(Tab::Scan), "Scan" }
                        button { class: "ghost", onclick: move |_| ctx.tab.set(Tab::Analytics), "Analytics" }
                        button { class: "ghost", onclick: move |_| ctx.tab.set(Tab::Heartbeat), "New versions" }
                        button { class: "ghost", onclick: move |_| ctx.tab.set(Tab::Production), "Production" }
                    }
                }
            }
        } else {
            rsx! {}
        }}
    }
}

fn vc_update_rows(
    report: &Option<Result<HeartbeatReport, String>>,
) -> Vec<(UpdatePriority, HeartbeatEntry)> {
    let mut rows: Vec<(UpdatePriority, HeartbeatEntry)> = match report {
        Some(Ok(r)) => r
            .entries
            .iter()
            .filter(|e| e.update_available)
            .filter_map(|e| {
                let latest = e.latest.as_deref()?;
                let pri = update_priority(&e.current, latest)?;
                Some((pri, e.clone()))
            })
            .collect(),
        _ => Vec::new(),
    };
    rows.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| b.1.latest.cmp(&a.1.latest))
            .then_with(|| a.1.name.cmp(&b.1.name))
    });
    rows
}

#[component]
fn RepoFilterMenu(repo_refs: Vec<(String, RepoSummary)>) -> Element {
    let job = use_context::<OverviewJob>();
    let mut filter = job.vc_filter;
    let mut scoped = job.vc_scoped;
    let mut vc_loading = job.vc_loading;
    let mut open = use_signal(|| false);
    let mut query = use_signal(String::new);
    let selected = filter();
    let n = repo_refs.len();
    let (main, sub) = if selected.is_empty() {
        ("All repositories".to_string(), format!("{n} repos"))
    } else if let Some(ws) = Workspace::decode(&selected) {
        match &ws.repo {
            Some(repo) => {
                let (owner, name) = repo_short(repo);
                if owner.is_empty() {
                    (name.to_string(), ws.folder.clone())
                } else {
                    (name.to_string(), owner.to_string())
                }
            }
            None => (ws.folder.clone(), String::new()),
        }
    } else {
        ("All repositories".to_string(), format!("{n} repos"))
    };
    let q = query().trim().to_lowercase();
    let show_all = q.is_empty() || "all repositories".contains(&q);
    let all_cls = if selected.is_empty() {
        "ws-opt selected"
    } else {
        "ws-opt"
    };
    rsx! {
        div {
            class: "ws-picker compact",
            onkeydown: move |evt| {
                if evt.key().to_string() == "Escape" {
                    open.set(false);
                }
            },
            button {
                class: "ws-trigger",
                r#type: "button",
                aria_haspopup: "listbox",
                aria_expanded: "{open()}",
                onclick: move |_| open.set(!open()),
                div { class: "ws-trigger-text",
                    span { class: "ws-trigger-main", "{main}" }
                    {if !sub.is_empty() {
                        rsx! { span { class: "ws-trigger-sub", "{sub}" } }
                    } else {
                        rsx! {}
                    }}
                }
                span { class: "ws-caret", "▾" }
            }
            {if open() {
                rsx! {
                    div {
                        class: "ws-menu-backdrop",
                        onclick: move |_| open.set(false),
                    }
                    div { class: "ws-menu", role: "listbox",
                        input {
                            class: "ws-filter",
                            r#type: "search",
                            placeholder: "Filter repos…",
                            value: "{query}",
                            oninput: move |e| query.set(e.value()),
                        }
                        {if show_all {
                            rsx! {
                                button {
                                    class: "{all_cls}",
                                    r#type: "button",
                                    onclick: move |_| {
                                        open.set(false);
                                        query.set(String::new());
                                        scoped.set(None);
                                        vc_loading.set(false);
                                        filter.set(String::new());
                                    },
                                    span { class: "ws-repo-name", "All repositories" }
                                    span { class: "ws-repo-owner", "every repo in this view" }
                                }
                            }
                        } else {
                            rsx! {}
                        }}
                        for (folder, r) in repo_refs.iter().filter(|(_, r)| {
                            q.is_empty() || r.full_name.to_lowercase().contains(&q)
                        }) {
                            {
                                let val = Workspace::repo(folder.clone(), r.full_name.clone()).encode();
                                let on = selected == val;
                                let cls = if on { "ws-opt ws-repo selected" } else { "ws-opt ws-repo" };
                                let (owner, name) = repo_short(&r.full_name);
                                rsx! {
                                    button {
                                        class: "{cls}",
                                        r#type: "button",
                                        key: "{val}",
                                        onclick: {
                                            let val = val.clone();
                                            move |_| {
                                                open.set(false);
                                                query.set(String::new());
                                                scoped.set(None);
                                                vc_loading.set(true);
                                                filter.set(val.clone());
                                            }
                                        },
                                        span { class: "ws-repo-name", "{name}" }
                                        {if !owner.is_empty() {
                                            rsx! { span { class: "ws-repo-owner", "{owner}" } }
                                        } else {
                                            rsx! {}
                                        }}
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                rsx! {}
            }}
        }
    }
}

#[component]
fn VersionControlPanel(repo_refs: Vec<(String, RepoSummary)>) -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let job = use_context::<OverviewJob>();
    let current = ctx.current.read().clone();
    let filter = (job.vc_filter)();
    let filtered = !filter.is_empty();
    let scoped = current
        .as_ref()
        .is_some_and(|w| job_scope_matches(&(job.scope)(), w));
    let raw = if filtered {
        job.vc_scoped.read().clone()
    } else {
        job.heartbeat.read().clone()
    };
    let belongs = if filtered {
        match (&raw, Workspace::decode(&filter)) {
            (Some(Ok(r)), Some(w)) => report_is_for(&w, &r.name),
            (Some(Err(_)), Some(_)) => true,
            _ => false,
        }
    } else {
        scoped
            && match &raw {
                Some(Ok(r)) => current.as_ref().is_some_and(|w| report_is_for(w, &r.name)),
                Some(Err(_)) => true,
                None => false,
            }
    };
    let loading = if filtered {
        (job.vc_loading)() || !belongs
    } else {
        (job.loading)() || !scoped
    };
    let done = if filtered {
        (job.vc_done)()
    } else {
        (job.done)()
    };
    let total = if filtered {
        (job.vc_total)()
    } else {
        (job.total)()
    };
    let report = if belongs { raw } else { None };
    let rows = vc_update_rows(&report);
    let count_label = if total > 0 {
        format!("{done}/{total}")
    } else {
        String::new()
    };

    rsx! {
        section { class: "panel",
            div { class: "vc-head",
                div { class: "vc-title",
                    h3 { "Version Control" }
                    {if loading {
                        rsx! {
                            span { class: "vc-spin", aria_label: "Checking crates.io" }
                            {if !count_label.is_empty() {
                                rsx! { span { class: "muted vc-count", "{count_label}" } }
                            } else {
                                rsx! {}
                            }}
                        }
                    } else {
                        rsx! {}
                    }}
                }
                {if repo_refs.len() > 1 {
                    rsx! { RepoFilterMenu { repo_refs: repo_refs.clone() } }
                } else {
                    rsx! {}
                }}
            }
            {match &report {
                Some(Err(e)) => rsx! { p { class: "err", "Couldn't check versions — {e}" } },
                _ if !rows.is_empty() => rsx! {
                    table { class: "vc-table",
                        tr {
                            th { "priority" }
                            th { "crate" }
                            th { "pinned" }
                            th { "latest" }
                            th { "updated" }
                        }
                        for (pri, e) in rows.iter() {
                            {
                                let cls = pri.class();
                                let hint = pri.hint();
                                let label = pri.label();
                                let latest = e.latest.clone().unwrap_or_default();
                                let updated = e
                                    .latest_updated
                                    .filter(|s| *s > 0)
                                    .map(format_updated_at)
                                    .unwrap_or_default();
                                rsx! {
                                    tr {
                                        td {
                                            span { class: "{cls}", title: "{hint}", "{label}" }
                                        }
                                        td { "{e.name}" }
                                        td { class: "muted", "{e.current}" }
                                        td { "{latest}" }
                                        td { class: "muted vc-updated", "{updated}" }
                                    }
                                }
                            }
                        }
                    }
                },
                _ if loading => rsx! {
                    p { class: "muted", "Checking crates.io for newer releases…" }
                },
                _ => rsx! {
                    p { class: "muted", "Every dependency is on its latest release." }
                },
            }}
        }
    }
}

#[component]
fn OverviewStats(
    ov: WorkspaceOverview,
    heartbeat: Option<Result<HeartbeatReport, String>>,
    health: Option<HealthView>,
) -> Element {
    let scan = use_context::<ScanJob>();
    let ov_job = use_context::<OverviewJob>();
    let hb_loading = (ov_job.loading)();
    let outdated = match &heartbeat {
        Some(Ok(r)) => Some(r.entries.iter().filter(|e| e.update_available).count()),
        Some(Err(_)) => None,
        None => None,
    };
    let mut flagged: Vec<HeartbeatEntry> = match &heartbeat {
        Some(Ok(r)) => r
            .entries
            .iter()
            .filter(|e| e.update_available || !e.advisories.is_empty())
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    flagged.sort_by_key(|e| (e.advisories.is_empty(), !e.update_available));
    flagged.truncate(8);

    let rustsec_n = (scan.advisories)().unwrap_or(ov.rustsec_loaded);
    let rustsec = if rustsec_n > 0 {
        format!("{rustsec_n} advisories loaded")
    } else if (scan.advisories)().is_none() {
        "loading…".to_string()
    } else {
        "couldn't load — scans won't flag CVEs".to_string()
    };
    let identity = match &health {
        Some(h) if h.mid_active => "mID signed in".to_string(),
        Some(_) => "local mode (no mID)".to_string(),
        None => "checking…".to_string(),
    };
    let archive = if ov.registry_total > 0 {
        format!(
            "{} of {} crates.io deps sealed ({} gaps)",
            ov.archived, ov.registry_total, ov.gaps
        )
    } else {
        "no crates.io dependencies to archive".to_string()
    };
    let vault = format!(
        "{} of {} unique deps in the vault · {} in production",
        ov.acquired, ov.unique_deps, ov.in_production
    );
    let outdated_cls = match outdated {
        Some(n) if n > 0 => "stat-value warn",
        Some(_) => "stat-value ok",
        None => "stat-value",
    };
    let outdated_text = match outdated {
        Some(n) => n.to_string(),
        None if matches!(&heartbeat, Some(Err(_))) => "?".to_string(),
        None => "…".to_string(),
    };
    let outdated_sub = match &heartbeat {
        None => "checking crates.io…".to_string(),
        Some(Err(e)) => format!("couldn't check — {e}"),
        Some(Ok(_)) if hb_loading => "newer releases found so far".to_string(),
        Some(Ok(_)) => "newer releases on crates.io".to_string(),
    };
    let adv_cls = if ov.advisory_hits > 0 {
        "stat-value warn"
    } else {
        "stat-value ok"
    };

    rsx! {
        {if ov.lockfiles == 0 {
            rsx! {
                p { class: "muted",
                    "No Cargo.lock in this workspace, so there is no pinned dependency tree. "
                    "Deputy still archives the GitHub source (and any crates.io crates named in "
                    "Cargo.toml) so the repo is not lost if GitHub or crates.io goes away. "
                    "Refresh on Infrastructure will retry the pull."
                }
            }
        } else {
            rsx! {}
        }}
        div { class: "stat-grid",
            div { class: "stat-card",
                span { class: "stat-value", "{ov.unique_deps}" }
                span { class: "stat-label", "dependencies" }
                span { class: "muted", "unique crates across {ov.lockfiles} lockfile(s)" }
            }
            div { class: "stat-card",
                span { class: "{outdated_cls}", "{outdated_text}" }
                span { class: "stat-label", "outdated" }
                span { class: "muted", "{outdated_sub}" }
            }
            div { class: "stat-card",
                span { class: "{adv_cls}", "{ov.advisory_hits}" }
                span { class: "stat-label", "with advisories" }
                span { class: "muted", "RUSTSEC hits on pinned versions" }
            }
            div { class: "stat-card",
                span { class: "stat-value", "{ov.repos}" }
                span { class: "stat-label", "repositories" }
                span { class: "muted", "{ov.acquired} acquired into the vault" }
            }
        }
        div { class: "tool-list",
            div { class: "tool-row",
                strong { "Vault" }
                span { class: "muted", "{vault}" }
            }
            div { class: "tool-row",
                strong { "Offline archive" }
                span { class: "muted", "{archive}" }
            }
            div { class: "tool-row",
                strong { "RUSTSEC" }
                span { class: "muted", "{rustsec}" }
            }
            div { class: "tool-row",
                strong { "Identity" }
                span { class: "muted", "{identity}" }
            }
        }
        {if flagged.is_empty() {
            rsx! {}
        } else {
            rsx! {
                h3 { "Needs attention" }
                table {
                    tr { th { "crate" } th { "pinned" } th { "latest" } th { "status" } }
                    for e in flagged.iter() {
                        HeartbeatRow { e: e.clone() }
                    }
                }
            }
        }}
    }
}

// ── GitHub tab: connect, select repos, name a folder, download + analyze ──────

/// Folder chooser for local ingestion. Desktop opens a **native folder picker**; web falls back to
/// a text field (a browser can't hand back a path the server can resolve).
#[cfg(not(target_arch = "wasm32"))]
fn folder_picker(local_path: Signal<String>) -> Element {
    rsx! {
        button {
            class: "gh",
            onclick: move |_| {
                let mut local_path = local_path;
                // Native picker runs async so it doesn't block the UI event loop.
                spawn(async move {
                    if let Some(handle) = rfd::AsyncFileDialog::new().pick_folder().await {
                        local_path.set(handle.path().display().to_string());
                    }
                });
            },
            "Choose folder…"
        }
        span { class: "muted local-chosen",
            {if local_path().trim().is_empty() {
                "no folder chosen".to_string()
            } else {
                local_path()
            }}
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn folder_picker(mut local_path: Signal<String>) -> Element {
    rsx! {
        input {
            class: "acct-label local-path",
            value: "{local_path}",
            oninput: move |e| local_path.set(e.value()),
            placeholder: "local folder path (e.g. /Users/you/code)",
        }
    }
}

#[component]
fn GitHubTab() -> Element {
    let mut token = use_signal(String::new);
    let mut owner = use_signal(String::new);
    let local_path = use_signal(String::new);
    let mut local_folder = use_signal(String::new);
    let mut hide_forks = use_signal(|| true);
    let mut connections = use_signal(Vec::<String>::new);
    let mut repos = use_signal(|| None::<Result<Vec<Repo>, String>>);
    let mut connecting = use_signal(|| false);
    let mut connect_err = use_signal(|| None::<String>);
    let mut oauth_hint = use_signal(|| None::<String>);
    let mut oauth_code = use_signal(|| None::<String>);
    let mut selected = use_signal(HashSet::<String>::new);
    let mut folder = use_signal(String::new);
    // The download job is owned by Dashboard so it keeps running across tab switches.
    let job = use_context::<DownloadJob>();
    let downloading = job.active;
    let progress = job.progress;
    let result = job.result;
    let mut request = job.request;

    // Restore the connected accounts + their repos from the server (set earlier this session).
    use_effect(move || {
        spawn(async move {
            if let Ok(labels) = get_json::<Vec<String>>("/github/connections").await {
                let has = !labels.is_empty();
                connections.set(labels);
                if has {
                    if let Ok(list) = get_json::<Vec<Repo>>("/github/repos").await {
                        repos.set(Some(Ok(list)));
                    }
                }
            }
        });
    });

    let snapshot = repos.read().clone();
    let fork_count = match &snapshot {
        Some(Ok(list)) => list.iter().filter(|r| r.fork).count(),
        _ => 0,
    };
    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "GitHub" } }

            // Connected accounts — OAuth (or PAT) tokens stay encrypted in the vault.
            div { class: "gh-accounts",
                {if connections.read().is_empty() {
                    rsx! { span { class: "muted", "No accounts connected yet." } }
                } else {
                    rsx! {
                        for acct in connections.read().iter() {
                            span { class: "acct-chip",
                                "{acct}"
                                button {
                                    class: "acct-x",
                                    title: "disconnect",
                                    aria_label: "disconnect",
                                    onclick: {
                                        let acct = acct.clone();
                                        move |_| {
                                            let body = serde_json::json!({ "label": acct.clone() });
                                            spawn(async move {
                                                let _ = post_json::<serde_json::Value>("/github/disconnect", &body).await;
                                                let labels = get_json::<Vec<String>>("/github/connections").await.unwrap_or_default();
                                                let empty = labels.is_empty();
                                                connections.set(labels);
                                                let list = if empty { Ok(vec![]) } else { get_json::<Vec<Repo>>("/github/repos").await };
                                                repos.set(Some(list));
                                                selected.write().clear();
                                            });
                                        }
                                    },
                                    "{rusty_symbols::status::CROSS}"
                                }
                            }
                        }
                    }
                }}
            }
            div { class: "gh-connect",
                input {
                    class: "acct-label",
                    value: "{owner}",
                    oninput: move |e| owner.set(e.value()),
                    placeholder: "org / user to list (e.g. Remade-With-Rust)",
                }
                button {
                    class: "gh",
                    disabled: connecting(),
                    onclick: move |_| {
                        let body = serde_json::json!({ "owner": owner() });
                        connecting.set(true);
                        connect_err.set(None);
                        oauth_hint.set(None);
                        oauth_code.set(None);
                        spawn(async move {
                            match post_json::<serde_json::Value>("/github/oauth/start", &body).await {
                                Ok(start) => {
                                    if let Some(msg) = start.get("message").and_then(|m| m.as_str()) {
                                        oauth_hint.set(Some(msg.to_owned()));
                                    }
                                    if let Some(code) = start.get("user_code").and_then(|c| c.as_str()) {
                                        oauth_code.set(Some(code.to_owned()));
                                    }
                                    if let Some(uri) = start.get("verification_uri").and_then(|u| u.as_str()) {
                                        open_url(uri);
                                    }
                                    let method = start.get("method").and_then(|m| m.as_str()).unwrap_or("");
                                    if method == "connected" {
                                        owner.set(String::new());
                                        if let Ok(labels) = get_json::<Vec<String>>("/github/connections").await {
                                            connections.set(labels);
                                        }
                                        repos.set(Some(get_json::<Vec<Repo>>("/github/repos").await));
                                    } else {
                                        let interval_ms = start
                                            .get("interval")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(5)
                                            .saturating_mul(1000)
                                            .clamp(2000, 15_000) as u32;
                                        let mut done = false;
                                        for _ in 0..180 {
                                            sleep_ms(interval_ms).await;
                                            match post_json::<serde_json::Value>("/github/oauth/poll", &serde_json::json!({})).await {
                                                Ok(p) => match p.get("status").and_then(|s| s.as_str()) {
                                                    Some("connected") => {
                                                        owner.set(String::new());
                                                        oauth_hint.set(None);
                                                        oauth_code.set(None);
                                                        if let Ok(labels) = get_json::<Vec<String>>("/github/connections").await {
                                                            connections.set(labels);
                                                        }
                                                        repos.set(Some(get_json::<Vec<Repo>>("/github/repos").await));
                                                        done = true;
                                                        break;
                                                    }
                                                    Some("pending") => {}
                                                    Some("denied") => {
                                                        connect_err.set(Some("GitHub approval was denied.".to_owned()));
                                                        done = true;
                                                        break;
                                                    }
                                                    Some("expired") => {
                                                        connect_err.set(Some("GitHub approval timed out — try Connect again.".to_owned()));
                                                        done = true;
                                                        break;
                                                    }
                                                    Some("error") => {
                                                        let msg = p.get("message").and_then(|m| m.as_str()).unwrap_or("GitHub sign-in failed");
                                                        connect_err.set(Some(msg.to_owned()));
                                                        done = true;
                                                        break;
                                                    }
                                                    _ => {}
                                                },
                                                Err(e) => {
                                                    connect_err.set(Some(e));
                                                    done = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if !done {
                                            connect_err.set(Some("GitHub approval timed out — try Connect again.".to_owned()));
                                        }
                                    }
                                }
                                Err(e) => connect_err.set(Some(e)),
                            }
                            connecting.set(false);
                        });
                    },
                    {if connecting() { "Waiting for GitHub…" } else { "Connect with GitHub" }}
                }
            }
            {match oauth_hint() {
                Some(h) => rsx! {
                    p { class: "muted gh-hint",
                        "{h}"
                        {match oauth_code() {
                            Some(code) => rsx! { span { class: "oauth-code", " Code: {code}" } },
                            None => rsx! {},
                        }}
                    }
                },
                None => rsx! {},
            }}
            {match connect_err() {
                Some(e) => rsx! { p { class: "err", "Couldn't connect — {e}" } },
                None => rsx! {},
            }}
            p { class: "muted gh-hint",
                "Opens GitHub in your browser so you can approve access. Tokens are saved "
                "encrypted in your vault and restored on next launch."
            }
            details { class: "pat-fallback",
                summary { "Use a personal access token instead" }
                div { class: "gh-connect",
                    input {
                        r#type: "password",
                        value: "{token}",
                        oninput: move |e| token.set(e.value()),
                        placeholder: "fine-grained GitHub PAT",
                    }
                    button {
                        class: "ghost",
                        disabled: connecting() || token().trim().is_empty(),
                        onclick: move |_| {
                            let body = serde_json::json!({ "token": token(), "label": "", "owner": owner() });
                            connecting.set(true);
                            connect_err.set(None);
                            spawn(async move {
                                match post_json::<serde_json::Value>("/github/connect", &body).await {
                                    Ok(_) => {
                                        token.set(String::new());
                                        owner.set(String::new());
                                        if let Ok(labels) = get_json::<Vec<String>>("/github/connections").await {
                                            connections.set(labels);
                                        }
                                        repos.set(Some(get_json::<Vec<Repo>>("/github/repos").await));
                                    }
                                    Err(e) => connect_err.set(Some(e)),
                                }
                                connecting.set(false);
                            });
                        },
                        {if connecting() { "Connecting…" } else { "Add token" }}
                    }
                }
            }

            // Local folder — pull dependency source straight from on-disk projects, no GitHub.
            div { class: "panel-head local-head", h2 { "Local folder" } }
            p { class: "muted gh-hint",
                "Point at a folder on this machine. Every Cargo.lock under it is read and all of "
                "its dependency source is pulled into the vault — no GitHub or PAT needed. "
                "Pull as a group to keep them together, or as repositories to add each lockfile "
                "as its own workspace."
            }
            div { class: "gh-connect",
                {folder_picker(local_path)}
                input {
                    class: "acct-label",
                    value: "{local_folder}",
                    oninput: move |e| local_folder.set(e.value()),
                    placeholder: "group name (e.g. Local Projects)",
                }
                button {
                    class: "primary",
                    disabled: downloading()
                        || local_path().trim().is_empty()
                        || local_folder().trim().is_empty(),
                    onclick: move |_| {
                        let body = serde_json::json!({
                            "folder": local_folder().trim(),
                            "path": local_path().trim(),
                            "split": false,
                        });
                        request.set(Some(DownloadReq {
                            url: "/local/download",
                            body,
                            stay: false,
                        }));
                    },
                    {if downloading() { "Pulling…" } else { "Pull as group" }}
                }
                button {
                    class: "ghost",
                    disabled: downloading() || local_path().trim().is_empty(),
                    onclick: move |_| {
                        let body = serde_json::json!({
                            "folder": "",
                            "path": local_path().trim(),
                            "split": true,
                        });
                        request.set(Some(DownloadReq {
                            url: "/local/download",
                            body,
                            stay: false,
                        }));
                    },
                    {if downloading() { "Pulling…" } else { "Pull as repositories" }}
                }
            }

            {match snapshot {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    div { class: "repolist-head",
                        p { class: "muted", "{list.len()} repositories — select which to add." }
                        div { class: "repolist-tools",
                            button {
                                class: "ghost",
                                onclick: {
                                    let names: Vec<String> = list
                                        .iter()
                                        .filter(|r| !hide_forks() || !r.fork)
                                        .map(|r| r.full_name.clone())
                                        .collect();
                                    move |_| {
                                        selected.with_mut(|s| {
                                            let all_in = names.iter().all(|n| s.contains(n));
                                            if all_in {
                                                for n in &names {
                                                    s.remove(n);
                                                }
                                            } else {
                                                for n in &names {
                                                    s.insert(n.clone());
                                                }
                                            }
                                        });
                                    }
                                },
                                "Select visible"
                            }
                            {if fork_count > 0 {
                                rsx! {
                                    label { class: "fork-toggle",
                                        input {
                                            r#type: "checkbox",
                                            checked: hide_forks(),
                                            onclick: move |_| { let v = hide_forks(); hide_forks.set(!v); },
                                        }
                                        " hide {fork_count} forks"
                                    }
                                }
                            } else { rsx! {} }}
                        }
                    }
                    ul { class: "repolist",
                        for r in list.iter().filter(|r| !hide_forks() || !r.fork) {
                            li { class: "repo-row",
                                div { class: "repo-info",
                                    span { class: "repo-name", "{r.full_name}" }
                                    {if r.private { rsx! { span { class: "badge", "private" } } } else { rsx! {} }}
                                    {if r.fork { rsx! { span { class: "badge fork", "fork" } } } else { rsx! {} }}
                                    {if !r.connection.is_empty() { rsx! { span { class: "acct-tag", "{r.connection}" } } } else { rsx! {} }}
                                    {match &r.language {
                                        Some(lang) => rsx! { span { class: "lang-tag", "{lang}" } },
                                        None => rsx! {},
                                    }}
                                }
                                input {
                                    r#type: "checkbox",
                                    checked: selected.read().contains(&r.full_name),
                                    onclick: {
                                        let name = r.full_name.clone();
                                        move |_| {
                                            let name = name.clone();
                                            selected.with_mut(|s| {
                                                if !s.remove(&name) {
                                                    s.insert(name);
                                                }
                                            });
                                        }
                                    },
                                }
                            }
                        }
                    }
                    p { class: "muted gh-hint",
                        "Add as repository keeps each selected repo as its own workspace "
                        "(e.g. mata-master). Add as group keeps them together — pick Remade-With-Rust "
                        "to scan every repo in that org at once, or open one repo from the sidebar."
                    }
                    div { class: "folder-bar",
                        input {
                            value: "{folder}",
                            oninput: move |e| folder.set(e.value()),
                            placeholder: "group name (defaults to org, e.g. Remade-With-Rust)",
                        }
                        button {
                            class: "primary",
                            disabled: downloading() || selected.read().is_empty() || {
                                folder().trim().is_empty() && common_owner(&selected()).is_none()
                            },
                            onclick: move |_| {
                                let repos: Vec<String> = selected.read().iter().cloned().collect();
                                let name = {
                                    let typed = folder().trim().to_string();
                                    if !typed.is_empty() {
                                        typed
                                    } else {
                                        common_owner(&selected()).unwrap_or_default()
                                    }
                                };
                                let body = serde_json::json!({
                                    "folder": name,
                                    "repos": repos,
                                    "split": false,
                                });
                                request.set(Some(DownloadReq {
                                    url: "/github/download",
                                    body,
                                    stay: false,
                                }));
                            },
                            {if downloading() { "Downloading…" } else { "Add as group" }}
                        }
                        button {
                            class: "ghost",
                            disabled: downloading() || selected.read().is_empty(),
                            onclick: move |_| {
                                let body = serde_json::json!({
                                    "folder": "",
                                    "repos": selected.read().iter().cloned().collect::<Vec<_>>(),
                                    "split": true,
                                });
                                request.set(Some(DownloadReq {
                                    url: "/github/download",
                                    body,
                                    stay: false,
                                }));
                            },
                            {if downloading() { "Downloading…" } else { "Add as repository" }}
                        }
                    }
                    {if downloading() {
                        let prog = progress.read().clone();
                        rsx! {
                            div { class: "dl-progress",
                                {match prog {
                                    Some(p) if p.total > 0 => rsx! {
                                        div { class: "dl-track", div { class: "dl-fill", style: "width: {p.done * 100 / p.total}%" } }
                                        span { class: "muted dl-label", "acquiring {p.done} / {p.total} dependencies into the vault…" }
                                    },
                                    _ => rsx! {
                                        div { class: "dl-track", div { class: "dl-fill indeterminate" } }
                                        span { class: "muted dl-label", "fetching lockfiles…" }
                                    },
                                }}
                            }
                        }
                    } else { rsx! {} }}
                    {match &*result.read() {
                        Some(Ok(f)) => rsx! { DownloadResult { folder: f.clone() } },
                        Some(Err(e)) => rsx! { p { class: "err", "Download failed — {e}" } },
                        None => rsx! {},
                    }}
                },
                Some(Ok(_)) => rsx! {
                    p { class: "muted",
                        "No repositories listed. If this is an organization-scoped PAT, put the org "
                        "name (e.g. Remade-With-Rust) in the “org / user to list” field above — an "
                        "org token can't be enumerated through GitHub's /user/repos."
                    }
                },
                Some(Err(e)) => rsx! { p { class: "err", "Couldn't load repositories — {e}" } },
                None => rsx! {},
            }}
        }
    }
}

#[component]
fn DownloadResult(folder: FolderSummary) -> Element {
    let total_deps: usize = folder.repos.iter().map(|r| r.deps).sum();
    let total_acq: usize = folder.repos.iter().map(|r| r.acquired).sum();
    rsx! {
        section { class: "panel result",
            h3 { "✓ {folder.name} — {total_acq} of {total_deps} dependencies acquired into the vault" }
            table {
                tr { th { "repository" } th { class: "num", "deps" } th { class: "num", "acquired" } th { "status" } }
                for r in folder.repos.iter() {
                    tr {
                        td { "{r.full_name}" }
                        td { class: "num", "{r.deps}" }
                        td { class: "num", "{r.acquired}" }
                        td {
                            {match &r.error {
                                Some(e) => rsx! { span { class: "err", "{e}" } },
                                None if lockfile_present(r.lockfile_found, r.deps) => {
                                    rsx! { span { class: "ok", "✓ sealed" } }
                                }
                                None if r.source_archived => rsx! { span { class: "ok", "✓ source archived" } },
                                None => rsx! { span { class: "muted", "no Cargo.lock" } },
                            }}
                        }
                    }
                }
            }
        }
    }
}

// ── Infrastructure tab: the folders you've created ────────────────────────────

#[component]
fn InfrastructureTab() -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let mut job = use_context::<DownloadJob>();
    let folders = ctx.folders.read().clone();
    let current = ctx.current.read().clone();
    let mut confirming = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let downloading = (job.active)();
    let refresh_label = current.as_ref().map(Workspace::label).unwrap_or_default();
    let can_refresh = current.is_some() && !folders.is_empty() && !downloading;
    let refresh_hint = match current.as_ref() {
        Some(ws) if ws.is_all() => {
            "Refresh re-pulls Cargo.lock from GitHub for every repository in the vault and acquires any new crates.".to_string()
        }
        Some(_) => format!(
            "Refresh re-pulls Cargo.lock from GitHub for {refresh_label} and acquires any new crates."
        ),
        None => "Select a workspace to refresh its lockfiles.".to_string(),
    };

    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                div { class: "vc-title",
                    h2 { "Infrastructure" }
                    button {
                        class: "ghost",
                        disabled: !can_refresh,
                        onclick: move |_| {
                            let Some(ws) = ctx.current.read().clone() else {
                                return;
                            };
                            job.request.set(Some(DownloadReq {
                                url: "/folders/refresh",
                                body: ws.api_body(),
                                stay: true,
                            }));
                        },
                        {if downloading { "Refreshing…" } else { "Refresh" }}
                    }
                    {if downloading {
                        let p = job.progress.read().clone();
                        let count = match p {
                            Some(ref p) if p.total > 0 => format!("{}/{}", p.done, p.total),
                            _ => String::new(),
                        };
                        rsx! {
                            span { class: "vc-spin", aria_label: "Refreshing lockfiles" }
                            {if !count.is_empty() {
                                rsx! { span { class: "muted vc-count", "{count}" } }
                            } else {
                                rsx! {}
                            }}
                        }
                    } else {
                        rsx! {}
                    }}
                }
            }
            p { class: "muted scan-hint",
                "Groups and repositories you've added. Click a group or a repo to make it the "
                "active workspace — Scan, Analytics, New Versions, and Production then show only "
                "that workspace's requirements. "
                "{refresh_hint}"
            }
            {if folders.is_empty() {
                rsx! { p { class: "muted", "No workspaces yet — add a repository or group from the GitHub tab." } }
            } else {
                rsx! {
                    for f in folders.iter() {
                        {
                            let group_ws = Workspace::group(f.name.clone());
                            let group_on = current.as_ref() == Some(&group_ws);
                            let card_cls = if group_on { "folder-card selected" } else { "folder-card" };
                            rsx! {
                                div { class: "{card_cls}",
                                    div { class: "folder-head",
                                        button {
                                            class: "ws-pick-btn",
                                            onclick: {
                                                let ws = group_ws.clone();
                                                move |_| {
                                                    select_workspace(ctx, ws.clone());
                                                }
                                            },
                                            strong { "{f.name}" }
                                            span { class: "muted",
                                                {if is_solo_repo(f) { " · repo" } else { " · group" }}
                                            }
                                        }
                                        div { class: "folder-actions",
                                            span { class: "muted", "{f.repos.len()} repos" }
                                            button {
                                                class: "ghost danger",
                                                onclick: {
                                                    let name = f.name.clone();
                                                    move |_| confirming.set(Some(name.clone()))
                                                },
                                                "Remove"
                                            }
                                        }
                                    }
                                    ul { class: "repolist",
                                        for r in f.repos.iter() {
                                            {
                                                let row_ws = if is_solo_repo(f) {
                                                    Workspace::group(f.name.clone())
                                                } else {
                                                    Workspace::repo(f.name.clone(), r.full_name.clone())
                                                };
                                                let on = current.as_ref() == Some(&row_ws);
                                                let row_cls = if on { "repo-row selected" } else { "repo-row" };
                                                rsx! {
                                                    li { class: "{row_cls}",
                                                        button {
                                                            class: "ws-pick-btn",
                                                            onclick: {
                                                                let ws = row_ws.clone();
                                                                move |_| {
                                                                    select_workspace(ctx, ws.clone());
                                                                }
                                                            },
                                                            span { class: "repo-name", "{r.full_name}" }
                                                        }
                                                        span { class: "muted", "{repo_vault_line(r)}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }}
            {match &*job.result.read() {
                Some(Ok(f)) if !f.repos.is_empty() => rsx! { DownloadResult { folder: f.clone() } },
                Some(Ok(_)) => rsx! { p { class: "muted", "No repositories needed a lockfile refresh." } },
                Some(Err(e)) => rsx! { p { class: "err", "Refresh failed — {e}" } },
                None => rsx! {},
            }}
        }
        {match confirming() {
            Some(name) => {
                let confirm_name = name.clone();
                rsx! {
                    div { class: "modal-overlay",
                        div { class: "modal",
                            h3 { "Remove “{name}”?" }
                            p { class: "muted", "This deletes the workspace and its repositories from Deputy. This can't be undone." }
                            div { class: "modal-actions",
                                button {
                                    class: "ghost",
                                    disabled: busy(),
                                    onclick: move |_| confirming.set(None),
                                    "Cancel"
                                }
                                button {
                                    class: "danger",
                                    disabled: busy(),
                                    onclick: move |_| {
                                        let body = serde_json::json!({ "name": confirm_name.clone() });
                                        let folder_name = confirm_name.clone();
                                        let mut current = ctx.current;
                                        let mut rev = ctx.rev;
                                        busy.set(true);
                                        spawn(async move {
                                            let _ = post_json::<serde_json::Value>("/folders/delete", &body).await;
                                            busy.set(false);
                                            confirming.set(None);
                                            if current.read().as_ref().is_some_and(|w| w.folder == folder_name) {
                                                current.set(None);
                                            }
                                            rev.set(rev() + 1);
                                        });
                                    },
                                    {if busy() { "Removing…" } else { "Remove" }}
                                }
                            }
                        }
                    }
                }
            }
            None => rsx! {},
        }}
    }
}

// ── Scan Dependencies tab: scan the selected workspace ─────────────────────────

#[component]
fn ScanTab() -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let mut job = use_context::<ScanJob>();
    let current = ctx.current.read().clone();
    let ws_label = current.as_ref().map(Workspace::label).unwrap_or_default();
    let scanning = (job.active)();
    let rustsec_line = match (job.advisories)() {
        Some(n) if n > 0 => format!("RUSTSEC: {n} advisories loaded"),
        Some(_) => "RUSTSEC: couldn't load — scans won't flag CVEs".to_string(),
        None => "RUSTSEC: loading…".to_string(),
    };
    let last_scanned = match (&current, &*job.report.read()) {
        (Some(ws), Some(Ok(r))) if report_is_for(ws, &r.scan.name) => {
            format_scanned_at(r.scanned_at)
        }
        _ => String::new(),
    };

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Scan Dependencies" } }
            p { class: "muted", "{rustsec_line}" }
            {match current.as_ref() {
                None => rsx! {
                    p { class: "muted",
                        "Select a workspace in the sidebar — a single repository, a group like "
                        "an org, or click Deputy for everything in the vault — then scan its "
                        "requirements. Add one from the GitHub tab if the list is empty."
                    }
                },
                Some(ws) => {
                    let scan_body = ws.api_body();
                    rsx! {
                        p { class: "muted scan-hint",
                            {if ws.is_all() {
                                "Scans every workspace in the vault: lockfile verdicts, newer crates.io releases, and offline coverage.".to_string()
                            } else {
                                format!("Scans {ws_label}: lockfile verdicts, newer crates.io releases, and offline coverage.")
                            }}
                        }
                        div { class: "folder-actions scan-actions",
                            button {
                                class: "primary",
                                disabled: scanning,
                                onclick: move |_| job.request.set(Some(scan_body.clone())),
                                {if scanning { "Scanning…" } else { "Scan" }}
                            }
                        }
                        {if scanning {
                            rsx! { ScanProgressBar { progress: job.progress.read().clone() } }
                        } else {
                            rsx! {}
                        }}
                        {if !last_scanned.is_empty() {
                            rsx! {
                                p { class: "muted scan-when",
                                    {if scanning {
                                        format!("Refreshing · last scanned {last_scanned}")
                                    } else {
                                        format!("Last scanned {last_scanned}")
                                    }}
                                }
                            }
                        } else {
                            rsx! {}
                        }}
                    }
                },
            }}
        }
        {match (&current, &*job.report.read()) {
            (Some(ws), Some(Ok(report))) if report_is_for(ws, &report.scan.name) => rsx! {
                ScanReportPanel { report: report.scan.clone(), scanned_at: report.scanned_at }
                {if let Some(e) = &report.updates_error {
                    rsx! { section { class: "panel", p { class: "err", "Update check failed — {e}" } } }
                } else {
                    rsx! { NewVersionView { report: report.updates.clone() } }
                }}
                CoverageView { report: report.coverage.clone() }
            },
            (Some(ws), Some(Err(e))) if (job.req_key)() == ws.encode() => {
                rsx! { section { class: "panel", p { class: "err", "Scan failed — {e}" } } }
            },
            _ => rsx! {},
        }}
    }
}

#[component]
fn ScanProgressBar(progress: Option<ScanProgressView>) -> Element {
    let (pct, label, keyed) = match &progress {
        Some(p) if p.total > 0 => {
            let pct = p.done * 100 / p.total;
            (
                pct,
                format!("{} — {} / {}", p.label, p.done, p.total),
                format!("{pct}"),
            )
        }
        Some(p) if !p.label.is_empty() => (0, p.label.clone(), p.stage.clone()),
        _ => (0, "Scanning…".to_string(), "start".to_string()),
    };
    let fill_cls = if progress.as_ref().is_some_and(|p| p.total > 0) {
        "dl-fill"
    } else {
        "dl-fill indeterminate"
    };
    rsx! {
        div { class: "dl-progress",
            div { class: "dl-track",
                div {
                    class: "{fill_cls}",
                    key: "{keyed}",
                    style: "width: {pct}%",
                }
            }
            span { class: "muted dl-label", "{label}" }
        }
    }
}

#[component]
fn ScanReportPanel(report: FolderScanReport, scanned_at: u64) -> Element {
    let total_findings: usize = report.repos.iter().map(|r| r.findings.len()).sum();
    let total_deps: usize = report.repos.iter().map(|r| r.deps).sum();
    let when = format_scanned_at(scanned_at);
    rsx! {
        section { class: "panel result",
            h3 { "Scan — {report.name}" }
            p { class: "muted",
                "{report.repos.len()} repos · {total_deps} dependencies scanned · {total_findings} findings"
                {if !when.is_empty() {
                    rsx! { " · {when}" }
                } else {
                    rsx! {}
                }}
            }
            for r in report.repos.iter() {
                ScanRepoRow { r: r.clone() }
            }
        }
    }
}

#[component]
fn ScanRepoRow(r: RepoScanResult) -> Element {
    rsx! {
        div { class: "scan-repo",
            div { class: "scan-repo-head",
                strong { "{r.full_name}" }
                {
                    if let Some(e) = &r.error {
                        rsx! { span { class: "err", "{e}" } }
                    } else if !lockfile_present(r.lockfile_found, r.deps) {
                        rsx! { span { class: "muted", "no Cargo.lock" } }
                    } else if r.findings.is_empty() {
                        rsx! { span { class: "ok", "✓ {r.deps} clean" } }
                    } else {
                        rsx! { span { class: "warn", "{r.findings.len()} findings" } }
                    }
                }
            }
            {if r.findings.is_empty() {
                rsx! {}
            } else {
                rsx! {
                    ul { class: "findings",
                        for f in r.findings.iter() {
                            li {
                                span { class: "sev", "{f.severity}" }
                                strong { " {f.id}" }
                                " — {f.summary} ({f.dep})"
                            }
                        }
                    }
                }
            }}
        }
    }
}

#[component]
fn NewVersionView(report: NewVersionReport) -> Element {
    rsx! {
        section { class: "panel result",
            h3 { "New versions — {report.name}" }
            {if report.entries.is_empty() {
                rsx! { p { class: "muted", "Every dependency is on its latest release." } }
            } else {
                rsx! {
                    p { class: "muted summary",
                        "{report.entries.len()} dependencies have newer releases — both versions are now staged for review."
                    }
                    table {
                        tr { th { "dependency" } th { "current" } th { "new (pending New Versions)" } }
                        for e in report.entries.iter() {
                            tr {
                                td { "{e.name}" }
                                td {
                                    span { class: "muted", "{e.production} " }
                                    {if e.in_production {
                                        rsx! { span { class: "rb build", "in production" } }
                                    } else {
                                        rsx! { span { class: "badge", "staging" } }
                                    }}
                                }
                                td {
                                    span { "{e.staged} " }
                                    {if e.staged_ok {
                                        rsx! { span { class: "ok", "✓ staged" } }
                                    } else {
                                        rsx! { span { class: "err", "stage failed" } }
                                    }}
                                }
                            }
                        }
                    }
                }
            }}
        }
    }
}

#[component]
fn CoverageView(report: CoverageReport) -> Element {
    let complete = report.gaps.is_empty();
    rsx! {
        section { class: "panel result",
            h3 { "Offline coverage — {report.name}" }
            p { class: "muted summary",
                "{report.archived} of {report.registry_total} crates.io dependencies are sealed in your vault"
                {if report.gaps.is_empty() { rsx! { "." } } else { rsx! { " · {report.gaps.len()} gaps." } }}
            }
            {if complete {
                rsx! {
                    p { class: "ok",
                        "✓ Every archivable dependency is held offline. If crates.io disappears, you can still build."
                    }
                }
            } else {
                rsx! {
                    p { class: "muted",
                        "These aren't in your offline archive. “not acquired” = re-download it; "
                        "“git dependency” / “other registry” = Deputy can't content-verify it, so it's "
                        "vendored from its own source, not crates.io."
                    }
                    table {
                        tr { th { "dependency" } th { "version" } th { "gap" } }
                        for g in report.gaps.iter() {
                            tr {
                                td { "{g.name}" }
                                td { class: "muted", "{g.version}" }
                                td {
                                    {if g.reason == "not acquired" {
                                        rsx! { span { class: "rb unsafe", "{g.reason}" } }
                                    } else {
                                        rsx! { span { class: "rb build", "{g.reason}" } }
                                    }}
                                }
                            }
                        }
                    }
                }
            }}
        }
    }
}

// ── Dep Analytics tab: language mix across crate sources (visualization only) ─────────────────

fn pct(part: usize, total: usize) -> usize {
    match (part * 100).checked_div(total) {
        Some(p) if part > 0 => p.max(1),
        _ => 0,
    }
}

#[component]
fn AnalyticsTab() -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let job = use_context::<AnalyticsJob>();
    let mut lang_filter = use_signal(String::new);

    let current = ctx.current.read().clone();
    let ws_label = current.as_ref().map(Workspace::label).unwrap_or_default();
    let scoped = current
        .as_ref()
        .is_some_and(|w| job_scope_matches(&(job.scope)(), w));
    let loading = (job.loading)() || (current.is_some() && !scoped);
    let done = (job.done)();
    let total = (job.total)();
    let count_label = if total > 0 && scoped {
        format!("{done}/{total}")
    } else {
        String::new()
    };
    let view = match (scoped, current.as_ref(), &*job.result.read()) {
        (true, Some(ws), Some(Ok(a))) if report_is_for(ws, &a.name) => Some(Ok(a.clone())),
        (true, _, Some(Err(e))) => Some(Err(e.clone())),
        _ => None,
    };

    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                div { class: "vc-title",
                    h2 { "Dep Analytics" }
                    {if loading {
                        rsx! {
                            span { class: "vc-spin", aria_label: "Inspecting crates" }
                            {if !count_label.is_empty() {
                                rsx! { span { class: "muted vc-count", "{count_label}" } }
                            } else {
                                rsx! {}
                            }}
                        }
                    } else {
                        rsx! {}
                    }}
                }
            }
            {match current.as_ref() {
                None => rsx! {
                    p { class: "muted",
                        "Select a workspace in the sidebar to visualize languages used across "
                        "its dependencies, or click Deputy for a vault-wide view."
                    }
                },
                Some(_) => rsx! {
                    p { class: "muted scan-hint",
                        {if current.as_ref().is_some_and(Workspace::is_all) {
                            "Language mix across crates in every workspace.".to_string()
                        } else {
                            format!("Language mix across crates in {ws_label}.")
                        }}
                    }
                    div { class: "analytics-controls",
                        {match &view {
                            Some(Ok(a)) => rsx! {
                                label { "Language" }
                                select {
                                    onchange: move |e| lang_filter.set(e.value()),
                                    option { value: "", "All languages" }
                                    for ls in a.by_language.iter() {
                                        option { value: "{ls.language}", "{ls.language}" }
                                    }
                                }
                            },
                            _ => rsx! {},
                        }}
                    }
                },
            }}

            {if loading && view.as_ref().and_then(|r| r.as_ref().ok()).is_none() {
                rsx! {
                    p { class: "muted",
                        "Reading crate sources for language mix. Bars appear as each crate is inspected."
                    }
                }
            } else {
                match &view {
                    None if current.is_none() => rsx! {},
                    None => rsx! {},
                    Some(Ok(a)) => rsx! { AnalyticsView {
                        a: a.clone(),
                        lang: lang_filter(),
                    } },
                    Some(Err(e)) => rsx! { p { class: "err", "Analytics failed — {e}" } },
                }
            }}
        }
    }
}

#[component]
fn AnalyticsView(a: DepAnalytics, lang: String) -> Element {
    let total_lines: usize = a.by_language.iter().map(|l| l.lines).sum();
    let deps: Vec<DepLang> = a
        .deps
        .iter()
        .filter(|d| lang.is_empty() || d.languages.iter().any(|l| l == &lang))
        .cloned()
        .collect();
    rsx! {
        p { class: "muted summary",
            "{a.analyzed} of {a.total_deps} crates inspected · {a.by_language.len()} languages"
        }
        div { class: "lang-bars",
            for ls in a.by_language.iter() {
                div { class: "lang-bar",
                    div { class: "lang-bar-label",
                        span { class: "lang-name", "{ls.language}" }
                        span { class: "muted", "{ls.lines} lines · {ls.crates} crates" }
                    }
                    div { class: "bar-track",
                        div { class: "bar-fill", style: "width: {pct(ls.lines, total_lines)}%" }
                    }
                }
            }
        }
        h3 { "Dependencies ({deps.len()})" }
        table {
            tr { th { "crate" } th { "languages" } th { class: "num", "lines" } }
            for d in deps.iter() {
                LangDepRow { d: d.clone() }
            }
        }
    }
}

#[component]
fn LangDepRow(d: DepLang) -> Element {
    let langs = if d.languages.is_empty() {
        "—".to_string()
    } else {
        d.languages.join(", ")
    };
    rsx! {
        tr {
            td { "{d.name} {d.version}" }
            td { class: "muted", "{langs}" }
            td { class: "num", "{d.lines}" }
        }
    }
}

fn update_key(e: &HeartbeatEntry) -> Option<String> {
    e.latest.as_ref().map(|l| format!("{}@{}", e.name, l))
}

// ── New Versions tab: check updates to migrate those releases into production ─────────────────

#[component]
fn HeartbeatTab() -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let job = use_context::<OverviewJob>();
    let mut selected = use_signal(HashSet::<String>::new);
    let mut pushing = use_signal(|| false);
    let mut sending = use_signal(|| false);
    let mut push_msg = use_signal(|| None::<String>);
    let mut prod = use_context::<ProductionJob>();
    let current = ctx.current.read().clone();
    let ws_label = current.as_ref().map(Workspace::label).unwrap_or_default();
    let scoped = current
        .as_ref()
        .is_some_and(|w| job_scope_matches(&(job.scope)(), w));
    let loading = (job.loading)() || (current.is_some() && !scoped);
    let report = if scoped {
        match &*job.heartbeat.read() {
            Some(Ok(r)) if current.as_ref().is_some_and(|w| report_is_for(w, &r.name)) => {
                Some(Ok(r.clone()))
            }
            Some(Err(e)) => Some(Err(e.clone())),
            _ => None,
        }
    } else {
        None
    };
    let updates: Vec<HeartbeatEntry> = match &report {
        Some(Ok(r)) => r
            .entries
            .iter()
            .filter(|e| e.update_available)
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    let all_keys: Vec<String> = updates.iter().filter_map(update_key).collect();
    let all_checked = !all_keys.is_empty() && all_keys.iter().all(|k| selected.read().contains(k));
    let busy = pushing() || sending();
    let can_redeploy = !selected.read().is_empty() && !busy;
    let can_send_plans = current.is_some() && !busy;
    let promote_base = current
        .as_ref()
        .map(Workspace::api_body)
        .unwrap_or_else(|| serde_json::json!({ "name": "" }));
    let pick = updates.clone();

    rsx! {
        section { class: "panel",
            div { class: "panel-head",
                div { class: "vc-title",
                    h2 { "New Versions" }
                    {if loading {
                        rsx! { span { class: "vc-spin", aria_label: "Checking crates.io" } }
                    } else {
                        rsx! {}
                    }}
                }
            }
            p { class: "muted scan-hint",
                {if current.as_ref().is_some_and(Workspace::is_all) {
                    "Newer crates.io releases across all workspaces. Check the versions to send to production. Send Plans writes each repo's own week-old updates into docs/plans/deputy-upgrades.md.".to_string()
                } else if current.is_some() {
                    format!("Newer crates.io releases for {ws_label}. Check the versions to send to production. Send Plans writes week-old updates into that repo's docs/plans/deputy-upgrades.md (creating the folder if needed).")
                } else {
                    "Select a workspace in the sidebar to see dependencies with newer releases.".to_string()
                }}
            }
            {if current.is_some() {
                rsx! {
                    div { class: "prod-push-bar",
                        h3 { "Redeploy to production" }
                        div { class: "prod-push-actions",
                            button {
                                class: "ghost",
                                disabled: all_keys.is_empty() || busy,
                                onclick: {
                                    let keys = all_keys.clone();
                                    move |_| {
                                        if all_checked {
                                            selected.write().clear();
                                        } else {
                                            selected.set(keys.iter().cloned().collect());
                                        }
                                    }
                                },
                                {if all_checked { "Uncheck all" } else { "Check all" }}
                            }
                            button {
                                class: "ghost",
                                disabled: !can_send_plans,
                                onclick: {
                                    let body = promote_base.clone();
                                    move |_| {
                                        sending.set(true);
                                        push_msg.set(None);
                                        let body = body.clone();
                                        spawn(async move {
                                            match post_json::<serde_json::Value>(
                                                "/folders/upgrade-plans",
                                                &body,
                                            )
                                            .await
                                            {
                                                Ok(v) => {
                                                    let written = v
                                                        .get("written")
                                                        .and_then(|x| x.as_array())
                                                        .map(|a| a.len())
                                                        .unwrap_or(0);
                                                    let updates: u64 = v
                                                        .get("written")
                                                        .and_then(|x| x.as_array())
                                                        .map(|a| {
                                                            a.iter()
                                                                .filter_map(|r| {
                                                                    r.get("updates").and_then(|u| u.as_u64())
                                                                })
                                                                .sum()
                                                        })
                                                        .unwrap_or(0);
                                                    let skipped = v
                                                        .get("skipped")
                                                        .and_then(|x| x.as_array())
                                                        .map(|a| a.len())
                                                        .unwrap_or(0);
                                                    let failed = v
                                                        .get("errors")
                                                        .and_then(|x| x.as_array())
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    let mut msg = format!(
                                                        "✓ wrote plans to {written} repos ({updates} aged updates)"
                                                    );
                                                    if skipped > 0 {
                                                        msg.push_str(&format!(
                                                            " · skipped {skipped} local"
                                                        ));
                                                    }
                                                    if !failed.is_empty() {
                                                        let first = failed[0]
                                                            .get("repo")
                                                            .and_then(|r| r.as_str())
                                                            .unwrap_or("repo");
                                                        let err = failed[0]
                                                            .get("error")
                                                            .and_then(|r| r.as_str())
                                                            .unwrap_or("error");
                                                        msg.push_str(&format!(
                                                            " · {} failed (e.g. {first}: {err})",
                                                            failed.len()
                                                        ));
                                                    }
                                                    if written == 0 && skipped > 0 && failed.is_empty()
                                                    {
                                                        msg = "no GitHub repos in this workspace — plans are only written to GitHub".to_owned();
                                                    }
                                                    push_msg.set(Some(msg));
                                                }
                                                Err(e) => {
                                                    push_msg.set(Some(format!("send plans failed — {e}")))
                                                }
                                            }
                                            sending.set(false);
                                        });
                                    }
                                },
                                {if sending() { "Sending plans…" } else { "Send Plans" }}
                            }
                            button {
                                class: "primary",
                                disabled: !can_redeploy,
                                onclick: move |_| {
                                    let only: Vec<serde_json::Value> = pick
                                        .iter()
                                        .filter(|e| {
                                            update_key(e)
                                                .is_some_and(|k| selected.read().contains(&k))
                                        })
                                        .filter_map(|e| {
                                            e.latest.as_ref().map(|v| {
                                                serde_json::json!({ "name": e.name, "version": v })
                                            })
                                        })
                                        .collect();
                                    if only.is_empty() {
                                        return;
                                    }
                                    let mut body = promote_base.clone();
                                    if let Some(obj) = body.as_object_mut() {
                                        obj.insert("only".to_owned(), serde_json::Value::Array(only));
                                    }
                                    pushing.set(true);
                                    push_msg.set(None);
                                    spawn(async move {
                                        match post_json::<serde_json::Value>("/folders/promote", &body)
                                            .await
                                        {
                                            Ok(v) => {
                                                let n = v
                                                    .get("promoted")
                                                    .and_then(|x| x.as_u64())
                                                    .unwrap_or(0);
                                                push_msg.set(Some(format!(
                                                    "✓ migrated {n} new versions to production"
                                                )));
                                                prod.gen.set((prod.gen)() + 1);
                                            }
                                            Err(e) => {
                                                push_msg.set(Some(format!("redeploy failed — {e}")))
                                            }
                                        }
                                        pushing.set(false);
                                    });
                                },
                                {if pushing() { "Redeploying…" } else { "Redeploy to Production" }}
                            }
                        }
                    }
                    {match push_msg() {
                        Some(m) => rsx! { p { class: "muted", "{m}" } },
                        None => rsx! {},
                    }}
                }
            } else {
                rsx! {}
            }}
            {match (current.is_none(), &report) {
                (true, _) => rsx! {},
                (_, Some(Err(e))) => rsx! { p { class: "err", "New versions check failed — {e}" } },
                (_, Some(Ok(r))) if r.entries.iter().any(|e| e.update_available) => rsx! {
                    HeartbeatView { report: r.clone(), selected }
                },
                (_, _) if loading => rsx! {
                    p { class: "muted", "Checking crates.io for the latest versions…" }
                },
                (_, Some(Ok(r))) if r.entries.is_empty() => rsx! {
                    p { class: "muted", "No dependencies in this workspace yet." }
                },
                _ => rsx! { p { class: "muted", "Every dependency is on its latest release." } },
            }}
        }
    }
}

#[component]
fn HeartbeatView(report: HeartbeatReport, selected: Signal<HashSet<String>>) -> Element {
    let mut entries: Vec<HeartbeatEntry> = report
        .entries
        .iter()
        .filter(|e| e.update_available)
        .cloned()
        .collect();
    let flagged = entries.iter().filter(|e| !e.advisories.is_empty()).count();
    entries.sort_by_key(|e| e.advisories.is_empty());
    let summary = if flagged > 0 {
        format!(
            "{} with newer releases · {flagged} of those also have advisories — check the ones to migrate to production.",
            entries.len()
        )
    } else {
        format!(
            "{} with newer releases — check the ones to migrate to production.",
            entries.len()
        )
    };
    rsx! {
        p { class: "muted summary", "{summary}" }
        table {
            tr { th { "" } th { "dependency" } th { "pinned" } th { "latest" } th { "status" } }
            for e in entries.iter() {
                UpdatePickRow { e: e.clone(), selected }
            }
        }
    }
}

#[component]
fn UpdatePickRow(e: HeartbeatEntry, selected: Signal<HashSet<String>>) -> Element {
    let mut selected = selected;
    let key = update_key(&e).unwrap_or_default();
    let checked = !key.is_empty() && selected.read().contains(&key);
    let advisories = e.advisories.join(", ");
    rsx! {
        tr {
            td {
                input {
                    r#type: "checkbox",
                    checked,
                    disabled: key.is_empty(),
                    onclick: {
                        let key = key.clone();
                        move |_| {
                            let key = key.clone();
                            selected.with_mut(|h| {
                                if !h.remove(&key) {
                                    h.insert(key);
                                }
                            });
                        }
                    },
                }
            }
            td { "{e.name}" }
            td { class: "muted", "{e.current}" }
            td {
                {match &e.latest {
                    Some(l) => rsx! { "{l}" },
                    None => rsx! { span { class: "muted", "?" } },
                }}
            }
            td {
                {if !e.advisories.is_empty() {
                    rsx! { span { class: "rb unsafe", "⚠ {advisories}" } }
                } else {
                    rsx! { span { class: "rb build", "↑ update available" } }
                }}
            }
        }
    }
}

#[component]
fn HeartbeatRow(e: HeartbeatEntry) -> Element {
    let advisories = e.advisories.join(", ");
    rsx! {
        tr {
            td { "{e.name}" }
            td { class: "muted", "{e.current}" }
            td {
                {match &e.latest {
                    Some(l) => rsx! { "{l}" },
                    None => rsx! { span { class: "muted", "?" } },
                }}
            }
            td {
                {if !e.advisories.is_empty() {
                    rsx! { span { class: "rb unsafe", "⚠ {advisories}" } }
                } else if e.update_available {
                    rsx! { span { class: "rb build", "↑ update available" } }
                } else {
                    rsx! { span { class: "ok", "✓ current" } }
                }}
            }
        }
    }
}

// ── Production Dependencies tab: the validated/promoted set ────────────────────────────────────

#[component]
fn ProductionTab() -> Element {
    let ctx = use_context::<WorkspaceCtx>();
    let mut job = use_context::<ProductionJob>();
    let mut promote_msg = use_signal(|| None::<String>);
    let mut promoting = use_signal(|| false);
    let current = ctx.current.read().clone();
    let ws_label = current.as_ref().map(Workspace::label).unwrap_or_default();
    let scoped = current
        .as_ref()
        .is_some_and(|w| job_scope_matches(&(job.scope)(), w));
    let loading = (job.loading)() || (current.is_some() && !scoped);
    let result = if scoped {
        job.result.read().clone()
    } else {
        None
    };

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Production Dependencies" } }
            p { class: "muted scan-hint",
                {if current.as_ref().is_some_and(Workspace::is_all) {
                    "Validated, content-addressed production deps across all workspaces. Scan first, then promote.".to_string()
                } else if current.is_some() {
                    format!("Validated, content-addressed production deps for {ws_label}. Scan first, then promote.")
                } else {
                    "Select a workspace in the sidebar to see its promoted production dependencies.".to_string()
                }}
            }
            {if let Some(ws) = current.clone() {
                rsx! {
                    div { class: "analytics-controls",
                        button {
                            class: "primary",
                            disabled: promoting(),
                            onclick: move |_| {
                                promoting.set(true);
                                promote_msg.set(None);
                                let body = ws.api_body();
                                spawn(async move {
                                    match post_json::<serde_json::Value>("/folders/promote", &body).await {
                                        Ok(v) => {
                                            let n = v.get("promoted").and_then(|x| x.as_u64()).unwrap_or(0);
                                            promote_msg.set(Some(format!("✓ promoted {n} validated dependencies")));
                                            job.gen.set((job.gen)() + 1);
                                        }
                                        Err(e) => promote_msg.set(Some(format!("promote failed — {e}"))),
                                    }
                                    promoting.set(false);
                                });
                            },
                            {if promoting() { "Promoting…" } else { "Promote clean deps" }}
                        }
                    }
                }
            } else {
                rsx! {}
            }}
            {match promote_msg() {
                Some(m) => rsx! { p { class: "muted", "{m}" } },
                None => rsx! {},
            }}
            {match (current.is_none(), loading, &result) {
                (true, _, _) => rsx! {},
                (_, _, Some(Err(e))) => rsx! { p { class: "err", "Couldn't load — {e}" } },
                (_, _, Some(Ok(list))) if !list.is_empty() => rsx! {
                    p { class: "muted summary", "{list.len()} validated dependency versions" }
                    table {
                        tr { th { "crate" } th { "version" } th { "content hash" } }
                        for d in list.iter() {
                            ProdRow { d: d.clone() }
                        }
                    }
                },
                (_, true, _) => rsx! {
                    div { class: "loading-block",
                        span { class: "spiral" }
                        p { class: "muted", "Loading production dependencies…" }
                    }
                },
                (_, _, Some(Ok(_))) => rsx! {
                    p { class: "muted", "No validated dependencies in this workspace yet — scan, then promote above." }
                },
                (_, _, None) => rsx! {
                    div { class: "loading-block",
                        span { class: "spiral" }
                        p { class: "muted", "Loading production dependencies…" }
                    }
                },
            }}
        }
    }
}

#[component]
fn ProdRow(d: ProdDep) -> Element {
    let short: String = d.hash.chars().take(16).collect();
    rsx! {
        tr {
            td { "{d.name}" }
            td { class: "muted", "{d.version}" }
            td { class: "muted hash", "{short}…" }
        }
    }
}

const DEPUTY_THEME: &str = "
:root {
  --rt-color-fg: #e2ebe2;
  --rt-color-bg: #151e18;
  --rt-color-muted: #8a9b8e;
  --rt-color-accent: #b8860b;
  --rt-color-accent-hover: #9a7209;
  --rt-color-on-accent: #151e18;
  --rt-color-success: #34d399;
  --rt-color-danger: #f87171;
  --rt-color-warn: #c49a2c;
  --rt-color-border: #2a382f;
  --rt-color-surface: #1c2620;
  --rt-color-hover: rgba(184, 134, 11, 0.18);
}
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
";

const CSS: &str = "
* { box-sizing: border-box; }
html { color-scheme: dark; }
html, body { height: 100%; margin: 0; }
body { font-family: -apple-system, system-ui, sans-serif; background: var(--rt-color-bg); color: var(--rt-color-fg); }
html, body, .content, .ws-menu {
  scrollbar-width: thin;
  scrollbar-color: #4a6350 transparent;
}
*::-webkit-scrollbar { width: 10px; height: 10px; }
*::-webkit-scrollbar-track { background: transparent; }
*::-webkit-scrollbar-thumb {
  background-color: #4a6350;
  border-radius: 999px;
  border: 2px solid transparent;
  background-clip: padding-box;
}
*::-webkit-scrollbar-thumb:hover { background-color: var(--rt-color-accent); }
*::-webkit-scrollbar-corner { background: transparent; }
.brand { font-size: 28px; font-weight: 700; color: var(--rt-color-accent); letter-spacing: -0.5px; }
.tag { color: var(--rt-color-muted); margin: 4px 0 16px; }
.muted { color: var(--rt-color-muted); } .ok { color: var(--rt-color-success); } .err { color: var(--rt-color-danger); }

/* Landing / login */
.landing { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 18px; padding: 24px; background: var(--rt-color-bg); }
.login-card { background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 14px; padding: 36px 40px; max-width: 420px; width: 100%; text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.35); }
.login-card .brand { font-size: 34px; }
.login-hint { margin: 18px 0; }
button.big { width: 100%; padding: 12px 16px; font-size: 15px; }
button.dev { background: transparent; border: 1px dashed var(--rt-color-border); color: var(--rt-color-muted); }
button.dev:hover { background: var(--rt-color-hover); color: var(--rt-color-fg); border-color: var(--rt-color-accent); }
.divider { display: flex; align-items: center; text-align: center; color: var(--rt-color-muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin: 14px 0; }
.divider::before, .divider::after { content: \"\"; flex: 1; border-bottom: 1px solid var(--rt-color-border); }
.divider span { padding: 0 10px; }

/* Shell: sidebar + content */
.shell { display: flex; min-height: 100vh; height: 100vh; overflow: hidden; background: var(--rt-color-bg); }
.sidebar { width: 248px; flex: none; background: var(--rt-color-bg); border-right: 1px solid var(--rt-color-border); padding: 20px 14px; display: flex; flex-direction: column; position: relative; z-index: 2; overflow: visible; }
.content { flex: 1; min-width: 0; background: var(--rt-color-bg); padding: 20px 16px 24px 20px; overflow: auto; scrollbar-gutter: stable; }
.ws-picker { margin: 0 0 16px; padding: 0 6px; position: relative; }
.ws-label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--rt-color-muted); margin-bottom: 6px; }
.ws-pick-btn { background: transparent; border: 0; color: inherit; padding: 0; text-align: left; display: flex; align-items: center; gap: 6px; font-weight: inherit; cursor: pointer; }
.ws-pick-btn:hover { background: transparent; color: var(--rt-color-accent); }
.folder-card.selected { border-color: var(--rt-color-accent); }
.repo-row.selected { background: var(--rt-color-hover); border-radius: 6px; }
.scan-actions { margin: 8px 0 0; }
.repolist-tools { display: flex; align-items: center; gap: 10px; }
.nav { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.nav-item { text-align: left; background: transparent; color: var(--rt-color-fg); border: 0; padding: 10px 12px; border-radius: 6px; font-size: 14px; }
.nav-item:hover { background: var(--rt-color-hover); }
.nav-item.active { background: var(--rt-color-hover); color: var(--rt-color-accent); }
.sb-footer { display: flex; flex-direction: column; gap: 8px; font-size: 13px; padding: 0 6px; }
.sb-busy { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--rt-color-accent); padding: 8px 6px; }
.sb-spinner { width: 12px; height: 12px; border: 2px solid var(--rt-color-border); border-top-color: var(--rt-color-accent); border-radius: 50%; animation: spin 0.8s linear infinite; flex: none; }
@keyframes spin { to { transform: rotate(360deg); } }
.spiral { width: 40px; height: 40px; border: 3px solid var(--rt-color-border); border-top-color: var(--rt-color-accent); border-radius: 50%; animation: spin 0.85s linear infinite; display: block; margin: 0 auto 14px; }
.loading-block { text-align: center; padding: 36px 20px 28px; }
.loading-block.compact { padding: 18px 12px 8px; }
.loading-block p { max-width: 520px; margin: 0 auto; }
.did { color: var(--rt-color-success); word-break: break-all; }
.ov-kicker { margin: 4px 0 0; text-transform: uppercase; letter-spacing: 0.6px; font-size: 11px; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 8px 0 18px; }
.stat-card { background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 10px; padding: 14px 16px; display: flex; flex-direction: column; gap: 4px; }
.stat-value { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
.stat-label { font-size: 13px; font-weight: 500; }
.tool-list { display: flex; flex-direction: column; gap: 8px; margin-bottom: 8px; }
.tool-row { display: flex; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--rt-color-border); }
.tool-row strong { min-width: 140px; }
.ov-actions { display: flex; flex-wrap: wrap; gap: 10px; }

button { background: var(--rt-color-accent); color: var(--rt-color-on-accent); border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; font-weight: 500; }
button:hover { background: var(--rt-color-accent-hover); }
button:disabled { opacity: 0.5; cursor: default; }
button.ghost { background: transparent; border: 1px solid var(--rt-color-border); color: var(--rt-color-fg); }
button.ghost:hover { background: var(--rt-color-hover); border-color: var(--rt-color-accent); color: var(--rt-color-accent); }
button.gh { background: var(--rt-color-accent); color: var(--rt-color-on-accent); }
button.gh:hover { background: var(--rt-color-accent-hover); }
button.sb-logo { background: transparent; border: 0; padding: 4px 6px; margin: 0 0 12px; text-align: left; width: 100%; color: var(--rt-color-accent); border-radius: 6px; }
button.sb-logo:hover { background: var(--rt-color-hover); color: var(--rt-color-accent); }
button.ws-trigger { width: 100%; display: flex; align-items: center; gap: 8px; text-align: left; background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); color: var(--rt-color-fg); border-radius: 8px; padding: 8px 10px; }
button.ws-trigger:hover { background: var(--rt-color-hover); border-color: var(--rt-color-accent); color: var(--rt-color-fg); }
.ws-trigger-text { display: flex; flex-direction: column; gap: 1px; min-width: 0; flex: 1; }
.ws-trigger-main { font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ws-trigger-sub { font-size: 11px; color: var(--rt-color-muted); font-weight: 400; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ws-caret { color: var(--rt-color-muted); font-size: 11px; flex: none; }
.ws-menu-backdrop { position: fixed; inset: 0; z-index: 30; background: transparent; }
.ws-menu { position: absolute; left: 6px; right: 6px; top: calc(100% + 4px); z-index: 31; background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 10px; padding: 6px; max-height: 380px; overflow-y: auto; box-shadow: 0 12px 32px rgba(0,0,0,0.45); }
.ws-filter { width: 100%; margin-bottom: 6px; font-size: 13px; }
button.ws-opt { width: 100%; display: flex; flex-direction: column; align-items: flex-start; gap: 1px; background: transparent; border: 0; color: var(--rt-color-fg); padding: 8px 10px; border-radius: 6px; text-align: left; font-weight: 500; }
button.ws-opt:hover { background: var(--rt-color-hover); color: var(--rt-color-fg); }
button.ws-opt.selected { background: var(--rt-color-hover); color: var(--rt-color-accent); }
button.ws-opt.ws-group { font-size: 11px; letter-spacing: 0.4px; color: var(--rt-color-muted); font-weight: 600; padding: 10px 10px 4px; }
button.ws-opt.ws-group:hover { color: var(--rt-color-accent); background: var(--rt-color-hover); }
button.ws-opt.ws-repo { padding-left: 14px; }
.ws-repo-name { font-size: 13px; }
.ws-repo-owner { font-size: 11px; color: var(--rt-color-muted); font-weight: 400; }
button.ws-opt.ws-add { color: var(--rt-color-accent); margin-top: 4px; border-top: 1px solid var(--rt-color-border); border-radius: 0 0 6px 6px; }
button.ws-opt.ws-add:hover { color: var(--rt-color-accent); }
input { padding: 8px; border-radius: 6px; border: 1px solid var(--rt-color-border); background: var(--rt-color-surface); color: var(--rt-color-fg); }
input[type=checkbox] { width: 18px; height: 18px; accent-color: var(--rt-color-accent); cursor: pointer; padding: 0; }

.panel { background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 10px; padding: 16px; margin: 0 0 16px; }
.panel:last-child { margin-bottom: 0; }
.panel h2, .panel h3 { margin-top: 0; }
.panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
.panel-head h2 { margin: 0; }
.vc-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.vc-head h3 { margin: 0; }
.vc-title { display: flex; align-items: center; gap: 10px; min-width: 0; }
.vc-title h2, .vc-title h3 { margin: 0; }
.vc-spin { width: 16px; height: 16px; border: 2px solid var(--rt-color-border); border-top-color: var(--rt-color-accent); border-radius: 50%; animation: spin 0.85s linear infinite; flex: none; }
.vc-count { font-size: 12px; }
.vc-head .ws-picker { margin: 0; padding: 0; min-width: 200px; flex: 0 1 260px; }
.vc-head .ws-menu { left: auto; right: 0; min-width: 240px; }
.vc-table { font-size: 14px; }
.vc-updated { white-space: nowrap; font-size: 12px; }
.vc-pri { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; padding: 2px 8px; border-radius: 999px; }
.vc-pri.high { background: rgba(248,113,113,0.16); color: #f87171; }
.vc-pri.medium { background: rgba(196,154,44,0.18); color: var(--rt-color-warn); }
.vc-pri.low { background: rgba(52,211,153,0.14); color: #34d399; }
.result h3 { color: var(--rt-color-success); }

.gh-connect { display: flex; gap: 10px; align-items: center; margin: 12px 0 8px; }
.gh-connect input { flex: 1; }
.gh-hint { font-size: 13px; }
.oauth-code { font-family: ui-monospace, SFMono-Regular, monospace; color: var(--rt-color-accent); letter-spacing: 0.06em; }
.pat-fallback { margin: 8px 0 0; }
.pat-fallback summary { cursor: pointer; color: var(--rt-color-muted); font-size: 13px; }
.pat-fallback .gh-connect { margin-top: 10px; }
.local-head { margin-top: 28px; border-top: 1px solid var(--rt-color-border); padding-top: 18px; }
.local-path { max-width: 380px; flex: 1; }
.local-chosen { align-self: center; word-break: break-all; }

.repolist { list-style: none; padding: 0; margin: 12px 0; }
.repo-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--rt-color-border); }
.repo-info { display: flex; align-items: center; gap: 8px; }
.repo-name { font-weight: 500; }
.lang-tag { font-size: 11px; color: var(--rt-color-muted); }
.badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: var(--rt-color-hover); color: var(--rt-color-fg); text-transform: uppercase; letter-spacing: 0.5px; }
.badge.mid { background: var(--rt-color-hover); color: var(--rt-color-accent); }

.folder-bar { display: flex; gap: 10px; margin-top: 16px; align-items: center; }
.folder-bar input { flex: 1; }

.dl-progress { margin-top: 12px; }
.dl-track { height: 8px; background: rgba(0,0,0,0.22); border-radius: 999px; overflow: hidden; }
.dl-fill { height: 100%; background: var(--rt-color-accent); border-radius: 999px; transition: width 0.3s ease; }
.dl-fill.indeterminate { width: 35%; animation: dl-indet 1.1s ease-in-out infinite; }
@keyframes dl-indet { 0% { margin-left: -35%; } 100% { margin-left: 100%; } }
.dl-label { display: inline-block; margin-top: 6px; font-size: 13px; }

.folder-card { border: 1px solid var(--rt-color-border); border-radius: 8px; padding: 14px; margin-bottom: 12px; background: var(--rt-color-surface); }
.folder-head { display: flex; justify-content: space-between; align-items: center; }
.folder-actions { display: flex; align-items: center; gap: 14px; }
.folder-card .repolist { margin: 8px 0 0; }
.folder-card .repo-row { padding: 6px 0; }

button.danger { background: #b3261e; color: #fff; }
button.danger:hover { background: #c5362e; }
button.ghost.danger { background: transparent; border: 1px solid #5a2a2a; color: #f87171; }
button.ghost.danger:hover { background: rgba(179,38,30,0.15); border-color: #7a3a3a; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 12px; padding: 24px 26px; max-width: 420px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
.modal h3 { margin-top: 0; }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }

.advisory-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; padding: 10px 14px; background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); border-radius: 8px; }
.scan-hint { margin-bottom: 14px; }
.scan-when { margin: 10px 0 0; font-size: 13px; }
.warn { color: var(--rt-color-warn); }
.scan-repo { padding: 10px 0; border-bottom: 1px solid var(--rt-color-border); }
.scan-repo-head { display: flex; justify-content: space-between; align-items: center; }
.findings { list-style: none; padding: 0; margin: 8px 0 0; }
.findings li { padding: 6px 0; font-size: 14px; }
.sev { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: rgba(251,191,36,0.15); color: var(--rt-color-warn); text-transform: uppercase; letter-spacing: 0.5px; }

.analytics-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }
.analytics-controls label { color: var(--rt-color-muted); font-size: 14px; }
select { padding: 8px 10px; border-radius: 6px; border: 1px solid var(--rt-color-border); background: var(--rt-color-surface); color: var(--rt-color-fg); }
.lang-bars { margin: 8px 0 20px; display: flex; flex-direction: column; gap: 10px; }
.lang-bar-label { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px; }
.lang-name { font-weight: 500; }
.bar-track { height: 8px; background: rgba(0,0,0,0.22); border-radius: 999px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--rt-color-accent); border-radius: 999px; }
.summary { font-size: 13px; margin-bottom: 14px; }
.filter-chips { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.chips-label { color: var(--rt-color-muted); font-size: 13px; margin-right: 2px; }
.chip { background: transparent; border: 1px solid var(--rt-color-border); color: var(--rt-color-fg); border-radius: 999px; padding: 5px 12px; font-size: 13px; }
.chip:hover { background: var(--rt-color-hover); }
.chip.active { background: var(--rt-color-hover); border-color: var(--rt-color-accent); color: var(--rt-color-accent); }
.risk-badges { display: flex; gap: 5px; flex-wrap: wrap; }
.rb { font-size: 10px; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap; }
.rb.build { background: rgba(96,165,250,0.16); color: #60a5fa; }
.rb.macro { background: rgba(184, 134, 11, 0.18); color: var(--rt-color-accent); }
.rb.ffi { background: rgba(251,146,60,0.16); color: #fb923c; }
.rb.unsafe { background: rgba(248,113,113,0.16); color: #f87171; }

table { width: 100%; border-collapse: collapse; margin-top: 10px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--rt-color-border); }
th { color: var(--rt-color-muted); font-weight: 500; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.hash { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.prod-push-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 0 0 14px; }
.prod-push-bar h3 { margin: 0; font-size: 1.05rem; }
.prod-push-actions { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
.gh-accounts { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.acct-chip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 6px 3px 10px; border-radius: 999px; background: var(--rt-color-surface); border: 1px solid var(--rt-color-border); font-size: 13px; }
.acct-x { background: transparent; border: none; color: var(--rt-color-muted); cursor: pointer; font-size: 15px; line-height: 1; padding: 0 2px; }
.acct-x:hover { color: var(--rt-color-danger); }
.acct-label { max-width: 200px; }
.acct-tag { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: rgba(184, 134, 11, 0.16); color: var(--rt-color-accent); border: 1px solid var(--rt-color-accent); }
.badge.fork { background: #3b2f0b; color: #fcd34d; border: 1px solid #5e4a15; }
.repolist-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.fork-toggle { font-size: 13px; color: var(--rt-color-muted); display: inline-flex; align-items: center; gap: 4px; cursor: pointer; white-space: nowrap; }
.area-tag { font-size: 11px; padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
.area-tag.prod { background: rgba(184, 134, 11, 0.16); color: var(--rt-color-accent); border: 1px solid var(--rt-color-accent); }
.area-tag.staging { background: var(--rt-color-hover); color: var(--rt-color-muted); border: 1px solid var(--rt-color-border); }
";

#[cfg(test)]
mod workspace_encode {
    use super::*;

    #[test]
    fn all_workspaces_round_trips_through_the_picker_encoding() {
        let w = Workspace::all();
        assert!(w.is_all());
        assert_eq!(w.encode(), "a");
        assert_eq!(Workspace::decode("a").as_ref(), Some(&w));
        assert_eq!(w.label(), "All workspaces");
        assert_eq!(w.api_body()["name"], "*");
        assert!(w.api_body().get("repo").is_none());
    }

    #[test]
    fn repo_short_splits_owner_and_name() {
        assert_eq!(repo_short("tokio-rs/tokio"), ("tokio-rs", "tokio"));
        assert_eq!(repo_short("orphan"), ("", "orphan"));
    }

    #[test]
    fn update_priority_is_major_minor_patch() {
        assert_eq!(
            update_priority("1.2.3", "2.0.0"),
            Some(UpdatePriority::High)
        );
        assert_eq!(
            update_priority("1.2.3", "1.5.0"),
            Some(UpdatePriority::Medium)
        );
        assert_eq!(update_priority("1.2.3", "1.2.9"), Some(UpdatePriority::Low));
        assert_eq!(update_priority("1.2.3", "1.2.3"), None);
        assert_eq!(
            update_priority("1.2.3-alpha", "1.3.0"),
            Some(UpdatePriority::Medium)
        );
    }

    #[test]
    fn format_scanned_at_is_empty_for_unknown() {
        assert_eq!(format_scanned_at(0), "");
    }

    #[test]
    fn format_scanned_at_renders_unix_epoch_utc() {
        assert_eq!(format_scanned_at(1), "1970-01-01 00:00 UTC");
        assert_eq!(format_scanned_at(3_600), "1970-01-01 01:00 UTC");
    }

    #[test]
    fn format_updated_at_is_date_only() {
        assert_eq!(format_updated_at(0), "");
        assert_eq!(format_updated_at(1), "1970-01-01");
        assert_eq!(format_updated_at(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn job_scope_matches_encode_prefix_not_a_string_prefix() {
        let repo = Workspace::repo("Remade-With-Rust", "Remade-With-Rust/rusty_alloc");
        let group = Workspace::group("Remade-With-Rust");
        let scope = format!("{}#3#1", repo.encode());
        assert!(job_scope_matches(&scope, &repo));
        assert!(!job_scope_matches(&scope, &group));
        assert!(!job_scope_matches("", &repo));
        assert!(job_scope_matches(&repo.encode(), &repo));
    }

    #[test]
    fn report_is_for_uses_workspace_label() {
        let repo = Workspace::repo("Remade-With-Rust", "Remade-With-Rust/rusty_alloc");
        assert!(report_is_for(&repo, "Remade-With-Rust/rusty_alloc"));
        assert!(!report_is_for(&repo, "Remade-With-Rust/rusty_tokens"));
        assert!(report_is_for(&Workspace::all(), "All workspaces"));
        let group = Workspace::group("Remade With Rust");
        assert!(report_is_for(&group, "Remade With Rust"));
        assert!(!report_is_for(&group, "Remade-With-Rust/rusty_alloc"));
    }

    #[test]
    fn lockfile_present_treats_dep_count_as_a_parsed_lockfile() {
        assert!(lockfile_present(true, 0));
        assert!(lockfile_present(false, 60));
        assert!(!lockfile_present(false, 0));
        let archived = RepoSummary {
            full_name: "Remade-With-Rust/rusty_alloc".into(),
            deps: 60,
            acquired: 60,
            lockfile_found: false,
            source_archived: true,
            error: None,
        };
        assert_eq!(repo_vault_line(&archived), "60/60 acquired");
        let source_only = RepoSummary {
            full_name: "Remade-With-Rust/rusty_tokens".into(),
            deps: 0,
            acquired: 0,
            lockfile_found: false,
            source_archived: true,
            error: None,
        };
        assert_eq!(
            repo_vault_line(&source_only),
            "source archived · no Cargo.lock"
        );
    }
}
