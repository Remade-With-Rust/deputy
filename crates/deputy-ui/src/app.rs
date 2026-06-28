//! The Dioxus single-page app (web + desktop). A thin client of the Deputy API.
//!
//! Flow: an **mID login landing page** gates the app; once signed in, a left **sidebar** selects
//! tabs. The **GitHub** tab connects a PAT, lists your repositories, lets you select some, name a
//! folder, and **Download and Analyze** them into that folder. The **Infrastructure** tab lists
//! the folders you've created.

use std::collections::HashSet;

use dioxus::prelude::*;
use serde::Deserialize;

const API_BASE: &str = "http://127.0.0.1:7878";

pub fn launch() {
    dioxus::launch(App);
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
    error: Option<String>,
}

/// A named folder grouping the repositories allocated to it.
#[derive(Deserialize, Clone, PartialEq)]
struct FolderSummary {
    name: String,
    repos: Vec<RepoSummary>,
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
}

#[derive(Deserialize, Clone, PartialEq)]
struct HeartbeatReport {
    name: String,
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

// ── Root: the mID auth gate ───────────────────────────────────────────────────

#[component]
fn App() -> Element {
    let session = use_signal(|| None::<Session>);
    rsx! {
        style { {CSS} }
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

    rsx! {
        div { class: "landing",
            div { class: "login-card",
                div { class: "brand", "Deputy" }
                p { class: "tag", "Your personally-owned, verified dependency vault." }
                p { class: "muted login-hint", "Sign in with your MATA mID to continue." }
                button {
                    class: "primary big",
                    disabled: busy(),
                    onclick: move |_| {
                        busy.set(true);
                        error.set(None);
                        spawn(async move {
                            // 1. Ask Deputy for a single-use challenge (nonce + audience).
                            status.set(Some("Requesting a sign-in challenge…".to_string()));
                            let challenge = match get_json::<Challenge>("/auth/challenge").await {
                                Ok(c) => c,
                                Err(e) => { status.set(None); error.set(Some(format!("couldn't start sign-in — {e}"))); busy.set(false); return; }
                            };
                            // 2. Have the MATA extension sign it. rp_origin MUST be the page's real
                            //    origin (localhost vs 127.0.0.1) or the wallet rejects origin_mismatch.
                            let origin = page_origin().await;
                            status.set(Some("Waiting for the MATA extension…".to_string()));
                            let token = match request_mid_token(&origin, &challenge.nonce).await {
                                Ok(t) => t,
                                Err(e) => { status.set(None); error.set(Some(e)); busy.set(false); return; }
                            };
                            // 3. Verify the token with Deputy (against that same origin) → mID session.
                            status.set(Some("Verifying…".to_string()));
                            let body = serde_json::json!({ "token": token, "nonce": challenge.nonce, "audience": origin });
                            match post_json::<Session>("/auth/verify", &body).await {
                                Ok(s) => sess.set(Some(s)),
                                Err(e) => error.set(Some(format!("verification failed — {e}"))),
                            }
                            status.set(None);
                            busy.set(false);
                        });
                    },
                    {if busy() { "Signing in…" } else { "Sign in with mID" }}
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
            p { class: "footnote muted", "Dev access enters with a local identity and no mID verification — for development only." }
        }
    }
}

// ── Authenticated shell: sidebar + tabbed content ─────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    GitHub,
    Infrastructure,
    Scan,
    Heartbeat,
    Analytics,
    Production,
}

#[component]
fn Dashboard(session: Session, sess: Signal<Option<Session>>) -> Element {
    let mut sess = sess;
    let tab = use_signal(|| Tab::GitHub);

    rsx! {
        div { class: "shell",
            nav { class: "sidebar",
                div { class: "brand sb-brand", "Deputy" }
                div { class: "nav",
                    NavItem { tab, this: Tab::GitHub, label: "GitHub" }
                    NavItem { tab, this: Tab::Infrastructure, label: "Infrastructure" }
                    NavItem { tab, this: Tab::Scan, label: "Scan Dependencies" }
                    NavItem { tab, this: Tab::Heartbeat, label: "Social Heartbeat" }
                    NavItem { tab, this: Tab::Analytics, label: "Dep Analytics" }
                    NavItem { tab, this: Tab::Production, label: "Production Dependencies" }
                }
                div { class: "sb-footer",
                    span { class: "did", "● {session.did}" }
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
                    Tab::GitHub => rsx! { GitHubTab {} },
                    Tab::Infrastructure => rsx! { InfrastructureTab {} },
                    Tab::Scan => rsx! { ScanTab {} },
                    Tab::Heartbeat => rsx! { HeartbeatTab {} },
                    Tab::Analytics => rsx! { AnalyticsTab {} },
                    Tab::Production => rsx! { ProductionTab {} },
                }}
            }
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

// ── GitHub tab: connect, select repos, name a folder, download + analyze ──────

#[component]
fn GitHubTab() -> Element {
    let mut token = use_signal(String::new);
    let mut label = use_signal(String::new);
    let mut owner = use_signal(String::new);
    let mut hide_forks = use_signal(|| true);
    let mut connections = use_signal(Vec::<String>::new);
    let mut repos = use_signal(|| None::<Result<Vec<Repo>, String>>);
    let mut connecting = use_signal(|| false);
    let mut connect_err = use_signal(|| None::<String>);
    let mut selected = use_signal(HashSet::<String>::new);
    let mut folder = use_signal(|| "MATA Infra".to_string());
    let mut downloading = use_signal(|| false);
    let mut progress = use_signal(|| None::<ProgressView>);
    let mut result = use_signal(|| None::<Result<FolderSummary, String>>);

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

            // Connected accounts — each PAT keeps its own token; repos are listed together.
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
                                    "×"
                                }
                            }
                        }
                    }
                }}
            }
            div { class: "gh-connect",
                input {
                    class: "acct-label",
                    value: "{label}",
                    oninput: move |e| label.set(e.value()),
                    placeholder: "label (optional)",
                }
                input {
                    class: "acct-label",
                    value: "{owner}",
                    oninput: move |e| owner.set(e.value()),
                    placeholder: "org / user to list (e.g. Remade-With-Rust)",
                }
                input {
                    r#type: "password",
                    value: "{token}",
                    oninput: move |e| token.set(e.value()),
                    placeholder: "fine-grained GitHub PAT",
                }
                button {
                    class: "gh",
                    disabled: connecting() || token().trim().is_empty(),
                    onclick: move |_| {
                        let body = serde_json::json!({ "token": token(), "label": label(), "owner": owner() });
                        connecting.set(true);
                        connect_err.set(None);
                        spawn(async move {
                            match post_json::<serde_json::Value>("/github/connect", &body).await {
                                Ok(_) => {
                                    token.set(String::new());
                                    label.set(String::new());
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
                    {if connecting() { "Connecting…" } else { "Add account" }}
                }
            }
            {match connect_err() {
                Some(e) => rsx! { p { class: "err", "Couldn't connect — {e}" } },
                None => rsx! {},
            }}
            p { class: "muted gh-hint",
                "Add one or more fine-grained PATs (read access to your repos). Each is held in "
                "memory for this session only; repositories from every account are listed together."
            }

            {match snapshot {
                Some(Ok(list)) if !list.is_empty() => rsx! {
                    div { class: "repolist-head",
                        p { class: "muted", "{list.len()} repositories — select which to download." }
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
                    div { class: "folder-bar",
                        input {
                            value: "{folder}",
                            oninput: move |e| folder.set(e.value()),
                            placeholder: "folder name (e.g. MATA Infra)",
                        }
                        button {
                            class: "primary",
                            disabled: downloading() || selected.read().is_empty() || folder().trim().is_empty(),
                            onclick: move |_| {
                                let body = serde_json::json!({
                                    "folder": folder().trim(),
                                    "repos": selected.read().iter().cloned().collect::<Vec<_>>(),
                                });
                                downloading.set(true);
                                progress.set(None);
                                // Poll acquisition progress while the download runs.
                                spawn(async move {
                                    while downloading() {
                                        if let Ok(p) = get_json::<Option<ProgressView>>("/github/download/progress").await {
                                            progress.set(p);
                                        }
                                        sleep_ms(400).await;
                                    }
                                    progress.set(None);
                                });
                                spawn(async move {
                                    result.set(Some(post_json::<FolderSummary>("/github/download", &body).await));
                                    downloading.set(false);
                                });
                            },
                            {if downloading() { "Downloading…" } else { "Download and Analyze" }}
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
                                None if r.lockfile_found => rsx! { span { class: "ok", "✓ sealed" } },
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
    let mut folders = use_resource(|| async { get_json::<Vec<FolderSummary>>("/folders").await });
    let mut confirming = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Infrastructure" } }
            {match &*folders.read() {
                None => rsx! { p { class: "muted", "Loading…" } },
                Some(Ok(list)) if list.is_empty() => rsx! {
                    p { class: "muted", "No infrastructure folders yet — create one from the GitHub tab." }
                },
                Some(Ok(list)) => rsx! {
                    for f in list.iter() {
                        div { class: "folder-card",
                            div { class: "folder-head",
                                strong { "{f.name}" }
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
                                    li { class: "repo-row",
                                        span { class: "repo-name", "{r.full_name}" }
                                        span { class: "muted", "{r.acquired}/{r.deps} acquired" }
                                    }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "err", "Couldn't load folders — {e}" } },
            }}
        }
        {match confirming() {
            Some(name) => {
                let confirm_name = name.clone();
                rsx! {
                    div { class: "modal-overlay",
                        div { class: "modal",
                            h3 { "Remove “{name}”?" }
                            p { class: "muted", "This deletes the folder and its repositories from Deputy. This can't be undone." }
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
                                        let body = serde_json::json!({ "name": confirm_name });
                                        busy.set(true);
                                        spawn(async move {
                                            let _ = post_json::<serde_json::Value>("/folders/delete", &body).await;
                                            busy.set(false);
                                            confirming.set(None);
                                            folders.restart();
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

// ── Scan Dependencies tab: pick an infrastructure, scan its repos ──────────────

#[component]
fn ScanTab() -> Element {
    let folders = use_resource(|| async { get_json::<Vec<FolderSummary>>("/folders").await });
    let mut scanning = use_signal(|| None::<String>);
    let mut result = use_signal(|| None::<Result<FolderScanReport, String>>);
    let mut advisories = use_signal(|| None::<usize>);
    let mut loading_adv = use_signal(|| false);
    let mut nv_result = use_signal(|| None::<Result<NewVersionReport, String>>);
    let mut nv_scanning = use_signal(|| None::<String>);
    let mut cov_result = use_signal(|| None::<Result<CoverageReport, String>>);
    let mut cov_scanning = use_signal(|| None::<String>);

    use_effect(move || {
        spawn(async move {
            if let Ok(v) = get_json::<serde_json::Value>("/advisories").await {
                advisories.set(
                    v.get("advisories")
                        .and_then(|a| a.as_u64())
                        .map(|n| n as usize),
                );
            }
        });
    });

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Scan Dependencies" } }
            div { class: "advisory-bar",
                {match advisories() {
                    Some(n) if n > 0 => rsx! { span { class: "ok", "● {n} RUSTSEC advisories loaded" } },
                    _ => rsx! { span { class: "muted", "no advisory DB loaded — scans won't flag CVEs yet" } },
                }}
                button {
                    class: "gh",
                    disabled: loading_adv(),
                    onclick: move |_| {
                        loading_adv.set(true);
                        spawn(async move {
                            if let Ok(v) = post_json::<serde_json::Value>("/advisories/rustsec", &serde_json::json!({})).await {
                                advisories.set(v.get("advisories").and_then(|a| a.as_u64()).map(|n| n as usize));
                            }
                            loading_adv.set(false);
                        });
                    },
                    {if loading_adv() { "Loading RUSTSEC…" } else { "Load RUSTSEC advisories" }}
                }
            }
            {match &*folders.read() {
                None => rsx! { p { class: "muted", "Loading…" } },
                Some(Ok(list)) if list.is_empty() => rsx! {
                    p { class: "muted", "No infrastructure to scan yet — create a folder in the GitHub tab." }
                },
                Some(Ok(list)) => rsx! {
                    p { class: "muted scan-hint", "Select an infrastructure to scan its repositories' dependencies." }
                    for f in list.iter() {
                        div { class: "folder-card",
                            div { class: "folder-head",
                                strong { "{f.name}" }
                                div { class: "folder-actions",
                                    span { class: "muted", "{f.repos.len()} repos" }
                                    button {
                                        class: "primary",
                                        disabled: scanning().is_some(),
                                        onclick: {
                                            let name = f.name.clone();
                                            move |_| {
                                                let name = name.clone();
                                                let body = serde_json::json!({ "name": name });
                                                scanning.set(Some(name));
                                                result.set(None);
                                                spawn(async move {
                                                    result.set(Some(post_json::<FolderScanReport>("/folders/scan", &body).await));
                                                    scanning.set(None);
                                                });
                                            }
                                        },
                                        {if scanning() == Some(f.name.clone()) { "Scanning…" } else { "Scan" }}
                                    }
                                    button {
                                        class: "ghost",
                                        disabled: nv_scanning().is_some(),
                                        onclick: {
                                            let name = f.name.clone();
                                            move |_| {
                                                let name = name.clone();
                                                let body = serde_json::json!({ "name": name });
                                                nv_scanning.set(Some(name));
                                                nv_result.set(None);
                                                spawn(async move {
                                                    nv_result.set(Some(post_json::<NewVersionReport>("/folders/scan-new-versions", &body).await));
                                                    nv_scanning.set(None);
                                                });
                                            }
                                        },
                                        {if nv_scanning() == Some(f.name.clone()) { "Checking…" } else { "Scan for updates" }}
                                    }
                                    button {
                                        class: "ghost",
                                        disabled: cov_scanning().is_some(),
                                        onclick: {
                                            let name = f.name.clone();
                                            move |_| {
                                                let name = name.clone();
                                                let body = serde_json::json!({ "name": name });
                                                cov_scanning.set(Some(name));
                                                cov_result.set(None);
                                                spawn(async move {
                                                    cov_result.set(Some(post_json::<CoverageReport>("/folders/coverage", &body).await));
                                                    cov_scanning.set(None);
                                                });
                                            }
                                        },
                                        {if cov_scanning() == Some(f.name.clone()) { "Checking…" } else { "Check offline coverage" }}
                                    }
                                }
                            }
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "err", "Couldn't load folders — {e}" } },
            }}
        }
        {match &*result.read() {
            Some(Ok(report)) => rsx! { ScanReportPanel { report: report.clone() } },
            Some(Err(e)) => rsx! { section { class: "panel", p { class: "err", "Scan failed — {e}" } } },
            None => rsx! {},
        }}
        {match &*nv_result.read() {
            Some(Ok(report)) => rsx! { NewVersionView { report: report.clone() } },
            Some(Err(e)) => rsx! { section { class: "panel", p { class: "err", "Update scan failed — {e}" } } },
            None => rsx! {},
        }}
        {match &*cov_result.read() {
            Some(Ok(report)) => rsx! { CoverageView { report: report.clone() } },
            Some(Err(e)) => rsx! { section { class: "panel", p { class: "err", "Coverage check failed — {e}" } } },
            None => rsx! {},
        }}
    }
}

#[component]
fn ScanReportPanel(report: FolderScanReport) -> Element {
    let total_findings: usize = report.repos.iter().map(|r| r.findings.len()).sum();
    let total_deps: usize = report.repos.iter().map(|r| r.deps).sum();
    rsx! {
        section { class: "panel result",
            h3 { "Scan — {report.name}" }
            p { class: "muted", "{report.repos.len()} repos · {total_deps} dependencies scanned · {total_findings} findings" }
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
                    } else if !r.lockfile_found {
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
                        tr { th { "dependency" } th { "current" } th { "new (pending Social Heartbeat)" } }
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

// ── Dep Analytics tab: pick an infrastructure, break dependencies down by language ────────────

fn pct(part: usize, total: usize) -> usize {
    match (part * 100).checked_div(total) {
        Some(p) if part > 0 => p.max(1),
        _ => 0,
    }
}

#[component]
fn AnalyticsTab() -> Element {
    let folders = use_resource(|| async { get_json::<Vec<FolderSummary>>("/folders").await });
    let mut analytics = use_signal(|| None::<Result<DepAnalytics, String>>);
    let mut loading = use_signal(|| false);
    let mut lang_filter = use_signal(String::new);
    let mut f_build = use_signal(|| false);
    let mut f_proc = use_signal(|| false);
    let mut f_native = use_signal(|| false);
    let mut f_unsafe = use_signal(|| false);
    let mut held = use_signal(HashSet::<String>::new);

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Dep Analytics" } }
            div { class: "analytics-controls",
                label { "Infrastructure" }
                select {
                    onchange: move |e| {
                        let name = e.value();
                        lang_filter.set(String::new());
                        f_build.set(false);
                        f_proc.set(false);
                        f_native.set(false);
                        f_unsafe.set(false);
                        held.write().clear();
                        analytics.set(None);
                        if name.is_empty() {
                            return;
                        }
                        loading.set(true);
                        let body = serde_json::json!({ "name": name });
                        spawn(async move {
                            analytics.set(Some(post_json::<DepAnalytics>("/folders/analytics", &body).await));
                            loading.set(false);
                        });
                    },
                    option { value: "", "Select an infrastructure…" }
                    {match &*folders.read() {
                        Some(Ok(list)) => rsx! {
                            for f in list.iter() {
                                option { value: "{f.name}", "{f.name}" }
                            }
                        },
                        _ => rsx! {},
                    }}
                }
                {match &*analytics.read() {
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

            {match &*analytics.read() {
                Some(Ok(_)) => rsx! {
                    div { class: "filter-chips",
                        span { class: "chips-label", "Risk filters:" }
                        FilterChip { active: f_build, label: "Build script" }
                        FilterChip { active: f_proc, label: "Proc-macro" }
                        FilterChip { active: f_native, label: "Native / FFI" }
                        FilterChip { active: f_unsafe, label: "Unsafe" }
                    }
                },
                _ => rsx! {},
            }}

            {if loading() {
                rsx! { p { class: "muted", "Reading staged crates from your vault and inspecting them (languages + risk). First run re-reads each repo's lockfile and inspects every crate — anything not already downloaded is fetched on demand. Cached after." } }
            } else {
                match &*analytics.read() {
                    None => rsx! { p { class: "muted", "Pick an infrastructure to break its dependencies down by language and supply-chain risk." } },
                    Some(Ok(a)) => rsx! { AnalyticsView {
                        a: a.clone(),
                        lang: lang_filter(),
                        build_filter: f_build(),
                        proc_macro: f_proc(),
                        native: f_native(),
                        unsafe_flag: f_unsafe(),
                        held,
                    } },
                    Some(Err(e)) => rsx! { p { class: "err", "Analytics failed — {e}" } },
                }
            }}
        }
    }
}

#[component]
fn FilterChip(active: Signal<bool>, label: String) -> Element {
    let mut active = active;
    let cls = if active() { "chip active" } else { "chip" };
    rsx! {
        button {
            class: "{cls}",
            onclick: move |_| {
                let v = active();
                active.set(!v);
            },
            "{label}"
        }
    }
}

#[component]
fn AnalyticsView(
    a: DepAnalytics,
    lang: String,
    build_filter: bool,
    proc_macro: bool,
    native: bool,
    unsafe_flag: bool,
    held: Signal<HashSet<String>>,
) -> Element {
    let total_lines: usize = a.by_language.iter().map(|l| l.lines).sum();
    let deps: Vec<DepLang> = a
        .deps
        .iter()
        .filter(|d| {
            (lang.is_empty() || d.languages.iter().any(|l| l == &lang))
                && (!build_filter || d.has_build_script)
                && (!proc_macro || d.is_proc_macro)
                && (!native || d.links_native.is_some() || d.native_unsafe_lines > 0)
                && (!unsafe_flag || d.unsafe_occurrences > 0)
        })
        .cloned()
        .collect();
    let mut pushing = use_signal(|| false);
    let mut push_msg = use_signal(|| None::<String>);
    let folder = a.name.clone();
    let push_deps = a.deps.clone();
    let in_prod = a.deps.iter().filter(|d| d.in_production).count();
    let in_staging = a.deps.len().saturating_sub(in_prod);
    rsx! {
        p { class: "muted summary",
            "{a.analyzed} of {a.total_deps} crates inspected · {a.build_scripts} build scripts · "
            "{a.proc_macros} proc-macros · {a.native_crates} native/FFI · {a.unsafe_crates} use unsafe"
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
        p { class: "muted summary",
            "{in_prod} in production · {in_staging} in staging — "
            "check anything that's NOT ready for production; the rest are redeployed."
        }
        div { class: "prod-push-bar",
            span { class: "muted", "Checked deps stay in staging. Everything else clean is flipped staging → production." }
            button {
                class: "primary",
                disabled: pushing(),
                onclick: move |_| {
                    let hold: Vec<serde_json::Value> = push_deps
                        .iter()
                        .filter(|d| held.read().contains(&format!("{}@{}", d.name, d.version)))
                        .map(|d| serde_json::json!({ "name": d.name, "version": d.version }))
                        .collect();
                    let body = serde_json::json!({ "name": folder, "hold": hold });
                    pushing.set(true);
                    push_msg.set(None);
                    spawn(async move {
                        match post_json::<serde_json::Value>("/folders/promote", &body).await {
                            Ok(v) => {
                                let n = v.get("promoted").and_then(|x| x.as_u64()).unwrap_or(0);
                                push_msg.set(Some(format!("✓ redeployed {n} dependencies to production")));
                            }
                            Err(e) => push_msg.set(Some(format!("redeploy failed — {e}"))),
                        }
                        pushing.set(false);
                    });
                },
                {if pushing() { "Redeploying…" } else { "Redeploy to Production" }}
            }
        }
        {match push_msg() {
            Some(m) => rsx! { p { class: "muted", "{m}" } },
            None => rsx! {},
        }}
        table {
            tr { th { "" } th { "crate" } th { "area" } th { "languages" } th { "risk" } th { class: "num", "lines" } }
            for d in deps.iter() {
                DepRow { d: d.clone(), held }
            }
        }
    }
}

#[component]
fn DepRow(d: DepLang, held: Signal<HashSet<String>>) -> Element {
    let mut held = held;
    let key = format!("{}@{}", d.name, d.version);
    let checked = held.read().contains(&key);
    let langs = if d.languages.is_empty() {
        "—".to_string()
    } else {
        d.languages.join(", ")
    };
    rsx! {
        tr {
            td {
                input {
                    r#type: "checkbox",
                    checked,
                    onclick: {
                        let key = key.clone();
                        move |_| {
                            let key = key.clone();
                            held.with_mut(|h| {
                                if !h.remove(&key) {
                                    h.insert(key);
                                }
                            });
                        }
                    },
                }
            }
            td { "{d.name} {d.version}" }
            td {
                {if d.in_production {
                    rsx! { span { class: "area-tag prod", "production" } }
                } else {
                    rsx! { span { class: "area-tag staging", "staging" } }
                }}
            }
            td { class: "muted", "{langs}" }
            td { class: "risk-badges",
                {if d.has_build_script { rsx! { span { class: "rb build", "build" } } } else { rsx! {} }}
                {if d.is_proc_macro { rsx! { span { class: "rb macro", "macro" } } } else { rsx! {} }}
                {if d.links_native.is_some() || d.native_unsafe_lines > 0 { rsx! { span { class: "rb ffi", "native" } } } else { rsx! {} }}
                {if d.unsafe_occurrences > 0 { rsx! { span { class: "rb unsafe", "unsafe {d.unsafe_occurrences}" } } } else { rsx! {} }}
            }
            td { class: "num", "{d.lines}" }
        }
    }
}

// ── Social Heartbeat tab: newer releases + public advisories on a folder's deps ───────────────

#[component]
fn HeartbeatTab() -> Element {
    let folders = use_resource(|| async { get_json::<Vec<FolderSummary>>("/folders").await });
    let mut report = use_signal(|| None::<Result<HeartbeatReport, String>>);
    let mut loading = use_signal(|| false);

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Social Heartbeat" } }
            p { class: "muted scan-hint",
                "Check an infrastructure's dependencies for newer releases on crates.io and any "
                "publicly-disclosed advisories on the versions you're pinned to."
            }
            div { class: "analytics-controls",
                label { "Infrastructure" }
                select {
                    onchange: move |e| {
                        let name = e.value();
                        report.set(None);
                        if name.is_empty() { return; }
                        loading.set(true);
                        let body = serde_json::json!({ "name": name });
                        spawn(async move {
                            report.set(Some(post_json::<HeartbeatReport>("/folders/heartbeat", &body).await));
                            loading.set(false);
                        });
                    },
                    option { value: "", "Select an infrastructure…" }
                    {match &*folders.read() {
                        Some(Ok(list)) => rsx! {
                            for f in list.iter() { option { value: "{f.name}", "{f.name}" } }
                        },
                        _ => rsx! {},
                    }}
                }
            }
            {if loading() {
                rsx! { p { class: "muted", "Checking crates.io for the latest versions…" } }
            } else {
                match &*report.read() {
                    None => rsx! {},
                    Some(Ok(r)) => rsx! { HeartbeatView { report: r.clone() } },
                    Some(Err(e)) => rsx! { p { class: "err", "Heartbeat failed — {e}" } },
                }
            }}
        }
    }
}

#[component]
fn HeartbeatView(report: HeartbeatReport) -> Element {
    let updates = report.entries.iter().filter(|e| e.update_available).count();
    let flagged = report
        .entries
        .iter()
        .filter(|e| !e.advisories.is_empty())
        .count();
    let mut entries = report.entries.clone();
    // Advisories first, then update-available, then current.
    entries.sort_by_key(|e| (e.advisories.is_empty(), !e.update_available));
    rsx! {
        p { class: "muted summary",
            "{report.entries.len()} dependencies · {updates} with newer releases · {flagged} with advisories"
        }
        table {
            tr { th { "dependency" } th { "pinned" } th { "latest" } th { "heartbeat" } }
            for e in entries.iter() {
                HeartbeatRow { e: e.clone() }
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
    let mut prod = use_resource(|| async { get_json::<Vec<ProdDep>>("/production").await });
    let folders = use_resource(|| async { get_json::<Vec<FolderSummary>>("/folders").await });
    let mut promote_msg = use_signal(|| None::<String>);
    let mut promoting = use_signal(|| false);

    rsx! {
        section { class: "panel",
            div { class: "panel-head", h2 { "Production Dependencies" } }
            p { class: "muted scan-hint",
                "The dependency versions you've validated and promoted to production — clean-scanned, "
                "content-addressed, and receipted. Scan a folder first, then promote it here."
            }
            div { class: "analytics-controls",
                label { "Promote a scanned folder" }
                select {
                    disabled: promoting(),
                    onchange: move |e| {
                        let name = e.value();
                        if name.is_empty() { return; }
                        promoting.set(true);
                        promote_msg.set(None);
                        let body = serde_json::json!({ "name": name });
                        spawn(async move {
                            match post_json::<serde_json::Value>("/folders/promote", &body).await {
                                Ok(v) => {
                                    let n = v.get("promoted").and_then(|x| x.as_u64()).unwrap_or(0);
                                    promote_msg.set(Some(format!("✓ promoted {n} validated dependencies")));
                                    prod.restart();
                                }
                                Err(e) => promote_msg.set(Some(format!("promote failed — {e}"))),
                            }
                            promoting.set(false);
                        });
                    },
                    option { value: "", "Select a folder to promote its clean deps…" }
                    {match &*folders.read() {
                        Some(Ok(list)) => rsx! {
                            for f in list.iter() { option { value: "{f.name}", "{f.name}" } }
                        },
                        _ => rsx! {},
                    }}
                }
                {if promoting() { rsx! { span { class: "muted", "promoting…" } } } else { rsx! {} }}
            }
            {match promote_msg() {
                Some(m) => rsx! { p { class: "muted", "{m}" } },
                None => rsx! {},
            }}
            {match &*prod.read() {
                None => rsx! { p { class: "muted", "Loading…" } },
                Some(Ok(list)) if list.is_empty() => rsx! {
                    p { class: "muted", "No validated dependencies yet — scan a folder, then promote it above." }
                },
                Some(Ok(list)) => rsx! {
                    p { class: "muted summary", "{list.len()} validated dependency versions" }
                    table {
                        tr { th { "crate" } th { "version" } th { "content hash" } }
                        for d in list.iter() {
                            ProdRow { d: d.clone() }
                        }
                    }
                },
                Some(Err(e)) => rsx! { p { class: "err", "Couldn't load — {e}" } },
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

const CSS: &str = "
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, system-ui, sans-serif; background: #0f1115; color: #e6e6e6; }
.brand { font-size: 28px; font-weight: 700; color: #8b5cf6; letter-spacing: -0.5px; }
.tag { color: #9aa0aa; margin: 4px 0 16px; }
.muted { color: #9aa0aa; } .ok { color: #34d399; } .err { color: #f87171; }

/* Landing / login */
.landing { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 18px; padding: 24px; }
.login-card { background: #161922; border: 1px solid #2a2f3a; border-radius: 14px; padding: 36px 40px; max-width: 420px; width: 100%; text-align: center; box-shadow: 0 12px 40px rgba(0,0,0,0.35); }
.login-card .brand { font-size: 34px; }
.login-hint { margin: 18px 0; }
.footnote { font-size: 13px; max-width: 420px; text-align: center; }
button.big { width: 100%; padding: 12px 16px; font-size: 15px; }
button.dev { background: transparent; border: 1px dashed #3a4150; color: #9aa0aa; }
button.dev:hover { background: #1c2029; color: #c4c9d4; border-color: #4a5160; }
.divider { display: flex; align-items: center; text-align: center; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin: 14px 0; }
.divider::before, .divider::after { content: \"\"; flex: 1; border-bottom: 1px solid #2a2f3a; }
.divider span { padding: 0 10px; }

/* Shell: sidebar + content */
.shell { display: flex; min-height: 100vh; }
.sidebar { width: 220px; background: #12151c; border-right: 1px solid #2a2f3a; padding: 20px 14px; display: flex; flex-direction: column; }
.sb-brand { margin-bottom: 18px; padding: 0 6px; }
.nav { display: flex; flex-direction: column; gap: 4px; flex: 1; }
.nav-item { text-align: left; background: transparent; color: #c4c9d4; border: 0; padding: 10px 12px; border-radius: 6px; font-size: 14px; }
.nav-item:hover { background: #1c2029; }
.nav-item.active { background: rgba(139,92,246,0.15); color: #b794ff; }
.sb-footer { display: flex; flex-direction: column; gap: 8px; font-size: 13px; padding: 0 6px; }
.did { color: #34d399; word-break: break-all; }
.content { flex: 1; padding: 24px 32px; max-width: 920px; }

button { background: #8b5cf6; color: white; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; font-weight: 500; }
button:hover { background: #7c3aed; }
button:disabled { opacity: 0.5; cursor: default; }
button.ghost { background: transparent; border: 1px solid #2a2f3a; color: #c4c9d4; }
button.ghost:hover { background: #1c2029; }
button.gh { background: #24292f; }
button.gh:hover { background: #30363d; }
input { padding: 8px; border-radius: 6px; border: 1px solid #2a2f3a; background: #161922; color: #e6e6e6; }
input[type=checkbox] { width: 18px; height: 18px; accent-color: #8b5cf6; cursor: pointer; padding: 0; }

.panel { background: #161922; border: 1px solid #2a2f3a; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.panel h2, .panel h3 { margin-top: 0; }
.panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
.panel-head h2 { margin: 0; }
.result h3 { color: #34d399; }

.gh-connect { display: flex; gap: 10px; align-items: center; margin: 12px 0 8px; }
.gh-connect input { flex: 1; }
.gh-hint { font-size: 13px; }

.repolist { list-style: none; padding: 0; margin: 12px 0; }
.repo-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 0; border-bottom: 1px solid #2a2f3a; }
.repo-info { display: flex; align-items: center; gap: 8px; }
.repo-name { font-weight: 500; }
.lang-tag { font-size: 11px; color: #9aa0aa; }
.badge { font-size: 11px; padding: 2px 8px; border-radius: 999px; background: #2a2f3a; color: #c4c9d4; text-transform: uppercase; letter-spacing: 0.5px; }
.badge.mid { background: rgba(139,92,246,0.18); color: #b794ff; }

.folder-bar { display: flex; gap: 10px; margin-top: 16px; align-items: center; }
.folder-bar input { flex: 1; }

.dl-progress { margin-top: 12px; }
.dl-track { height: 8px; background: #1c2029; border-radius: 999px; overflow: hidden; }
.dl-fill { height: 100%; background: #8b5cf6; border-radius: 999px; transition: width 0.3s ease; }
.dl-fill.indeterminate { width: 35%; animation: dl-indet 1.1s ease-in-out infinite; }
@keyframes dl-indet { 0% { margin-left: -35%; } 100% { margin-left: 100%; } }
.dl-label { display: inline-block; margin-top: 6px; font-size: 13px; }

.folder-card { border: 1px solid #2a2f3a; border-radius: 8px; padding: 14px; margin-bottom: 12px; }
.folder-head { display: flex; justify-content: space-between; align-items: center; }
.folder-actions { display: flex; align-items: center; gap: 14px; }
.folder-card .repolist { margin: 8px 0 0; }
.folder-card .repo-row { padding: 6px 0; }

button.danger { background: #b3261e; }
button.danger:hover { background: #c5362e; }
button.ghost.danger { background: transparent; border: 1px solid #5a2a2a; color: #f87171; }
button.ghost.danger:hover { background: rgba(179,38,30,0.15); border-color: #7a3a3a; }

.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: flex; align-items: center; justify-content: center; z-index: 100; }
.modal { background: #161922; border: 1px solid #2a2f3a; border-radius: 12px; padding: 24px 26px; max-width: 420px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
.modal h3 { margin-top: 0; }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }

.advisory-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 16px; padding: 10px 14px; background: #12151c; border: 1px solid #2a2f3a; border-radius: 8px; }
.scan-hint { margin-bottom: 14px; }
.warn { color: #fbbf24; }
.scan-repo { padding: 10px 0; border-bottom: 1px solid #2a2f3a; }
.scan-repo-head { display: flex; justify-content: space-between; align-items: center; }
.findings { list-style: none; padding: 0; margin: 8px 0 0; }
.findings li { padding: 6px 0; font-size: 14px; }
.sev { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: rgba(251,191,36,0.15); color: #fbbf24; text-transform: uppercase; letter-spacing: 0.5px; }

.analytics-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }
.analytics-controls label { color: #9aa0aa; font-size: 14px; }
select { padding: 8px 10px; border-radius: 6px; border: 1px solid #2a2f3a; background: #161922; color: #e6e6e6; }
.lang-bars { margin: 8px 0 20px; display: flex; flex-direction: column; gap: 10px; }
.lang-bar-label { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px; }
.lang-name { font-weight: 500; }
.bar-track { height: 8px; background: #1c2029; border-radius: 999px; overflow: hidden; }
.bar-fill { height: 100%; background: #8b5cf6; border-radius: 999px; }
.summary { font-size: 13px; margin-bottom: 14px; }
.filter-chips { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.chips-label { color: #9aa0aa; font-size: 13px; margin-right: 2px; }
.chip { background: transparent; border: 1px solid #2a2f3a; color: #c4c9d4; border-radius: 999px; padding: 5px 12px; font-size: 13px; }
.chip:hover { background: #1c2029; }
.chip.active { background: rgba(139,92,246,0.2); border-color: #8b5cf6; color: #c4b5fd; }
.risk-badges { display: flex; gap: 5px; flex-wrap: wrap; }
.rb { font-size: 10px; padding: 2px 7px; border-radius: 999px; text-transform: uppercase; letter-spacing: 0.4px; white-space: nowrap; }
.rb.build { background: rgba(96,165,250,0.16); color: #60a5fa; }
.rb.macro { background: rgba(167,139,250,0.16); color: #a78bfa; }
.rb.ffi { background: rgba(251,146,60,0.16); color: #fb923c; }
.rb.unsafe { background: rgba(248,113,113,0.16); color: #f87171; }

table { width: 100%; border-collapse: collapse; margin-top: 10px; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #2a2f3a; }
th { color: #9aa0aa; font-weight: 500; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.hash { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.prod-push-bar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin: 14px 0 6px; }
.gh-accounts { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 10px; }
.acct-chip { display: inline-flex; align-items: center; gap: 6px; padding: 3px 6px 3px 10px; border-radius: 999px; background: #1e293b; border: 1px solid #334155; font-size: 13px; }
.acct-x { background: transparent; border: none; color: #94a3b8; cursor: pointer; font-size: 15px; line-height: 1; padding: 0 2px; }
.acct-x:hover { color: #f87171; }
.acct-label { max-width: 200px; }
.acct-tag { font-size: 11px; padding: 1px 7px; border-radius: 999px; background: #0b3b2e; color: #6ee7b7; border: 1px solid #155e47; }
.badge.fork { background: #3b2f0b; color: #fcd34d; border: 1px solid #5e4a15; }
.repolist-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.fork-toggle { font-size: 13px; color: #94a3b8; display: inline-flex; align-items: center; gap: 4px; cursor: pointer; white-space: nowrap; }
.area-tag { font-size: 11px; padding: 1px 8px; border-radius: 999px; white-space: nowrap; }
.area-tag.prod { background: #0b3b2e; color: #6ee7b7; border: 1px solid #155e47; }
.area-tag.staging { background: #2a2f3a; color: #94a3b8; border: 1px solid #3a4150; }
";
