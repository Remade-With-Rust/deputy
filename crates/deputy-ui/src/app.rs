//! The Dioxus single-page app (wasm32 only). A thin client of the Deputy API: it fetches JSON
//! from `deputy-api` and renders the session, the deploy gate, and the analysis dashboards.

use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde::Deserialize;

const API_BASE: &str = "http://127.0.0.1:7878";

pub fn launch() {
    dioxus::launch(App);
}

// ── API response types (mirror the deputy-api JSON) ──────────────────────────

#[derive(Deserialize, Clone, PartialEq)]
struct Health {
    status: String,
    did: String,
}

#[derive(Deserialize, Clone, PartialEq)]
enum GateResult {
    Allowed { cleared: usize },
    Blocked { violations: Vec<Violation> },
}

#[derive(Deserialize, Clone, PartialEq)]
struct Violation {
    name: String,
    version: String,
    reason: String,
}

#[derive(Deserialize, Clone, PartialEq)]
struct Analysis {
    language_report: LangReport,
    risks: Vec<Risk>,
    total_crates: usize,
    inspected: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct LangReport {
    by_language: BTreeMap<String, usize>,
    crates_analyzed: usize,
}

#[derive(Deserialize, Clone, PartialEq)]
struct Risk {
    name: String,
    version: String,
    blast_radius: usize,
    score: f64,
    reasons: Vec<String>,
    inspected: bool,
}

// ── API client (browser fetch via gloo-net) ──────────────────────────────────

async fn get_json<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T, String> {
    gloo_net::http::Request::get(&format!("{API_BASE}{path}"))
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<T>()
        .await
        .map_err(|e| e.to_string())
}

async fn post_source<T: for<'de> Deserialize<'de>>(path: &str, source: &str) -> Result<T, String> {
    gloo_net::http::Request::post(&format!("{API_BASE}{path}"))
        .json(&serde_json::json!({ "source": source }))
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json::<T>()
        .await
        .map_err(|e| e.to_string())
}

// ── Components ────────────────────────────────────────────────────────────────

#[component]
fn App() -> Element {
    let mut source = use_signal(|| ".".to_string());
    let mut health = use_signal(|| None::<Result<Health, String>>);
    let mut gate = use_signal(|| None::<Result<GateResult, String>>);
    let mut analysis = use_signal(|| None::<Result<Analysis, String>>);

    rsx! {
        style { {CSS} }
        div { class: "app",
            header {
                h1 { "Deputy" }
                p { class: "tag", "Your personally-owned, verified dependency vault." }
                div { class: "session",
                    {match &*health.read() {
                        Some(Ok(h)) => rsx! { span { class: "ok", "● signed in — {h.did}" } },
                        Some(Err(e)) => rsx! { span { class: "err", "● API offline — {e}" } },
                        None => rsx! { span { class: "muted", "not connected" } },
                    }}
                    button {
                        onclick: move |_| {
                            spawn(async move {
                                health.set(Some(get_json::<Health>("/health").await));
                            });
                        },
                        "Sign in with mID"
                    }
                }
            }

            section { class: "controls",
                label { "Source" }
                input {
                    value: "{source}",
                    oninput: move |e| source.set(e.value()),
                    placeholder: "repo directory or Cargo.lock path",
                }
                button {
                    onclick: move |_| {
                        let src = source();
                        spawn(async move { gate.set(Some(post_source::<GateResult>("/gate", &src).await)); });
                    },
                    "Run deploy gate"
                }
                button {
                    onclick: move |_| {
                        let src = source();
                        spawn(async move { analysis.set(Some(post_source::<Analysis>("/analyze", &src).await)); });
                    },
                    "Analyze"
                }
            }

            {match &*gate.read() {
                Some(result) => rsx! { GatePanel { result: result.clone() } },
                None => rsx! {},
            }}

            {match &*analysis.read() {
                Some(result) => rsx! { AnalysisPanel { result: result.clone() } },
                None => rsx! {},
            }}
        }
    }
}

#[component]
fn GatePanel(result: Result<GateResult, String>) -> Element {
    rsx! {
        section { class: "panel",
            h2 { "Deploy gate" }
            {match result {
                Ok(GateResult::Allowed { cleared }) => rsx! {
                    div { class: "verdict allowed", "✓ ALLOWED — {cleared} dependencies promoted, clean, and receipted" }
                },
                Ok(GateResult::Blocked { violations }) => rsx! {
                    div { class: "verdict blocked", "✗ BLOCKED — {violations.len()} violation(s)" }
                    ul { class: "violations",
                        for v in violations.iter() {
                            li { strong { "{v.name} {v.version}" } " — {v.reason}" }
                        }
                    }
                },
                Err(e) => rsx! { div { class: "err", "error: {e}" } },
            }}
        }
    }
}

#[component]
fn AnalysisPanel(result: Result<Analysis, String>) -> Element {
    rsx! {
        section { class: "panel",
            h2 { "Analysis" }
            {match result {
                Ok(a) => rsx! {
                    p { class: "muted", "{a.inspected} of {a.total_crates} crates inspected" }
                    h3 { "Languages" }
                    table { class: "lang",
                        for (lang, lines) in a.language_report.by_language.iter() {
                            tr { td { "{lang}" } td { class: "num", "{lines}" } }
                        }
                    }
                    h3 { "Critical points of failure" }
                    table { class: "risk",
                        tr { th { "score" } th { "crate" } th { "blast radius" } }
                        for r in a.risks.iter().take(12) {
                            tr {
                                td { class: "num", "{r.score:.1}" }
                                td { "{r.name} {r.version}" }
                                td { class: "num", "{r.blast_radius}" }
                            }
                        }
                    }
                },
                Err(e) => rsx! { div { class: "err", "error: {e}" } },
            }}
        }
    }
}

const CSS: &str = "
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, system-ui, sans-serif; background: #0f1115; color: #e6e6e6; }
.app { max-width: 880px; margin: 0 auto; padding: 24px; }
header h1 { margin: 0; color: #8b5cf6; }
.tag { color: #9aa0aa; margin: 4px 0 16px; }
.session { display: flex; gap: 12px; align-items: center; margin-bottom: 20px; }
.ok { color: #34d399; } .err { color: #f87171; } .muted { color: #9aa0aa; }
button { background: #8b5cf6; color: white; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; }
button:hover { background: #7c3aed; }
.controls { display: flex; gap: 10px; align-items: center; margin-bottom: 20px; }
.controls label { color: #9aa0aa; }
input { flex: 1; padding: 8px; border-radius: 6px; border: 1px solid #2a2f3a; background: #161922; color: #e6e6e6; }
.panel { background: #161922; border: 1px solid #2a2f3a; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.panel h2 { margin-top: 0; }
.verdict { padding: 10px; border-radius: 6px; font-weight: 600; }
.verdict.allowed { background: rgba(52,211,153,0.12); color: #34d399; }
.verdict.blocked { background: rgba(248,113,113,0.12); color: #f87171; }
.violations { margin: 10px 0 0; }
table { width: 100%; border-collapse: collapse; }
td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid #2a2f3a; }
th { color: #9aa0aa; font-weight: 500; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
";
