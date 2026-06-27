use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use deputy_acquire::AcquireReport;
use deputy_analyze::AnalysisReport;
use deputy_core::Pin;
use deputy_deploy::{GateDecision, MaterializePlan, Promotion};
use deputy_scan::ScanReport;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;

use crate::error::ApiError;
use crate::service::{
    CoverageReport, DepAnalytics, DeputyService, FolderScanReport, FolderSummary, HeartbeatReport,
    NewVersionReport, ProdDep,
};

type AppState = State<Arc<DeputyService>>;

#[derive(Deserialize)]
struct SourceRequest {
    source: String,
}

#[derive(Deserialize)]
struct DeployRequest {
    source: String,
    into: String,
}

#[derive(Deserialize)]
struct GitHubConnect {
    token: String,
    /// Human label for this account (e.g. "Work"). Defaults to the GitHub login if empty.
    #[serde(default)]
    label: String,
    /// Optional org/user to scope the repo listing to. Empty = the token user's affiliations.
    #[serde(default)]
    owner: String,
}

#[derive(Deserialize)]
struct GitHubDisconnect {
    label: String,
}

#[derive(Deserialize)]
struct DownloadRequest {
    folder: String,
    repos: Vec<String>,
}

#[derive(Deserialize)]
struct DeleteFolder {
    name: String,
}

#[derive(Deserialize)]
struct ScanFolder {
    name: String,
}

#[derive(Deserialize)]
struct AnalyticsRequest {
    name: String,
}

#[derive(Deserialize)]
struct DepRef {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct PromoteRequest {
    name: String,
    /// Dependencies to hold back in staging (everything else clean is pushed to production).
    #[serde(default)]
    hold: Vec<DepRef>,
}

/// A GitHub repository, as surfaced to the UI (a subset of the GitHub REST `repo` object —
/// extra fields are ignored on deserialize).
#[derive(Serialize, Deserialize)]
struct Repo {
    full_name: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    fork: bool,
    /// Which connected account this repo came from (filled in by `github_repos`).
    #[serde(default)]
    connection: String,
}

/// Build the API router. Every handler shares one unlocked [`DeputyService`].
///
/// Note: the service methods are synchronous (network/disk/Argon2); for a personal localhost
/// tool calling them inline is acceptable. CORS is permissive so the local UI dev server can
/// reach it.
pub fn router(service: Arc<DeputyService>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/session", get(session))
        .route("/auth/challenge", get(auth_challenge))
        .route("/auth/verify", post(auth_verify))
        .route("/discover", post(discover))
        .route("/acquire", post(acquire))
        .route("/analyze", post(analyze))
        .route("/scan", post(scan))
        .route("/promote", post(promote))
        .route("/gate", post(gate))
        .route("/deploy", post(deploy))
        .route("/github/connect", post(github_connect))
        .route("/github/disconnect", post(github_disconnect))
        .route("/github/connections", get(github_connections))
        .route("/github/repos", get(github_repos))
        .route("/github/download", post(github_download))
        .route("/github/download/progress", get(download_progress))
        .route("/folders", get(folders))
        .route("/folders/delete", post(delete_folder))
        .route("/folders/scan", post(folder_scan))
        .route("/folders/scan-new-versions", post(folder_scan_new_versions))
        .route("/folders/coverage", post(folder_coverage))
        .route("/folders/analytics", post(folder_analytics))
        .route("/folders/heartbeat", post(folder_heartbeat))
        .route("/folders/promote", post(folder_promote))
        .route("/production", get(production))
        .route("/advisories", get(advisory_count))
        .route("/advisories/rustsec", post(load_rustsec))
        .layer(CorsLayer::permissive())
        .with_state(service)
}

async fn health(State(svc): AppState) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "did": svc.session().did,
        "mid_active": svc.mid_active(),
    }))
}

#[derive(Deserialize)]
struct AuthVerify {
    /// The wallet's mID token (compact JWS) as returned by the MATA extension.
    token: String,
    /// The nonce from the matching `/auth/challenge`, echoed back so we consume the right one.
    nonce: String,
    /// The page's real origin (`window.location.origin`) the wallet bound the token's `aud` to.
    #[serde(default)]
    audience: String,
}

/// Issue a single-use sign-in challenge: the nonce the wallet embeds + the audience its token's
/// `aud` must equal. The browser hands these to the MATA extension to sign.
async fn auth_challenge(State(svc): AppState) -> Json<Value> {
    let (nonce, audience) = svc.issue_challenge();
    Json(json!({ "nonce": nonce, "audience": audience }))
}

/// Verify the extension's signed token and, on success, make its mID the acting principal.
async fn auth_verify(
    State(svc): AppState,
    Json(req): Json<AuthVerify>,
) -> Result<Json<Value>, ApiError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = svc.sign_in(&req.token, &req.nonce, &req.audience, now)?;
    Ok(Json(json!({
        "status": "ok",
        "did": s.did,
        "exp": s.exp,
        "mid_active": svc.mid_active(),
    })))
}

async fn session(State(svc): AppState) -> Json<Value> {
    let s = svc.session();
    Json(json!({
        "did": s.did,
        "exp": s.exp,
        "current_version": s.current_version,
        "claims": s.claims.keys().collect::<Vec<_>>(),
    }))
}

async fn discover(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<Vec<Pin>>, ApiError> {
    Ok(Json(svc.discover(&req.source)?))
}

async fn acquire(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<AcquireReport>, ApiError> {
    Ok(Json(svc.acquire(&req.source)?))
}

async fn analyze(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<AnalysisReport>, ApiError> {
    Ok(Json(svc.analyze(&req.source)?))
}

async fn scan(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<Vec<ScanReport>>, ApiError> {
    Ok(Json(svc.scan(&req.source)?))
}

async fn promote(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<Vec<Promotion>>, ApiError> {
    Ok(Json(svc.promote(&req.source)?))
}

async fn gate(
    State(svc): AppState,
    Json(req): Json<SourceRequest>,
) -> Result<Json<GateDecision>, ApiError> {
    Ok(Json(svc.gate(&req.source)?))
}

async fn deploy(
    State(svc): AppState,
    Json(req): Json<DeployRequest>,
) -> Result<Json<MaterializePlan>, ApiError> {
    Ok(Json(svc.deploy(&req.source, &req.into)?))
}

/// Fetch the login for a PAT — both validates the token and gives us a default account label.
async fn github_login(token: &str) -> Result<String, ApiError> {
    let resp = reqwest::Client::new()
        .get("https://api.github.com/user")
        .bearer_auth(token)
        .header("User-Agent", "deputy")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("GitHub request failed: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("GitHub rejected the token ({})", resp.status()),
        ));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, format!("GitHub parse failed: {e}")))?;
    Ok(body
        .get("login")
        .and_then(|l| l.as_str())
        .unwrap_or("GitHub")
        .to_owned())
}

async fn github_connect(
    State(svc): AppState,
    Json(req): Json<GitHubConnect>,
) -> Result<Json<Value>, ApiError> {
    // Validate the PAT up front and use its login as the label when none was given.
    let login = github_login(&req.token).await?;
    // Label preference: explicit label > owner (so org repos read as the org) > login.
    let label = match (req.label.trim(), req.owner.trim()) {
        (l, _) if !l.is_empty() => l.to_owned(),
        (_, o) if !o.is_empty() => o.to_owned(),
        _ => login.clone(),
    };
    svc.connect_github(label.clone(), req.token, req.owner)?;
    Ok(Json(
        json!({ "connected": true, "label": label, "login": login }),
    ))
}

async fn github_disconnect(
    State(svc): AppState,
    Json(req): Json<GitHubDisconnect>,
) -> Result<Json<Value>, ApiError> {
    svc.disconnect_github(&req.label)?;
    Ok(Json(json!({ "disconnected": true })))
}

async fn github_connections(State(svc): AppState) -> Result<Json<Vec<String>>, ApiError> {
    Ok(Json(svc.github_connection_labels()?))
}

/// Fetch + parse one repo-listing page. `None` on any failure, so callers can fall back or skip.
async fn fetch_repos(client: &reqwest::Client, token: &str, url: &str) -> Option<Vec<Repo>> {
    let resp = client
        .get(url)
        .bearer_auth(token)
        .header("User-Agent", "deputy")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Vec<Repo>>().await.ok()
}

/// Repos across every connected account, each tagged with its account label.
///
/// When a connection sets an `owner`, the listing is scoped to that org's repos
/// (`GET /orgs/{owner}/repos`) — or, if `owner` isn't an org, the token user's own repos. This
/// avoids GitHub's `/user/repos`, which lists by the *user's* affiliations and so returns the same
/// cross-org firehose for every token the same person created. One account's failure (e.g. an
/// expired token) is skipped rather than blocking the whole list.
async fn github_repos(State(svc): AppState) -> Result<Json<Vec<Repo>>, ApiError> {
    let conns = svc.github_connections()?;
    let client = reqwest::Client::new();
    let mut all: Vec<Repo> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for conn in conns {
        let repos = if conn.owner.is_empty() {
            fetch_repos(
                &client,
                &conn.token,
                "https://api.github.com/user/repos?per_page=100&sort=updated",
            )
            .await
        } else {
            // Try the owner as an org; if it isn't one (404), fall back to the token user's repos.
            let org_url = format!(
                "https://api.github.com/orgs/{}/repos?per_page=100&type=all",
                conn.owner
            );
            match fetch_repos(&client, &conn.token, &org_url).await {
                Some(repos) => Some(repos),
                None => {
                    fetch_repos(
                        &client,
                        &conn.token,
                        "https://api.github.com/user/repos?per_page=100&affiliation=owner",
                    )
                    .await
                }
            }
        };
        let Some(repos) = repos else {
            continue;
        };
        for mut r in repos {
            if seen.insert(r.full_name.clone()) {
                r.connection = conn.label.clone();
                all.push(r);
            }
        }
    }
    Ok(Json(all))
}

async fn github_download(
    State(svc): AppState,
    Json(req): Json<DownloadRequest>,
) -> Result<Json<FolderSummary>, ApiError> {
    Ok(Json(svc.download_repos(req.folder, req.repos).await?))
}

async fn download_progress(State(svc): AppState) -> Json<Value> {
    match svc.download_progress() {
        Some((done, total)) => Json(json!({ "done": done, "total": total })),
        None => Json(Value::Null),
    }
}

async fn folders(State(svc): AppState) -> Result<Json<Vec<FolderSummary>>, ApiError> {
    Ok(Json(svc.folders()?))
}

async fn delete_folder(
    State(svc): AppState,
    Json(req): Json<DeleteFolder>,
) -> Result<Json<Value>, ApiError> {
    svc.delete_folder(&req.name)?;
    Ok(Json(json!({ "deleted": true })))
}

async fn folder_scan(
    State(svc): AppState,
    Json(req): Json<ScanFolder>,
) -> Result<Json<FolderScanReport>, ApiError> {
    Ok(Json(svc.scan_folder(req.name).await?))
}

async fn folder_analytics(
    State(svc): AppState,
    Json(req): Json<AnalyticsRequest>,
) -> Result<Json<DepAnalytics>, ApiError> {
    Ok(Json(svc.folder_analytics(req.name).await?))
}

async fn folder_scan_new_versions(
    State(svc): AppState,
    Json(req): Json<AnalyticsRequest>,
) -> Result<Json<NewVersionReport>, ApiError> {
    Ok(Json(svc.scan_new_versions(req.name).await?))
}

async fn folder_coverage(
    State(svc): AppState,
    Json(req): Json<AnalyticsRequest>,
) -> Result<Json<CoverageReport>, ApiError> {
    Ok(Json(svc.folder_coverage(req.name).await?))
}

async fn folder_heartbeat(
    State(svc): AppState,
    Json(req): Json<AnalyticsRequest>,
) -> Result<Json<HeartbeatReport>, ApiError> {
    Ok(Json(svc.folder_heartbeat(req.name).await?))
}

async fn folder_promote(
    State(svc): AppState,
    Json(req): Json<PromoteRequest>,
) -> Result<Json<Value>, ApiError> {
    let hold = req.hold.into_iter().map(|d| (d.name, d.version)).collect();
    Ok(Json(
        json!({ "promoted": svc.promote_folder(req.name, hold).await? }),
    ))
}

async fn production(State(svc): AppState) -> Result<Json<Vec<ProdDep>>, ApiError> {
    Ok(Json(svc.production_deps()?))
}

async fn advisory_count(State(svc): AppState) -> Json<Value> {
    Json(json!({ "advisories": svc.advisory_count() }))
}

async fn load_rustsec(State(svc): AppState) -> Result<Json<Value>, ApiError> {
    let count = svc.load_rustsec_advisories().await?;
    Ok(Json(json!({ "advisories": count })))
}
