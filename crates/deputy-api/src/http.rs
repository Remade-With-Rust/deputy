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
    DepAnalytics, DeputyService, FolderScanReport, FolderSummary, HeartbeatReport,
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
        .route("/discover", post(discover))
        .route("/acquire", post(acquire))
        .route("/analyze", post(analyze))
        .route("/scan", post(scan))
        .route("/promote", post(promote))
        .route("/gate", post(gate))
        .route("/deploy", post(deploy))
        .route("/github/connect", post(github_connect))
        .route("/github/repos", get(github_repos))
        .route("/github/download", post(github_download))
        .route("/github/download/progress", get(download_progress))
        .route("/folders", get(folders))
        .route("/folders/delete", post(delete_folder))
        .route("/folders/scan", post(folder_scan))
        .route("/folders/scan-new-versions", post(folder_scan_new_versions))
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

async fn github_connect(
    State(svc): AppState,
    Json(req): Json<GitHubConnect>,
) -> Result<Json<Value>, ApiError> {
    svc.connect_github(req.token)?;
    Ok(Json(json!({ "connected": true })))
}

async fn github_repos(State(svc): AppState) -> Result<Json<Vec<Repo>>, ApiError> {
    let token = svc.github_token()?;
    let resp = reqwest::Client::new()
        .get("https://api.github.com/user/repos?per_page=100&sort=updated")
        .bearer_auth(&token)
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
            StatusCode::BAD_GATEWAY,
            format!("GitHub API returned {}", resp.status()),
        ));
    }
    resp.json::<Vec<Repo>>().await.map(Json).map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("GitHub response parse failed: {e}"),
        )
    })
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
