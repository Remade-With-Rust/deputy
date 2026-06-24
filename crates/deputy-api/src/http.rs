use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use deputy_acquire::AcquireReport;
use deputy_analyze::AnalysisReport;
use deputy_core::Pin;
use deputy_deploy::{GateDecision, MaterializePlan, Promotion};
use deputy_scan::ScanReport;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;

use crate::error::ApiError;
use crate::service::DeputyService;

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
