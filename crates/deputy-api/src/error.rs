use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use deputy_deploy::GateViolation;
use serde_json::json;

/// An API error with an HTTP status and a JSON body.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    pub detail: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            detail: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    /// The deploy gate blocked: 409 Conflict with the violations as structured detail.
    pub fn gate_blocked(violations: Vec<GateViolation>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: "deploy gate blocked".to_owned(),
            detail: Some(json!({
                "violations": violations
                    .iter()
                    .map(|v| json!({ "name": v.name, "version": v.version, "reason": v.reason }))
                    .collect::<Vec<_>>(),
            })),
        }
    }
}

impl From<deputy_core::Error> for ApiError {
    fn from(err: deputy_core::Error) -> Self {
        use deputy_core::Error;
        let status = match &err {
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::NotFound { .. } => StatusCode::NOT_FOUND,
            Error::Malformed { .. } | Error::IllegalTransition { .. } => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self::new(status, err.to_string())
    }
}

impl From<deputy_store::StoreError> for ApiError {
    fn from(err: deputy_store::StoreError) -> Self {
        ApiError::from(deputy_core::Error::from(err))
    }
}

impl From<deputy_id::IdError> for ApiError {
    fn from(err: deputy_id::IdError) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, err.to_string())
    }
}

impl From<spacedb_access::AccessError> for ApiError {
    fn from(err: spacedb_access::AccessError) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("access error: {err}"),
        )
    }
}

impl ApiError {
    /// A capability check denied the operation (403).
    pub fn forbidden(decision: spacedb_access::Decision) -> Self {
        let detail = match decision {
            spacedb_access::Decision::Deny(reason) => format!("{reason:?}"),
            spacedb_access::Decision::Allow => "allowed".to_owned(),
        };
        Self::new(
            StatusCode::FORBIDDEN,
            format!("capability denied: {detail}"),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({ "error": self.message, "detail": self.detail });
        (self.status, Json(body)).into_response()
    }
}
