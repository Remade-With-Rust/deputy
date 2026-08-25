//! GitHub sign-in without pasting a PAT.
//!
//! Two paths, same result (a user-to-server token stored like today's connections):
//!
//! 1. **Device flow** when `DEPUTY_GITHUB_CLIENT_ID` is set (an OAuth App with Device Flow
//!    enabled). Deputy opens GitHub's approve page; no client secret is required.
//! 2. **GitHub CLI** (`gh auth login --web`) when no client id is configured but `gh` is on
//!    PATH — the same browser-approve UX, using the CLI's already-registered app.
//!
//! The token is then handed to [`crate::DeputyService::connect_github`].

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Classic scopes: private repo contents (Cargo.lock) + org listing + login.
pub const GITHUB_SCOPES: &str = "repo read:org read:user";

const DEVICE_CODE_URL: &str = "https://github.com/login/device/code";
const ACCESS_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// How we will ask GitHub for a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OauthPlan {
    Device { client_id: String },
    GhCli,
    Unavailable,
}

/// In-flight browser approval, held on the service until poll finishes or expires.
#[derive(Debug, Clone)]
pub enum PendingGithubOauth {
    Device {
        client_id: String,
        device_code: String,
        owner: String,
        expires_at: Instant,
    },
    Gh {
        owner: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct OauthStart {
    /// `device`, `gh`, or `connected` (already had a `gh` session — no browser hop).
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default = "default_expires")]
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_expires() -> u64 {
    900
}
fn default_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// `DEPUTY_GITHUB_CLIENT_ID` — public id of a GitHub OAuth App with Device Flow enabled.
pub fn github_client_id() -> Option<String> {
    std::env::var("DEPUTY_GITHUB_CLIENT_ID")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

pub fn oauth_plan(client_id: Option<String>, gh_on_path: bool) -> OauthPlan {
    match client_id {
        Some(id) => OauthPlan::Device { client_id: id },
        None if gh_on_path => OauthPlan::GhCli,
        None => OauthPlan::Unavailable,
    }
}

pub fn gh_available() -> bool {
    gh_cmd()
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn gh_auth_token() -> Result<String, String> {
    let out = gh_cmd()
        .args(["auth", "token"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("could not run gh: {e}"))?;
    if !out.status.success() {
        return Err("GitHub CLI is not signed in".to_owned());
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if token.is_empty() {
        return Err("GitHub CLI returned an empty token".to_owned());
    }
    Ok(token)
}

/// Open GitHub's approve page via `gh auth login --web`. Non-blocking.
pub fn spawn_gh_login() -> Result<(), String> {
    gh_cmd()
        .args([
            "auth",
            "login",
            "--hostname",
            "github.com",
            "--git-protocol",
            "https",
            "--web",
            "--scopes",
            "repo,read:org,read:user",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not start GitHub CLI sign-in: {e}"))
}

fn gh_cmd() -> Command {
    let mut cmd = Command::new("gh");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

pub struct DeviceStart {
    pub start: OauthStart,
    pub device_code: String,
    pub expires_in: u64,
}

pub async fn request_device_code(client_id: &str) -> Result<DeviceStart, ApiError> {
    let body = format!("client_id={}&scope={}", pct(client_id), pct(GITHUB_SCOPES));
    let resp = reqwest::Client::new()
        .post(DEVICE_CODE_URL)
        .header("Accept", "application/json")
        .header("User-Agent", "deputy")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("GitHub device-code request failed: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("GitHub device-code request rejected ({})", resp.status()),
        ));
    }
    let parsed: DeviceCodeResponse = resp.json().await.map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("GitHub device-code parse failed: {e}"),
        )
    })?;
    let uri = parsed
        .verification_uri_complete
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}?user_code={}",
                parsed.verification_uri.trim_end_matches('/'),
                parsed.user_code
            )
        });
    Ok(DeviceStart {
        start: OauthStart {
            method: "device".to_owned(),
            verification_uri: Some(uri),
            user_code: Some(parsed.user_code),
            interval: Some(parsed.interval.max(5)),
            label: None,
            message: Some("Approve Deputy in the GitHub tab that just opened.".to_owned()),
        },
        device_code: parsed.device_code,
        expires_in: parsed.expires_in,
    })
}

pub fn device_pending(
    client_id: String,
    device_code: String,
    owner: String,
    expires_in: u64,
) -> PendingGithubOauth {
    PendingGithubOauth::Device {
        client_id,
        device_code,
        owner,
        expires_at: Instant::now() + Duration::from_secs(expires_in.max(60)),
    }
}

pub async fn poll_device_token(client_id: &str, device_code: &str) -> Result<DevicePoll, ApiError> {
    let body = format!(
        "client_id={}&device_code={}&grant_type={}",
        pct(client_id),
        pct(device_code),
        pct(GRANT_TYPE)
    );
    let resp = reqwest::Client::new()
        .post(ACCESS_TOKEN_URL)
        .header("Accept", "application/json")
        .header("User-Agent", "deputy")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("GitHub token poll failed: {e}"),
            )
        })?;
    let parsed: AccessTokenResponse = resp.json().await.map_err(|e| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("GitHub token poll parse failed: {e}"),
        )
    })?;
    Ok(classify_token_response(
        parsed.access_token,
        parsed.error,
        parsed.error_description,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    Token(String),
    Pending,
    Denied,
    Expired,
    Error(String),
}

pub fn classify_token_response(
    access_token: Option<String>,
    error: Option<String>,
    description: Option<String>,
) -> DevicePoll {
    if let Some(token) = access_token.filter(|t| !t.is_empty()) {
        return DevicePoll::Token(token);
    }
    match error.as_deref() {
        Some("authorization_pending") | Some("slow_down") | None => DevicePoll::Pending,
        Some("access_denied") => DevicePoll::Denied,
        Some("expired_token") => DevicePoll::Expired,
        Some(other) => DevicePoll::Error(
            description
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| other.to_owned()),
        ),
    }
}

pub fn unavailable_message() -> String {
    "Set DEPUTY_GITHUB_CLIENT_ID (a GitHub OAuth App with Device Flow enabled) or install the GitHub CLI (`gh`) and run Connect again. You can still paste a PAT below.".to_owned()
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_prefers_device_flow_when_a_client_id_is_set() {
        assert_eq!(
            oauth_plan(Some("Iv1.abc".to_owned()), true),
            OauthPlan::Device {
                client_id: "Iv1.abc".to_owned()
            }
        );
    }

    #[test]
    fn plan_falls_back_to_gh_cli() {
        assert_eq!(oauth_plan(None, true), OauthPlan::GhCli);
    }

    #[test]
    fn plan_unavailable_without_client_id_or_gh() {
        assert_eq!(oauth_plan(None, false), OauthPlan::Unavailable);
    }

    #[test]
    fn classify_pending_and_success() {
        assert_eq!(
            classify_token_response(None, Some("authorization_pending".into()), None),
            DevicePoll::Pending
        );
        assert_eq!(
            classify_token_response(Some("gho_x".into()), None, None),
            DevicePoll::Token("gho_x".into())
        );
        assert_eq!(
            classify_token_response(None, Some("access_denied".into()), None),
            DevicePoll::Denied
        );
        assert_eq!(
            classify_token_response(None, Some("expired_token".into()), None),
            DevicePoll::Expired
        );
    }

    #[test]
    fn pct_encodes_spaces_in_scope() {
        assert_eq!(pct("repo read:org"), "repo%20read%3Aorg");
    }
}
