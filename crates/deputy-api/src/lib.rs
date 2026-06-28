//! # deputy-api
//!
//! Deputy's API-first surface (`docs/ARCHITECTURE.md` §6). [`DeputyService`] is the canonical
//! in-process capability layer — the CLI, the HTTP server, and the UI all drive the same
//! methods. [`serve`] exposes it as a localhost HTTP/JSON server.
//!
//! Opening the service is **mID-gated**: a valid [`deputy_id::Session`] authorizes the vault
//! unlock, while the passphrase derives the at-rest key (`docs/AUTH.md` §8) — the
//! session↔unlock composition deferred from M2 lands here.
#![forbid(unsafe_code)]

mod error;
mod http;
mod rustsec;
mod service;

#[cfg(test)]
mod tests;

pub use error::ApiError;
pub use http::router;
pub use service::{DeputyService, LOCAL_DID};

// Re-export the identity types + verification entry point callers need to open a service. With
// mID active, build a `Session` by verifying a wallet token via [`verify`] + [`VerifyParams`];
// with mID deactivated, use [`DeputyService::open_local`].
pub use deputy_id::{verify, Session, VerifyParams};

// Re-export the SpaceDB Layer 5 capability vocabulary (for granting agent access).
pub use spacedb_access::{Capability, Did, Identity, Ops, Scope, SignedCapability};

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Deputy's default vault directory (`<home>/.deputy`), resolved cross-platform.
///
/// Honors `$DEPUTY_VAULT` first; otherwise the platform home — `$HOME` on Unix, falling back to
/// `%USERPROFILE%` / `%APPDATA%` on Windows. Returns `None` only when none are set (pass an
/// explicit path then).
pub fn default_vault_dir() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("DEPUTY_VAULT") {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .or_else(|| std::env::var_os("APPDATA"))
        .map(|home| PathBuf::from(home).join(".deputy"))
}

/// Open a **local-identity** service at `dir`, creating the vault on first run (mID deactivated —
/// the *embed / off* mode). One-call convenience for embedding the API in software that already
/// owns its auth + encryption. Access is gated by the passphrase only; the vault is **not** bound
/// to an mID identity and is unlocked immediately.
pub fn open_or_create_local(dir: &Path, passphrase: &[u8]) -> Result<DeputyService, ApiError> {
    DeputyService::open_local(dir, passphrase)
}

/// Open an **mID-gated** service at `dir` (the secure default). The vault stays sealed until an mID
/// sign-in supplies a verified DID, then unlocks **bound to that identity** — so a different mID can
/// never open it, and no vault data is reachable before sign-in. Created on first sign-in.
pub fn open_gated(dir: &Path, passphrase: &[u8]) -> Result<DeputyService, ApiError> {
    DeputyService::open_gated_locked(dir, passphrase)
}

/// Serve the API on `addr`. Bind to loopback (e.g. `127.0.0.1`) — this is a personal,
/// local-only tool and must never be exposed to the network by default.
pub async fn serve(service: DeputyService, addr: SocketAddr) -> std::io::Result<()> {
    let app = router(Arc::new(service));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

/// Build a multi-thread runtime and [`serve`], blocking the current thread.
pub fn serve_blocking(service: DeputyService, addr: SocketAddr) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(service, addr))
}
