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
mod service;

#[cfg(test)]
mod tests;

pub use error::ApiError;
pub use http::router;
pub use service::DeputyService;

// Re-export the identity types + verification entry point callers need to open a service. With
// mID active, build a `Session` by verifying a wallet token via [`verify`] + [`VerifyParams`];
// with mID deactivated, use [`DeputyService::open_local`].
pub use deputy_id::{verify, Session, VerifyParams};

// Re-export the SpaceDB Layer 5 capability vocabulary (for granting agent access).
pub use spacedb_access::{Capability, Did, Identity, Ops, Scope, SignedCapability};

use std::net::SocketAddr;
use std::sync::Arc;

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
