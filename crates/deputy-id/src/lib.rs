//! # deputy-id
//!
//! Deputy's authentication layer: MATA mID verification plus the out-of-band duties the
//! verifier leaves to the relying party. Implements `docs/AUTH.md`.
//!
//! Since v0.3 this crate is a **thin adapter over the published
//! [`mid-signin`](https://crates.io/crates/mid-signin) relying-party kit** — the crate that
//! productized this module's original design (single-use nonces, genesis anchoring, rollback
//! detection composed around `mid-verify`). Deputy keeps its own crate for two reasons: the
//! stable `deputy-*` API surface (`Session`, `IdError`, a clock-owning [`Authenticator`]),
//! and the exact-pin trust-base policy (`=0.1.0`, per AUTH.md §10).
//!
//! - [`verify`] runs the cryptographic checks and yields a [`Session`].
//! - [`Authenticator`] composes the full sign-in flow: verify → single-use **nonce**
//!   consumption → genesis-**anchor** + rollback check.
//!
//! mID is sign/verify-only and exports no secret, so a [`Session`] *authorizes* actions but
//! does not derive any encryption key — the at-rest key comes from a separate passphrase
//! (`deputy-crypto` / `deputy-store`). See `docs/AUTH.md` §8.
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests;

// The mID vocabulary callers need, re-exported so they depend only on `deputy-id`.
// `Session` and `IdError` keep their historical Deputy names.
pub use mid_signin::{
    verify, AnchorStore, ClaimValue, InMemoryAnchorStore, InMemoryNonceStore, NonceStore,
    RpError as IdError, RpSession as Session, VerifyError, VerifyParams,
};

/// The full relying-party sign-in flow: cryptographic verification plus the out-of-band
/// duties it leaves to the relying party — single-use nonce enforcement and the
/// genesis-anchor / rollback checks (`docs/AUTH.md` §5, §9).
///
/// Wraps [`mid_signin::Authenticator`], owning the one impurity Deputy's callers expect:
/// [`Authenticator::issue_nonce`] reads the wall clock so issued nonces age out on the
/// kit's TTL. Verification time stays caller-supplied via [`VerifyParams`].
pub struct Authenticator(mid_signin::Authenticator);

impl Authenticator {
    /// Construct over explicit stores (e.g. persistent ones). One object may serve as both
    /// stores by cloning its `Arc`.
    pub fn new(nonces: Arc<dyn NonceStore>, anchors: Arc<dyn AnchorStore>) -> Self {
        Self(mid_signin::Authenticator::new(nonces, anchors))
    }

    /// A process-local authenticator backed by in-memory stores.
    pub fn in_memory() -> Self {
        Self(mid_signin::Authenticator::in_memory())
    }

    /// Issue a fresh single-use nonce to embed in a sign-in request.
    pub fn issue_nonce(&self) -> String {
        self.0
            .issue_nonce(now_unix())
            .expect("OS RNG must be available to issue a nonce")
    }

    /// Run the full flow and return the authenticated [`Session`]:
    ///
    /// 1. Verify the token cryptographically (signature, audience, nonce equality, expiry,
    ///    roster chain) — a failure here does **not** consume the nonce, so a legitimate retry
    ///    is possible.
    /// 2. Consume the expected nonce; if it was not live, reject as replay.
    /// 3. Check the DID's genesis anchor and version monotonicity.
    pub fn authenticate(&self, jwt: &str, params: &VerifyParams) -> Result<Session, IdError> {
        self.0.authenticate(jwt, params)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}
