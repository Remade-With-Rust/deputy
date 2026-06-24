use crate::anchor::{AnchorStore, InMemoryAnchorStore};
use crate::error::IdError;
use crate::nonce::{InMemoryNonceStore, NonceStore};
use crate::session::{verify, Session, VerifyParams};

/// The full relying-party sign-in flow: cryptographic verification (`mid-verify`) plus the
/// out-of-band duties it leaves to the relying party — single-use nonce enforcement and the
/// genesis-anchor / rollback checks (`docs/AUTH.md` §5, §9).
///
/// Backed by pluggable [`NonceStore`] and [`AnchorStore`]; [`Authenticator::in_memory`] wires
/// up the process-local implementations.
pub struct Authenticator {
    nonces: Box<dyn NonceStore>,
    anchors: Box<dyn AnchorStore>,
}

impl Authenticator {
    /// Construct over explicit stores (e.g. persistent ones).
    pub fn new(nonces: Box<dyn NonceStore>, anchors: Box<dyn AnchorStore>) -> Self {
        Self { nonces, anchors }
    }

    /// A process-local authenticator backed by in-memory stores.
    pub fn in_memory() -> Self {
        Self {
            nonces: Box::new(InMemoryNonceStore::new()),
            anchors: Box::new(InMemoryAnchorStore::new()),
        }
    }

    /// Issue a fresh single-use nonce to embed in a sign-in request.
    pub fn issue_nonce(&self) -> String {
        self.nonces.issue()
    }

    /// Run the full flow and return the authenticated [`Session`]:
    ///
    /// 1. Verify the token cryptographically (signature, audience, nonce equality, expiry,
    ///    roster chain) — a failure here does **not** consume the nonce, so a legitimate retry
    ///    is possible.
    /// 2. Consume the expected nonce; if it was not live, reject as replay.
    /// 3. Check the DID's genesis anchor and version monotonicity.
    pub fn authenticate(&self, jwt: &str, params: &VerifyParams) -> Result<Session, IdError> {
        let session = verify(jwt, params)?;
        if !self.nonces.consume(&params.expected_nonce) {
            return Err(IdError::NonceRejected);
        }
        self.anchors.check_and_update(
            &session.did,
            &session.genesis_roster_hash,
            session.current_version,
        )?;
        Ok(session)
    }
}
