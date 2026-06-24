use mid_verify::VerifyError;

/// Errors from Deputy's authentication layer: a failed cryptographic verification, or a
/// failure of one of the relying-party duties (`docs/AUTH.md` §5).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The mID token failed cryptographic verification (signature, audience, nonce equality,
    /// expiry, roster chain, …). Wraps the underlying `mid-verify` error.
    #[error("mID verification failed: {0}")]
    Verify(#[from] VerifyError),

    /// The expected nonce was never issued, or was already consumed — a possible replay.
    #[error("nonce was not issued or has already been used (possible replay)")]
    NonceRejected,

    /// A known DID presented a different genesis roster than first recorded — possible
    /// identity spoofing.
    #[error("genesis roster mismatch for DID {did}: possible identity spoofing")]
    GenesisMismatch { did: String },

    /// The presented head-roster version is lower than the last seen — possible stolen-device
    /// rollback.
    #[error(
        "rollback detected for DID {did}: presented version {presented} < last seen {last_seen}"
    )]
    Rollback {
        did: String,
        presented: u64,
        last_seen: u64,
    },

    /// The session has passed its expiry.
    #[error("session expired: exp={exp}, now={now}")]
    SessionExpired { exp: u64, now: u64 },
}
