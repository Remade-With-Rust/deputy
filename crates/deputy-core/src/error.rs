use std::fmt;

/// Convenience alias for fallible Deputy operations.
pub type Result<T> = std::result::Result<T, Error>;

/// The error surface shared across Deputy. Kept small and `#[non_exhaustive]` so new
/// variants can be added without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An artifact was asked to move along an edge the state machine does not permit.
    /// See `docs/PIPELINE.md` §7.
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },
    /// A downloaded artifact's content hash did not match its pinned, expected hash.
    Integrity { expected: String, actual: String },
    /// A referenced entity (artifact, repo, record) was not found.
    NotFound { what: String },
    /// The current actor lacks a valid mID session for a privileged operation.
    Unauthorized,
    /// Input could not be parsed into a well-formed domain value.
    Malformed { what: String },
    /// A lower layer (storage, database, crypto, I/O) failed. Carries a human-readable
    /// detail; the originating crate keeps the richer typed error.
    Backend { detail: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::IllegalTransition { from, to } => {
                write!(f, "illegal state transition: {from} -> {to}")
            }
            Error::Integrity { expected, actual } => {
                write!(
                    f,
                    "integrity check failed: expected {expected}, got {actual}"
                )
            }
            Error::NotFound { what } => write!(f, "not found: {what}"),
            Error::Unauthorized => f.write_str("unauthorized: a verified mID session is required"),
            Error::Malformed { what } => write!(f, "malformed input: {what}"),
            Error::Backend { detail } => write!(f, "backend error: {detail}"),
        }
    }
}

impl std::error::Error for Error {}
