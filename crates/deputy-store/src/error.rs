/// Convenience alias for fallible store operations.
pub type Result<T> = core::result::Result<T, StoreError>;

/// Errors from the storage layer. Richer than [`deputy_core::Error`]; it converts into the
/// core error (via `From`) at the API boundary, preserving a human-readable detail.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] deputy_crypto::CryptoError),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Db(String),

    #[error("integrity check failed: stored bytes do not match their content address")]
    Integrity,

    #[error("not found: {0}")]
    NotFound(String),

    #[error("audit log chain broken at sequence {seq}")]
    AuditChain { seq: u64 },

    #[error("a vault is already initialized at this path")]
    AlreadyInitialized,

    #[error("no vault is initialized at this path")]
    NotInitialized,

    #[error("wrong passphrase")]
    WrongPassphrase,

    #[error("malformed stored data: {0}")]
    Malformed(String),

    #[error("snapshot error: {0}")]
    Snapshot(String),

    #[error("sync error: {0}")]
    Sync(String),
}

impl From<StoreError> for deputy_core::Error {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Integrity => deputy_core::Error::Integrity {
                expected: "content address".to_owned(),
                actual: "stored bytes".to_owned(),
            },
            StoreError::WrongPassphrase => deputy_core::Error::Unauthorized,
            StoreError::NotFound(what) => deputy_core::Error::NotFound { what },
            StoreError::Malformed(what) => deputy_core::Error::Malformed { what },
            other => deputy_core::Error::Backend {
                detail: other.to_string(),
            },
        }
    }
}
