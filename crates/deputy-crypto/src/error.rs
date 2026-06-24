/// Convenience alias for fallible crypto operations.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Errors from key derivation and authenticated encryption. Deliberately coarse: decryption
/// failures do not distinguish "wrong key" from "tampered ciphertext" from "wrong AAD", to
/// avoid handing an attacker an oracle.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("invalid Argon2 parameters: {0}")]
    Params(String),
    #[error("key derivation failed")]
    Kdf,
    #[error("secure random source failed")]
    Random,
    #[error("sealed data is malformed (too short)")]
    Malformed,
    #[error("authenticated encryption failed")]
    Seal,
    #[error("decryption or authentication failed")]
    Open,
}
