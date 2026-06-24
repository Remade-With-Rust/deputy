//! # deputy-id
//!
//! Deputy's authentication layer: MATA mID verification plus the out-of-band duties the
//! verifier leaves to the relying party. Implements `docs/AUTH.md`.
//!
//! - [`verify`] runs the cryptographic checks via MATA's vendored `mid-verify` reference and
//!   yields a [`Session`].
//! - [`Authenticator`] composes the full sign-in flow: verify → single-use **nonce**
//!   consumption ([`NonceStore`]) → genesis-**anchor** + rollback check ([`AnchorStore`]).
//!
//! mID is sign/verify-only and exports no secret, so a [`Session`] *authorizes* actions but
//! does not derive any encryption key — the at-rest key comes from a separate passphrase
//! (`deputy-crypto` / `deputy-store`). See `docs/AUTH.md` §8.
#![forbid(unsafe_code)]

mod anchor;
mod auth;
mod error;
mod nonce;
mod session;

#[cfg(test)]
mod tests;

pub use anchor::{AnchorStore, InMemoryAnchorStore};
pub use auth::Authenticator;
pub use error::IdError;
pub use nonce::{InMemoryNonceStore, NonceStore};
pub use session::{verify, Session, VerifyParams};

// The mID vocabulary callers need, re-exported so they depend only on `deputy-id`.
pub use mid_verify::{ClaimValue, VerifyError};
