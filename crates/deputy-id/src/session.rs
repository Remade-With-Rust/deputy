use std::collections::BTreeMap;

use mid_verify::{verify_mid_response, ClaimValue, VerifiedMid, VerifyConfig};

use crate::error::IdError;

/// Relying-party verification parameters for a single sign-in.
#[derive(Debug, Clone)]
pub struct VerifyParams {
    /// Deputy's origin; must equal the token's `aud`.
    pub expected_audience: String,
    /// The single-use nonce Deputy issued for this sign-in; must equal the token's `nonce`.
    pub expected_nonce: String,
    /// Deputy's current wall-clock time, Unix seconds.
    pub now_unix_secs: u64,
    /// Maximum allowed forward clock skew on the token's `iat`, in seconds.
    pub max_iat_skew_secs: u64,
}

impl VerifyParams {
    /// Construct with the default 120s forward-skew allowance.
    pub fn new(
        expected_audience: impl Into<String>,
        expected_nonce: impl Into<String>,
        now_unix_secs: u64,
    ) -> Self {
        Self {
            expected_audience: expected_audience.into(),
            expected_nonce: expected_nonce.into(),
            now_unix_secs,
            max_iat_skew_secs: 120,
        }
    }
}

/// A verified mID identity for the current sign-in. Produced by [`verify`] / the
/// [`crate::Authenticator`]. Holds the user's DID, disclosed claims, and the anchoring data
/// (genesis hash + head version) the relying party must persist.
#[derive(Debug, Clone)]
pub struct Session {
    pub did: String,
    pub claims: BTreeMap<String, ClaimValue>,
    pub current_version: u64,
    pub genesis_roster_hash: [u8; 32],
    pub iat: u64,
    pub exp: u64,
    pub aud: String,
}

impl Session {
    fn from_verified(verified: VerifiedMid) -> Self {
        Self {
            did: verified.did,
            claims: verified.claims,
            current_version: verified.current_version,
            genesis_roster_hash: verified.genesis_roster_hash,
            iat: verified.iat,
            exp: verified.exp,
            aud: verified.aud,
        }
    }

    /// Whether the session is at or past its expiry at `now_unix_secs`.
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.exp
    }

    /// `Ok` if the session has not expired, else [`IdError::SessionExpired`].
    pub fn ensure_valid(&self, now_unix_secs: u64) -> Result<(), IdError> {
        if self.is_expired(now_unix_secs) {
            Err(IdError::SessionExpired {
                exp: self.exp,
                now: now_unix_secs,
            })
        } else {
            Ok(())
        }
    }

    /// A disclosed claim value by name (e.g. `"did"`, `"email"`).
    pub fn claim(&self, name: &str) -> Option<&ClaimValue> {
        self.claims.get(name)
    }
}

/// Run mID's cryptographic verification and produce a [`Session`].
///
/// This is the pure verification step. It does **not** enforce single-use of the nonce or the
/// genesis-anchor / rollback invariants — those are the relying party's duty and are handled
/// by [`crate::Authenticator::authenticate`].
pub fn verify(jwt: &str, params: &VerifyParams) -> Result<Session, IdError> {
    let config = VerifyConfig {
        expected_audience: params.expected_audience.clone(),
        expected_nonce: params.expected_nonce.clone(),
        max_iat_skew_secs: params.max_iat_skew_secs,
        now_unix_secs: params.now_unix_secs,
    };
    let verified = verify_mid_response(jwt, &config)?;
    Ok(Session::from_verified(verified))
}
