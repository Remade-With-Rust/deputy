use crate::error::{CryptoError, Result};
use crate::key::MasterKey;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Argon2id parameters and salt. These are **non-secret** and are persisted alongside a
/// verifier blob (see [`crate::make_verifier`]) so a wrong passphrase is detected without
/// ever storing the derived key (`docs/STORAGE.md` §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism.
    pub p_cost: u32,
    /// Per-device random salt.
    pub salt: [u8; 16],
}

impl KdfParams {
    /// Recommended parameters for a local vault: 64 MiB memory, 3 passes, 1 lane, with a
    /// fresh random salt.
    pub fn recommended() -> Result<Self> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| CryptoError::Random)?;
        Ok(Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
            salt,
        })
    }
}

/// Derive the 256-bit [`MasterKey`] from `passphrase` using Argon2id with the given `params`.
pub fn derive_master(passphrase: &[u8], params: &KdfParams) -> Result<MasterKey> {
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| CryptoError::Params(e.to_string()))?,
    );
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, &params.salt, &mut out)
        .map_err(|_| CryptoError::Kdf)?;
    let key = MasterKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}
