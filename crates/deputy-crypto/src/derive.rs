use crate::key::{MasterKey, SubKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Domain-separation labels for HKDF subkey derivation. The label is versioned, so changing
/// it deliberately rotates the derived key. Distinct domains guarantee that, e.g., the store
/// key can never decrypt metadata sealed under the metadata key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDomain {
    /// Seals dependency artifacts in the dirty/prod stores.
    Store,
    /// Seals the metadata database.
    Meta,
    /// Seals the audit log.
    Audit,
    /// Seals the master-key verifier blob.
    Verify,
}

impl KeyDomain {
    const fn info(self) -> &'static [u8] {
        match self {
            KeyDomain::Store => b"deputy:subkey:store:v1",
            KeyDomain::Meta => b"deputy:subkey:meta:v1",
            KeyDomain::Audit => b"deputy:subkey:audit:v1",
            KeyDomain::Verify => b"deputy:subkey:verify:v1",
        }
    }
}

/// Derive a domain-separated [`SubKey`] from the master key.
pub fn derive_subkey(master: &MasterKey, domain: KeyDomain) -> SubKey {
    expand(master.as_bytes(), domain.info())
}

/// Derive a per-artifact [`SubKey`] from the store subkey and the artifact's content hash, so
/// every artifact is sealed under a distinct key (`docs/STORAGE.md` §2). This makes random
/// 96-bit nonces collision-safe even across very large stores.
pub fn derive_artifact_subkey(store_key: &SubKey, content_hash: &[u8]) -> SubKey {
    const PREFIX: &[u8] = b"deputy:artifact:v1:";
    let mut info = Vec::with_capacity(PREFIX.len() + content_hash.len());
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(content_hash);
    let subkey = expand(store_key.as_bytes(), &info);
    info.zeroize();
    subkey
}

fn expand(ikm: &[u8], info: &[u8]) -> SubKey {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte output is within HKDF's 255*HashLen limit");
    let subkey = SubKey::from_bytes(okm);
    okm.zeroize();
    subkey
}
