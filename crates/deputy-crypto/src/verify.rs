use crate::aead::{open, seal};
use crate::derive::{derive_subkey, KeyDomain};
use crate::error::Result;
use crate::key::MasterKey;

const VERIFIER_PLAINTEXT: &[u8] = b"deputy-master-key-verifier-v1";
const VERIFIER_AAD: &[u8] = b"deputy:verifier:v1";

/// Produce a verifier blob that proves knowledge of `master`. It is safe to persist in the
/// clear: it is an AEAD sealing of a fixed constant under a derived verify-subkey and reveals
/// nothing about the key (`docs/STORAGE.md` §2).
pub fn make_verifier(master: &MasterKey) -> Result<Vec<u8>> {
    let key = derive_subkey(master, KeyDomain::Verify);
    seal(&key, VERIFIER_PLAINTEXT, VERIFIER_AAD)
}

/// Check a candidate master key against a stored verifier. Returns `true` iff `master` is the
/// key the verifier was made from — i.e. the passphrase was correct.
pub fn check_verifier(master: &MasterKey, verifier: &[u8]) -> bool {
    let key = derive_subkey(master, KeyDomain::Verify);
    matches!(open(&key, verifier, VERIFIER_AAD), Ok(pt) if pt == VERIFIER_PLAINTEXT)
}
