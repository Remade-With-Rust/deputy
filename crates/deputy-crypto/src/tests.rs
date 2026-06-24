//! Behavioural + adversarial tests for the crypto primitives: round-trips, wrong-key /
//! tamper / wrong-AAD rejection, KDF determinism, domain separation, and the verifier.

use crate::key::SubKey;
use crate::{
    check_verifier, derive_artifact_subkey, derive_master, derive_subkey, make_verifier, open,
    seal, CryptoError, KdfParams, KeyDomain,
};

/// Fast Argon2id params for tests (real strength is exercised once in
/// [`recommended_params_are_valid`]).
fn fast_params(salt: [u8; 16]) -> KdfParams {
    KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
        salt,
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).unwrap();
    b
}

fn random_subkey() -> SubKey {
    SubKey::from_bytes(random_bytes::<32>())
}

#[test]
fn seal_open_roundtrip() {
    let key = random_subkey();
    let pt = b"hello deputy";
    let aad = b"context";
    let sealed = seal(&key, pt, aad).unwrap();
    assert!(
        sealed.len() >= pt.len() + 12 + 16,
        "expect nonce + ct + tag"
    );
    assert_eq!(open(&key, &sealed, aad).unwrap(), pt);
}

#[test]
fn seal_is_nondeterministic() {
    let key = random_subkey();
    let a = seal(&key, b"same", b"").unwrap();
    let b = seal(&key, b"same", b"").unwrap();
    assert_ne!(a, b, "random nonce must make repeated seals differ");
}

#[test]
fn wrong_key_fails_to_open() {
    let sealed = seal(&random_subkey(), b"secret", b"").unwrap();
    assert!(matches!(
        open(&random_subkey(), &sealed, b""),
        Err(CryptoError::Open)
    ));
}

#[test]
fn tampered_ciphertext_fails() {
    let key = random_subkey();
    let mut sealed = seal(&key, b"secret data", b"").unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    assert!(matches!(open(&key, &sealed, b""), Err(CryptoError::Open)));
}

#[test]
fn wrong_aad_fails() {
    let key = random_subkey();
    let sealed = seal(&key, b"data", b"aad-1").unwrap();
    assert!(matches!(
        open(&key, &sealed, b"aad-2"),
        Err(CryptoError::Open)
    ));
}

#[test]
fn too_short_blob_is_malformed() {
    let key = random_subkey();
    assert!(matches!(
        open(&key, &[0u8; 10], b""),
        Err(CryptoError::Malformed)
    ));
}

#[test]
fn kdf_is_deterministic_and_passphrase_sensitive() {
    let params = fast_params([3u8; 16]);
    let mk = derive_master(b"correct horse battery staple", &params).unwrap();
    let verifier = make_verifier(&mk).unwrap();

    let mk_again = derive_master(b"correct horse battery staple", &params).unwrap();
    assert!(
        check_verifier(&mk_again, &verifier),
        "same passphrase + params => same key"
    );

    let wrong = derive_master(b"Tr0ub4dor&3", &params).unwrap();
    assert!(
        !check_verifier(&wrong, &verifier),
        "wrong passphrase must fail the verifier"
    );
}

#[test]
fn different_salt_changes_key() {
    let mk_a = derive_master(b"pw", &fast_params([1u8; 16])).unwrap();
    let mk_b = derive_master(b"pw", &fast_params([2u8; 16])).unwrap();
    let verifier = make_verifier(&mk_a).unwrap();
    assert!(!check_verifier(&mk_b, &verifier));
}

#[test]
fn domains_are_separated() {
    let mk = derive_master(b"pw", &fast_params([9u8; 16])).unwrap();
    let store = derive_subkey(&mk, KeyDomain::Store);
    let meta = derive_subkey(&mk, KeyDomain::Meta);
    let sealed = seal(&store, b"artifact", b"").unwrap();
    assert!(
        matches!(open(&meta, &sealed, b""), Err(CryptoError::Open)),
        "the metadata key must not open store-sealed data"
    );
}

#[test]
fn artifact_subkeys_differ_by_content_hash() {
    let mk = derive_master(b"pw", &fast_params([5u8; 16])).unwrap();
    let store = derive_subkey(&mk, KeyDomain::Store);
    let key_a = derive_artifact_subkey(&store, b"hash-A");
    let key_b = derive_artifact_subkey(&store, b"hash-B");

    let sealed = seal(&key_a, b"data", b"").unwrap();
    assert!(matches!(open(&key_b, &sealed, b""), Err(CryptoError::Open)));

    // Same content hash re-derives the same key.
    let key_a2 = derive_artifact_subkey(&store, b"hash-A");
    assert_eq!(open(&key_a2, &sealed, b"").unwrap(), b"data");
}

#[test]
fn recommended_params_are_valid() {
    let params = KdfParams::recommended().unwrap();
    let mk = derive_master(b"a strong passphrase", &params).unwrap();
    let verifier = make_verifier(&mk).unwrap();
    assert!(check_verifier(&mk, &verifier));
}

#[test]
fn randomized_roundtrips() {
    for i in 0..32usize {
        let key = random_subkey();
        let mut pt = vec![0u8; i * 3 + 1];
        getrandom::fill(&mut pt).unwrap();
        let aad = random_bytes::<8>();
        let sealed = seal(&key, &pt, &aad).unwrap();
        assert_eq!(open(&key, &sealed, &aad).unwrap(), pt);
    }
}
