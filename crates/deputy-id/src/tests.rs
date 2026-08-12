//! Tests against **real wallet-minted mID tokens**. A single-device identity is built and
//! signed exactly as the wallet would (genesis self-signature + ES256 JWT via `mid-issuer`),
//! then driven through Deputy's [`Authenticator`]. Covers known-good sign-in, replay, tamper,
//! wrong audience, expiry, single-use nonces, and the anchor (rollback / spoof) invariants.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kms_client::InMemoryDeviceSigner;
use mid_issuer::{
    build_mid_jwt, AttestedBy, ClaimRequest, ClaimValue, EmbeddedGenesisRoster,
    EmbeddedVerificationMethod, IdentitySnapshot, RpRequest, VerificationMethod,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{
    AnchorStore, Authenticator, IdError, InMemoryAnchorStore, InMemoryNonceStore, NonceStore,
    Session, VerifyParams,
};

const AUD: &str = "https://deputy.local";
const IAT: u64 = 1_716_700_000;
const VM_TYPE: &str = "EcdsaSecp256r1VerificationKey2019";

fn signing_key(seed: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(b"-deputy-id-test-seed");
    let bytes: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&bytes.into()).unwrap()
}

fn sign_genesis(roster: &EmbeddedGenesisRoster, key: &SigningKey) -> String {
    let canonical = mid_issuer::canonical::genesis_canonical_bytes(roster);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = key.sign_prehash(&prehash).unwrap();
    let normalized = sig.normalize_s().unwrap_or(sig);
    URL_SAFE_NO_PAD.encode(normalized.to_bytes())
}

/// A single-device mID identity that can mint real tokens.
struct Identity {
    did: String,
    device_id: String,
    key: SigningKey,
}

impl Identity {
    fn new(seed: &str) -> Self {
        let key = signing_key(seed);
        let did = mid_verify::did_from_pubkey(key.verifying_key());
        Self {
            did,
            device_id: "device-A".into(),
            key,
        }
    }

    fn snapshot(&self) -> IdentitySnapshot {
        let multibase = mid_verify::multibase_from_pubkey(self.key.verifying_key());
        let vm = VerificationMethod {
            id: format!("{}#{}", self.did, self.device_id),
            vm_type: VM_TYPE.into(),
            controller: self.did.clone(),
            public_key_multibase: multibase.clone(),
        };
        let mut genesis = EmbeddedGenesisRoster {
            version: 1,
            did: self.did.clone(),
            verification_methods: vec![vm],
            signed_at: 1_700_000_000,
            self_signed_by_genesis_key: String::new(),
        };
        genesis.self_signed_by_genesis_key = sign_genesis(&genesis, &self.key);

        let mut approved = BTreeMap::new();
        approved.insert(
            "did".to_string(),
            ClaimValue {
                value: serde_json::Value::String(self.did.clone()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );

        IdentitySnapshot {
            did: self.did.clone(),
            genesis_roster: genesis,
            roster_chain: vec![],
            current_verification_method: EmbeddedVerificationMethod {
                id: format!("{}#{}", self.did, self.device_id),
                vm_type: VM_TYPE.into(),
                controller: self.did.clone(),
                public_key_multibase: multibase,
            },
            approved_claims: approved,
        }
    }

    fn mint(&self, nonce: &str) -> String {
        let signer = InMemoryDeviceSigner::new(self.device_id.clone(), self.key.clone());
        let request = RpRequest {
            rp_origin: AUD.into(),
            nonce: nonce.into(),
            claims: ClaimRequest {
                required: vec!["did".into()],
                optional: vec![],
                custom: BTreeMap::new(),
            },
        };
        build_mid_jwt(&request, &self.snapshot(), &signer, IAT).expect("mint jwt")
    }
}

fn params(nonce: &str, now: u64) -> VerifyParams {
    VerifyParams::new(AUD, nonce, now)
}

#[test]
fn authenticates_a_valid_token() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("alice");
    let nonce = auth.issue_nonce();
    let jwt = id.mint(&nonce);

    let session: Session = auth.authenticate(&jwt, &params(&nonce, IAT + 10)).unwrap();
    assert_eq!(session.did, id.did);
    assert_eq!(session.aud, AUD);
    assert_eq!(session.current_version, 1);
    assert_eq!(
        session.claim("did").map(|c| &c.value),
        Some(&serde_json::Value::String(id.did.clone()))
    );
}

#[test]
fn replayed_token_is_rejected() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("bob");
    let nonce = auth.issue_nonce();
    let jwt = id.mint(&nonce);

    assert!(auth.authenticate(&jwt, &params(&nonce, IAT + 10)).is_ok());
    let replay = auth
        .authenticate(&jwt, &params(&nonce, IAT + 10))
        .unwrap_err();
    assert!(matches!(replay, IdError::NonceRejected));
}

#[test]
fn token_with_unissued_nonce_is_rejected() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("carol");
    // Cryptographically valid, but the authenticator never issued this nonce.
    let jwt = id.mint("never-issued");
    let err = auth
        .authenticate(&jwt, &params("never-issued", IAT + 10))
        .unwrap_err();
    assert!(matches!(err, IdError::NonceRejected));
}

#[test]
fn tampered_token_fails_verification() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("dave");
    let nonce = auth.issue_nonce();
    let mut bytes = id.mint(&nonce).into_bytes();
    // Flip the last char of the signature segment.
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();

    let err = auth
        .authenticate(&tampered, &params(&nonce, IAT + 10))
        .unwrap_err();
    assert!(matches!(err, IdError::Verify(_)));
}

#[test]
fn wrong_audience_fails_verification() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("erin");
    let nonce = auth.issue_nonce();
    let jwt = id.mint(&nonce);

    let mut p = params(&nonce, IAT + 10);
    p.expected_audience = "https://evil.example".into();
    assert!(matches!(
        auth.authenticate(&jwt, &p),
        Err(IdError::Verify(_))
    ));
}

#[test]
fn expired_token_fails_verification() {
    let auth = Authenticator::in_memory();
    let id = Identity::new("frank");
    let nonce = auth.issue_nonce();
    let jwt = id.mint(&nonce);

    // Far past the token's expiry.
    let err = auth
        .authenticate(&jwt, &params(&nonce, IAT + 1_000_000_000))
        .unwrap_err();
    assert!(matches!(err, IdError::Verify(_)));
}

#[test]
fn nonce_store_enforces_single_use() {
    // The mid-signin store takes the clock as a parameter (nonces age out on a TTL).
    let store = InMemoryNonceStore::new();
    let nonce = store.issue(IAT).unwrap();
    assert!(store.consume(&nonce, IAT + 1).unwrap(), "first use succeeds");
    assert!(!store.consume(&nonce, IAT + 1).unwrap(), "second use fails");
    assert!(
        !store.consume("never-issued", IAT + 1).unwrap(),
        "unknown nonce fails"
    );
}

#[test]
fn anchor_store_enforces_genesis_and_version() {
    let store = InMemoryAnchorStore::new();
    let did = "did:mata:example";
    let genesis = [1u8; 32];
    let other_genesis = [2u8; 32];

    store.check_and_update(did, &genesis, 5).unwrap(); // first sight
    store.check_and_update(did, &genesis, 5).unwrap(); // same version OK
    store.check_and_update(did, &genesis, 7).unwrap(); // higher version OK

    let rollback = store.check_and_update(did, &genesis, 6).unwrap_err();
    assert!(matches!(
        rollback,
        IdError::Rollback {
            presented: 6,
            last_seen: 7,
            ..
        }
    ));

    let spoof = store.check_and_update(did, &other_genesis, 8).unwrap_err();
    assert!(matches!(spoof, IdError::GenesisMismatch { .. }));
}

#[test]
fn session_expiry_helpers() {
    let id = Identity::new("grace");
    let nonce = "n";
    let jwt = id.mint(nonce);
    let session = crate::verify(&jwt, &params(nonce, IAT + 10)).unwrap();

    assert!(!session.is_expired(IAT + 10));
    assert!(session.ensure_valid(IAT + 10).is_ok());
    assert!(session.is_expired(session.exp));
    assert!(matches!(
        session.ensure_valid(session.exp),
        Err(IdError::SessionExpired { .. })
    ));
}
