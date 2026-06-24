use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use deputy_deploy::GateDecision;
use deputy_id::Session;
use deputy_store::Vault;
use tempfile::TempDir;
use tower::ServiceExt;

use crate::{router, DeputyService};

const LOCK: &str = r#"
version = 4
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"
"#;

fn test_session(exp: u64) -> Session {
    Session {
        did: "did:mata:test".to_owned(),
        claims: BTreeMap::new(),
        current_version: 1,
        genesis_roster_hash: [0u8; 32],
        iat: 0,
        exp,
        aud: "https://deputy.local".to_owned(),
    }
}

/// An opened service over a fresh vault, plus the temp dir keeping it alive.
fn test_service() -> (DeputyService, TempDir) {
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());
    let svc = DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap();
    (svc, dir)
}

fn source_with_lock() -> TempDir {
    let src = TempDir::new().unwrap();
    fs::write(src.path().join("Cargo.lock"), LOCK).unwrap();
    src
}

#[test]
fn open_is_gated_on_a_valid_session_and_passphrase() {
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());

    // Expired session → rejected even with the right passphrase.
    assert!(DeputyService::open(dir.path(), b"pw", test_session(100), 200).is_err());
    // Wrong passphrase → rejected even with a valid session.
    assert!(DeputyService::open(dir.path(), b"wrong", test_session(u64::MAX), 0).is_err());
    // Both correct → opens.
    assert!(DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).is_ok());
}

#[test]
fn discover_lists_pins_from_the_lockfile() {
    let (svc, _vault_dir) = test_service();
    let src = source_with_lock();

    let pins = svc.discover(src.path().to_str().unwrap()).unwrap();
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0].dep.name.as_str(), "serde");
}

#[test]
fn gate_blocks_an_unpromoted_tree() {
    let (svc, _vault_dir) = test_service();
    let src = source_with_lock();

    let decision = svc.gate(src.path().to_str().unwrap()).unwrap();
    let GateDecision::Blocked { violations } = decision else {
        panic!("expected the gate to block an unpromoted dependency");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].name, "serde");
}

#[test]
fn owner_has_full_access_but_scoped_capabilities_are_enforced() {
    use crate::Ops;
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());
    let mut svc = DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap();

    // The owner self-grant covers read, write, and compute.
    assert!(svc.authorize_op(Ops::READ).is_ok());
    assert!(svc.authorize_op(Ops::WRITE).is_ok());

    // Grant an AI agent a READ-only capability and act under it.
    let agent_cap = svc.grant("did:agent:assistant", Ops::READ, None).unwrap();
    svc.act_as(agent_cap.clone());
    assert!(svc.authorize_op(Ops::READ).is_ok(), "read is granted");
    assert!(
        svc.authorize_op(Ops::WRITE).is_err(),
        "write is not granted"
    );

    // Revoking the capability denies even the granted read.
    svc.revoke(agent_cap.capability.id);
    assert!(
        svc.authorize_op(Ops::READ).is_err(),
        "revoked capability is denied"
    );
}

#[test]
fn expired_capability_is_denied() {
    use crate::Ops;
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());
    let mut svc = DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap();

    // Expiry of 1 (1970) is far in the past.
    let cap = svc.grant("did:agent:stale", Ops::READ, Some(1)).unwrap();
    svc.act_as(cap);
    assert!(svc.authorize_op(Ops::READ).is_err());
}

#[test]
fn a_read_only_agent_cannot_run_a_write_operation() {
    use crate::Ops;
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());
    let mut svc = DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap();
    svc.act_as(svc.grant("did:agent:reader", Ops::READ, None).unwrap());

    // `acquire` is a WRITE op — the gate refuses before any work (no network touched).
    let err = svc.acquire("/nonexistent").unwrap_err();
    assert_eq!(err.status, StatusCode::FORBIDDEN);
}

#[test]
fn local_mode_deactivates_mid_but_still_gates_capabilities() {
    use crate::Ops;
    let dir = TempDir::new().unwrap();
    drop(Vault::create(dir.path(), b"pw").unwrap());

    // mID deactivated: no session/token needed, opens straight on the passphrase.
    let svc = DeputyService::open_local(dir.path(), b"pw").unwrap();
    assert!(!svc.mid_active(), "mID is off in local mode");
    assert_eq!(svc.session().did, "did:deputy:local");

    // The capability layer still applies — the owner self-grant covers read + write.
    assert!(svc.authorize_op(Ops::READ).is_ok());
    assert!(svc.authorize_op(Ops::WRITE).is_ok());
}

#[test]
fn mid_active_reflects_how_the_service_was_opened() {
    let (svc, _vault_dir) = test_service();
    assert!(svc.mid_active(), "open() with a session is mID-active");
}

#[tokio::test]
async fn health_endpoint_reports_the_session_did() {
    let (svc, _vault_dir) = test_service();
    let app = router(Arc::new(svc));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["did"], "did:mata:test");
}
