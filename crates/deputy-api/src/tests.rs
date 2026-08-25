use std::collections::BTreeMap;
use std::fs;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use deputy_deploy::GateDecision;
use deputy_id::Session;
use tempfile::TempDir;
use tower::ServiceExt;

use crate::service::{
    aged_plan_entries, base64_std, is_aged_update, unix_ymd, upgrade_plan_markdown, FolderSummary,
    HeartbeatEntry, HeartbeatReport, RepoSummary, UPGRADE_PLAN_MIN_AGE_SECS,
};
use crate::{router, DeputyService};

const LOCK: &str = r#"
version = 4
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"
"#;

const LOCK_TOKIO: &str = r#"
version = 4
[[package]]
name = "tokio"
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
    // First open creates the vault, bound to the session's verified DID.
    drop(DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap());

    // Expired session → rejected even with the right passphrase (before any unlock).
    assert!(DeputyService::open(dir.path(), b"pw", test_session(100), 200).is_err());
    // Wrong passphrase → rejected even with a valid session (verifier mismatch).
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

    // mID deactivated: no session/token needed, opens straight on the passphrase.
    let svc = DeputyService::open_local(dir.path(), b"pw").unwrap();
    assert!(!svc.mid_active(), "mID is off in local mode");
    assert_eq!(svc.session().did, "did:deputy:local");

    // The capability layer still applies — the owner self-grant covers read + write.
    assert!(svc.authorize_op(Ops::READ).is_ok());
    assert!(svc.authorize_op(Ops::WRITE).is_ok());
}

#[test]
fn a_vault_bound_to_one_mid_cannot_be_opened_by_another() {
    let dir = TempDir::new().unwrap();
    let with_did = |did: &str| Session {
        did: did.to_owned(),
        ..test_session(u64::MAX)
    };

    // First open creates the vault bound to identity A.
    drop(DeputyService::open(dir.path(), b"pw", with_did("did:mata:alice"), 0).unwrap());

    // Same passphrase, a DIFFERENT mID identity → refused (the DID-bound key won't match).
    assert!(
        DeputyService::open(dir.path(), b"pw", with_did("did:mata:mallory"), 0).is_err(),
        "a different mID identity must not open the vault"
    );

    // Identity A re-opens fine.
    assert!(DeputyService::open(dir.path(), b"pw", with_did("did:mata:alice"), 0).is_ok());
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

#[tokio::test]
async fn github_oauth_poll_without_start_is_a_bad_request() {
    let (svc, _vault_dir) = test_service();
    let app = router(Arc::new(svc));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/github/oauth/poll")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn all_workspaces_overview_on_an_empty_vault_is_zero() {
    let (svc, _vault_dir) = test_service();
    let ov = svc.folder_overview("*".into(), None).unwrap();
    assert_eq!(ov.name, "All workspaces");
    assert_eq!(ov.unique_deps, 0);
    assert_eq!(ov.repos, 0);
    assert_eq!(ov.lockfiles, 0);
}

#[test]
fn all_workspaces_overview_unions_every_folder() {
    let (svc, _vault_dir) = test_service();
    let a = source_with_lock();
    let b = source_with_lock();
    svc.download_local("alpha".into(), a.path().to_str().unwrap().into(), false)
        .unwrap();
    svc.download_local("beta".into(), b.path().to_str().unwrap().into(), false)
        .unwrap();

    let ov = svc.folder_overview("*".into(), None).unwrap();
    assert_eq!(ov.name, "All workspaces");
    assert_eq!(ov.unique_deps, 1);
    assert_eq!(ov.repos, 2);
    assert_eq!(ov.lockfiles, 2);

    let one = svc.folder_overview("alpha".into(), None).unwrap();
    assert_eq!(one.unique_deps, 1);
    assert_eq!(one.lockfiles, 1);
}

#[test]
fn all_workspaces_cannot_take_a_repo_slice() {
    let (svc, _vault_dir) = test_service();
    let err = match svc.folder_overview("*".into(), Some("acme/foo".into())) {
        Err(e) => e,
        Ok(_) => panic!("expected a bad request for a repo slice of all workspaces"),
    };
    assert!(err.message.contains("all-workspaces"));
}

#[test]
fn overview_of_a_repo_without_cargo_lock_is_empty_not_an_error() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade With Rust".into(),
            repos: vec![RepoSummary {
                full_name: "Remade-With-Rust/rusty_tokens".into(),
                deps: 0,
                acquired: 0,
                lockfile_found: false,
                source_archived: false,
                error: None,
            }],
        },
        vec![],
    );
    let ov = svc
        .folder_overview(
            "Remade With Rust".into(),
            Some("Remade-With-Rust/rusty_tokens".into()),
        )
        .unwrap();
    assert_eq!(ov.name, "Remade-With-Rust/rusty_tokens");
    assert_eq!(ov.lockfiles, 0);
    assert_eq!(ov.unique_deps, 0);
    assert_eq!(ov.repos, 1);
}

#[test]
fn folders_list_hydrates_lockfile_counts_when_summary_was_zeroed() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade With Rust".into(),
            repos: vec![RepoSummary {
                full_name: "Remade-With-Rust/rusty_alloc".into(),
                deps: 0,
                acquired: 0,
                lockfile_found: false,
                source_archived: false,
                error: Some("Cargo.lock not found on GitHub".into()),
            }],
        },
        vec![(
            "Remade-With-Rust/rusty_alloc".into(),
            LOCK.trim().to_owned(),
        )],
    );
    let list = svc.folders().unwrap();
    let repo = &list[0].repos[0];
    assert!(repo.lockfile_found);
    assert_eq!(repo.deps, 1);
}

#[test]
fn overview_still_rejects_an_unknown_repo_in_a_folder() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade With Rust".into(),
            repos: vec![RepoSummary {
                full_name: "Remade-With-Rust/rusty_tokens".into(),
                deps: 0,
                acquired: 0,
                lockfile_found: false,
                source_archived: false,
                error: None,
            }],
        },
        vec![],
    );
    let err = match svc.folder_overview(
        "Remade With Rust".into(),
        Some("Remade-With-Rust/other".into()),
    ) {
        Err(e) => e,
        Ok(_) => panic!("expected a bad request for an unknown repo"),
    };
    assert!(err.message.contains("no such repository"));
}

#[test]
fn scan_progress_is_idle_when_nothing_is_running() {
    let (svc, _vault_dir) = test_service();
    assert!(svc.scan_progress().is_none());
}

#[test]
fn last_scan_is_none_until_a_scan_is_stored() {
    let (svc, _vault_dir) = test_service();
    assert!(svc.last_scan("*".into(), None).unwrap().is_none());
}

#[test]
fn last_scan_returns_the_stored_report_for_that_scope() {
    let (svc, _vault_dir) = test_service();
    let report = crate::service::CombinedScanReport {
        advisories: 3,
        scan: crate::service::FolderScanReport {
            name: "All workspaces".into(),
            repos: Vec::new(),
        },
        updates: crate::service::NewVersionReport {
            name: "All workspaces".into(),
            entries: Vec::new(),
        },
        updates_error: None,
        coverage: crate::service::CoverageReport {
            name: "All workspaces".into(),
            registry_total: 0,
            archived: 0,
            gaps: Vec::new(),
        },
        scanned_at: 1_700_000_000,
    };
    svc.remember_scan("*", None, report.clone());
    let got = svc
        .last_scan("*".into(), None)
        .unwrap()
        .expect("stored scan");
    assert_eq!(got.advisories, 3);
    assert_eq!(got.scanned_at, 1_700_000_000);
    assert!(svc.last_scan("other".into(), None).unwrap().is_none());
}

#[test]
fn deleting_a_folder_drops_its_last_scan() {
    let (svc, _vault_dir) = test_service();
    let report = crate::service::CombinedScanReport {
        advisories: 0,
        scan: crate::service::FolderScanReport {
            name: "alpha".into(),
            repos: Vec::new(),
        },
        updates: crate::service::NewVersionReport {
            name: "alpha".into(),
            entries: Vec::new(),
        },
        updates_error: None,
        coverage: crate::service::CoverageReport {
            name: "alpha".into(),
            registry_total: 0,
            archived: 0,
            gaps: Vec::new(),
        },
        scanned_at: 1,
    };
    svc.remember_scan("alpha", None, report);
    svc.remember_scan(
        "*",
        None,
        crate::service::CombinedScanReport {
            advisories: 1,
            scan: crate::service::FolderScanReport {
                name: "All workspaces".into(),
                repos: Vec::new(),
            },
            updates: crate::service::NewVersionReport {
                name: "All workspaces".into(),
                entries: Vec::new(),
            },
            updates_error: None,
            coverage: crate::service::CoverageReport {
                name: "All workspaces".into(),
                registry_total: 0,
                archived: 0,
                gaps: Vec::new(),
            },
            scanned_at: 2,
        },
    );
    svc.delete_folder("alpha").unwrap();
    assert!(svc.last_scan("alpha".into(), None).unwrap().is_none());
    assert_eq!(
        svc.last_scan("*".into(), None)
            .unwrap()
            .expect("all-workspaces scan kept")
            .scanned_at,
        2
    );
}

#[test]
fn heartbeat_progress_is_idle_when_nothing_is_running() {
    let (svc, _vault_dir) = test_service();
    assert!(svc.heartbeat_progress().is_none());
}

fn hb_entry(name: &str, current: &str, latest: &str, update: bool) -> HeartbeatEntry {
    HeartbeatEntry {
        name: name.into(),
        current: current.into(),
        latest: Some(latest.into()),
        update_available: update,
        advisories: Vec::new(),
        latest_updated: Some(1_700_000_000),
    }
}

#[tokio::test]
async fn group_heartbeat_unions_updates_from_each_repo_cache() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade-With-Rust".into(),
            repos: vec![
                RepoSummary {
                    full_name: "Remade-With-Rust/rusty_alloc".into(),
                    deps: 1,
                    acquired: 1,
                    lockfile_found: true,
                    source_archived: true,
                    error: None,
                },
                RepoSummary {
                    full_name: "Remade-With-Rust/rusty_tokens".into(),
                    deps: 1,
                    acquired: 1,
                    lockfile_found: true,
                    source_archived: true,
                    error: None,
                },
            ],
        },
        vec![
            (
                "Remade-With-Rust/rusty_alloc".into(),
                LOCK.trim().to_owned(),
            ),
            (
                "Remade-With-Rust/rusty_tokens".into(),
                LOCK_TOKIO.trim().to_owned(),
            ),
        ],
    );
    svc.remember_heartbeat(
        "Remade-With-Rust",
        None,
        HeartbeatReport {
            name: "Remade-With-Rust".into(),
            entries: vec![hb_entry("serde", "1.0.0", "1.0.0", false)],
        },
    );
    svc.remember_heartbeat(
        "Remade-With-Rust",
        Some("Remade-With-Rust/rusty_alloc"),
        HeartbeatReport {
            name: "Remade-With-Rust/rusty_alloc".into(),
            entries: vec![hb_entry("serde", "1.0.0", "1.1.0", true)],
        },
    );
    svc.remember_heartbeat(
        "Remade-With-Rust",
        Some("Remade-With-Rust/rusty_tokens"),
        HeartbeatReport {
            name: "Remade-With-Rust/rusty_tokens".into(),
            entries: vec![hb_entry("tokio", "1.0.0", "1.2.0", true)],
        },
    );

    let report = svc
        .folder_heartbeat("Remade-With-Rust".into(), None)
        .await
        .unwrap();
    assert_eq!(report.name, "Remade-With-Rust");
    assert_eq!(report.entries.len(), 2);
    let outdated: Vec<&str> = report
        .entries
        .iter()
        .filter(|e| e.update_available)
        .map(|e| e.name.as_str())
        .collect();
    assert!(
        outdated.contains(&"serde"),
        "group kept rusty_alloc's serde update"
    );
    assert!(
        outdated.contains(&"tokio"),
        "group kept rusty_tokens' tokio update"
    );
}

#[tokio::test]
async fn group_heartbeat_reads_solo_folder_cache_and_ignores_stale_group_snapshot() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade With Rust".into(),
            repos: vec![RepoSummary {
                full_name: "Remade-With-Rust/rusty_alloc".into(),
                deps: 1,
                acquired: 1,
                lockfile_found: true,
                source_archived: true,
                error: None,
            }],
        },
        vec![(
            "Remade-With-Rust/rusty_alloc".into(),
            LOCK.trim().to_owned(),
        )],
    );
    svc.remember_heartbeat(
        "Remade With Rust",
        None,
        HeartbeatReport {
            name: "Remade With Rust".into(),
            entries: vec![hb_entry("serde", "1.0.0", "1.0.0", false)],
        },
    );
    svc.remember_heartbeat(
        "Remade-With-Rust/rusty_alloc",
        None,
        HeartbeatReport {
            name: "Remade-With-Rust/rusty_alloc".into(),
            entries: vec![hb_entry("serde", "1.0.0", "1.1.0", true)],
        },
    );

    let report = svc
        .folder_heartbeat("Remade With Rust".into(), None)
        .await
        .unwrap();
    assert_eq!(report.entries.len(), 1);
    assert!(
        report.entries[0].update_available,
        "group must surface the child repo's update, not the stale group snapshot"
    );
}

#[test]
fn analytics_progress_is_idle_when_nothing_is_running() {
    let (svc, _vault_dir) = test_service();
    assert!(svc.analytics_progress().is_none());
}

#[tokio::test]
async fn empty_analytics_is_cached_for_reload() {
    let (svc, _vault_dir) = test_service();
    let svc = Arc::new(svc);
    let first = svc
        .clone()
        .folder_analytics("*".into(), None)
        .await
        .unwrap();
    assert_eq!(first.total_deps, 0);
    assert_eq!(first.name, "All workspaces");
    let second = svc
        .clone()
        .folder_analytics("*".into(), None)
        .await
        .unwrap();
    assert_eq!(second.total_deps, first.total_deps);
    assert!(svc.analytics_progress().is_none());
}

#[tokio::test]
async fn analytics_and_heartbeat_reload_from_vault() {
    let dir = TempDir::new().unwrap();
    {
        let svc =
            Arc::new(DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap());
        let _ = svc
            .clone()
            .folder_analytics("*".into(), None)
            .await
            .unwrap();
        let _ = svc.folder_heartbeat("*".into(), None).await.unwrap();
    }
    let svc = Arc::new(DeputyService::open(dir.path(), b"pw", test_session(u64::MAX), 0).unwrap());
    let analytics = svc
        .clone()
        .folder_analytics("*".into(), None)
        .await
        .unwrap();
    let heartbeat = svc.folder_heartbeat("*".into(), None).await.unwrap();
    assert_eq!(analytics.total_deps, 0);
    assert_eq!(analytics.name, "All workspaces");
    assert!(heartbeat.entries.is_empty());
    assert_eq!(heartbeat.name, "All workspaces");
}

#[tokio::test]
async fn heartbeat_on_empty_vault_has_no_entries_and_clears_progress() {
    let (svc, _vault_dir) = test_service();
    let report = svc.folder_heartbeat("*".into(), None).await.unwrap();
    assert!(report.entries.is_empty());
    assert_eq!(report.name, "All workspaces");
    assert!(svc.heartbeat_progress().is_none());
}

#[tokio::test]
async fn heartbeat_progress_endpoint_is_null_when_idle() {
    let (svc, _vault_dir) = test_service();
    let app = router(Arc::new(svc));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/folders/heartbeat/progress")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body.is_null());
}

#[test]
fn scan_folder_on_empty_all_workspaces_is_empty() {
    let (svc, _vault_dir) = test_service();
    let report = svc.scan_folder("*".into(), None).unwrap();
    assert!(report.repos.is_empty());
    assert_eq!(report.name, "All workspaces");
    assert!(svc.scan_progress().is_some());
}

#[test]
fn github_full_name_is_owner_slash_repo() {
    assert!(crate::service::is_github_full_name("acme/widget"));
    assert!(!crate::service::is_github_full_name("alpha"));
    assert!(!crate::service::is_github_full_name("a/b/c"));
    assert!(!crate::service::is_github_full_name(r"C:\src"));
}

#[test]
fn rfc3339_to_unix_parses_crates_io_timestamps() {
    assert_eq!(
        crate::service::rfc3339_to_unix("1970-01-01T00:00:00Z"),
        Some(0)
    );
    assert_eq!(
        crate::service::rfc3339_to_unix("1970-01-01T01:00:00.123456Z"),
        Some(3_600)
    );
    assert_eq!(
        crate::service::rfc3339_to_unix("2023-11-14T22:13:20+00:00"),
        Some(1_700_000_000)
    );
}

#[test]
fn crates_io_latest_from_json_uses_version_created_at() {
    let v = serde_json::json!({
        "crate": {
            "max_stable_version": "1.2.3",
            "updated_at": "2020-01-01T00:00:00Z"
        },
        "versions": [{
            "num": "1.2.3",
            "created_at": "1970-01-01T01:00:00Z",
            "checksum": "aa"
        }]
    });
    let (latest, updated) = crate::service::crates_io_latest_from_json(&v).unwrap();
    assert_eq!(latest, "1.2.3");
    assert_eq!(updated, Some(3_600));
}

#[tokio::test]
async fn refresh_empty_all_workspaces_is_empty() {
    let (svc, _vault_dir) = test_service();
    let report = svc.refresh_workspace("*".into(), None).await.unwrap();
    assert!(report.repos.is_empty());
    assert_eq!(report.name, "All workspaces");
}

#[tokio::test]
async fn refresh_unknown_folder_is_a_bad_request() {
    let (svc, _vault_dir) = test_service();
    let err = match svc.refresh_workspace("missing".into(), None).await {
        Err(e) => e,
        Ok(_) => panic!("expected a bad request for an unknown folder"),
    };
    assert!(err.message.contains("no such folder"));
}

#[tokio::test]
async fn refresh_local_folder_keeps_the_workspace() {
    let (svc, _vault_dir) = test_service();
    let src = source_with_lock();
    svc.download_local("alpha".into(), src.path().to_str().unwrap().into(), false)
        .unwrap();
    let before = svc.folders().unwrap();
    assert_eq!(before.len(), 1);
    let err = match svc.refresh_workspace("alpha".into(), None).await {
        Err(e) => e,
        Ok(_) => panic!("expected a bad request for a local-only folder"),
    };
    assert!(err.message.contains("GitHub"));
    let after = svc.folders().unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].name, "alpha");
    assert_eq!(after[0].repos.len(), before[0].repos.len());
}

#[test]
fn crates_from_manifest_skips_path_and_git_and_keeps_crates_io() {
    let toml = r#"
[package]
name = "rusty_tokens"
version = "0.2.0"

[dependencies]
serde = "1.0"
mine = { path = "../mine" }
remote = { git = "https://github.com/acme/remote" }
toml = { version = "0.8", default-features = false }
"#;
    let got = crate::service::crates_from_manifest(toml);
    assert!(got.contains(&("rusty_tokens".into(), "0.2.0".into())));
    assert!(got.contains(&("serde".into(), "1.0".into())));
    assert!(got.contains(&("toml".into(), "0.8".into())));
    assert!(!got.iter().any(|(n, _)| n == "mine" || n == "remote"));
}

#[test]
fn cargo_tomls_from_github_tarball_reads_nested_manifests() {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let files = [
        (
            "rusty_tokens-abc/Cargo.toml",
            "[package]\nname = \"rusty_tokens\"\nversion = \"0.1.0\"\n",
        ),
        (
            "rusty_tokens-abc/target/Cargo.toml",
            "[package]\nname = \"skip\"\nversion = \"0.0.0\"\n",
        ),
    ];
    for (path, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, content.as_bytes())
            .unwrap();
    }
    let gz = builder.into_inner().unwrap().finish().unwrap();
    let tomls = crate::service::cargo_tomls_from_github_tarball(&gz);
    assert_eq!(tomls.len(), 1);
    assert!(tomls[0].contains("rusty_tokens"));
}

fn repo_summary(full_name: &str) -> RepoSummary {
    RepoSummary {
        full_name: full_name.into(),
        deps: 1,
        acquired: 1,
        lockfile_found: true,
        source_archived: true,
        error: None,
    }
}

#[test]
fn unix_ymd_is_utc_civil_date() {
    assert_eq!(unix_ymd(0), "1970-01-01");
    assert_eq!(unix_ymd(86_400), "1970-01-02");
    assert_eq!(unix_ymd(1_700_000_000), "2023-11-14");
}

#[test]
fn base64_std_pads_remainders() {
    assert_eq!(base64_std(b"Man"), "TWFu");
    assert_eq!(base64_std(b"Ma"), "TWE=");
    assert_eq!(base64_std(b"M"), "TQ==");
}

#[test]
fn aged_update_requires_a_week_old_crates_io_release() {
    let now = 1_800_000_000;
    let min = UPGRADE_PLAN_MIN_AGE_SECS;
    let old = hb_entry("serde", "1.0.0", "1.1.0", true);
    assert!(is_aged_update(&old, now), "fixture date is far in the past");

    let mut fresh = hb_entry("tokio", "1.0.0", "1.2.0", true);
    fresh.latest_updated = Some(now.saturating_sub(min) + 1);
    assert!(!is_aged_update(&fresh, now), "released in the last week");

    let mut boundary = hb_entry("bytes", "1.0.0", "1.1.0", true);
    boundary.latest_updated = Some(now.saturating_sub(min));
    assert!(
        is_aged_update(&boundary, now),
        "exactly seven days old is eligible"
    );

    let mut missing = hb_entry("anyhow", "1.0.0", "1.1.0", true);
    missing.latest_updated = None;
    assert!(!is_aged_update(&missing, now));

    let mut zero = hb_entry("foo", "1.0.0", "1.1.0", true);
    zero.latest_updated = Some(0);
    assert!(!is_aged_update(&zero, now));

    let current = hb_entry("bar", "1.0.0", "1.0.0", false);
    assert!(!is_aged_update(&current, now));
}

#[test]
fn upgrade_plan_markdown_lists_only_the_aged_rows() {
    let now = 1_800_000_000;
    let serde = hb_entry("serde", "1.0.0", "1.1.0", true);
    let md = upgrade_plan_markdown("owner/repo", &[serde.clone()], now);
    assert!(md.contains("owner/repo"));
    assert!(md.contains("`serde`"));
    assert!(md.contains("`1.0.0`"));
    assert!(md.contains("`1.1.0`"));
    assert!(md.contains("For this GitHub repository only"));
    assert!(md.contains("at least 7 days old"));
    assert!(md.contains("cargo update"));
    assert!(!md.contains("tokio"));

    let long = hb_entry("aho-corasick", "1.1.4", "1.1.5", true);
    let aligned = upgrade_plan_markdown("owner/repo", &[serde.clone(), long], now);
    let table: Vec<&str> = aligned.lines().filter(|l| l.starts_with('|')).collect();
    assert!(table.len() >= 3, "header, rule, rows");
    let pipes = |line: &str| {
        line.chars()
            .enumerate()
            .filter(|(_, c)| *c == '|')
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
    };
    let header_pipes = pipes(table[0]);
    for line in &table {
        assert_eq!(pipes(line), header_pipes, "columns line up in `{line}`");
    }

    let empty = upgrade_plan_markdown("owner/repo", &[], now);
    assert!(empty.contains("No crates in this repository's `Cargo.lock` currently meet that bar."));
}

#[test]
fn aged_plan_entries_are_per_repo_pins_not_the_group_union() {
    let now = 1_800_000_000;
    let mut pins = std::collections::HashSet::new();
    pins.insert(("serde".into(), "1.0.0".into()));
    let mut by_pin = std::collections::HashMap::new();
    by_pin.insert(
        ("serde".into(), "1.0.0".into()),
        hb_entry("serde", "1.0.0", "1.1.0", true),
    );
    by_pin.insert(
        ("tokio".into(), "1.0.0".into()),
        hb_entry("tokio", "1.0.0", "1.2.0", true),
    );
    let aged = aged_plan_entries(&pins, &by_pin, now);
    assert_eq!(aged.len(), 1);
    assert_eq!(aged[0].name, "serde");
}

#[tokio::test]
async fn send_upgrade_plans_skips_local_ingest_names() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "local-app".into(),
            repos: vec![repo_summary("local-app")],
        },
        vec![("local-app".into(), LOCK.trim().to_owned())],
    );
    let report = svc
        .send_upgrade_plans("local-app".into(), None)
        .await
        .unwrap();
    assert_eq!(report.skipped, vec!["local-app".to_owned()]);
    assert!(report.written.is_empty());
    assert!(report.errors.is_empty());
}

#[tokio::test]
async fn send_upgrade_plans_needs_github_for_owner_repo_names() {
    let (svc, _vault_dir) = test_service();
    svc.test_put_folder(
        FolderSummary {
            name: "Remade-With-Rust".into(),
            repos: vec![repo_summary("Remade-With-Rust/rusty_alloc")],
        },
        vec![(
            "Remade-With-Rust/rusty_alloc".into(),
            LOCK.trim().to_owned(),
        )],
    );
    let err = svc
        .send_upgrade_plans("Remade-With-Rust".into(), None)
        .await
        .unwrap_err();
    assert!(
        err.message.contains("GitHub not connected"),
        "{}",
        err.message
    );
}
