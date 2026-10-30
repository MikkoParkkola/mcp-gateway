// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The capability editor's `capability_editor` audit record: a save and a
//! delete each record who acted, on which capability, the kind of change and
//! the file's hash before and after with the pin change, never the file's
//! content; and when the audit log refuses the record, the answer is withheld.

use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use super::AppState;
use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::test_helpers::write_owner_only;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

const KEY: &str = "cap-edit-admin";
/// Each wait's bound: long enough for a loaded host, short enough to fail by name.
const GUARD: Duration = Duration::from_secs(30);
/// Strings in the file's content; no audit record may carry either.
const CANARY_BEFORE: &str = "CONTENT-CANARY-before-71c3";
const CANARY_AFTER: &str = "CONTENT-CANARY-after-9e0d";

/// A valid capability named `kept` whose description is `canary`.
fn capability(canary: &str) -> String {
    format!(
        "fulcrum: \"1.0\"\nname: kept\ndescription: {canary}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.example.com\n      path: /kept\n"
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Fixture {
    state: Arc<AppState>,
    log: Arc<TransparencyLogger>,
    file: std::path::PathBuf,
    _dirs: (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
}

fn admin_auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: KEY.to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// An admin-keyed gateway with one capability directory holding `kept.yaml`
/// (`text`) and an audit log under `policy`.
async fn fixture(text: &str, policy: AuditFailurePolicy) -> Fixture {
    let (mut state, store) = test_router_app_state_with_auth(&admin_auth()).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let caps = dir.path().join("capabilities");
    std::fs::create_dir(&caps).expect("capability dir");
    let file = caps.join("kept.yaml");
    write_owner_only(&file, text).expect("write capability");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "cap-edit".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let unique = Arc::get_mut(&mut state).expect("state is unique");
    unique.capability_dirs = vec![caps.to_string_lossy().into_owned()];
    unique.transparency_log = Some(Arc::clone(&log));
    Fixture {
        state,
        log,
        file,
        _dirs: (dir, store),
    }
}

/// A request as the admin naming `base` (the loaded file's sha256) in If-Match.
fn request(
    method: &str,
    uri: &str,
    base: &str,
    body: &str,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/x-yaml")
        .header("if-match", format!("\"{base}\""))
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request")
}

impl Fixture {
    async fn send(&self, request: axum::http::Request<axum::body::Body>) -> (StatusCode, String) {
        let response = tokio::time::timeout(
            GUARD,
            create_router(Arc::clone(&self.state)).oneshot(request),
        )
        .await
        .expect("the request finished")
        .expect("a response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn raw(&self) -> String {
        std::fs::read_to_string(self.log.path()).unwrap_or_default()
    }

    /// The `capability_editor` records, in order.
    fn edits(&self) -> Vec<Value> {
        self.raw()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|e| e["event"] == "admin_action" && e["surface"] == "capability_editor")
            .collect()
    }

    /// No record, of any kind, carries the file's content.
    fn assert_no_content(&self) {
        let raw = self.raw();
        for canary in [CANARY_BEFORE, CANARY_AFTER] {
            assert!(
                !raw.contains(canary),
                "the audit log carries file content ({canary}): {raw}"
            );
        }
    }
}
/// The fields every `capability_editor` record carries, as the AC names them:
/// who acted, which capability, the kind of change, the hash before and after.
fn assert_record(record: &Value, action: &str, before: &str, after: Option<&str>) {
    assert_eq!(record["who"]["account"], KEY, "who: {record}");
    assert_eq!(record["action"], action, "kind of change: {record}");
    assert_eq!(record["capability"], "kept", "which capability: {record}");
    assert_eq!(record["sha256_before"], before, "hash before: {record}");
    match after {
        Some(after) => assert_eq!(record["sha256_after"], after, "hash after: {record}"),
        None => assert!(
            record["sha256_after"].is_null(),
            "a delete leaves no file: {record}"
        ),
    }
}

/// CAPED.11: a save records who, which capability, `save`, the hash before
/// and after and the pin change (`none` for an unpinned file), and no record
/// carries the old or the new content.
#[tokio::test]
async fn caped11_a_save_records_the_change_never_the_content() {
    let before = capability(CANARY_BEFORE);
    let after = capability(CANARY_AFTER);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    let base = sha256_hex(before.as_bytes());
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &base, &after))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let written = std::fs::read(&fx.file).expect("the saved file");
    let edits = fx.edits();
    assert_eq!(edits.len(), 1, "one record per save: {edits:#?}");
    assert_record(&edits[0], "save", &base, Some(&sha256_hex(&written)));
    assert_eq!(edits[0]["pin"], "none", "{}", edits[0]);
    fx.assert_no_content();
}

/// CAPED.11: a pinned file saved in place records the pin change (`updated`)
/// beside the hashes, still without content.
#[tokio::test]
async fn caped11_a_pinned_save_records_the_pin_change() {
    use crate::capability::{compute_capability_hash, rewrite_with_pin};
    let plain = capability(CANARY_BEFORE);
    let before = rewrite_with_pin(&plain, &compute_capability_hash(&plain));
    // One value changed, the old pin line kept: the writer rewrites the pin.
    let edited = before.replace(CANARY_BEFORE, CANARY_AFTER);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    let base = sha256_hex(before.as_bytes());
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &base, &edited))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let written = std::fs::read(&fx.file).expect("the saved file");
    let edits = fx.edits();
    assert_eq!(edits.len(), 1, "{edits:#?}");
    assert_record(&edits[0], "save", &base, Some(&sha256_hex(&written)));
    assert_eq!(edits[0]["pin"], "updated", "{}", edits[0]);
    fx.assert_no_content();
}

/// CAPED.11: a delete records who, which capability, `delete`, the hash
/// before and no hash after, and no record carries the content.
#[tokio::test]
async fn caped11_a_delete_records_the_change_never_the_content() {
    let before = capability(CANARY_BEFORE);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    let base = sha256_hex(before.as_bytes());
    let (status, body) = fx
        .send(request("DELETE", "/ui/api/capabilities/kept", &base, ""))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!fx.file.exists(), "the file is deleted");
    let edits = fx.edits();
    assert_eq!(edits.len(), 1, "{edits:#?}");
    assert_record(&edits[0], "delete", &base, None);
    fx.assert_no_content();
}

/// CAPED.11: when the audit log refuses the record (fail-closed), the save's
/// answer is withheld: a 503 that names no saved result.
#[tokio::test]
async fn caped11_a_refused_record_withholds_the_answer() {
    let before = capability(CANARY_BEFORE);
    let after = capability(CANARY_AFTER);
    let fx = fixture(&before, AuditFailurePolicy::FailClosed).await;
    // Fail the next append without priming it: the log is still healthy when
    // the request is admitted, so the save commits and only its record is
    // refused. A primed, degraded log would refuse the request before the
    // handler, which says nothing about the record.
    fx.log.set_append_failure_for_test(true);
    let base = sha256_hex(before.as_bytes());
    let (status, body) = fx
        .send(request("PUT", "/ui/api/capabilities/kept", &base, &after))
        .await;
    assert_eq!(
        std::fs::read_to_string(&fx.file).expect("the file"),
        after,
        "the handler ran and the save committed before the record was refused"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let answer: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    for key in ["status", "name", "sha256"] {
        assert!(
            answer.get(key).is_none(),
            "the withheld answer names {key}: {body}"
        );
    }
    assert!(!body.contains(CANARY_AFTER), "{body}");
    assert!(fx.edits().is_empty(), "no record was written: {}", fx.raw());
}
