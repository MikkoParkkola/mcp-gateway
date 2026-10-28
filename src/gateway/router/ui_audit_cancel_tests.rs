// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A UI write's `admin_action` outlives a client cancel with the handler: a
//! detached write that commits after the client left is still recorded,
//! naming the caller, and a request refused before its handler writes
//! nothing and records nothing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use super::AppState;
use crate::config::{ApiKeyConfig, AuthConfig, Config, FailsafeConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::test_helpers::write_owner_only;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

const KEY: &str = "ui-cancel-admin";
const START: &str = "backends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";
/// Each wait's bound: long enough for a loaded host, short enough to fail by name.
const GUARD: Duration = Duration::from_secs(30);

struct Fixture {
    state: Arc<AppState>,
    log: Arc<TransparencyLogger>,
    ctx: Arc<ReloadContext>,
    path: PathBuf,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
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

/// An admin-keyed gateway writing `gateway.yaml` (backend `a`) through a live
/// reload context, with an audit log under `policy`.
async fn fixture(policy: AuditFailurePolicy) -> Fixture {
    let (mut state, store) = test_router_app_state_with_auth(&admin_auth()).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, START).expect("write config");
    let running = Config::load(Some(&path)).expect("config loads");
    let ctx = Arc::new(
        ReloadContext::new(
            path.clone(),
            Arc::new(LiveConfig::new(running)),
            Arc::new(crate::backend::BackendRegistry::new()),
            FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("the registry pairs with the config"),
    );
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir.path().join("audit.jsonl").to_string_lossy().into_owned(),
            key_id: "ui-cancel".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let unique = Arc::get_mut(&mut state).expect("state is unique");
    unique.config_path = Some(path.clone());
    unique.transparency_log = Some(Arc::clone(&log));
    state.meta_mcp.set_reload_context(Arc::clone(&ctx));
    Fixture {
        state,
        log,
        ctx,
        path,
        _dirs: (dir, store),
    }
}

impl Fixture {
    fn request(&self, method: &str, uri: &str, body: &Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {KEY}"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request")
    }

    /// The request sent on a task of its own, so a row can abort it as a
    /// disconnecting client's request is dropped.
    fn spawn(&self, request: axum::http::Request<axum::body::Body>) -> tokio::task::JoinHandle<StatusCode> {
        let router = create_router(Arc::clone(&self.state));
        tokio::spawn(async move {
            router.oneshot(request).await.expect("a response").status()
        })
    }

    fn admin_actions(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == "admin_action")
            .collect()
    }

    /// Poll until `count` admin actions are in the log, within the guard.
    async fn wait_for_admin_actions(&self, count: usize) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + GUARD;
        loop {
            let records = self.admin_actions();
            if records.len() >= count {
                return records;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{count} admin_action record(s) never appeared; the log holds {records:#?}"
            );
            tokio::task::yield_now().await;
        }
    }

    /// Poll until the running gateway's config passes `ready`, within the guard.
    async fn wait_for_live(&self, what: &str, ready: impl Fn(&Config) -> bool) {
        let deadline = tokio::time::Instant::now() + GUARD;
        while !ready(&self.ctx.live_config.get()) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the running gateway never {what}"
            );
            tokio::task::yield_now().await;
        }
    }
}

/// One detached write cancelled after its writer started: the write is
/// paused between writing the file and publishing its reload, the client's
/// request is dropped there, then the reload goes on. The change must land,
/// and exactly one `admin_action` naming the caller must be in the log.
async fn cancel_after_writer_start(
    method: &str,
    uri: &str,
    body: &Value,
    route: &str,
    landed: impl Fn(&Config, &str) -> bool,
) {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let pause = crate::config_reload::arm_reload_pause(&fx.path);
    let request = fx.spawn(fx.request(method, uri, body));
    tokio::time::timeout(GUARD, pause.reached.notified())
        .await
        .expect("the write reached its reload");
    request.abort();
    let _ = request.await;
    pause.release.notify_one();

    let records = fx.wait_for_admin_actions(1).await;
    let file = std::fs::read_to_string(&fx.path).expect("read config");
    assert!(landed(&fx.ctx.live_config.get(), &file), "the write did not land: {file}");
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    let record = &records[0];
    assert_eq!(record["route"], route, "{record}");
    assert_eq!(record["method"], method, "{record}");
    assert_eq!(record["who"]["account"], KEY, "the caller is named: {record}");
    assert!(
        record["http_status"]
            .as_u64()
            .is_some_and(|status| (200..300).contains(&status)),
        "the handler's own answer: {record}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_backend_add_still_records_its_caller() {
    cancel_after_writer_start(
        "POST",
        "/ui/api/backends",
        &json!({"name": "b", "url": "http://127.0.0.1:9/b"}),
        "/ui/api/backends",
        |live, file| live.backends.contains_key("b") && file.contains("\n  b:"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_backend_edit_still_records_its_caller() {
    cancel_after_writer_start(
        "PATCH",
        "/ui/api/backends/a",
        &json!({"description": "edited-after-cancel"}),
        "/ui/api/backends/{name}",
        |_, file| file.contains("edited-after-cancel"),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_backend_remove_still_records_its_caller() {
    cancel_after_writer_start(
        "DELETE",
        "/ui/api/backends/a",
        &json!({}),
        "/ui/api/backends/{name}",
        |live, file| !live.backends.contains_key("a") && !file.contains("\n  a:"),
    )
    .await;
}

/// A write the audit log refuses before its handler writes nothing and
/// records nothing, as before: the layer admits before anything runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_refused_before_its_handler_writes_and_records_nothing() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);
    assert!(fx.log.probe().is_err(), "the priming append fails");
    assert!(fx.log.is_degraded(), "the logger is degraded");

    let request = fx.request(
        "POST",
        "/ui/api/backends",
        &json!({"name": "b", "url": "http://127.0.0.1:9/b"}),
    );
    let status = tokio::time::timeout(GUARD, fx.spawn(request))
        .await
        .expect("the request finished")
        .expect("the request task");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let file = std::fs::read_to_string(&fx.path).expect("read config");
    assert_eq!(file, START, "nothing was written");
    assert!(!fx.ctx.live_config.get().backends.contains_key("b"));
    fx.log.set_append_failure_for_test(false);
    assert!(fx.admin_actions().is_empty(), "{:#?}", fx.admin_actions());
}

/// Control: the same write, not cancelled, is recorded exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_uncancelled_write_is_recorded_once() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let request = fx.request(
        "POST",
        "/ui/api/backends",
        &json!({"name": "b", "url": "http://127.0.0.1:9/b"}),
    );
    let status = tokio::time::timeout(GUARD, fx.spawn(request))
        .await
        .expect("the request finished")
        .expect("the request task");
    assert!(status.is_success(), "{status}");
    fx.wait_for_live("loaded b", |live| live.backends.contains_key("b")).await;
    let records = fx.admin_actions();
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    assert_eq!(records[0]["who"]["account"], KEY, "{}", records[0]);
}
