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

use super::AppState;
use super::create_router;
use super::tests::test_router_app_state_with_auth;
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
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
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

/// A request as the admin, with a JSON body.
fn request(method: &str, uri: &str, body: &Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request")
}

impl Fixture {
    /// The request sent on a task of its own, so a row can abort it as a
    /// disconnecting client's request is dropped.
    fn spawn(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> tokio::task::JoinHandle<StatusCode> {
        let router = create_router(Arc::clone(&self.state));
        tokio::spawn(async move { router.oneshot(request).await.expect("a response").status() })
    }

    /// The request sent to its answer: the status and the JSON body.
    async fn send_json(
        &self,
        request: axum::http::Request<axum::body::Body>,
    ) -> (StatusCode, Value) {
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
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
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

    /// The log's admin actions once every task started since `baseline` (a
    /// count of live tasks) has ended, so a late duplicate cannot slip past.
    async fn settled_admin_actions(&self, baseline: usize) -> Vec<Value> {
        let metrics = tokio::runtime::Handle::current().metrics();
        let deadline = tokio::time::Instant::now() + GUARD;
        while metrics.num_alive_tasks() > baseline {
            assert!(
                tokio::time::Instant::now() < deadline,
                "a task the request started never ended"
            );
            tokio::task::yield_now().await;
        }
        self.admin_actions()
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
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let request = fx.spawn(request(method, uri, body));
    tokio::time::timeout(GUARD, pause.reached.notified())
        .await
        .expect("the write reached its reload");
    request.abort();
    let _ = request.await;
    pause.release.notify_one();

    fx.wait_for_admin_actions(1).await;
    let records = fx.settled_admin_actions(baseline).await;
    let file = std::fs::read_to_string(&fx.path).expect("read config");
    assert!(
        landed(&fx.ctx.live_config.get(), &file),
        "the write did not land: {file}"
    );
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    let record = &records[0];
    assert_eq!(record["route"], route, "{record}");
    assert_eq!(record["method"], method, "{record}");
    assert_eq!(
        record["who"]["account"], KEY,
        "the caller is named: {record}"
    );
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

    let request = request(
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
    let request = request(
        "POST",
        "/ui/api/backends",
        &json!({"name": "b", "url": "http://127.0.0.1:9/b"}),
    );
    let status = tokio::time::timeout(GUARD, fx.spawn(request))
        .await
        .expect("the request finished")
        .expect("the request task");
    assert!(status.is_success(), "{status}");
    fx.wait_for_live("loaded b", |live| live.backends.contains_key("b"))
        .await;
    let records = fx.admin_actions();
    assert_eq!(records.len(), 1, "exactly one record: {records:#?}");
    assert_eq!(records[0]["who"]["account"], KEY, "{}", records[0]);
}

/// A request cancelled while the audit log is still admitting it runs no
/// handler: nothing is written and nothing is recorded. Admission is held by
/// stalling the probe write a degraded log makes before it admits; the
/// request is dropped there, then the probe is let go. Every task the
/// request started has ended before the effects are read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_cancelled_during_admission_writes_and_records_nothing() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);
    assert!(fx.log.probe().is_err(), "the priming append fails");
    fx.log.set_append_failure_for_test(false);
    assert!(fx.log.is_degraded(), "admission will probe");
    let stall = fx.log.stall_next_write_for_test(GUARD);
    let metrics = tokio::runtime::Handle::current().metrics();
    let baseline = metrics.num_alive_tasks();

    let request = fx.spawn(request(
        "POST",
        "/ui/api/backends",
        &json!({"name": "b", "url": "http://127.0.0.1:9/b"}),
    ));
    let gate = Arc::clone(&stall.0);
    let entered = tokio::task::spawn_blocking(move || gate.wait_entered())
        .await
        .expect("the gate wait");
    assert!(entered, "admission's probe reached the stalled write");
    request.abort();
    let _ = request.await;
    drop(stall);
    // The released write still runs on the blocking pool: wait for it, so it
    // never lands while the fixture's folder is being removed (a late `.hwm`
    // would keep the folder).
    let late = Arc::clone(&fx.log);
    assert!(
        tokio::task::spawn_blocking(move || {
            late.wait_write_cleared_for_test(crate::test_wait::HANG_BOUND)
        })
        .await
        .expect("the wait does not panic"),
        "the released audit write finishes"
    );

    let deadline = tokio::time::Instant::now() + GUARD;
    while metrics.num_alive_tasks() > baseline {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a task the request started never ended"
        );
        tokio::task::yield_now().await;
    }
    let file = std::fs::read_to_string(&fx.path).expect("read config");
    assert_eq!(file, START, "nothing was written");
    assert!(!fx.ctx.live_config.get().backends.contains_key("b"));
    assert!(fx.admin_actions().is_empty(), "{:#?}", fx.admin_actions());
}

/// A handler whose only act is to panic.
async fn panicking_handler() -> StatusCode {
    panic!("handler panic payload")
}

/// A handler that panics still panics out of the layer, with its own
/// payload, rather than being answered as a 500 (test and dev builds;
/// release builds abort on panic).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handler_panic_still_panics_out_of_the_layer() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let panics =
        axum::Router::new().route("/ui/api/panics", axum::routing::post(panicking_handler));
    let router = crate::gateway::ui::admin_audit::behind_admin_layer_for_test(panics, &fx.state)
        .with_state(Arc::clone(&fx.state));
    let request = request("POST", "/ui/api/panics", &json!({}));
    let joined = tokio::spawn(async move { router.oneshot(request).await }).await;
    let error = joined.expect_err("the layer panicked");
    assert!(error.is_panic(), "{error}");
    let payload = error.into_panic();
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"handler panic payload"),
        "the handler's own payload"
    );
    assert!(
        fx.admin_actions().is_empty(),
        "a panicking handler's answer is never recorded: {:#?}",
        fx.admin_actions()
    );
}

/// An MCP server on loopback whose `tools/list` waits until `release` has a
/// permit; `listing` is notified when a listing arrives.
async fn held_upstream() -> (
    String,
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Semaphore>,
) {
    use axum::response::IntoResponse as _;
    let listing = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let app = axum::Router::new().fallback({
        let (listing, release) = (Arc::clone(&listing), Arc::clone(&release));
        move |axum::Json(message): axum::Json<Value>| {
            let (listing, release) = (Arc::clone(&listing), Arc::clone(&release));
            async move {
                let method = message["method"].as_str().unwrap_or_default().to_string();
                let Some(id) = message.get("id").cloned() else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let result = match method.as_str() {
                    // No discover document: the start falls back to the handshake.
                    "server/discover" => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    "initialize" => json!({
                        "protocolVersion": crate::protocol::PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "held", "version": "0"}
                    }),
                    "tools/list" => {
                        listing.notify_one();
                        let _permit = release.acquire().await.expect("the release semaphore");
                        json!({"tools": []})
                    }
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response()
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, listing, release)
}

/// Describe then confirm a preview of `url`, as the admin; the confirm request
/// itself, not yet sent.
async fn confirmed_preview(fx: &Fixture, url: &str) -> axum::http::Request<axum::body::Body> {
    let body = json!({"name": "p", "url": url});
    let (status, described) = fx
        .send_json(request("POST", "/ui/api/previews", &body))
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{described}");
    let confirm = described["confirm"]
        .as_str()
        .expect("a confirmation")
        .to_string();
    request(
        "POST",
        "/ui/api/previews",
        &json!({"name": "p", "url": url, "confirm": confirm}),
    )
}

/// A confirmed preview whose client leaves mid-run runs to its teardown, as it
/// already did, and is now recorded naming its caller. The one-at-a-time
/// guard is released only after teardown, so a second confirmed preview being
/// admitted shows the teardown ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_preview_runs_to_its_teardown_and_records_its_caller() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let mut open = Config::clone(&fx.state.live_config.get());
    open.security.ssrf_protection = false;
    fx.state.live_config.set(open);
    let (url, listing, release) = held_upstream().await;

    let confirm = confirmed_preview(&fx, &url).await;
    assert_eq!(fx.admin_actions().len(), 1, "the describe step is recorded");
    let request = fx.spawn(confirm);
    tokio::time::timeout(GUARD, listing.notified())
        .await
        .expect("the preview reached its listing");
    request.abort();
    let _ = request.await;
    release.add_permits(1);

    let records = fx.wait_for_admin_actions(2).await;
    assert_eq!(
        records.len(),
        2,
        "describe, then the cancelled run: {records:#?}"
    );
    let run = &records[1];
    assert_eq!(run["route"], "/ui/api/previews", "{run}");
    assert_eq!(run["who"]["account"], KEY, "the caller is named: {run}");

    let confirm = confirmed_preview(&fx, &url).await;
    let (status, answer) = fx.send_json(confirm).await;
    assert_ne!(
        status,
        StatusCode::CONFLICT,
        "the guard was released: {answer}"
    );
}

/// A client that disconnects while its body is still arriving: the request
/// is dropped, then the body read fails, as the server's body does when the
/// connection closes. The handler answers the failed read, and that answer
/// is recorded naming the caller; nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disconnect_mid_body_records_the_handlers_refusal() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let (polled_tx, polled_rx) = tokio::sync::oneshot::channel::<()>();
    let (fail_tx, fail_rx) = tokio::sync::oneshot::channel::<()>();
    let body = futures::stream::unfold(
        (0u8, Some(polled_tx), Some(fail_rx)),
        |(step, polled, fail)| async move {
            match step {
                0 => Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{\"name\": \"b\", ")),
                    (1, polled, fail),
                )),
                1 => {
                    if let Some(polled) = polled {
                        let _ = polled.send(());
                    }
                    if let Some(fail) = fail {
                        let _ = fail.await;
                    }
                    Some((
                        Err(std::io::Error::other("the client disconnected")),
                        (2, None, None),
                    ))
                }
                _ => None,
            }
        },
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/backends")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from_stream(body))
        .expect("a request");
    let baseline = tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks();
    let request = fx.spawn(request);
    tokio::time::timeout(GUARD, polled_rx)
        .await
        .expect("the handler read the body")
        .expect("the body stream");
    request.abort();
    let _ = request.await;
    let _ = fail_tx.send(());

    fx.wait_for_admin_actions(1).await;
    let records = fx.settled_admin_actions(baseline).await;
    assert_eq!(records.len(), 1, "{records:#?}");
    let record = &records[0];
    assert_eq!(
        record["who"]["account"], KEY,
        "the caller is named: {record}"
    );
    assert!(
        record["http_status"]
            .as_u64()
            .is_some_and(|status| (400..500).contains(&status)),
        "the handler's refusal of the failed read: {record}"
    );
    let file = std::fs::read_to_string(&fx.path).expect("read config");
    assert_eq!(file, START, "nothing was written");
}
