// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The backend routes on a gateway with an audit log: each write appends its
//! intent before gateway.yaml changes, a refused append writes nothing, and a
//! crashed write found pending is recovered only after its recovery intent.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::Value;

use super::*;
use crate::config::{AuthConfig, Config, FailsafeConfig};
use crate::config_persistence::journal;
use crate::config_reload::{FileRevision, LiveConfig, ReloadContext};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::test_helpers::write_owner_only;
use crate::security::TransparencyLogger;

/// Backend `a`, with a comment the splice keeps.
const START: &str =
    "# keep me\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n";
/// `START` with backend `b` added: what a crashed write left renamed in.
const CRASHED: &str = "# keep me\nbackends:\n  a:\n    http_url: \"http://127.0.0.1:9/mcp\" # first\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n";

/// A gateway over `START` in a temp dir, with an audit log beside it.
struct Audited {
    dir: tempfile::TempDir,
    _store: crate::gateway::router::tests::FixtureDir,
    state: Arc<AppState>,
    ctx: Arc<ReloadContext>,
    log: Arc<TransparencyLogger>,
}

/// Whether the fixture's gateway has a reload context.
#[derive(Clone, Copy)]
enum Reload {
    Live,
    Absent,
}

impl Audited {
    async fn new() -> Self {
        Self::build(Reload::Live).await
    }

    async fn build(reload: Reload) -> Self {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("gateway.yaml");
        write_owner_only(&path, START).expect("write config");
        let (mut state, store) = crate::gateway::router::tests::audience_state(
            &AuthConfig::default(),
            (None, None),
            |m| m,
        )
        .await;
        let log = Arc::new(
            TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: dir
                        .path()
                        .join("audit.jsonl")
                        .to_string_lossy()
                        .into_owned(),
                    key_id: "backend-intent".to_string(),
                    ..Default::default()
                },
            ))
            .expect("open log"),
        );
        {
            let state = Arc::get_mut(&mut state).expect("state is unique");
            state.config_path = Some(path.clone());
            state.transparency_log = Some(Arc::clone(&log));
        }
        let running = Config::load(Some(&path)).expect("config loads");
        let ctx = Arc::new(
            ReloadContext::new(
                path,
                Arc::new(LiveConfig::new(running)),
                Arc::clone(&state.backends),
                FailsafeConfig::default(),
                Duration::from_secs(60),
            )
            .expect("the registry pairs with the config"),
        );
        if let Reload::Live = reload {
            state.meta_mcp.set_reload_context(Arc::clone(&ctx));
        }
        Self {
            dir,
            _store: store,
            state,
            ctx,
            log,
        }
    }

    fn config(&self) -> std::path::PathBuf {
        self.dir.path().join("gateway.yaml")
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.config()).expect("config reads")
    }

    fn running(&self) -> Vec<String> {
        let mut names: Vec<_> = self
            .ctx
            .live_config
            .get()
            .backends
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }

    /// The `event` of every log record, in order.
    fn events(&self) -> Vec<String> {
        std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|entry| entry["event"].as_str().map(str::to_owned))
            .collect()
    }

    /// The disk a writer killed after its rename leaves: `CRASHED` in place,
    /// `START` staged, the journal `staged`.
    fn crashed_after_rename(&self) {
        let path = self.config();
        journal::stage_original(&path, START.as_bytes()).expect("stage");
        journal::begin(
            &path,
            FileRevision::of(START.as_bytes()).as_str().to_owned(),
        )
        .expect("journal");
        write_owner_only(crate::identity_grants::journal::resolved(&path), CRASHED)
            .expect("rename");
    }

    fn guard(route: &str, method: &axum::http::Method) -> Guard {
        Guard::for_route(route, method, Some(admin()))
    }

    async fn add(&self, name: &str) -> (StatusCode, Value) {
        let req: AddBackendRequest = serde_json::from_value(serde_json::json!({
            "name": name,
            "url": "http://127.0.0.1:9/mcp",
        }))
        .expect("add body");
        let guard = Self::guard(routes::UI_BACKENDS, &axum::http::Method::POST);
        read(
            add_backend(State(Arc::clone(&self.state)), guard, Json(req))
                .await
                .into_response(),
        )
        .await
    }

    async fn remove(&self, name: &str) -> (StatusCode, Value) {
        let guard = Self::guard(routes::UI_BACKEND, &axum::http::Method::DELETE);
        read(
            remove_backend(
                State(Arc::clone(&self.state)),
                guard,
                AxumPath(name.to_owned()),
            )
            .await
            .into_response(),
        )
        .await
    }

    async fn update(&self, name: &str, description: &str) -> (StatusCode, Value) {
        let req: UpdateBackendRequest =
            serde_json::from_value(serde_json::json!({ "description": description }))
                .expect("update body");
        let guard = Self::guard(routes::UI_BACKEND, &axum::http::Method::PATCH);
        read(
            update_backend(
                State(Arc::clone(&self.state)),
                guard,
                AxumPath(name.to_owned()),
                Json(req),
            )
            .await
            .into_response(),
        )
        .await
    }
}

async fn read(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 16).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn admin() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "backend-route".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: true,
        principal: crate::gateway::auth::principal_of("backend-route-secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

const INTENT: &str = "config_backend_intent";

impl Audited {
    /// The `(operation, backend)` of the first backend intent in the log.
    fn intent_subject(&self) -> (Value, Value) {
        let intent = std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|entry| entry["event"] == INTENT)
            .expect("a backend intent was written");
        (intent["operation"].clone(), intent["backend"].clone())
    }
}
const RECOVERY: &str = "config_recovery_intent";

/// A backend add on an audited gateway appends its intent; with the append
/// refused it is answered as a failure and nothing is written or loaded.
#[tokio::test]
async fn an_audited_backend_add_appends_its_intent_first() {
    let gateway = Audited::new().await;
    let (status, body) = gateway.add("b").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(
        gateway.events().iter().any(|e| e == INTENT),
        "the add wrote no intent; the log holds {:?}",
        gateway.events()
    );

    let refused = Audited::new().await;
    refused.log.set_append_failure_for_test(true);
    let (status, body) = refused.add("b").await;
    refused.log.set_append_failure_for_test(false);
    assert!(status.is_server_error(), "{status}: {body}");
    assert_eq!(refused.text(), START, "a refused intent let the add write");
    assert_eq!(
        refused.running(),
        ["a"],
        "a refused intent let the add load"
    );
}

/// A backend remove on an audited gateway appends its intent; with the
/// append refused nothing is written or unloaded.
#[tokio::test]
async fn an_audited_backend_remove_appends_its_intent_first() {
    let gateway = Audited::new().await;
    let (status, body) = gateway.remove("a").await;
    assert!(status.is_success(), "{status}: {body}");
    assert!(
        gateway.events().iter().any(|e| e == INTENT),
        "the remove wrote no intent; the log holds {:?}",
        gateway.events()
    );
    assert_eq!(
        gateway.intent_subject(),
        (Value::from("remove"), Value::from("a"))
    );

    let refused = Audited::new().await;
    refused.log.set_append_failure_for_test(true);
    let (status, body) = refused.remove("a").await;
    refused.log.set_append_failure_for_test(false);
    assert!(status.is_server_error(), "{status}: {body}");
    assert_eq!(
        refused.text(),
        START,
        "a refused intent let the remove write"
    );
    assert_eq!(
        refused.running(),
        ["a"],
        "a refused intent let the remove unload"
    );
}

/// A backend update on an audited gateway appends its intent; with the
/// append refused nothing is written.
#[tokio::test]
async fn an_audited_backend_update_appends_its_intent_first() {
    let gateway = Audited::new().await;
    let (status, body) = gateway.update("a", "edited").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        gateway.events().iter().any(|e| e == INTENT),
        "the update wrote no intent; the log holds {:?}",
        gateway.events()
    );
    assert_eq!(
        gateway.intent_subject(),
        (Value::from("update"), Value::from("a"))
    );

    let refused = Audited::new().await;
    refused.log.set_append_failure_for_test(true);
    let (status, body) = refused.update("a", "edited").await;
    refused.log.set_append_failure_for_test(false);
    assert!(status.is_server_error(), "{status}: {body}");
    assert_eq!(
        refused.text(),
        START,
        "a refused intent let the update write"
    );
}

/// A crashed write is pending when a backend update arrives: its recovery
/// intent comes first, then the update's own. With the append refused the
/// journal is not applied: the crashed bytes and the journal stay, and the
/// update is not answered as done.
#[tokio::test]
async fn a_backend_update_recovers_a_pending_journal_only_after_its_intent() {
    let gateway = Audited::new().await;
    gateway.crashed_after_rename();
    let (status, body) = gateway.update("a", "edited").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = gateway.events();
    let recovery = events.iter().position(|e| e == RECOVERY);
    let own = events.iter().position(|e| e == INTENT);
    assert!(
        matches!((recovery, own), (Some(r), Some(o)) if r < o),
        "no recovery intent before the update's own; the log holds {events:?}"
    );
    assert!(
        !gateway.text().contains("\n  b:"),
        "the crashed bytes stayed"
    );

    let refused = Audited::new().await;
    refused.crashed_after_rename();
    refused.log.set_append_failure_for_test(true);
    let (status, body) = refused.update("a", "edited").await;
    refused.log.set_append_failure_for_test(false);
    assert!(!status.is_success(), "{status}: {body}");
    assert_eq!(refused.text(), CRASHED, "the journal was applied unaudited");
    assert!(
        journal::journal_path(&refused.config()).exists(),
        "the journal was settled unaudited"
    );
}

/// The backend intent names its operation and backend, never a value.
#[tokio::test]
async fn a_backend_intent_names_its_operation_and_backend() {
    let gateway = Audited::new().await;
    let (status, body) = gateway.add("b").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let intent = std::fs::read_to_string(gateway.log.path())
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|entry| entry["event"] == INTENT)
        .expect("the add wrote its intent");
    assert_eq!(
        (&intent["operation"], &intent["backend"]),
        (&Value::from("add"), &Value::from("b")),
        "{intent}"
    );
}

/// An update that changes no byte still reloads; on an audited gateway a
/// refused intent stops that reload, so a hand edit made since the last
/// reload is not applied unaudited.
#[tokio::test]
async fn a_no_op_update_with_a_refused_intent_applies_no_outside_change() {
    let gateway = Audited::new().await;
    write_owner_only(gateway.config(), CRASHED).expect("hand edit adds b");
    gateway.log.set_append_failure_for_test(true);
    let (status, body) = gateway.update("a", "").await;
    gateway.log.set_append_failure_for_test(false);
    assert!(!status.is_success(), "{status}: {body}");
    assert_eq!(
        gateway.running(),
        ["a"],
        "the no-op reload applied the outside change unaudited"
    );
}

/// What every backend route answers with no gateway.yaml to write into.
const NO_CONFIG_FILE: &str = "no gateway.yaml exists yet; create one with `mcp-gateway init --profile local` (see QUICKSTART), then retry";

/// Add, remove and update on a missing gateway.yaml: each is refused with
/// 409 `no_config_file` and the way forward, appends no intent and leaves
/// nothing behind: no file, no lock, no secret entry.
#[tokio::test]
async fn the_backend_routes_refuse_a_missing_config_with_the_way_forward() {
    let gateway = Audited::new().await;
    std::fs::remove_file(gateway.config()).expect("remove config");
    let answers = [
        ("add", gateway.add("b").await),
        ("remove", gateway.remove("a").await),
        ("update", gateway.update("a", "edited").await),
    ];
    for (route, (status, body)) in answers {
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert_eq!(
            (&body["error"], &body["message"]),
            (&Value::from("no_config_file"), &Value::from(NO_CONFIG_FILE)),
            "{route}: {body}"
        );
    }
    assert!(
        !gateway.events().iter().any(|e| e.ends_with("_intent")),
        "a refused route appended an intent: {:?}",
        gateway.events()
    );
    let mut left: Vec<_> = std::fs::read_dir(gateway.dir.path())
        .expect("list")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| !name.contains("audit"))
        .collect();
    left.sort();
    assert_eq!(left, Vec::<String>::new(), "a refused route left files");
}

/// A gateway with a config path but no reload context: every backend route
/// fails closed with 503 and writes nothing.
#[tokio::test]
async fn without_a_reload_context_the_backend_routes_write_nothing() {
    let gateway = Audited::build(Reload::Absent).await;
    let answers = [
        ("add", gateway.add("b").await),
        ("remove", gateway.remove("a").await),
        ("update", gateway.update("a", "edited").await),
    ];
    for (route, (status, body)) in answers {
        assert_eq!(
            (status, &body["error"]),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                &Value::from("Config reload is not enabled on this gateway")
            ),
            "{route}: {body}"
        );
    }
    assert_eq!(gateway.text(), START, "a route with no context wrote");
}

/// Auth on and no audit log: a backend write is refused by the audit
/// posture, for that reason, and nothing is written.
#[tokio::test]
async fn with_auth_on_and_no_audit_log_a_backend_add_is_refused() {
    let mut gateway = Audited::new().await;
    let mut running = Config::load(Some(&gateway.config())).expect("config loads");
    running.auth.enabled = true;
    {
        let state = Arc::get_mut(&mut gateway.state).expect("state is unique");
        state.transparency_log = None;
        state.live_config = Arc::new(LiveConfig::new(running));
    }

    let (status, body) = gateway.add("b").await;

    assert_eq!(
        (status, &body["error"]),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            &Value::from("audit_log_required")
        ),
        "{body}"
    );
    assert_eq!(gateway.text(), START, "the refused add wrote");
}

/// A comment-loss refusal names the comment lines under a fixed
/// `gateway.yaml` label, never the server's filesystem path.
#[tokio::test]
async fn a_comment_loss_refusal_names_lines_not_the_server_path() {
    let gateway = Audited::new().await;
    let flow = "# top\nbackends: {a: {http_url: \"http://127.0.0.1:9/mcp\"}}\n";
    write_owner_only(gateway.config(), flow).expect("flow-style file");
    let (status, body) = gateway.update("a", "edited").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let message = body.to_string();
    assert!(message.contains("line 1"), "{message}");
    assert!(message.contains("gateway.yaml"), "{message}");
    let dir = gateway.dir.path().display().to_string();
    assert!(!message.contains(&dir), "the server path leaked: {message}");
    assert_eq!(gateway.text(), flow, "the refused edit wrote");
}

/// gateway.yaml deleted after the route's own check, while the writer waits
/// for the config lock: the writer's read finds it gone, and the answer is
/// the same 409 `no_config_file` the check gives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_config_deleted_under_the_writer_answers_no_config_file() {
    let gateway = Arc::new(Audited::new().await);
    let lock = crate::config_persistence::lock::lock_path(
        &crate::identity_grants::journal::resolved(&gateway.config()),
    );
    let held = crate::fs_lock::ExclusiveFileLock::try_acquire(&lock).expect("hold the lock");
    let baseline = crate::fs_lock::lock_attempts(&lock);
    let writing = Arc::clone(&gateway);
    let update = tokio::spawn(async move { writing.update("a", "edited").await });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while crate::fs_lock::lock_attempts(&lock) <= baseline {
        assert!(
            std::time::Instant::now() < deadline,
            "the writer never tried the config lock"
        );
        tokio::task::yield_now().await;
    }
    std::fs::remove_file(gateway.config()).expect("delete under the writer");
    drop(held);

    let (status, body) = update.await.expect("the update task");

    assert_eq!(
        (status, &body["error"], &body["message"]),
        (
            StatusCode::CONFLICT,
            &Value::from("no_config_file"),
            &Value::from(NO_CONFIG_FILE)
        ),
        "{body}"
    );
}
