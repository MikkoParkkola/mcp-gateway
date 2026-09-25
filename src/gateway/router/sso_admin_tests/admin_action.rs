// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E1 part 2 (E1-d, E1-f): every admin action, on the meta-tool gate and on
//! the admin UI, writes an `admin_action` record naming the caller, and is
//! refused while the audit log is down. The E1-core fixture plus one real
//! `TransparencyLogger` shared by `AppState` and the meta layer.

use std::time::Duration;

use super::*;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::control_plane::InMemoryControlPlaneStore;
use crate::gateway::meta_mcp::MetaMcp;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

/// A verified email on alice's token; no record may carry it.
const EMAIL_CANARY: &str = "alice.canary@corp.example";
/// A string in a request body; no record may carry it.
const BODY_CANARY: &str = "BODY-CANARY-5d1e";
const PREVIEW: &str = "/ui/api/import/openapi/preview";
const GRANTS: &str = "/ui/api/control-plane/grants";

struct Audited {
    gw: Gateway,
    log: Arc<TransparencyLogger>,
    alpha: Arc<Backend>,
    _dir: tempfile::TempDir,
}

/// The E1 gateway with an audit log under `policy`, backend `alpha`, a
/// control-plane store, and `exposed` as the meta-tool allow-list.
async fn audited(policy: AuditFailurePolicy, exposed: &[String]) -> Audited {
    let mut gw = gateway(&[ADMIN_GROUP_RULE]).await;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir.path().join("audit.jsonl").to_string_lossy().into_owned(),
            key_id: "e1".to_string(),
            shared_secret: String::new(),
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let alpha = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    let state = Arc::get_mut(&mut gw.state).expect("state is unique");
    assert!(state.backends.register(Arc::clone(&alpha)), "register alpha");
    let mut meta = MetaMcp::new(Arc::clone(&state.backends)).with_exposed_meta_tools(exposed);
    // One logger, shared by the meta layer and `AppState`, as the server wires it.
    meta.enable_transparency_log(Arc::clone(&log));
    state.meta_mcp = Arc::new(meta);
    state.transparency_log = Some(Arc::clone(&log));
    state.control_plane_store = Some(Arc::new(InMemoryControlPlaneStore::new()));
    Audited {
        gw,
        log,
        alpha,
        _dir: dir,
    }
}

impl Audited {
    fn alice(&self) -> String {
        let claims = json!({"email": EMAIL_CANARY, "email_verified": true});
        self.gw.a.token("alice", &["ops-admins"], &claims)
    }

    fn bob(&self) -> String {
        self.gw.a.token("bob", &["devs"], &json!({}))
    }

    /// Bounded, so a mutant that lets a handler hang fails by name.
    async fn send(&self, request: axum::http::Request<axum::body::Body>) -> (StatusCode, Value) {
        tokio::time::timeout(Duration::from_secs(30), send(&self.gw.state, request))
            .await
            .expect("the request finished")
    }

    async fn revive(&self, bearer: &str) -> (StatusCode, Value) {
        let call = json!({"name": "gateway_revive_server", "arguments": {"server": "alpha"}});
        self.send(rpc(bearer, "tools/call", &call)).await
    }

    fn raw(&self) -> String {
        std::fs::read_to_string(self.log.path()).unwrap_or_default()
    }

    fn entries(&self) -> Vec<Value> {
        self.raw()
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON entry"))
            .collect()
    }

    fn admin_actions(&self) -> Vec<Value> {
        self.entries()
            .into_iter()
            .filter(|e| e["event"] == "admin_action")
            .collect()
    }

    /// A failed append, so the logger is degraded before the call (D1-T17).
    fn degrade(&self) {
        self.log.set_append_failure_for_test(true);
        assert!(self.log.probe().is_err(), "the priming append fails");
        assert!(self.log.is_degraded(), "the logger is degraded");
    }
}

fn ui(method: &str, uri: &str, bearer: &str, body: &Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

/// An inline one-operation spec whose description is the body canary.
fn preview_body() -> Value {
    let spec = json!({
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "servers": [{"url": "https://api.example"}],
        "paths": {"/ping": {"get": {
            "operationId": "ping",
            "description": BODY_CANARY,
            "responses": {"200": {"description": "ok"}},
        }}},
    });
    json!({"spec": spec.to_string()})
}

fn grant_body() -> Value {
    json!({
        "grant": {"grant_id": "g1", "subject_id": "s1", "server_id": "alpha", "status": "approved"},
        "reason": "T-1",
        "rollback": {"summary": "revoke g1", "step": "revoke"},
    })
}

fn assert_record(record: &Value, surface: &str, outcome: &str, code: Option<i64>) {
    assert_eq!(record["event"], "admin_action", "{record}");
    assert_eq!(record["surface"], surface, "{record}");
    assert_eq!(record["outcome"], outcome, "{record}");
    assert_eq!(record.get("error_code").and_then(Value::as_i64), code, "{record}");
}

fn assert_ui_record(record: &Value, route: &str, status: u16, outcome: &str, code: Option<i64>) {
    assert_record(record, "admin_ui", outcome, code);
    assert_eq!(record["route"], route, "{record}");
    assert_eq!(record["method"], "POST", "{record}");
    assert_eq!(record["http_status"], status, "{record}");
}

fn assert_alice(record: &Value) {
    assert_eq!(record["who"]["authority"], ISS_A, "{record}");
    assert_eq!(record["who"]["subject"], "alice", "{record}");
}

fn assert_audit_unavailable_ui(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(
        body["error"],
        crate::Error::AuditUnavailable.to_string(),
        "{body}"
    );
}

fn assert_audit_unavailable_rpc(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
    assert!(body.get("result").is_none(), "{body}");
}

// ── E1-d: the admin meta-tool gate ──────────────────────────────────

/// E1-T10: a permitted and a refused admin meta-tool call each write one
/// record naming the person, never the email.
#[tokio::test]
async fn admin_action_record_names_person() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let (status, body) = fx.revive(&fx.alice()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fx.revive(&fx.bob()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let records = fx.admin_actions();
    assert_eq!(records.len(), 2, "{records:#?}");
    assert_record(&records[0], "meta_tool", "ok", None);
    assert_eq!(records[0]["tool"], "gateway_revive_server");
    assert_alice(&records[0]);
    assert_record(&records[1], "meta_tool", "denied", Some(-32600));
    assert_eq!(records[1]["tool"], "gateway_revive_server");
    assert_eq!(records[1]["who"]["authority"], ISS_A);
    assert_eq!(records[1]["who"]["subject"], "bob");
    assert!(!fx.raw().contains(EMAIL_CANARY), "the email was logged");
}

/// Control: an admin meta-tool the operator does not expose never reaches
/// the gate, so it writes no record.
#[tokio::test]
async fn unexposed_admin_meta_tool_writes_no_record() {
    let fx = audited(
        AuditFailurePolicy::FailClosed,
        &["gateway_list_servers".to_string()],
    )
    .await;
    let (status, body) = fx.revive(&fx.alice()).await;
    assert!(body.get("result").is_none(), "{status} {body}");
    assert!(fx.admin_actions().is_empty(), "{:#?}", fx.entries());
}

/// E1-T13b: while degraded the gate refuses before the tool runs; once
/// storage heals, the gate's admit writes the probe before the record.
#[tokio::test]
async fn admin_meta_tool_refused_while_degraded() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let kill_switch = fx.gw.state.meta_mcp.kill_switch();
    kill_switch.kill("alpha");
    fx.degrade();
    let (status, body) = fx.revive(&fx.alice()).await;
    assert_audit_unavailable_rpc(status, &body);
    assert!(kill_switch.is_killed("alpha"), "the revive ran");

    fx.log.set_append_failure_for_test(false);
    let before = fx.entries().len();
    let (status, body) = fx.revive(&fx.alice()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!kill_switch.is_killed("alpha"), "the healed revive did not run");
    let new = &fx.entries()[before..];
    assert!(new.len() >= 2, "{new:#?}");
    assert_eq!(new[0]["type"], "audit_probe", "admit wrote no probe: {new:#?}");
    assert_record(&new[1], "meta_tool", "ok", None);
}

/// E1-T13c (meta): admit passes, the record append fails, and the result is
/// withheld before the tool runs.
#[tokio::test]
async fn failed_admin_record_withholds_meta_tool() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let kill_switch = fx.gw.state.meta_mcp.kill_switch();
    kill_switch.kill("alpha");
    fx.log.fail_next_append_for_test();
    let (status, body) = fx.revive(&fx.alice()).await;
    assert_audit_unavailable_rpc(status, &body);
    assert!(kill_switch.is_killed("alpha"), "the revive ran");
}

// ── E1-f: the admin UI layer ────────────────────────────────────────

/// E1-T12: an admin UI mutation and a refused one each write one record;
/// neither the body nor the email is logged.
#[cfg(feature = "webui")]
#[tokio::test]
async fn ui_admin_mutation_writes_admin_action() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let (status, body) = fx.send(ui("POST", PREVIEW, &fx.alice(), &preview_body())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fx
        .send(ui("POST", "/ui/api/reload", STANDARD_KEY, &json!({})))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let records = fx.admin_actions();
    assert_eq!(records.len(), 2, "{records:#?}");
    assert_ui_record(&records[0], PREVIEW, 200, "ok", None);
    assert_alice(&records[0]);
    assert_ui_record(&records[1], "/ui/api/reload", 403, "denied", Some(-32600));
    assert_eq!(records[1]["who"]["account"], STANDARD_KEY);
    let raw = fx.raw();
    assert!(!raw.contains(BODY_CANARY), "the request body was logged");
    assert!(!raw.contains(EMAIL_CANARY), "the email was logged");
}

/// E1-T12a: a handler failure is `error` with the shared code.
#[cfg(feature = "webui")]
#[tokio::test]
async fn ui_admin_error_is_error() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let (status, body) = fx
        .send(ui("POST", "/ui/api/reload", &fx.alice(), &json!({})))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let records = fx.admin_actions();
    assert_eq!(records.len(), 1, "{records:#?}");
    assert_ui_record(&records[0], "/ui/api/reload", 503, "error", Some(-32603));
}

/// E1-T12b (control): reads write nothing.
#[cfg(feature = "webui")]
#[tokio::test]
async fn ui_get_writes_no_record() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    for method in ["GET", "HEAD"] {
        let request = axum::http::Request::builder()
            .method(method)
            .uri("/ui/api/config")
            .header("authorization", format!("Bearer {}", fx.alice()))
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, _) = fx.send(request).await;
        assert_eq!(status, StatusCode::OK, "{method}");
    }
    assert!(fx.entries().is_empty(), "{:#?}", fx.entries());
}

/// E1-T12c (amended): a control-plane POST writes one `admin_action` each,
/// the 409 as `error` and the RBAC refusal as `denied`, and nothing else.
#[cfg(feature = "webui")]
#[tokio::test]
async fn control_plane_mutation_is_recorded() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let (status, body) = fx.send(ui("POST", GRANTS, &fx.alice(), &grant_body())).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = fx.send(ui("POST", GRANTS, STANDARD_KEY, &grant_body())).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let entries = fx.entries();
    assert_eq!(entries.len(), 2, "only admin_action entries: {entries:#?}");
    assert_ui_record(&entries[0], GRANTS, 409, "error", Some(-32603));
    assert_alice(&entries[0]);
    assert_ui_record(&entries[1], GRANTS, 403, "denied", Some(-32600));
}

/// E1-T12d: the route is the matched template, never the path or query.
#[cfg(feature = "webui")]
#[tokio::test]
async fn route_is_the_template_not_the_path() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    let uri = "/ui/api/backends/secret-backend-canary/revive?x=QUERY-CANARY";
    let (status, body) = fx.send(ui("POST", uri, &fx.alice(), &json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let records = fx.admin_actions();
    assert_eq!(records.len(), 1, "{records:#?}");
    let route = "/ui/api/backends/{name}/revive";
    assert_ui_record(&records[0], route, 404, "invalid", Some(-32602));
    let raw = fx.raw();
    assert!(!raw.contains("secret-backend-canary"), "the path was logged");
    assert!(!raw.contains("QUERY-CANARY"), "the query was logged");
}

/// E1-T13: while degraded the handler does not run.
#[cfg(feature = "webui")]
#[tokio::test]
async fn ui_admin_mutation_refused_while_degraded() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    fx.alpha.trip_circuit_breaker("e1-t13");
    fx.degrade();
    let uri = "/ui/api/backends/alpha/revive";
    let (status, body) = fx.send(ui("POST", uri, &fx.alice(), &json!({}))).await;
    assert_audit_unavailable_ui(status, &body);
    assert!(fx.alpha.is_circuit_tripped(), "the revive handler ran");
}

/// E1-T13c (UI): admit passes, the record append fails, the result is withheld.
#[cfg(feature = "webui")]
#[tokio::test]
async fn failed_admin_record_withholds_ui_result() {
    let fx = audited(AuditFailurePolicy::FailClosed, &[]).await;
    fx.log.fail_next_append_for_test();
    let (status, body) = fx.send(ui("POST", PREVIEW, &fx.alice(), &preview_body())).await;
    assert_audit_unavailable_ui(status, &body);
    assert!(body.get("tools").is_none(), "{body}");
}

/// E1-T13d: under BestEffort a failed record append is counted and both
/// surfaces answer as usual.
#[cfg(feature = "webui")]
#[tokio::test]
async fn best_effort_admin_record_failure_does_not_refuse() {
    let fx = audited(AuditFailurePolicy::BestEffort, &[]).await;
    fx.log.set_append_failure_for_test(true);
    let (status, body) = fx.send(ui("POST", PREVIEW, &fx.alice(), &preview_body())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fx.revive(&fx.alice()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(fx.log.append_failures() >= 2, "no record was attempted");
    assert!(!fx.log.is_degraded());
}
