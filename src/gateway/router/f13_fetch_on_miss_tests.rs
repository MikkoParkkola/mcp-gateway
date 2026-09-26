// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F13 (MIK-7586): R2's check fetches the caller's catalogue when the slot is
//! cold, instead of forwarding the call unchecked.
//!
//! Router-level red-first cells. They drive only existing entry points: a
//! POST on `/mcp` (`gateway_invoke`) or `/mcp/{name}`, and counter labels read
//! as strings from a local Prometheus render. The wire counts `tools/list`
//! and `tools/call` separately and records the headers of every request, so
//! "refused" means the backend saw no call and "fetched" means it saw a list.

use axum::body::to_bytes;
use axum::http::StatusCode;
use parking_lot::Mutex;
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::r2_identity_keys_tests::{PerIdentityMint, transparency_logger};
use super::tests::{direct_route_state_with_identity, test_router_app_state_with_backend};
use crate::backend::{Backend, PoolKey};
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

/// Stable fragment of refusal text U (schema unavailable), design §2 step 4.
const TEXT_U: &str = "could not read this tool's input schema";
/// Stable fragment of refusal text A (absent from a complete catalogue).
const TEXT_A: &str = "does not list a tool named";

/// How the wire answers `tools/list`.
#[derive(Clone, Copy, Default)]
pub(super) enum ListMode {
    #[default]
    Serve,
    Fail,
    Hang,
}

/// The extra headers one request carried.
type Headers = Vec<(String, String)>;

/// What one pool slot's wire saw, and how it answers.
#[derive(Default)]
pub(super) struct Rec {
    calls: Mutex<Vec<Value>>,
    lists: AtomicUsize,
    headers: Mutex<Vec<(String, Headers)>>,
    mode: Mutex<ListMode>,
    tools: Mutex<Option<Value>>,
}

impl Rec {
    fn with_mode(mode: ListMode) -> Arc<Self> {
        let rec = Arc::new(Self::default());
        *rec.mode.lock() = mode;
        rec
    }

    pub(super) fn lists(&self) -> usize {
        self.lists.load(Ordering::SeqCst)
    }

    pub(super) fn calls(&self) -> usize {
        self.calls.lock().len()
    }

    fn serve(&self, tools: Value) {
        *self.tools.lock() = Some(tools);
    }

    /// The extra headers each request of `method` carried, in order.
    fn headers_of(&self, method: &str) -> Vec<Headers> {
        self.headers
            .lock()
            .iter()
            .filter(|(m, _)| m == method)
            .map(|(_, h)| h.clone())
            .collect()
    }
}

fn edit_schema() -> Value {
    json!({"type": "object", "properties": {
        "edits": {"type": "array", "items": {"type": "object",
            "properties": {"oldText": {"type": "string"}, "newText": {"type": "string"}},
            "required": ["oldText", "newText"]}},
        "note": {"type": "string"},
        "count": {"type": "integer"}
    }})
}

fn has_header(headers: &[(String, String)], name: &str, value: &str) -> bool {
    headers.iter().any(|(n, v)| n == name && v == value)
}

fn tool(name: &str, schema: &Value) -> Value {
    json!({"name": name, "description": "fixture", "inputSchema": schema})
}

struct Wire {
    rec: Arc<Rec>,
}

fn wire(rec: &Arc<Rec>) -> Arc<Wire> {
    Arc::new(Wire {
        rec: Arc::clone(rec),
    })
}

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        self.request_with_headers(
            method,
            params,
            &[],
            None,
            crate::transport::ResendPermission::Permitted,
        )
        .await
    }

    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let rec = &self.rec;
        rec.headers
            .lock()
            .push((method.to_string(), extra_headers.to_vec()));
        let result = match method {
            "tools/list" => {
                rec.lists.fetch_add(1, Ordering::SeqCst);
                let mode = *rec.mode.lock();
                match mode {
                    ListMode::Serve => {}
                    ListMode::Fail => {
                        return Err(crate::Error::BackendUnavailable(
                            "f13 fixture: tools/list fails".to_string(),
                        ));
                    }
                    ListMode::Hang => std::future::pending::<()>().await,
                }
                let tools = rec.tools.lock().clone();
                json!({"tools": tools.unwrap_or_else(|| json!([tool("edit", &edit_schema())]))})
            }
            "tools/call" => {
                rec.calls.lock().push(params.unwrap_or(Value::Null));
                json!({"content": [{"type": "text", "text": "done"}]})
            }
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
    }

    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A single-tenant gateway: one `edits` backend on the `Shared` slot.
pub(super) struct Fx {
    pub(super) router: axum::Router,
    pub(super) rec: Arc<Rec>,
    backend: Arc<Backend>,
    _store: tempfile::TempDir,
}

/// Knobs of the single-tenant fixture. `unwired` leaves the slot with no
/// wire, so its start fails as a dead backend's does; `ttl` defaults to 60 s.
#[derive(Default)]
struct Setup {
    config: BackendConfig,
    failsafe: FailsafeConfig,
    ttl: Option<Duration>,
    list: ListMode,
    warm: bool,
    unwired: bool,
}

/// A cold `Shared` slot under `mode_of_check`, its list answered per `list`.
pub(super) async fn cold(mode_of_check: InputSchemaEnforcement, list: ListMode) -> Fx {
    let config = BackendConfig {
        input_schema_enforcement: mode_of_check,
        ..BackendConfig::default()
    };
    build(Setup {
        config,
        list,
        ..Setup::default()
    })
    .await
}

async fn build(setup: Setup) -> Fx {
    let ttl = setup.ttl.unwrap_or(Duration::from_secs(60));
    let backend = Arc::new(Backend::new("edits", setup.config, &setup.failsafe, ttl));
    let rec = Rec::with_mode(setup.list);
    if !setup.unwired {
        backend.set_transport_for_test(wire(&rec));
    }
    if setup.warm {
        let listed = backend.get_tools_for_binding(None, &[]).await;
        listed.expect("the fixture lists its tools");
    }
    let (state, store) = test_router_app_state_with_backend(Arc::clone(&backend)).await;
    Fx {
        router: create_router(state),
        rec,
        backend,
        _store: store,
    }
}

/// A per-user propagating gateway: each subject has its own `PerUser` slot
/// and wire; `shared` is the canonical slot's wire.
struct PerUser {
    router: axum::Router,
    slots: Vec<Arc<Rec>>,
    shared: Arc<Rec>,
    _store: tempfile::TempDir,
    _audit: [tempfile::NamedTempFile; 2],
}

async fn per_user(subjects: &[&str]) -> PerUser {
    let backend = Arc::new(Backend::new(
        "edits",
        BackendConfig {
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "edits".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let shared = Arc::<Rec>::default();
    backend.set_transport_for_test(wire(&shared));
    let slots: Vec<Arc<Rec>> = subjects.iter().map(|_| Arc::default()).collect();
    for (subject, rec) in subjects.iter().zip(&slots) {
        let binding = format!("{subject}@edits");
        backend.set_pooled_transport_for_test(&PoolKey::PerUser { binding }, wire(rec));
    }
    let (mut state, store) =
        direct_route_state_with_identity(crate::config::AgentIdentityConfig::default()).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    assert!(state_mut.backends.register(backend), "fixture registration");
    let audit = [
        tempfile::NamedTempFile::new().expect("tempfile"),
        tempfile::NamedTempFile::new().expect("tempfile"),
    ];
    let mut meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.set_identity_propagation(Arc::new(PerIdentityMint));
    meta.enable_transparency_log(transparency_logger(&audit[0]));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(transparency_logger(&audit[1]));
    PerUser {
        router: create_router(state),
        slots,
        shared,
        _store: store,
        _audit: audit,
    }
}

/// POST `body` to `uri`, as `subject` when one is given.
async fn post(
    router: &axum::Router,
    uri: &str,
    body: &Value,
    subject: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    if let Some(subject) = subject {
        // Auth is disabled in this state, so the middleware leaves it in place.
        request.extensions_mut().insert(VerifiedIdentity {
            subject: subject.to_string(),
            email: format!("{subject}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://idp.example.invalid".to_string(),
        });
    }
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The route a cell drives: Meta-MCP `gateway_invoke`, or direct `/mcp/edits`.
#[derive(Clone, Copy, Debug)]
enum Route {
    Meta,
    Direct,
}

impl Route {
    fn uri(self) -> &'static str {
        match self {
            Self::Meta => "/mcp",
            Self::Direct => "/mcp/edits",
        }
    }

    fn body(self, tool: &str, arguments: &Value) -> Value {
        match self {
            Self::Meta => json!({"jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {"name": "gateway_invoke", "arguments":
                    {"server": "edits", "tool": tool, "arguments": arguments}}}),
            Self::Direct => json!({"jsonrpc": "2.0", "id": 32, "method": "tools/call",
                "params": {"name": tool, "arguments": arguments}}),
        }
    }
}

/// Call `tool` on `route`, anonymously or as `subject`.
async fn call(
    router: &axum::Router,
    route: Route,
    tool: &str,
    arguments: &Value,
    subject: Option<&str>,
) -> (StatusCode, Value) {
    post(router, route.uri(), &route.body(tool, arguments), subject).await
}

fn nested_invented() -> Value {
    json!({"edits": [{"oldText": "a", "newText": "b", "type": "replace"}]})
}

/// The tool result the caller sees, through `gateway_invoke`'s envelope or
/// as the direct route's JSON-RPC result.
fn tool_result(body: &Value) -> Value {
    body["result"]["content"][0]["text"]
        .as_str()
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .filter(|inner| inner.get("isError").is_some())
        .unwrap_or_else(|| body["result"].clone())
}

fn is_error(body: &Value) -> bool {
    tool_result(body)["isError"] == json!(true)
}

/// Refused with a text containing `fragment` (a key path or a text U/A part).
fn refused_with(body: &Value, fragment: &str) -> bool {
    is_error(body) && body.to_string().contains(fragment)
}

/// Any refusal or error, whichever layer produced it.
fn failed(status: StatusCode, body: &Value) -> bool {
    status != StatusCode::OK || !body["error"].is_null() || is_error(body)
}

/// Run `fut` under a local Prometheus recorder; return its output and the render.
#[cfg(feature = "metrics")]
pub(super) fn metered<F: std::future::Future>(fut: F) -> (F::Output, String) {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = telemetry_metrics::with_local_recorder(&recorder, || runtime.block_on(fut));
    (out, handle.render())
}

/// A non-zero sample line of `mcp_input_schema_events_total{kind="<label>"}`.
#[cfg(feature = "metrics")]
pub(super) fn kind_counted(rendered: &str, label: &str) -> bool {
    counted(
        rendered,
        &["mcp_input_schema_events_total", &format!("\"{label}\"")],
    )
}

/// A non-zero sample line carrying every fragment.
#[cfg(feature = "metrics")]
fn counted(rendered: &str, fragments: &[&str]) -> bool {
    rendered.lines().any(|l| {
        !l.starts_with('#') && !l.ends_with(" 0") && fragments.iter().all(|f| l.contains(f))
    })
}
/// T1/T2 body: alpha's `PerUser` slot is cold, `closed`, nested invented key.
async fn cold_per_user_refuses(route: Route) {
    let gw = per_user(&["alpha"]).await;
    let (_, body) = call(&gw.router, route, "edit", &nested_invented(), Some("alpha")).await;
    let alpha = &gw.slots[0];
    assert!(
        refused_with(&body, "edits[0].type"),
        "{route:?}: forwarded instead of refused: {body}"
    );
    assert_eq!(
        alpha.lists(),
        1,
        "{route:?}: alpha's slot was not listed once"
    );
    assert_eq!(
        alpha.calls() + gw.shared.calls(),
        0,
        "{route:?}: the backend saw the call"
    );
}

/// F13-T1: cold `PerUser` slot on the Meta-MCP route (`gateway_invoke`):
/// refused after one `tools/list`, zero `tools/call`. Red on base: the check
/// counts `input_schema_unknown` and forwards, and no list is sent.
#[tokio::test]
async fn f13_t1_cold_per_user_meta_refuses_after_one_list() {
    cold_per_user_refuses(Route::Meta).await;
}

/// F13-T2: T1 on the direct `/mcp/edits` route. Red on base: forwarded
/// unchecked, no list sent.
#[tokio::test]
async fn f13_t2_cold_per_user_direct_refuses_after_one_list() {
    cold_per_user_refuses(Route::Direct).await;
}

/// F13-T8b (and T1's `Shared` form): `Shared` slot, no caller credential,
/// cold, `closed`, on both routes: exactly one `tools/list`, then judged.
/// Red on base: no list, forwarded.
#[tokio::test]
async fn f13_t8b_cold_shared_no_credential_lists_once_then_judges() {
    for route in [Route::Meta, Route::Direct] {
        let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
        let (_, body) = call(&fx.router, route, "edit", &nested_invented(), None).await;
        assert!(refused_with(&body, "edits[0].type"), "{route:?}: {body}");
        assert_eq!(fx.rec.lists(), 1, "{route:?}");
        assert_eq!(fx.rec.calls(), 0, "{route:?}: the backend saw the call");
    }
}

/// F13-T3: 16 concurrent cold calls send exactly one `tools/list` (the fill
/// is single-flight), and every call is refused. Red on base: zero lists.
#[tokio::test]
async fn f13_t3_concurrent_cold_calls_share_one_list() {
    let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
    let args = nested_invented();
    let calls = (0..16).map(|_| call(&fx.router, Route::Direct, "edit", &args, None));
    let results = futures::future::join_all(calls).await;
    assert_eq!(fx.rec.lists(), 1, "not single-flight");
    assert_eq!(fx.rec.calls(), 0, "a cold call reached the backend");
    assert!(
        results
            .iter()
            .all(|(_, b)| refused_with(b, "edits[0].type"))
    );
}

/// Review-fold waiter cell: 16 concurrent cold calls on a hanging list all
/// return within `timeout` + grace, with exactly one `tools/list`, refused
/// with text U. Red on base: zero lists (each call is forwarded at once).
#[tokio::test]
async fn f13_waiters_on_a_hanging_list_share_one_bounded_fill() {
    let fx = build(Setup {
        config: BackendConfig {
            timeout: Duration::from_millis(300),
            ..BackendConfig::default()
        },
        list: ListMode::Hang,
        ..Setup::default()
    })
    .await;
    let args = nested_invented();
    let calls = (0..16).map(|_| call(&fx.router, Route::Direct, "edit", &args, None));
    let results = tokio::time::timeout(Duration::from_secs(10), futures::future::join_all(calls))
        .await
        .expect("a waiter was not bounded by timeout + grace");
    assert_eq!(fx.rec.lists(), 1, "not single-flight");
    assert_eq!(fx.rec.calls(), 0, "a cold call reached the backend");
    assert!(results.iter().all(|(_, b)| refused_with(b, TEXT_U)));
}
/// F13-T4: the cold fetch fails. `closed`: text U, zero `tools/call`,
/// `refused_unavailable` and `fetch_failed` counted. `standard`: forwarded,
/// `unknown` counted. `off`: forwarded, zero `tools/list`. Red on base:
/// `closed` forwards and neither `closed` label exists.
#[cfg(feature = "metrics")]
#[test]
fn f13_t4_failed_fetch_per_mode() {
    let row = |mode| {
        metered(async move {
            let fx = cold(mode, ListMode::Fail).await;
            let args = nested_invented();
            let (_, body) = call(&fx.router, Route::Direct, "edit", &args, None).await;
            (body, fx.rec.lists(), fx.rec.calls())
        })
    };
    let ((body, lists, calls), rendered) = row(InputSchemaEnforcement::Closed);
    assert!(refused_with(&body, TEXT_U), "closed: {body}");
    assert_eq!((lists, calls), (1, 0), "closed");
    for label in [
        "input_schema_refused_unavailable",
        "input_schema_fetch_failed",
    ] {
        assert!(kind_counted(&rendered, label), "{label}: {rendered}");
    }
    let ((body, lists, calls), rendered) = row(InputSchemaEnforcement::Standard);
    assert!(!is_error(&body), "standard: {body}");
    assert_eq!((lists, calls), (1, 1), "standard");
    assert!(
        kind_counted(&rendered, "input_schema_unknown"),
        "{rendered}"
    );
    let ((body, lists, calls), _) = row(InputSchemaEnforcement::Off);
    assert!(!is_error(&body), "off: {body}");
    assert_eq!((lists, calls), (0, 1), "off must not fetch");
}

/// F13-T7: fresh complete slot, invented tool name, 5 calls: zero
/// `tools/list`, text A without a list-and-retry instruction. Once the slot
/// is stale (1.5 s TTL, real sleep), one call sends exactly one list. Red on
/// base: forwarded, and the stale call sends no list.
#[tokio::test]
async fn f13_t7_invented_tool_on_a_complete_slot_is_absent() {
    let fx = build(Setup {
        ttl: Some(Duration::from_millis(1500)),
        ..Setup::default()
    })
    .await;
    // Warmed here, not in `build`: the fresh phase must fit inside the TTL.
    let warm = fx.backend.get_tools_for_binding(None, &[]).await;
    warm.expect("the fixture lists its tools");
    let warmed = fx.rec.lists();
    for _ in 0..5 {
        let (_, body) = call(&fx.router, Route::Direct, "nosuch", &json!({}), None).await;
        assert!(refused_with(&body, TEXT_A), "{body}");
        let retry = body.to_string().contains("retry");
        assert!(!retry, "text A says retry: {body}");
    }
    assert_eq!(fx.rec.lists(), warmed, "a fresh slot was refetched");
    assert_eq!(fx.rec.calls(), 0, "an absent tool reached the backend");

    tokio::time::sleep(Duration::from_millis(1700)).await;
    let (_, body) = call(&fx.router, Route::Direct, "nosuch", &json!({}), None).await;
    assert!(refused_with(&body, TEXT_A), "{body}");
    assert_eq!(fx.rec.lists(), warmed + 1, "a stale slot must refetch once");
}

/// F13-T7b: a tool added upstream after the fill is picked up once the slot
/// goes stale: its declared key is forwarded, its undeclared key refused with
/// the key-refusal text. Red on base: the undeclared key is forwarded.
#[tokio::test]
async fn f13_t7b_tool_added_upstream_is_judged_after_refetch() {
    let fx = build(Setup {
        ttl: Some(Duration::from_millis(50)),
        warm: true,
        ..Setup::default()
    })
    .await;
    let added = json!({"type": "object", "properties": {"alpha": {"type": "string"}}});
    fx.rec
        .serve(json!([tool("edit", &edit_schema()), tool("added", &added)]));
    tokio::time::sleep(Duration::from_millis(120)).await;

    let (undeclared, declared) = (json!({"zzinvented": 1}), json!({"alpha": "x"}));
    let (_, body) = call(&fx.router, Route::Direct, "added", &undeclared, None).await;
    assert!(refused_with(&body, "zzinvented"), "{body}");
    assert_eq!(fx.rec.calls(), 0, "the undeclared key was forwarded");
    let (_, body) = call(&fx.router, Route::Direct, "added", &declared, None).await;
    assert!(!is_error(&body), "the declared key was refused: {body}");
    assert_eq!(fx.rec.calls(), 1);
}

/// F13-T10b: complete slot, invented tool name, `standard`: forwarded and
/// counted `input_schema_absent_forward`, not `input_schema_unknown`. Red on
/// base: counted `unknown`, and the label does not exist.
#[cfg(feature = "metrics")]
#[test]
fn f13_t10b_absent_forward_is_its_own_label() {
    let ((body, rec), rendered) = metered(async {
        let fx = build(Setup {
            config: BackendConfig {
                input_schema_enforcement: InputSchemaEnforcement::Standard,
                ..BackendConfig::default()
            },
            warm: true,
            ..Setup::default()
        })
        .await;
        let (_, body) = call(&fx.router, Route::Direct, "nosuch", &json!({}), None).await;
        (body, fx.rec)
    });
    assert!(!is_error(&body), "{body}");
    assert_eq!(rec.calls(), 1, "standard must forward");
    let absent = kind_counted(&rendered, "input_schema_absent_forward");
    let unknown = kind_counted(&rendered, "input_schema_unknown");
    assert!(absent && !unknown, "{rendered}");
}

/// F13-T11: the first cold call carries its `Mcp-Param-*` mirror, because the
/// fill warmed the slot `param_header_set` reads. Red on base: the slot is
/// cold at dispatch, so the first call carries no mirror.
#[tokio::test]
async fn f13_t11_first_cold_call_carries_its_param_mirror() {
    let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
    let schema = json!({"type": "object", "properties": {
        "edits": {"type": "array"},
        "note": {"type": "string", "x-mcp-header": "Note"}
    }});
    fx.rec.serve(json!([tool("edit", &schema)]));
    let args = json!({"edits": [], "note": "n1"});
    let (_, body) = call(&fx.router, Route::Direct, "edit", &args, None).await;
    assert!(!is_error(&body), "{body}");
    let sent = fx.rec.headers_of("tools/call");
    assert_eq!(sent.len(), 1, "{body}");
    let mirrored = has_header(&sent[0], "Mcp-Param-Note", "n1");
    assert!(mirrored, "the first call carried no mirror: {sent:?}");
}

/// F13-T9 (A3), on both routes: alpha's slot is warm with a schema that
/// declares `zzextra`; beta's is cold and its catalogue does not. Beta's cold
/// call fetches with beta's own minted token and is judged against beta's
/// schema. Red on base: beta's slot is never listed and the call forwards.
#[tokio::test]
async fn f13_t9_cold_caller_fetches_its_own_catalogue_with_its_own_token() {
    for route in [Route::Meta, Route::Direct] {
        let gw = per_user(&["alpha", "beta"]).await;
        let (alpha, beta) = (&gw.slots[0], &gw.slots[1]);
        let with_extra = json!({"type": "object", "properties": {
            "edits": {"type": "array"}, "zzextra": {"type": "integer"}}});
        let without = json!({"type": "object", "properties": {"edits": {"type": "array"}}});
        alpha.serve(json!([tool("edit", &with_extra)]));
        beta.serve(json!([tool("edit", &without)]));
        let list = json!({"jsonrpc": "2.0", "id": 33, "method": "tools/list"});
        let (status, _) = post(&gw.router, "/mcp/edits", &list, Some("alpha")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(alpha.lists(), 1, "{route:?}: alpha did not warm its slot");

        let args = json!({"edits": [], "zzextra": 1});
        let (_, body) = call(&gw.router, route, "edit", &args, Some("beta")).await;
        assert!(refused_with(&body, "zzextra"), "{route:?}: {body}");
        assert_eq!(beta.lists(), 1, "{route:?}: beta's slot was not listed");
        let token = beta.headers_of("tools/list");
        let as_beta = has_header(&token[0], "Authorization", "Bearer minted-for-beta");
        assert!(
            as_beta,
            "{route:?}: beta's list was not fetched as beta: {token:?}"
        );
        let calls = beta.calls() + alpha.calls() + gw.shared.calls();
        assert_eq!((calls, gw.shared.lists()), (0, 0), "{route:?}");
    }
}

/// F13-T12: the caller's breaker is open, cold, `closed`: the call fails with
/// zero `tools/list` and `input_schema_fill_refused{reason="circuit"}` is
/// counted. Red on base: the dispatch returns `CircuitOpen` already, but the
/// fill-origin label does not exist.
#[cfg(feature = "metrics")]
#[test]
fn f13_t12_open_breaker_refuses_the_fill_and_counts_it() {
    let ((status, body, rec), rendered) = metered(async {
        let fx = cold(InputSchemaEnforcement::Closed, ListMode::Serve).await;
        fx.backend.trip_circuit_breaker_for_test();
        let (status, body) =
            call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
        (status, body, fx.rec)
    });
    assert!(failed(status, &body), "{body}");
    assert_eq!((rec.lists(), rec.calls()), (0, 0));
    assert!(
        counted(&rendered, &["input_schema_fill_refused", "circuit"]),
        "the fill-origin refusal was not counted: {rendered}"
    );
}

/// Failsafe with a breaker of `threshold` and a 500 ms reset timeout.
fn breaker(threshold: u32) -> FailsafeConfig {
    let mut failsafe = FailsafeConfig::default();
    failsafe.circuit_breaker.failure_threshold = threshold;
    failsafe.circuit_breaker.reset_timeout = Duration::from_millis(500);
    failsafe
}

/// F13-T12b: rate limit of one token, cold, `closed`, a valid call: the fill
/// spends the token and sends one `tools/list`; the dispatch is refused as
/// rate-limited. Red on base: no list, and the dispatch spends the token and
/// succeeds.
#[tokio::test]
async fn f13_t12b_one_token_is_spent_by_the_fill() {
    let mut failsafe = FailsafeConfig::default();
    failsafe.rate_limit.enabled = true;
    failsafe.rate_limit.requests_per_second = 1;
    failsafe.rate_limit.burst_size = 1;
    let fx = build(Setup {
        failsafe,
        ..Setup::default()
    })
    .await;
    let (status, body) = call(
        &fx.router,
        Route::Direct,
        "edit",
        &json!({"edits": []}),
        None,
    )
    .await;
    assert_eq!(fx.rec.lists(), 1, "the fill did not run: {body}");
    assert_eq!(fx.rec.calls(), 0, "the dispatch got a token: {body}");
    assert!(failed(status, &body), "{body}");
}

/// F13-T12c: a failing check-site fill counts toward the breaker. Threshold
/// 1: one cold `closed` call with a failing list is refused with text U, sends
/// zero `tools/call`, and leaves the breaker open. Red on base: the call is
/// forwarded (one `tools/call`) and the list failure is never observed.
#[tokio::test]
async fn f13_t12c_failed_fill_trips_the_breaker() {
    let fx = build(Setup {
        failsafe: breaker(1),
        list: ListMode::Fail,
        ..Setup::default()
    })
    .await;
    let (_, body) = call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
    assert!(refused_with(&body, TEXT_U), "{body}");
    assert_eq!(fx.rec.calls(), 0, "the call was forwarded");
    assert!(
        fx.backend.is_circuit_tripped(),
        "the failed fill was not recorded"
    );
}

/// F13-T12e: half-open breaker, cold, `closed`, failing list: refused with
/// text U and zero `tools/call`; the breaker is open again. Red on base: the
/// half-open dispatch is forwarded and succeeds.
#[tokio::test]
async fn f13_t12e_half_open_failed_fill_reopens_the_breaker() {
    let fx = build(Setup {
        failsafe: breaker(1),
        list: ListMode::Fail,
        ..Setup::default()
    })
    .await;
    fx.backend.trip_circuit_breaker_for_test();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (_, body) = call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
    assert!(refused_with(&body, TEXT_U), "{body}");
    assert_eq!(fx.rec.calls(), 0, "the half-open call was forwarded");
    assert_eq!(
        fx.backend.circuit_breaker_stats().state,
        crate::failsafe::CircuitState::Open,
        "the failed half-open fill did not reopen the breaker"
    );
}

/// F13-T12g: a backend whose start fails (no wire, empty URL), cold,
/// `closed`: refused with text U; with threshold 1 the breaker is then open.
/// Red on base: the call returns the dispatch's start error, not text U.
#[tokio::test]
async fn f13_t12g_start_failure_is_text_u_and_recorded() {
    let fx = build(Setup {
        config: BackendConfig {
            timeout: Duration::from_secs(2),
            ..BackendConfig::default()
        },
        failsafe: breaker(1),
        unwired: true,
        ..Setup::default()
    })
    .await;
    let (_, body) = call(&fx.router, Route::Direct, "edit", &nested_invented(), None).await;
    assert!(refused_with(&body, TEXT_U), "{body}");
    assert!(
        fx.backend.is_circuit_tripped(),
        "the start failure was not recorded"
    );
}
