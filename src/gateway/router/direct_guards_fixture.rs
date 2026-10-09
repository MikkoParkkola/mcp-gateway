// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixture (test plan `2026-09-27-direct-route-guards-test-plan.md`
//! "Shared fixture") for the direct-route guard cells (MIK-7597). Red-commit
//! scaffolding only: no test module calls these yet.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::{test_router_app_state_with_auth, test_router_app_state_with_auth_and_config};
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// What a cell wants the shared `alpha` / `alpha-pt` backend to answer with,
/// covering the adapter table's classification rows (design doc §2.1a).
#[derive(Clone, Copy)]
pub(crate) enum Answer {
    /// Ordinary success, `isError: false`.
    Ok,
    /// Like `Ok`, its `tools/list` also naming a second tool, `note`.
    WithNote,
    /// Success envelope, `isError: true` (a tool refusing a request).
    IsError,
    /// JSON-RPC `error`, an arbitrary non-rate-limit code.
    RpcError(i32),
    /// A rate-limit refusal, carried as `isError: true` (test plan T5/T3b
    /// need the JSON-RPC-error flavour too; build one with `RpcError` and a
    /// "rate limit" message, since `is_rate_limited` matches on text, not
    /// shape).
    RateLimited,
    /// A transport-level failure: the backend was never reachable.
    Transport,
    /// Success, `isError: false`, whose text is the given payload (response
    /// inspection and context-integrity cells).
    Text(&'static str),
    /// The first `tools/call` asks the client a question (`input_required`);
    /// every later call succeeds. Drives a bridged input round (T3c).
    AskOnce,
    /// Like `AskOnce`, the question carrying no `requestState` (MIK-8078).
    AskNoState,
    /// A completed answer that still carries a `requestState` (MIK-8078).
    DoneWithState,
    /// Like `AskOnce`, a question `InputRequired::from_result` declines (an
    /// `inputRequests` that is not an object) beside a string state (MIK-8078).
    AskMalformed,
    /// Like `AskOnce`, its state longer than a continuation can seal.
    AskBig,
    /// Like `AskOnce`, the question and a `content` text carrying this text.
    AskWith(&'static str),
    /// Like `AskOnce`, the question carrying a `_meta` that is not an object.
    AskBadMeta,
    /// A response carrying both the question and a JSON-RPC `error`.
    AskAndError,
    /// The first `tools/call` succeeds, the second asks, every later one
    /// succeeds: a chain whose second step asks (MIK-8137 P1 G4).
    AskSecond,
    /// The backend cannot be reached: nothing was sent (`TransportConnect`).
    Unreachable,
    /// Like `Ok`, from a 2026-07-28 backend: its `tools/list` carries
    /// `resultType`, `ttlMs` (5000) and `cacheScope` itself, and every other
    /// answer a `ttlMs` of 3000 (MIK-8022).
    ModernList,
    /// A two-page `tools/list` whose pages carry these `ttlMs` hints.
    Paged(Option<u64>, Option<u64>),
    /// A two-page `tools/list` whose first page carries this `ttlMs` hint and
    /// whose last page is unreadable (its `tools` is not an array).
    Unreadable(Option<u64>),
    /// A two-page `tools/list` whose first page carries this `ttlMs` hint and
    /// whose last page a non-numeric one (MIK-8049).
    NonNumeric(u64),
    /// Like `Ok`, claiming `cacheScope: "public"` for the call's answer.
    PublicScope,
    /// JSON-RPC `error` whose message is the given text (MIK-8139).
    RpcErrorText(&'static str),
    /// JSON-RPC `error` with a plain message and the given text in `data`.
    RpcErrorData(&'static str),
    /// A failed dispatch: the backend's refusal as `Error::JsonRpc` with the
    /// given message, as a non-2xx JSON-RPC answer arrives (MIK-8139).
    FailedWith(&'static str),
    /// A failed dispatch dressed as an `accounts.v1` account refusal, with
    /// the given message (MIK-8139: a backend can forge the marker).
    ForgedAccount(&'static str),
}

/// The question an `Ask*` answer opens with.
fn question(answer: Answer) -> Value {
    let mut asked = json!({
        "resultType": "input_required",
        "inputRequests": {
            "k1": {
                "method": "elicitation/create",
                "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
            }
        },
        "requestState": "backend-state-1"
    });
    if matches!(answer, Answer::AskNoState) {
        asked.as_object_mut().unwrap().remove("requestState");
    }
    if matches!(answer, Answer::AskMalformed) {
        asked["inputRequests"] = json!("surprise");
    }
    if matches!(answer, Answer::AskBig) {
        asked["requestState"] = json!("s".repeat(16 * 1024));
    }
    if matches!(answer, Answer::AskBadMeta) {
        asked["_meta"] = json!(5);
    }
    if let Answer::AskWith(text) = answer {
        asked["inputRequests"]["k1"]["params"]["message"] = json!(text);
        asked["content"] = json!([{"type": "text", "text": text}]);
    }
    asked
}

/// What the backend answers a `tools/call` with, past the question rounds.
fn call_answer(answer: Answer, id: RequestId) -> crate::Result<JsonRpcResponse> {
    match answer {
        Answer::DoneWithState => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false,
                   "requestState": "backend-state-1"}),
        )),
        Answer::Ok
        | Answer::WithNote
        | Answer::Paged(..)
        | Answer::Unreadable(_)
        | Answer::NonNumeric(_) => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        )),
        Answer::ModernList => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false, "ttlMs": 3000}),
        )),
        Answer::PublicScope => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false,
                   "cacheScope": "public"}),
        )),
        Answer::IsError => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "backend says no"}], "isError": true}),
        )),
        Answer::RpcError(code) => Ok(JsonRpcResponse::error(Some(id), code, "backend says no")),
        Answer::RateLimited => Ok(JsonRpcResponse::error(
            Some(id),
            -32000,
            "rate limit exceeded",
        )),
        Answer::Transport => Err(crate::Error::Transport("connection refused".to_string())),
        Answer::RpcErrorText(_)
        | Answer::RpcErrorData(_)
        | Answer::FailedWith(_)
        | Answer::ForgedAccount(_) => error_answer(answer, id),
        Answer::Unreachable => Err(crate::Error::TransportConnect("no route".to_string())),
        Answer::AskOnce
        | Answer::AskNoState
        | Answer::AskMalformed
        | Answer::AskBig
        | Answer::AskWith(_)
        | Answer::AskBadMeta
        | Answer::AskAndError
        | Answer::AskSecond => {
            unreachable!("answered above")
        }
        Answer::Text(text) => Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": text}], "isError": false}),
        )),
    }
}

/// One `Transport` shared by `alpha` and `alpha-pt`, scripted with `Answer`
/// and counting every `tools/call`. `tools/list` names the one tool the rows
/// call, `read`, so the direct route's listing check (F13) admits it; a
/// listing never counts as a call.
struct CountingBackend {
    calls: Arc<AtomicUsize>,
    /// The params of every `tools/call`, in order (MIK-8078).
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
    answer: Answer,
}

/// The `tools/list` page `answer` scripts for the request carrying `params`.
fn listing(answer: Answer, params: Option<&Value>) -> Value {
    let mut result = json!({"tools": [{"name": "read", "inputSchema": {
        "type": "object",
        "properties": {"cmd": {"type": "string"}}
    }}]});
    match answer {
        Answer::WithNote => {
            result["tools"] = json!([
                {"name": "read", "inputSchema": {"type": "object"}},
                {"name": "note", "inputSchema": {"type": "object"}}
            ]);
        }
        Answer::ModernList => {
            result["resultType"] = json!("complete");
            result["ttlMs"] = json!(5000);
            result["cacheScope"] = json!("private");
        }
        Answer::Paged(first, second) => {
            let later = params.and_then(|p| p.get("cursor")).is_some();
            let hint = if later { second } else { first };
            if later {
                result["tools"] = json!([]);
            } else {
                result["nextCursor"] = json!("page-2");
            }
            if let Some(hint) = hint {
                result["ttlMs"] = json!(hint);
            }
        }
        Answer::NonNumeric(hint) => {
            if params.and_then(|p| p.get("cursor")).is_some() {
                result["tools"] = json!([{"name": "later", "inputSchema": {"type": "object"}}]);
                result["ttlMs"] = json!("soon");
            } else {
                result["nextCursor"] = json!("page-2");
                result["ttlMs"] = json!(hint);
            }
        }
        Answer::Unreadable(hint) => {
            if params.and_then(|p| p.get("cursor")).is_some() {
                result["tools"] = json!("not a list");
            } else {
                result["nextCursor"] = json!("page-2");
                if let Some(hint) = hint {
                    result["ttlMs"] = json!(hint);
                }
            }
        }
        _ => {}
    }
    result
}

#[async_trait::async_trait]
impl Transport for CountingBackend {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(
                id,
                listing(self.answer, params.as_ref()),
            ));
        }
        self.seen
            .lock()
            .unwrap()
            .push(params.clone().unwrap_or(Value::Null));
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if matches!(
            self.answer,
            Answer::AskOnce
                | Answer::AskNoState
                | Answer::AskMalformed
                | Answer::AskBig
                | Answer::AskWith(_)
                | Answer::AskBadMeta
                | Answer::AskAndError
                | Answer::AskSecond
        ) {
            let asks_now = n == usize::from(matches!(self.answer, Answer::AskSecond));
            return Ok(if asks_now {
                let mut asked = JsonRpcResponse::success(id, question(self.answer));
                if matches!(self.answer, Answer::AskAndError) {
                    asked.error = Some(crate::protocol::JsonRpcError {
                        code: -32000,
                        message: "backend failed".to_string(),
                        data: None,
                    });
                }
                asked
            } else {
                JsonRpcResponse::success(
                    id,
                    json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
                )
            });
        }
        call_answer(self.answer, id)
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

/// A router wired for the direct-route guard cells: non-admin keys
/// (`k-std`, `k-budget`, `k-rl` with a rate limit of 1, `k-deny` denied `read`;
/// all `backends: ["*"]`), and `alpha` / `alpha-pt`
/// (`passthrough: true`) sharing one call counter and one `Answer`.
pub(crate) struct Fx {
    pub state: Arc<super::AppState>,
    pub router: axum::Router,
    pub calls: Arc<AtomicUsize>,
    /// The params every `tools/call` reached the backend with.
    pub seen: Arc<std::sync::Mutex<Vec<Value>>>,
    _store: tempfile::TempDir,
}

fn key(name: &str) -> ApiKeyConfig {
    // `hardened` refuses a request with no per-caller identity, so its keys
    // are personal ones.
    let kind = if HARDENED.with(std::cell::Cell::get) {
        crate::config::ApiKeyKind::Personal
    } else {
        crate::config::ApiKeyKind::Shared
    };
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind,
    }
}

/// Replace backend `name` with a fresh instance under the same name, as a
/// live reload does (MIK-8168): same config, its own call counter, answering
/// `Ok`. Returns the new backend's counter.
pub(crate) fn replace_backend(fx: &Fx, name: &str) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            passthrough: name.ends_with("-pt"),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(CountingBackend {
        calls: Arc::clone(&calls),
        seen: Arc::default(),
        answer: Answer::Ok,
    }));
    assert!(
        fx.state.backends.register(backend),
        "replacement registration"
    );
    calls
}

/// Build the fixture, arming the replaced `MetaMcp` with `arm` before it is
/// installed (idempotency is enabled first, so `arm` can layer more on top).
pub(crate) async fn fixture(answer: Answer, arm: impl FnOnce(&mut MetaMcp)) -> Fx {
    fixture_built(answer, |mut meta| {
        arm(&mut meta);
        meta
    })
    .await
}

/// [`fixture`], for arming that needs the owned builder methods
/// (`with_profile_registry`, `with_cost_governance`).
pub(crate) async fn fixture_built(answer: Answer, build: impl FnOnce(MetaMcp) -> MetaMcp) -> Fx {
    fixture_inner(answer, false, build).await
}

/// [`fixture`] with the production firewall installed on both the router and
/// the Meta-MCP (request scanning, response scanning, credential redaction),
/// as `server/mod.rs` wires it.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled(answer: Answer) -> Fx {
    fixture_inner(answer, true, |meta| meta).await
}

/// [`fixture_firewalled`] with a firewall rule for `read` and a client
/// circuit breaker that opens after one counted failure, so a cell can tell a
/// refusal the gateway excludes from client accounting from one it charges.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_with(
    answer: Answer,
    rule: Option<crate::security::firewall::FirewallAction>,
    breaker: bool,
) -> Fx {
    FIREWALL_RULE.with(|r| r.set(rule));
    CLIENT_BREAKER.with(|b| b.set(breaker));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    FIREWALL_RULE.with(|r| r.set(None));
    CLIENT_BREAKER.with(|b| b.set(false));
    fx
}

#[path = "direct_guards_fixture_egress.rs"]
mod egress;
pub(crate) use egress::fixture_inspecting_on;
use egress::{backend_transport, error_answer};
#[cfg(feature = "firewall")]
pub(crate) use egress::{fixture_audited_on, fixture_firewalled_on, meta_firewall};

pub(crate) const SIGNING_KEY: &str = "direct-guards-signing-key-0123456789abcdef";

/// The fixture under `security.posture: hardened` (personal keys) with message
/// signing armed, so the direct route signs every `tools/call` it serves.
pub(crate) async fn fixture_hardened_signed(answer: Answer, require_nonce: bool) -> Fx {
    fixture_hardened_signed_built(answer, require_nonce, |meta| meta).await
}

/// [`fixture_hardened_signed`], arming the signed `MetaMcp` with `build`.
pub(crate) async fn fixture_hardened_signed_built(
    answer: Answer,
    require_nonce: bool,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    HARDENED.with(|h| h.set(true));
    let fx = fixture_inner(answer, false, |meta| build(signing(meta, require_nonce))).await;
    HARDENED.with(|h| h.set(false));
    fx
}

/// `meta` with message signing armed under [`SIGNING_KEY`].
fn signing(mut meta: MetaMcp, require_nonce: bool) -> MetaMcp {
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            SIGNING_KEY.as_bytes().to_vec(),
            None,
            "hardened".into(),
        ),
        Duration::from_secs(300),
        require_nonce,
    );
    meta
}

/// [`fixture_hardened_signed`] with relay detection on as in
/// [`fixture_relayed`]: every direct `tools/call` is signed and staged.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_signed_relayed(answer: Answer) -> Fx {
    HARDENED.with(|h| h.set(true));
    RELAY.with(|r| r.set(true));
    let fx = fixture_inner(answer, true, |meta| signing(meta, false)).await;
    HARDENED.with(|h| h.set(false));
    RELAY.with(|r| r.set(false));
    fx
}

/// [`fixture_firewalled`] with relay detection on for `alpha:read` and
/// `alpha:resources/read`, so the direct route stages receipts (MIK-8022).
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_relayed(answer: Answer) -> Fx {
    RELAY.with(|r| r.set(true));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    RELAY.with(|r| r.set(false));
    fx
}

/// A key whose name the response redactor reads as a GitHub token (a fake,
/// split so no scanner reads the source as one), so text naming it (a
/// per-key cost warning) is redacted on the way out.
#[cfg(feature = "firewall")]
pub(crate) const CREDENTIAL_KEY: &str = concat!("ghp_", "abcdefghijklmnopqrstuvwxyz1234567890");

/// [`fixture`] under the default posture with `server.modern_protocol: false`,
/// the rollback gate that turns the 2026-07-28 revision off.
pub(crate) async fn fixture_modern_off(answer: Answer) -> Fx {
    MODERN_OFF.with(|m| m.set(true));
    let fx = fixture_inner(answer, false, |meta| meta).await;
    MODERN_OFF.with(|m| m.set(false));
    fx
}

/// [`fixture_firewalled`] with sequence-anomaly blocking armed: `read` was only
/// ever followed by `other`, so a second `read` in one session scores as a
/// never-seen transition and is blocked.
#[cfg(feature = "firewall")]
pub(crate) async fn fixture_firewalled_anomaly(answer: Answer) -> Fx {
    ANOMALY.with(|a| a.set(true));
    let fx = fixture_inner(answer, true, |meta| meta).await;
    ANOMALY.with(|a| a.set(false));
    fx
}

// Per-thread knobs `fixture_firewalled_with` sets around one `fixture_inner`
// call, so the plain fixtures keep their signatures.
thread_local! {
    static HARDENED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static MODERN_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// A transport that replaces the scripted backend (the egress matrix).
    static TRANSPORT: std::cell::RefCell<Option<Arc<dyn Transport>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(feature = "firewall")]
thread_local! {
    static FIREWALL_RULE: std::cell::Cell<Option<crate::security::firewall::FirewallAction>> =
        const { std::cell::Cell::new(None) };
    static CLIENT_BREAKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ANOMALY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RELAY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static META_FIREWALL: std::cell::RefCell<Option<Arc<crate::security::firewall::Firewall>>> =
        const { std::cell::RefCell::new(None) };
    static AUDIT_LOG: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// The auth the fixture serves: four keys, plus a client breaker when asked.
fn fixture_auth() -> AuthConfig {
    #[cfg_attr(not(feature = "firewall"), allow(unused_mut))]
    let mut auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            key("k-std"),
            key("k-budget"),
            ApiKeyConfig {
                rate_limit: 1,
                ..key("k-rl")
            },
            ApiKeyConfig {
                denied_tools: Some(vec!["read".to_string()]),
                ..key("k-deny")
            },
        ],
        ..Default::default()
    };
    #[cfg(feature = "firewall")]
    if CLIENT_BREAKER.with(std::cell::Cell::get) {
        auth.client_circuit_breaker = Some(crate::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            ..crate::config::CircuitBreakerConfig::default()
        });
    }
    auth
}

/// The rebuilt Meta-MCP keeps the state's admission store: sync calls and
/// tasks share one, as `server/task_runtime.rs` wires it.
async fn fixture_inner(
    answer: Answer,
    #[cfg_attr(not(feature = "firewall"), allow(unused_variables))] firewalled: bool,
    build: impl FnOnce(MetaMcp) -> MetaMcp,
) -> Fx {
    let auth = fixture_auth();
    let hardened = HARDENED.with(std::cell::Cell::get);
    let modern_off = MODERN_OFF.with(std::cell::Cell::get);
    let (mut state, store) = if hardened || modern_off {
        let mut config = crate::config::Config::default();
        if hardened {
            config.security.posture = crate::security::SecurityPosture::Hardened;
        }
        if modern_off {
            config.server.modern_protocol = false;
        }
        test_router_app_state_with_auth_and_config(&auth, config).await
    } else {
        test_router_app_state_with_auth(&auth).await
    };
    let (calls, seen) = (Arc::new(AtomicUsize::new(0)), Arc::default());
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    for (name, passthrough) in [("alpha", false), ("alpha-pt", true)] {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig {
                passthrough,
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        backend.set_transport_for_test(backend_transport((&calls, &seen), answer));
        assert!(state_mut.backends.register(backend), "fixture registration");
    }
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends)).admitting_as(&state_mut.meta_mcp);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    #[cfg(feature = "firewall")]
    if firewalled {
        use crate::security::firewall::{Firewall, FirewallConfig};
        let rules = FIREWALL_RULE
            .with(std::cell::Cell::get)
            // `send_message` is the A2A backend's one tool (MIK-8139).
            .map_or_else(Vec::new, |action| {
                ["read", "send_message"]
                    .map(|tool| crate::security::firewall::FirewallRule {
                        tool_match: tool.to_string(),
                        action,
                        reason: None,
                        scan: Vec::new(),
                    })
                    .to_vec()
            });
        let anomaly = ANOMALY.with(std::cell::Cell::get);
        let tracker = anomaly.then(|| {
            let tracker = Arc::new(crate::transition::TransitionTracker::new());
            for _ in 0..10 {
                tracker.record_transition("train", "alpha:read");
                tracker.record_transition("train", "alpha:other");
            }
            tracker
        });
        let config = FirewallConfig {
            enabled: true,
            scan_requests: true,
            scan_responses: true,
            credential_redaction: true,
            rules,
            audit_log: AUDIT_LOG.with(|a| a.borrow().clone()),
            anomaly_detection: anomaly,
            anomaly_threshold: 0.7,
            anomaly_block_threshold: anomaly.then_some(0.9),
            anomaly_min_observations: 1,
            collusion: if RELAY.with(std::cell::Cell::get) {
                crate::security::firewall::CollusionConfig {
                    action: crate::security::firewall::CollusionAction::Block,
                    sources: vec!["alpha:read".into(), "alpha:resources/read".into()],
                    ..crate::security::firewall::CollusionConfig::default()
                }
            } else {
                crate::security::firewall::CollusionConfig::default()
            },
            ..FirewallConfig::default()
        };
        state_mut.firewall = Some(Arc::new(Firewall::from_config(
            config.clone(),
            tracker.clone(),
        )));
        let meta_firewall = Arc::new(Firewall::from_config(config, tracker));
        META_FIREWALL.with(|f| *f.borrow_mut() = Some(Arc::clone(&meta_firewall)));
        meta.set_firewall(Some(meta_firewall));
    }
    state_mut.meta_mcp = Arc::new(build(meta));
    let router = create_router(Arc::clone(&state));
    Fx {
        state,
        router,
        calls,
        seen,
        _store: store,
    }
}

/// Build `params._meta` carrying an idempotency key, when one is given.
fn set_idem(params: &mut Value, idem: Option<&str>) {
    if let Some(value) = idem {
        params["_meta"] = json!({ IDEMPOTENCY_KEY_META: value });
    }
}

/// `POST /mcp/{backend}` `tools/call`, as the direct route takes it.
pub(crate) async fn post_direct(
    fx: &Fx,
    backend: &str,
    key: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({ "name": tool, "arguments": args });
    set_idem(&mut params, idem);
    send(
        fx,
        &format!("/mcp/{backend}"),
        key,
        "tools/call",
        params,
        session,
    )
    .await
}

/// `POST /mcp` `tools/call gateway_invoke`, the meta-route twin a parity
/// table compares against `post_direct`.
pub(crate) async fn post_meta_invoke(
    fx: &Fx,
    key: &str,
    server: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": { "server": server, "tool": tool, "arguments": args },
    });
    set_idem(&mut params, idem);
    send(fx, "/mcp", key, "tools/call", params, session).await
}

/// `initialize` on `/mcp` for `key`; returns the session id the gateway
/// minted (it never adopts a client-chosen one).
pub(crate) async fn initialize(fx: &Fx, key: &str) -> String {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "t8", "version": "1"}
                }
            })
            .to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .expect("initialize mints a session id")
        .to_string()
}

/// [`post_meta_invoke`] carrying a signing `nonce` in the `gateway_invoke`
/// arguments.
pub(crate) async fn post_meta_invoke_nonce(
    fx: &Fx,
    key: &str,
    server: &str,
    tool: &str,
    nonce: &str,
) -> (StatusCode, Value) {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": { "server": server, "tool": tool, "arguments": {}, "nonce": nonce },
    });
    send(fx, "/mcp", key, "tools/call", params, None).await
}

pub(crate) async fn send(
    fx: &Fx,
    uri: &str,
    key: &str,
    method: &str,
    params: Value,
    session: Option<&str>,
) -> (StatusCode, Value) {
    send_with_headers(fx, uri, key, method, params, session, &[]).await
}

/// [`send`] plus extra request headers, such as the modern era's mirrors.
pub(crate) async fn send_with_headers(
    fx: &Fx,
    uri: &str,
    key: &str,
    method: &str,
    params: Value,
    session: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    if let Some(session_id) = session {
        builder = builder.header("mcp-session-id", session_id);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
