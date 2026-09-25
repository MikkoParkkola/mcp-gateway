// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The MRTR.7 bridge's fallthrough arms, entered through `invoke_tool` (#569).
//!
//! The bridge's own rows (`tests/mik_7212_mrtr7_bridge_acs.rs`) build
//! `InputBridge` directly, so they cannot see what the call site does with an
//! outcome: whether the bridge is entered at all, whether `NoSession` still
//! mints, and which round `RoundsExhausted` hands back.

use super::*;
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};

/// A backend that asks on every call. Round `n` asks key `k{n}` with state
/// `round-{n}`, so which round reached the client is readable off the result.
/// `method(n)` is what round `n` asks for; `None` is a state-only round.
struct AlwaysAsks {
    calls: Arc<parking_lot::Mutex<Vec<Value>>>,
    method: fn(usize) -> Option<&'static str>,
}

/// Every round asks for roots.
const ROOTS: fn(usize) -> Option<&'static str> = |_| Some("roots/list");

fn state_only(_: usize) -> Option<&'static str> {
    None
}

#[async_trait::async_trait]
impl crate::transport::Transport for AlwaysAsks {
    async fn request(
        &self,
        _method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let n = {
            let mut calls = self.calls.lock();
            calls.push(params.unwrap_or(Value::Null));
            calls.len()
        };
        let requests = match (self.method)(n) {
            Some(method) => json!({ format!("k{n}"): {"method": method} }),
            None => json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            crate::protocol::RequestId::Number(1),
            json!({
                "resultType": "input_required",
                "inputRequests": requests,
                "requestState": format!("round-{n}"),
            }),
        ))
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

/// A `MetaMcp` with one backend, `asks`, wired to [`AlwaysAsks`].
fn meta_that_always_asks(
    method: fn(usize) -> Option<&'static str>,
) -> (MetaMcp, Arc<parking_lot::Mutex<Vec<Value>>>) {
    use crate::config::{BackendConfig, TransportConfig};
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://asks.internal/mcp".to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Arc::new(crate::backend::Backend::new(
        "asks",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    backend.set_transport_for_test(Arc::new(AlwaysAsks {
        calls: Arc::clone(&calls),
        method,
    }));
    let _ = registry.register(backend);
    (MetaMcp::new(registry), calls)
}

/// A legacy client that answers `roots/list`, counting what it was asked.
#[derive(Default)]
struct Answering {
    asked: parking_lot::Mutex<usize>,
}

#[async_trait::async_trait]
impl ClientChannel for Answering {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> std::result::Result<Value, DeliveryError> {
        *self.asked.lock() += 1;
        Ok(json!({"jsonrpc": "2.0", "result": {"roots": []}}))
    }
}

/// A channel with no session to reach, counting the attempts: the observable
/// that the bridge was entered, which `NoClientChannel` cannot give.
#[derive(Default)]
struct NoSessionCounted {
    attempts: parking_lot::Mutex<usize>,
}

#[async_trait::async_trait]
impl ClientChannel for NoSessionCounted {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> std::result::Result<Value, DeliveryError> {
        *self.attempts.lock() += 1;
        Err(DeliveryError::NoSession)
    }
}

const ARGS: &str = r#"{"server": "asks", "tool": "ask", "arguments": {}}"#;

fn args() -> Value {
    serde_json::from_str(ARGS).expect("fixture args")
}

/// A legacy caller the gateway can bind a continuation to, declaring `roots`.
fn legacy_caller<'a>(
    channel: &'a dyn ClientChannel,
    retry: &'a crate::protocol::mrtr::RetryFields,
) -> crate::gateway::meta_mcp::MetaMcpCallerContext<'a> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        input_capabilities: declaring(&json!({"roots": {}})),
        verified_identity: Some(&NAMED_CALLER),
        era: crate::protocol::meta::Era::Legacy,
        channel,
        retry,
        ..allow_all_ctx_named(None, None)
    }
}

fn keyed(key: &str) -> crate::protocol::mrtr::RetryFields {
    crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(key.to_string()),
        ..Default::default()
    }
}

fn with_idempotency(mut m: MetaMcp) -> MetaMcp {
    m.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        std::time::Duration::from_secs(60),
    );
    m
}

/// The `requestState` the caller was handed: a gateway envelope, never the
/// backend's own `round-N` string.
fn envelope(result: &Value) -> String {
    let state = result["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("no continuation was minted: {result}"));
    assert!(
        !state.starts_with("round-"),
        "the backend's raw state leaked: {state}"
    );
    state.to_string()
}

/// T1a — the stdio `dispatch_single` shape: a session, `NoClientChannel`, and
/// nothing declared. MRTR.9 refuses the question before the bridge.
#[tokio::test]
async fn t1a_an_undeclaring_legacy_caller_is_refused_before_the_bridge() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let caller = allow_all_ctx_named(None, None);
    let err = m
        .invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect_err("an undeclared question is refused");
    assert!(err.to_string().contains("did not declare"), "{err}");
    assert_eq!(
        calls.lock().len(),
        1,
        "the bridge must not re-invoke the backend"
    );
}

/// T1b — declared, with a session, and no client to reach: the bridge is
/// entered, meets `NoSession`, and the call falls through to a continuation.
#[tokio::test]
async fn t1b_a_declared_caller_with_no_reachable_session_gets_a_continuation() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let channel = NoSessionCounted::default();
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let result = m
        .invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("NoSession falls through, it does not fail the call");
    assert_eq!(*channel.attempts.lock(), 1, "the bridge was never entered");
    let _ = envelope(&result);
    assert_eq!(
        calls.lock().len(),
        1,
        "no bridged round reached the backend"
    );
}

/// T1c — a state-only interim has nothing to ask, so the bridge is not
/// entered. Without the non-empty-requests guard it re-invokes the backend
/// every round until it runs out.
#[tokio::test]
async fn t1c_a_state_only_interim_is_minted_without_a_bridged_round() {
    let (m, calls) = meta_that_always_asks(state_only);
    let channel = Answering::default();
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let result = m
        .invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("a state-only interim is minted");
    let _ = envelope(&result);
    assert_eq!(
        calls.lock().len(),
        1,
        "the backend was re-invoked by the bridge"
    );
}

/// T2 — the `NoSession` fallthrough declines the reservation: a retry under
/// the same key reaches the backend again rather than being replayed.
#[tokio::test]
async fn t2_the_no_session_fallthrough_releases_the_idempotency_key() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let m = with_idempotency(m);
    let channel = NoSessionCounted::default();
    let retry = keyed("key-t2");
    let caller = legacy_caller(&channel, &retry);
    m.invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("first call mints");
    m.invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("second call mints");
    assert_eq!(
        calls.lock().len(),
        2,
        "the key was settled, so the retry was replayed"
    );
}

/// Rounds the shipped bridge runs; the backend's last interim is call `+ 1`
/// (the call that produced the first question came before the bridge).
fn last_round() -> usize {
    crate::gateway::input_bridge::BridgeBounds::DEFAULT.rounds as usize + 1
}

/// T3 — out of rounds, the caller is handed the LAST round to resume: its
/// question and its state together, sealed. Redeeming the envelope reaches the
/// backend with that round's state, not the first round's.
#[tokio::test]
async fn t3_an_exhausted_exchange_resumes_from_its_last_round() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let channel = Answering::default();
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let result = m
        .invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("an exhausted exchange is handed back, not failed with -32003");
    let last = last_round();
    assert_eq!(calls.lock().len(), last, "the bridge ran every round");
    let key = format!("k{last}");
    assert!(
        result["inputRequests"].get(&key).is_some(),
        "the client must see the last round's question {key}: {result}"
    );
    let handle = envelope(&result);

    let resume = crate::protocol::mrtr::RetryFields {
        request_state: Some(handle),
        input_responses: Some(json!({ key: {"roots": []} })),
        ..Default::default()
    };
    let caller = legacy_caller(&channel, &resume);
    m.invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("redeeming the envelope resumes the exchange");
    let calls = calls.lock().clone();
    let resumed = calls.get(last).map(Value::to_string).unwrap_or_default();
    assert!(
        resumed.contains(&format!("\"round-{last}\"")),
        "the resume must carry the last round's state: {resumed}"
    );
}

/// T3b — exhausting the rounds does not settle the idempotency key: a backend
/// that stopped to ask has not acted, so a retry under the key is admitted.
#[tokio::test]
async fn t3b_an_exhausted_exchange_releases_the_idempotency_key() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let m = with_idempotency(m);
    let channel = Answering::default();
    let retry = keyed("key-t3b");
    let caller = legacy_caller(&channel, &retry);
    m.invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect("an exhausted exchange is handed back, not failed");
    let first = calls.lock().len();
    let _ = m.invoke_tool(&args(), Some("session-1"), &caller).await;
    assert!(
        calls.lock().len() > first,
        "the key was settled, so the retry was replayed"
    );
}

/// T3c — the last round reaches the client for the first time at the
/// fallthrough, so MRTR.9 is applied to it there: a question this caller never
/// declared is refused, not sealed into an envelope.
#[tokio::test]
async fn t3c_the_last_round_is_held_to_the_callers_declaration() {
    // Only the last round asks for what the caller never declared: every
    // earlier round passes `plan`, so the exchange really runs out of rounds
    // and the last body is the one no gate has seen yet.
    let (m, _calls) = meta_that_always_asks(|n| {
        Some(if n == last_round() {
            "sampling/createMessage"
        } else {
            "roots/list"
        })
    });
    let channel = Answering::default();
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let outcome = m.invoke_tool(&args(), Some("session-1"), &caller).await;
    let err = outcome.expect_err("an undeclared last round is refused");
    assert!(err.to_string().contains("did not declare"), "{err}");
}
