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
    /// How many keys round `n` asks; every key asks `method(n)`.
    width: fn(usize) -> usize,
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
            Some(method) => (0..(self.width)(n))
                .map(|i| {
                    let key = if i == 0 {
                        format!("k{n}")
                    } else {
                        format!("k{n}-{i}")
                    };
                    (key, json!({"method": method}))
                })
                .collect::<serde_json::Map<_, _>>()
                .into(),
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
    meta_asking(method, |_| 1)
}

/// [`meta_that_always_asks`] with round `n` asking `width(n)` keys.
fn meta_asking(
    method: fn(usize) -> Option<&'static str>,
    width: fn(usize) -> usize,
) -> (MetaMcp, Arc<parking_lot::Mutex<Vec<Value>>>) {
    use crate::config::{BackendConfig, TransportConfig};
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let config = BackendConfig {
        transport: TransportConfig::Http {
            http_url: "https://asks.internal/mcp".to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        // The fake answers every request with an interim, tools/list included;
        // the F13 key check would otherwise refuse the call before the bridge.
        input_schema_enforcement: crate::config::InputSchemaEnforcement::Off,
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
        width,
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
    // Counted, so bridge entry is observed directly rather than inferred from
    // the error text: nothing declared, and a channel the bridge would use.
    let channel = NoSessionCounted::default();
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        channel: &channel,
        ..allow_all_ctx_named(None, None)
    };
    let err = m
        .invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect_err("an undeclared question is refused");
    assert!(err.to_string().contains("did not declare"), "{err}");
    assert_eq!(
        *channel.attempts.lock(),
        0,
        "expected the bridge not to be entered"
    );
    assert_eq!(
        calls.lock().len(),
        1,
        "expected no bridged round to re-invoke the backend"
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
    assert_eq!(
        *channel.attempts.lock(),
        1,
        "expected the bridge to be entered once"
    );
    let _ = envelope(&result);
    assert_eq!(
        calls.lock().len(),
        1,
        "expected no bridged round to reach the backend"
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

/// T3d — the same rule on a path that ends before the result completes: a
/// caller the gateway cannot bind a continuation to is refused after the
/// exhausted exchange, and the key must still be released on the way out. T3b
/// cannot see this, because a completed interim removes the key regardless.
#[tokio::test]
async fn t3d_an_exhausted_exchange_that_cannot_be_sealed_releases_the_key() {
    let (m, calls) = meta_that_always_asks(ROOTS);
    let m = with_idempotency(m);
    let channel = Answering::default();
    let retry = keyed("key-t3d");
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: None,
        ..legacy_caller(&channel, &retry)
    };
    m.invoke_tool(&args(), Some("session-1"), &caller)
        .await
        .expect_err("no principal to bind the continuation to");
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

/// MIK-7691: the last round is handed back rather than asked, but its requests
/// still count against the call's budget. Three one-request rounds leave five
/// of the default eight, so an eight-wide last round is refused.
#[tokio::test]
async fn a_wide_last_round_is_held_to_the_request_budget() {
    let (m, _calls) = meta_asking(ROOTS, |n| if n == last_round() { 8 } else { 1 });
    let channel = Answering::default();
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let outcome = m.invoke_tool(&args(), Some("session-1"), &caller).await;
    assert!(
        outcome.is_err(),
        "a last round past the request budget must not be handed back: {outcome:?}"
    );
}

/// A backend that asks on its first `tools/call` and answers the retry.
#[cfg(feature = "firewall")]
struct AsksThenAnswers {
    calls: parking_lot::Mutex<usize>,
}

#[cfg(feature = "firewall")]
#[async_trait::async_trait]
impl crate::transport::Transport for AsksThenAnswers {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let first = method == "tools/call" && {
            let mut calls = self.calls.lock();
            *calls += 1;
            *calls == 1
        };
        let result = if first {
            json!({
                "resultType": "input_required",
                "inputRequests": {"k1": {"method": "roots/list"}},
                "requestState": "round-1",
            })
        } else {
            json!({"content": [{"type": "text", "text": "answered"}], "isError": false})
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            result,
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

/// MIK-7707.GH2431.1: a retry minted for a backend tool that shares a
/// discovery name takes the direct-backend route, so the Meta-MCP never marks
/// its response as already inspected and the delivery pass inspects it once.
/// Were the marker set on that route, the pass would skip it and nothing would
/// have scanned the result.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_minted_retry_under_a_discovery_name_is_inspected_once_and_unmarked() {
    use crate::gateway::meta_mcp::response_security::{
        ChainSource, ResponseCorrelation, ResponseDeliveryContext,
    };
    use crate::security::firewall::{Firewall, FirewallConfig};

    let (mut m, _calls) = meta_that_always_asks(ROOTS);
    m.backends
        .get("asks")
        .expect("the fixture registers asks")
        .set_transport_for_test(Arc::new(AsksThenAnswers {
            calls: parking_lot::Mutex::new(0),
        }));
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            enabled: true,
            scan_responses: true,
            scan_requests: false,
            ..FirewallConfig::default()
        },
        None,
    ));
    m.set_firewall(Some(Arc::clone(&firewall)));

    let channel = NoSessionCounted::default();
    let first = json!({"server": "asks", "tool": "gateway_list_tools", "arguments": {}});
    let caller = legacy_caller(&channel, &crate::protocol::mrtr::NO_RETRY);
    let asked = m
        .invoke_tool(&first, Some("session-1"), &caller)
        .await
        .expect("the first call mints a continuation");
    let resume = crate::protocol::mrtr::RetryFields {
        request_state: Some(envelope(&asked)),
        input_responses: Some(json!({"k1": {"roots": []}})),
        ..Default::default()
    };
    let caller = legacy_caller(&channel, &resume);
    let before = firewall.response_inspection_counts().inspections;

    let response = m
        .dispatch_below_gate(
            crate::protocol::RequestId::Number(2),
            "gateway_list_tools",
            std::borrow::Cow::Owned(json!({})),
            Some("session-1"),
            &caller,
            false,
        )
        .await;
    assert!(response.error.is_none(), "{response:?}");
    assert!(
        response
            .result
            .as_ref()
            .is_some_and(|r| r.to_string().contains("answered")),
        "the retry reached the backend and completed: {response:?}"
    );
    assert!(
        !response.egress_scanned,
        "a retry routed to its origin backend is never marked inspected"
    );
    assert_eq!(
        firewall.response_inspection_counts().inspections,
        before,
        "dispatch itself inspects nothing; the delivery pass does"
    );
    let targets = [crate::security::response_policy::ResponsePolicyTarget {
        server: "asks".to_owned(),
        tool: "gateway_list_tools".to_owned(),
    }];
    let delivered = m
        .finalize_response_for_delivery(
            response,
            &ResponseDeliveryContext {
                method: "tools/call",
                targets: &targets,
                correlation: ResponseCorrelation {
                    session_id: "session-1",
                    caller: "known-caller",
                    external_server: "gateway",
                    external_tool: "gateway_list_tools",
                    subject: None,
                },
                signing: None,
                chain_source: ChainSource::NotEligible,
                chain_nonce: None,
            },
        )
        .await;
    assert!(delivered.error.is_none(), "{delivered:?}");
    assert_eq!(
        firewall.response_inspection_counts().inspections - before,
        1,
        "the delivery pass inspects the retry's result exactly once"
    );
}

/// Every round asks `roots/list` (declared) except the last, which asks for
/// sampling (undeclared): the bridge refuses the handed-back round (#2173).
const ROOTS_THEN_SAMPLING: fn(usize) -> Option<&'static str> = |n| {
    Some(if n >= last_round() {
        "sampling/createMessage"
    } else {
        "roots/list"
    })
};

/// MIK-8191 on the legacy bridge (gpt i1): a bridged exchange whose last round
/// asks an undeclared question is refused, and the execution lease does not
/// keep that refusal: a keyed retry is admitted afresh, never replayed.
/// Mutant: the bridge's undeclared refusal leaving the dispatch marked.
#[tokio::test]
async fn t4_a_bridged_undeclared_last_round_is_not_kept_by_the_lease() {
    use crate::gateway::meta_mcp::admission::SyncAdmission;
    use crate::gateway::meta_mcp::{AdmissionOwner, error_response_preserving_status};
    let (m, _calls) = meta_that_always_asks(ROOTS_THEN_SAMPLING);
    let channel = Answering::default();
    let retry = keyed("bridge-op");
    let caller = legacy_caller(&channel, &retry);
    let owner = AdmissionOwner::for_test(caller.owner_principal());
    let id = crate::protocol::RequestId::Number(1);
    let Ok(SyncAdmission::Owned(lease)) =
        m.admit_meta_sync(owner, &caller, "gateway_invoke", &args(), None, &id)
    else {
        panic!("a keyed call takes the lease");
    };
    let leased = crate::gateway::meta_mcp::MetaMcpCallerContext {
        execution: Some(&lease),
        ..legacy_caller(&channel, &retry)
    };
    let error = m
        .invoke_tool(&args(), Some("session-1"), &leased)
        .await
        .expect_err("the undeclared last round is refused");
    lease.complete_secured(&error_response_preserving_status(id.clone(), &error));
    let again = m.admit_meta_sync(owner, &caller, "gateway_invoke", &args(), None, &id);
    assert!(
        matches!(again, Ok(SyncAdmission::Owned(_))),
        "the refusal was kept by the lease and would be replayed"
    );
}
