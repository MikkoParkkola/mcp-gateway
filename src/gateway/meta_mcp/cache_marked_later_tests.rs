// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A response-cache hit stored while a value was plain, served after the
//! value is marked secret: the hit is scrubbed against the values current
//! when it is sent.

use super::*;

const TOOL: &str = "lookup";
const MARKED: &str = "cached-token-9105-c4";

/// How the backend answers a call.
#[derive(Clone, Copy)]
enum Answer {
    /// A result saying `MARKED`.
    Ok,
    /// A JSON-RPC error whose message says `MARKED`.
    Error,
}

/// Lists `TOOL` read-only and answers each call as `Answer` says.
struct Wire(Arc<AtomicUsize>, Answer);

#[async_trait::async_trait]
impl crate::transport::Transport for Wire {
    async fn request(
        &self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
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
        _params: Option<serde_json::Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        let body = match method {
            "tools/list" => json!({"tools": listing(TOOL, &ann(READ_ONLY))}),
            "tools/call" => {
                self.0.fetch_add(1, Ordering::SeqCst);
                if let Answer::Error = self.1 {
                    return Ok(crate::protocol::JsonRpcResponse::error(
                        Some(RequestId::Number(1)),
                        -32000,
                        format!("failed {MARKED}"),
                    ));
                }
                json!({"content": [{"type": "text", "text": format!("ok {MARKED}")}], "isError": false})
            }
            _ => json!({}),
        };
        Ok(crate::protocol::JsonRpcResponse::success(
            RequestId::Number(1),
            body,
        ))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The second call is served from the response cache (the backend is
/// called once), and the value marked in between is removed from it.
#[tokio::test]
async fn a_cache_hit_removes_a_value_marked_after_it_was_stored() {
    use crate::backend::{Backend, BackendRegistry};
    use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};

    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            input_schema_enforcement: InputSchemaEnforcement::Off,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Wire(Arc::clone(&calls), Answer::Ok)));
    backend.set_read_only_declared_for_test(&[TOOL]);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(Arc::clone(&backend)));
    let meta = MetaMcp::with_features(
        Arc::clone(&registry),
        Some(Arc::new(crate::cache::ResponseCache::new())),
        None,
        None,
        Duration::from_secs(300),
    );
    let call = async || {
        meta.invoke_tool(
            &json!({"server": "ledger", "tool": TOOL, "arguments": {}}),
            Some("session-cache"),
            &allow_all_ctx_named(Some("alice"), None),
        )
        .await
        .expect("the call is answered")
    };

    let first = call().await;
    assert!(
        first.to_string().contains(MARKED),
        "premise: stored while plain: {first}"
    );
    registry.mark_for_test("ledger", MARKED);
    let hit = call().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the second call was a cache hit"
    );
    let text = hit.to_string();
    assert!(
        !text.contains(MARKED),
        "the cache hit carries the marked value: {hit}"
    );
    assert!(
        text.contains("[redacted]"),
        "the cache hit was emptied, not redacted: {hit}"
    );
}

/// A backend `ledger` answering as `answer`, in a gateway with the keyed
/// idempotency cache (7a) and no execution store, so a keyed repeat is served
/// from 7a. The registry, the gateway and the backend's call count.
fn keyed_gateway(
    answer: Answer,
) -> (
    Arc<crate::backend::BackendRegistry>,
    MetaMcp,
    Arc<AtomicUsize>,
) {
    use crate::backend::{Backend, BackendRegistry};
    use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "ledger",
        BackendConfig {
            input_schema_enforcement: InputSchemaEnforcement::Off,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Wire(Arc::clone(&calls), answer)));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));
    let mut meta = MetaMcp::new(Arc::clone(&registry));
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    (registry, meta, calls)
}

/// 7a: a keyed call's cached result, served again after the value it holds
/// was marked, is redacted; the backend is called once.
#[tokio::test]
async fn a_keyed_cached_result_removes_a_value_marked_after_it_was_stored() {
    let (registry, meta, calls) = keyed_gateway(Answer::Ok);
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("keyed-7a-ok".to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..allow_all_ctx_named(Some("alice"), None)
    };
    let call = async || {
        meta.invoke_tool(
            &json!({"server": "ledger", "tool": TOOL, "arguments": {}}),
            Some("session-7a"),
            &caller,
        )
        .await
        .expect("the call is answered")
    };
    let first = call().await;
    assert!(
        first.to_string().contains(MARKED),
        "premise: stored while plain: {first}"
    );
    registry.mark_for_test("ledger", MARKED);
    let repeat = call().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the repeat came from 7a"
    );
    assert!(
        !repeat.to_string().contains(MARKED),
        "the 7a result carries the value: {repeat}"
    );
}

/// 7a: a keyed call's stored failure, served again after the value its
/// message holds was marked, comes back redacted; the backend is called
/// once. A backend error is answered and stored as a result, so the entry
/// the first call stored is made a stored failure (as a chain-refused
/// dispatch stores one) before the value is marked.
#[tokio::test]
async fn a_keyed_cached_error_removes_a_value_marked_after_it_was_stored() {
    let (registry, meta, calls) = keyed_gateway(Answer::Error);
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("keyed-7a-error".to_owned()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..allow_all_ctx_named(Some("alice"), None)
    };
    let call = async || {
        meta.invoke_tool(
            &json!({"server": "ledger", "tool": TOOL, "arguments": {}}),
            Some("session-7a"),
            &caller,
        )
        .await
        .map_or_else(|e| e.to_string(), |answer| answer.to_string())
    };
    let first = call().await;
    assert!(
        first.contains(MARKED),
        "premise: stored while plain: {first}"
    );
    meta.idempotency_cache
        .as_ref()
        .expect("premise: idempotency is on")
        .fail_every_entry_for_test(&json!({"code": -32000, "message": format!("failed {MARKED}")}));
    let plain = call().await;
    assert!(
        plain.contains(MARKED),
        "premise: the stored failure is served while plain: {plain}"
    );
    registry.mark_for_test("ledger", MARKED);
    let repeat = call().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "premise: the repeat came from 7a"
    );
    assert!(
        !repeat.contains(MARKED),
        "the 7a error carries the value: {repeat}"
    );
}
