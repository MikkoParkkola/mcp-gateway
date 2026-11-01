// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A response-cache hit stored while a value was plain, served after the
//! value is marked secret: the hit is scrubbed against the values current
//! when it is sent (MIK-9105).

use super::*;

const TOOL: &str = "lookup";
const MARKED: &str = "cached-token-9105-c4";

/// Lists `TOOL` read-only and answers each call with `MARKED`.
struct Wire(Arc<AtomicUsize>);

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
    backend.set_transport_for_test(Arc::new(Wire(Arc::clone(&calls))));
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
