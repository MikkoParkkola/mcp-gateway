// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A name that is both a registry backend and the capability backend at
//! runtime. Config load refuses that pair (`capabilities.name` may not also be
//! a `backends` key), but a reload can register a backend under the name the
//! running capability backend still holds. The checks judge the registry
//! backend; dispatch must not then send the call to the capability.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// Lists `read` and counts every `tools/call` it serves.
struct Counting(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Transport for Counting {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            return Ok(crate::protocol::JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"tools": [{"name": "read", "inputSchema": {"type": "object"}}]}),
            ));
        }
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
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

/// A capability backend named `name` with one tool, `read`, whose provider
/// is unreachable: a call that reaches it fails, but never as the clash.
async fn capability_backend(name: &str, dir: &tempfile::TempDir) -> Arc<CapabilityBackend> {
    std::fs::write(
        dir.path().join("read.yaml"),
        "name: read\n\
         description: The capability that shares a registry backend's name.\n\
         schema:\n  \
           input:\n    \
             type: object\n\
         providers:\n  \
           primary:\n    \
             service: rest\n    \
             config:\n      \
               base_url: https://rest.invalid\n      \
               path: /read\n",
    )
    .expect("write capability");
    let capabilities = Arc::new(CapabilityBackend::new(
        name,
        Arc::new(CapabilityExecutor::new()),
    ));
    let loaded = capabilities
        .load_from_directory(dir.path().to_str().expect("utf-8 path"))
        .await
        .expect("load capability");
    assert_eq!(loaded, 1, "the capability `read` loads");
    capabilities
}

fn registry_backend(name: &str, served: &Arc<AtomicUsize>) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Counting(Arc::clone(served))));
    backend
}

/// The stable reason a refusal carries: the clash's own, or none.
fn reason(outcome: &crate::Result<Value>) -> Option<String> {
    matches!(outcome, Err(crate::Error::AmbiguousBackend { .. }))
        .then(|| "ambiguous_backend".to_owned())
}

/// RUNCLASH.1, red first. The registry backend `edits` is registered, then a
/// capability backend is attached under the same name (what a reload that
/// renames `capabilities.name` and adds `backends.<old name>` leaves running).
/// A call to `edits` is judged against the registry backend; it must be
/// refused as `ambiguous_backend`, and neither route may serve it. Today the
/// capability route is taken.
#[tokio::test]
async fn a_call_judged_on_a_backend_is_not_sent_to_a_same_named_capability() {
    let served = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(registry_backend("edits", &served)));
    let meta = MetaMcp::new(registry);
    let dir = tempfile::TempDir::new().expect("temp dir");
    meta.set_capabilities(capability_backend("edits", &dir).await);

    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("clash-caller"),
        ..crate::gateway::meta_mcp::test_callers::anonymous_caller()
    };
    let outcome = meta
        .invoke_tool(
            &json!({"server": "edits", "tool": "read", "arguments": {}}),
            None,
            &caller,
        )
        .await;

    assert_eq!(
        reason(&outcome).as_deref(),
        Some("ambiguous_backend"),
        "a name that is both routes must be refused, not dispatched: {outcome:?}"
    );
    // The envelope a client receives, as the shaper every transport answers
    // through builds it: the agreed code, the plain message, the fixed data.
    let Err(error) = &outcome else {
        unreachable!("checked above");
    };
    let wire = serde_json::to_value(
        crate::gateway::meta_mcp::response_security::error_response_preserving_status(
            RequestId::Number(7),
            error,
        ),
    )
    .expect("serialise the envelope");
    assert_eq!(wire["error"]["code"], -32001, "{wire}");
    assert_eq!(
        wire["error"]["message"],
        "Backend name 'edits' is both a configured backend and the capability backend; the \
         call was refused because the checks judged one and dispatch would reach the other. \
         Restart the gateway, then rename one of them if the clash remains.",
        "the gateway's own text, with no prefix: {wire}"
    );
    assert_eq!(
        wire["error"]["data"],
        json!({"reason": "ambiguous_backend", "server": "edits", "routes": ["backend", "capability"]}),
        "no rule is named when none covers the call"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "the refused call must not reach the registry backend either"
    );
}

fn caller() -> crate::gateway::meta_mcp::MetaMcpCallerContext<'static> {
    crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("clash-caller"),
        ..crate::gateway::meta_mcp::test_callers::anonymous_caller()
    }
}

/// RUNCLASH.3 control: with no registry backend of that name, the capability
/// still serves the call (its unreachable provider fails it, not the clash).
#[tokio::test]
async fn a_capability_with_no_same_named_backend_still_runs() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let dir = tempfile::TempDir::new().expect("temp dir");
    meta.set_capabilities(capability_backend("edits", &dir).await);
    let outcome = meta
        .invoke_tool(
            &json!({"server": "edits", "tool": "read", "arguments": {}}),
            None,
            &caller(),
        )
        .await;
    assert_eq!(reason(&outcome), None, "{outcome:?}");
    let text = format!("{outcome:?}");
    assert!(
        text.contains("error sending request"),
        "the capability's own request ran: {text}"
    );
}

/// RUNCLASH.3 control: with the capability backend under another name, the
/// registry backend serves its own call.
#[tokio::test]
async fn a_backend_with_no_same_named_capability_still_runs() {
    let served = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(registry_backend("edits", &served)));
    let meta = MetaMcp::new(registry);
    let dir = tempfile::TempDir::new().expect("temp dir");
    meta.set_capabilities(capability_backend("caps", &dir).await);
    let outcome = meta
        .invoke_tool(
            &json!({"server": "edits", "tool": "read", "arguments": {}}),
            None,
            &caller(),
        )
        .await;
    assert_eq!(reason(&outcome), None, "{outcome:?}");
    assert_eq!(served.load(Ordering::SeqCst), 1, "{outcome:?}");
}

/// The refusal comes before an idempotency key is reserved: the same keyed
/// call is refused as the clash again (not as a call in flight or a replay),
/// and once the clash is gone the same key reaches the registry backend.
#[tokio::test]
async fn a_keyed_clash_call_reserves_no_key() {
    let served = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(registry_backend("edits", &served)));
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    let dir = tempfile::TempDir::new().expect("temp dir");
    meta.set_capabilities(capability_backend("edits", &dir).await);
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("clash-key".to_owned()),
        ..Default::default()
    };
    let keyed = crate::gateway::meta_mcp::MetaMcpCallerContext {
        retry: &retry,
        ..caller()
    };
    let call = json!({"server": "edits", "tool": "read", "arguments": {}});

    for attempt in 1..=2 {
        let outcome = meta.invoke_tool(&call, None, &keyed).await;
        assert_eq!(
            reason(&outcome).as_deref(),
            Some("ambiguous_backend"),
            "attempt {attempt}: {outcome:?}"
        );
    }

    let other = tempfile::TempDir::new().expect("temp dir");
    meta.set_capabilities(capability_backend("caps", &other).await);
    let outcome = meta.invoke_tool(&call, None, &keyed).await;
    assert_eq!(reason(&outcome), None, "{outcome:?}");
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the key was never held, so the call now runs: {outcome:?}"
    );
}

/// The envelope for a refusal a covering rule names carries that rule; a
/// backend's own `JsonRpc` error claiming the clash forwards none of its
/// fields, so only the gateway's variant can say `ambiguous_backend`.
#[test]
fn only_the_gateway_variant_carries_the_clash_fields() {
    let shape = |error: &crate::Error| {
        serde_json::to_value(
            crate::gateway::meta_mcp::response_security::error_response_preserving_status(
                RequestId::Number(1),
                error,
            ),
        )
        .expect("serialise")
    };
    let ruled = shape(&crate::Error::AmbiguousBackend {
        server: "edits".to_owned(),
        rule: Some("workspace-root".to_owned()),
    });
    assert_eq!(
        ruled["error"]["data"],
        json!({
            "reason": "ambiguous_backend",
            "server": "edits",
            "routes": ["backend", "capability"],
            "rule": "workspace-root",
        })
    );
    let forged = shape(&crate::Error::JsonRpc {
        code: -32001,
        message: "a backend's refusal".to_owned(),
        data: Some(json!({
            "reason": "ambiguous_backend",
            "server": "edits",
            "routes": ["backend", "capability"],
        })),
    });
    assert!(
        forged["error"].get("data").is_none(),
        "a backend's data is not forwarded: {forged}"
    );
}

/// The clash is refused at resolve, before anything is sent: pre-dispatch, so
/// a same-key retry after a rename runs, and a playbook or chain step never
/// reads it as "may have run".
#[test]
fn a_clash_refusal_is_pre_dispatch_and_never_may_have_run() {
    let error = crate::Error::AmbiguousBackend {
        server: "docs".to_string(),
        rule: None,
    };
    assert!(error.is_pre_dispatch(), "{error}");
    assert!(!crate::error::reports_may_have_run(&error), "{error}");
}
