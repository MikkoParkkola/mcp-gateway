// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared dispatch fixtures for the authorization chokepoint tests: a counted
//! backend and a caller context built the way the production sites build one.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::ToolAuthorizer;
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::protocol::RequestId;
use crate::transport::Transport;

/// A backend transport that counts the calls that actually reach it.
///
/// The oracle for "a refused call never dispatched": a check placed after
/// dispatch still refuses, and only this counter can tell the two apart.
struct CountingTransport {
    calls: Arc<AtomicUsize>,
    result: Value,
}

#[async_trait::async_trait]
impl Transport for CountingTransport {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        assert_eq!(method, "tools/call");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            self.result.clone(),
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

/// A registry holding one backend whose calls are counted.
pub(in crate::gateway::meta_mcp) fn counted_backend(
    name: &str,
) -> (Arc<BackendRegistry>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(CountingTransport {
        calls: Arc::clone(&calls),
        result: json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
    }));
    let _ = registry.register(backend);
    (registry, calls)
}

/// A caller context bound to a given authorizer.
///
/// Built exactly as `router/handlers.rs` and `server/mod.rs` build theirs: the
/// authorizer is the only thing that varies. A fixture that assembled the
/// context some other way would prove the double works rather than that the
/// chokepoint is reached.
pub(in crate::gateway::meta_mcp) fn ctx(
    authorizer: &(dyn ToolAuthorizer + Sync),
) -> MetaMcpCallerContext<'_> {
    MetaMcpCallerContext {
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer,
        api_key_name: Some("test-caller"),
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        verified_identity: None,
        is_admin: false,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        task: None,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

pub(in crate::gateway::meta_mcp) fn invoke_args(server: &str, tool: &str) -> Value {
    json!({ "server": server, "tool": tool, "arguments": {} })
}
