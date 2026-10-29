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

/// The stable reason a refusal carries, wherever it surfaced.
fn reason(outcome: &crate::Result<Value>) -> Option<String> {
    match outcome {
        Err(crate::Error::JsonRpc { data: Some(data), .. }) => {
            data.get("reason").and_then(Value::as_str).map(str::to_owned)
        }
        _ => None,
    }
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
    assert_eq!(
        served.load(Ordering::SeqCst),
        0,
        "the refused call must not reach the registry backend either"
    );
}
