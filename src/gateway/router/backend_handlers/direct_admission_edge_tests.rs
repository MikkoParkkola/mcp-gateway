// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusals on the direct route's admission path that no other cell reaches: a
//! key reused for a different request, and a chained backend whose challenge
//! cannot be written into malformed params.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::backend::Backend;
use crate::config::{BackendConfig, ChainEmit, ChainMode, FailsafeConfig};
use crate::gateway::chain_test_support::signer;
use crate::gateway::router::direct_guards_fixture::{Answer, fixture, post_direct, send};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A transport that answers every request and counts none: the chained backend
/// must never be reached.
struct Reached(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl crate::transport::Transport for Reached {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(JsonRpcResponse::success(RequestId::Number(1), json!({})))
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

/// MIK-7272.SUB.4: the direct route re-enforces the idempotency guard, so a key
/// reused for a different call is refused, not replayed as the first call's
/// result. The first call is the control: the same key runs once.
#[tokio::test]
async fn a_key_reused_for_a_different_call_is_refused() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let (status, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": "a"}),
        Some("reused-key"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "control: {body}");

    let (status, body) = post_direct(
        &fx,
        "alpha",
        "k-std",
        "read",
        json!({"cmd": "b"}),
        Some("reused-key"),
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_some(), "{body}");
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "the second call ran");
}

/// ASI07: a chained backend's challenge is written into `params._meta`; when
/// that cannot be done the call is refused before it reaches the backend.
#[tokio::test]
async fn a_chain_challenge_that_cannot_be_written_refuses_the_call() {
    let fx = fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(signer(), ChainEmit::OnRequest);
    })
    .await;
    let reached = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "alpha-chain",
        BackendConfig {
            signature_chain: ChainMode::Require,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Reached(Arc::clone(&reached))));
    assert!(fx.state.backends.register(backend), "fixture registration");

    let params = json!({"name": "read", "arguments": {}, "_meta": 5});
    let (status, body) = send(&fx, "/mcp/alpha-chain", "k-std", "tools/call", params, None).await;
    assert_eq!(body["error"]["code"], -32602, "{status} {body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the backend was reached");
}
