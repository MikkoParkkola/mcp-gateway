// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ledger probable defect (PRIORITIZED.md:215): does an ask that expires reach
//! the error budget as a failure and disable the capability for every caller?
//!
//! The real bridge, with its real 30 s `per_prompt` (`BridgeBounds::DEFAULT`,
//! `invoke.rs:1039`), in paused tokio time so the timeout fires at once. The
//! client never answers. P1 is the observation; P2 is the positive control that
//! the harness can see a capability disabled at all.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::authz::AllowAll;
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::meta_mcp::authz_tests::ctx;
use crate::protocol::RequestId;
use crate::transport::Transport;

const CALLS: usize = 12;

/// Answers every `tools/call` with `body`, or fails it when `fail` is set.
struct Scripted {
    calls: Arc<AtomicUsize>,
    body: Value,
    fail: bool,
}

#[async_trait::async_trait]
impl Transport for Scripted {
    async fn request(
        &self,
        _method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(crate::Error::Transport("backend went away".into()));
        }
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            RequestId::Number(1),
            self.body.clone(),
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

/// A client that never answers: every question waits until the bridge's own
/// `per_prompt` expires it.
struct SilentChannel;

#[async_trait::async_trait]
impl ClientChannel for SilentChannel {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        std::future::pending().await
    }
}

fn meta(body: Value, fail: bool) -> (MetaMcp, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(Backend::new(
        "asker",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Scripted {
        calls: Arc::clone(&calls),
        body,
        fail,
    }));
    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    (MetaMcp::new(registry), calls)
}

fn asking() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {
            "k1": {
                "method": "elicitation/create",
                "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
            }
        },
        "requestState": "s1"
    })
}

async fn run_calls(meta: &MetaMcp) -> Vec<crate::Result<Value>> {
    let channel = SilentChannel;
    let mut caller = ctx(&AllowAll);
    caller.era = crate::protocol::meta::Era::Legacy;
    caller.input_capabilities = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}},
        }})),
        None,
    )
    .declared_capabilities();
    caller.channel = &channel;
    let mut out = Vec::new();
    for n in 0..CALLS {
        let args = json!({"server": "asker", "tool": "book", "arguments": {"n": n}});
        out.push(
            meta.invoke_tool(&args, Some("session-ask-expiry"), &caller)
                .await,
        );
    }
    out
}

/// P1: twelve asks that all expire. Each call must end in the bridge's -32003,
/// the capability window must hold no failure, and the tool must stay enabled.
#[tokio::test(start_paused = true)]
async fn an_expired_ask_is_not_charged_to_the_capability() {
    let (meta, calls) = meta(asking(), false);
    let results = run_calls(&meta).await;
    for r in &results {
        let err = r.as_ref().expect_err("an expired ask cannot succeed");
        assert_eq!(err.to_rpc_code(), -32003, "the bridge's own expiry: {err}");
        assert!(
            err.to_string()
                .contains("asked for input and the bridged exchange could not be completed"),
            "the -32003 must be the bridged exchange's, not another refusal: {err}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        CALLS,
        "one backend round per call"
    );
    let (ok, failed) = meta.kill_switch.capability_window_counts("asker", "book");
    eprintln!("P1 capability window: ok={ok} failed={failed}");
    assert_eq!(failed, 0, "an expired ask is not a backend failure");
    // Exactly one sample per call: the first round's `input_required`, a
    // success. An expiry sampled as anything, success included, would show here.
    assert_eq!(
        ok, CALLS,
        "only the first round is sampled, never the expiry"
    );
    assert!(
        !meta.kill_switch.is_capability_disabled("asker", "book"),
        "expired asks disabled the capability for every caller"
    );
}

/// P2, the positive control: twelve real backend failures do disable it, so a
/// green P1 is the budget declining the expiries, not a harness that cannot see.
#[tokio::test(start_paused = true)]
async fn control_real_backend_failures_do_disable_the_capability() {
    let (meta, _calls) = meta(json!({}), true);
    let _ = run_calls(&meta).await;
    let (_, failed) = meta.kill_switch.capability_window_counts("asker", "book");
    assert!(
        failed >= 5,
        "the control must record failures, got {failed}"
    );
    assert!(meta.kill_switch.is_capability_disabled("asker", "book"));
}
