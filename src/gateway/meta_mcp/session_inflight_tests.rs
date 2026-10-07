// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7682.GH2568.2: a call in flight when its session ends writes under the
//! ended id after the first cleanup pass; the grace pass removes what it wrote.
//!
//! The call runs the real `invoke_tool` path against a backend that parks the
//! `tools/call` until released, and the session ends while it is parked.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::Notify;

use super::{MetaMcp, MetaMcpCallerContext};
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::session_lifecycle::{
    END_GRACE, SessionLifecycle, now_unix, wire_meta_session_cleanup,
};
use crate::protocol::meta::classify_request;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transition::TransitionTracker;

const SESSION: &str = "session-ended-mid-call";

/// A backend whose `tools/call` signals arrival, then waits for release.
struct Parked {
    arrived: Notify,
    release: Notify,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Parked {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            let tools = json!({"tools": [{"name": "act", "inputSchema": {"type": "object"}}]});
            return Ok(JsonRpcResponse::success(RequestId::Number(1), tools));
        }
        self.arrived.notify_one();
        self.release.notified().await;
        let done = json!({"content": [{"type": "text", "text": "done"}], "isError": false});
        Ok(JsonRpcResponse::success(RequestId::Number(1), done))
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

/// A client the call never needs to ask.
struct Silent;

#[async_trait::async_trait]
impl ClientChannel for Silent {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        Ok(json!({"jsonrpc": "2.0", "result": {}}))
    }
}

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// A keyless legacy caller: no caller key, as on stdio or HTTP with auth off.
fn keyless_legacy(retry: &crate::protocol::mrtr::RetryFields) -> MetaMcpCallerContext<'_> {
    let declared = classify_request(None, None).declared_capabilities();
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: declared,
        retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &Silent,
    }
}

/// Run one call under the legacy session `SESSION`.
async fn call(meta: &MetaMcp) -> crate::Result<Value> {
    let retry = crate::protocol::mrtr::RetryFields::default();
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    meta.invoke_tool(&args, Some(SESSION), &keyless_legacy(&retry))
        .await
}

/// MIK-7997: the A/B arm and the prefetch hints key on the caller key only.
/// A session id, legacy or stdio, never stands in for a missing key.
#[test]
fn a_keyless_caller_has_no_experiment_key_under_any_session() {
    let retry = crate::protocol::mrtr::RetryFields::default();
    let context = keyless_legacy(&retry);
    for session in [SESSION, "stdio-session"] {
        assert_eq!(context.experiment_key(Some(session)), None, "{session}");
    }
}

#[tokio::test]
async fn a_call_in_flight_when_its_session_ends_leaves_no_state_after_the_grace_pass() {
    let wire = Arc::new(Parked {
        arrived: Notify::new(),
        release: Notify::new(),
    });
    let backend = Arc::new(Backend::new(
        "svc",
        BackendConfig::r2_off(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::clone(&wire) as Arc<dyn crate::transport::Transport>);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend));
    let meta = Arc::new(MetaMcp::new(registry));
    let tracker = Arc::new(TransitionTracker::new());
    meta.set_transition_tracker(Arc::clone(&tracker));
    let lifecycle = Arc::new(SessionLifecycle::new());
    wire_meta_session_cleanup(&lifecycle, &meta);

    let call = call(&meta);
    tokio::pin!(call);
    tokio::select! {
        outcome = &mut call => panic!("the call finished early: {outcome:?}"),
        () = wire.arrived.notified() => {}
    }
    // The session ends while its call is at the backend.
    lifecycle.on_disconnect(SESSION);
    wire.release.notify_one();
    call.await.expect("the call completes");

    let cost = || meta.cost_tracker.session_snapshot(SESSION).is_some();
    assert!(cost(), "the call wrote its cost under the ended session");
    assert_eq!(
        tracker.key_count(),
        0,
        "a keyless caller records no last tool"
    );
    #[cfg(feature = "spec-preview")]
    assert!(
        meta.session_promoted.contains_key(SESSION),
        "and its promoted tool"
    );

    lifecycle.reap(now_unix());
    assert!(cost(), "the grace pass waits for its deadline");

    lifecycle.reap(now_unix() + END_GRACE.as_secs() + 1);
    assert!(!cost(), "the grace pass took the late cost bucket");
    assert_eq!(tracker.key_count(), 0, "and the late last tool");
    #[cfg(feature = "spec-preview")]
    assert!(
        !meta.session_promoted.contains_key(SESSION),
        "and the late promoted tool"
    );
}
