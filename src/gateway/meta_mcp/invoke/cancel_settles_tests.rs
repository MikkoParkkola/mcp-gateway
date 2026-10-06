// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1962: a call cancelled while its `tools/call` is in flight settles its
//! idempotency key, so a same-key retry is not executed a second time. A call
//! cancelled before anything reached the backend still releases the key.
//!
//! Every case runs the real `invoke_tool` path with idempotency on. The
//! caller "disconnects" by dropping the call's future once the scripted
//! backend reports that the dispatch under test has arrived.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::MetaMcp;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::meta_mcp::MetaMcpCallerContext;
use crate::idempotency::IdempotencyCache;
use crate::protocol::{JsonRpcResponse, RequestId};

const KEY: &str = "k-1962";
const UNCERTAIN: &str = "outcome is unknown";

/// What one `tools/call` does.
#[derive(Clone)]
enum Step {
    Answer(Value),
    /// Signal arrival, then never answer.
    Park,
}

/// A backend whose `tools/call` answers follow a script (the last step
/// repeats) and counts every call that reached it.
struct Scripted {
    steps: Mutex<Vec<Step>>,
    calls: AtomicUsize,
    parked: Arc<Notify>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Scripted {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/list" {
            let tools = json!({"tools": [{"name": "act", "inputSchema": {"type": "object"}}]});
            return Ok(JsonRpcResponse::success(RequestId::Number(1), tools));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        let step = {
            let mut steps = self.steps.lock();
            if steps.len() > 1 {
                steps.remove(0)
            } else {
                steps[0].clone()
            }
        };
        match step {
            Step::Answer(result) => Ok(JsonRpcResponse::success(RequestId::Number(1), result)),
            Step::Park => {
                self.parked.notify_one();
                std::future::pending().await
            }
        }
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

/// A client that answers every question, or parks on it after signalling.
struct Client {
    park: bool,
    asked: Arc<Notify>,
}

#[async_trait::async_trait]
impl ClientChannel for Client {
    async fn send_request(
        &self,
        _session_id: &str,
        _id: &str,
        _method: &str,
        _params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        self.asked.notify_one();
        if self.park {
            std::future::pending::<()>().await;
        }
        Ok(json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {"ok": true}}}))
    }
}

fn interim() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"q1": {
            "method": "elicitation/create",
            "params": {"message": "Proceed?", "requestedSchema": {"type": "object"}}
        }},
        "requestState": "backend-state-1962"
    })
}

fn done() -> Value {
    json!({"content": [{"type": "text", "text": "done"}], "isError": false})
}

fn gateway(steps: Vec<Step>) -> (MetaMcp, Arc<Scripted>) {
    let wire = Arc::new(Scripted {
        steps: Mutex::new(steps),
        calls: AtomicUsize::new(0),
        parked: Arc::new(Notify::new()),
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
    let mut meta = MetaMcp::new(registry);
    meta.enable_idempotency(Arc::new(IdempotencyCache::new()), Duration::from_secs(300));
    (meta, wire)
}

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// Run one keyed call as a legacy client that declared elicitation.
async fn call(meta: &MetaMcp, client: &Client) -> crate::Result<Value> {
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some(KEY.to_owned()),
        ..Default::default()
    };
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
            crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"elicitation": {"form": {}}}
        }})),
        None,
    )
    .declared_capabilities();
    let context = MetaMcpCallerContext {
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
        retry: &retry,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: client,
    };
    let args = json!({"server": "svc", "tool": "act", "arguments": {}});
    meta.invoke_tool(&args, Some("session-1962"), &context)
        .await
}

/// Start a call and drop it as soon as `arrived` fires.
async fn cancel_at(meta: &MetaMcp, client: &Client, arrived: &Notify) {
    tokio::select! {
        outcome = call(meta, client) => panic!("the call finished instead of parking: {outcome:?}"),
        () = arrived.notified() => {}
    }
}

fn answering() -> Client {
    Client {
        park: false,
        asked: Arc::new(Notify::new()),
    }
}

/// T1: cancelled during the first dispatch. The retry must be served the
/// uncertain-outcome notice, not run again.
#[tokio::test]
async fn a_call_cancelled_mid_dispatch_is_not_executed_again() {
    let (meta, wire) = gateway(vec![Step::Park, Step::Answer(done())]);
    let client = answering();
    cancel_at(&meta, &client, &wire.parked).await;
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);

    let retry = call(&meta, &client).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "the same-key retry reached the backend again: {retry:?}"
    );
    assert!(format!("{retry:?}").contains(UNCERTAIN), "{retry:?}");
}

/// T2: cancelled while a bridged round's dispatch is in flight.
#[tokio::test]
async fn a_bridged_round_cancelled_mid_dispatch_is_not_executed_again() {
    let (meta, wire) = gateway(vec![
        Step::Answer(interim()),
        Step::Park,
        Step::Answer(done()),
    ]);
    let client = answering();
    cancel_at(&meta, &client, &wire.parked).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "the bridged round was reached"
    );

    let retry = call(&meta, &client).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "the same-key retry reached the backend again: {retry:?}"
    );
    assert!(format!("{retry:?}").contains(UNCERTAIN), "{retry:?}");
}

/// T3: cancelled while the client is being asked. The backend stopped to ask
/// and nothing has been re-sent, so the key is released and a retry runs.
#[tokio::test]
async fn a_call_cancelled_while_asking_the_client_releases_its_key() {
    let (meta, wire) = gateway(vec![Step::Answer(interim())]);
    let asking = Client {
        park: true,
        asked: Arc::new(Notify::new()),
    };
    let asked = Arc::clone(&asking.asked);
    cancel_at(&meta, &asking, &asked).await;
    assert_eq!(wire.calls.load(Ordering::SeqCst), 1);

    let retry = cancel_at(&meta, &asking, &asked);
    retry.await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        2,
        "a key released before any re-dispatch lets the retry run"
    );
}
