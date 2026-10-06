// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1962: a call cancelled while its `tools/call` is in flight settles its
//! idempotency key, so a same-key retry is not executed a second time. A call
//! cancelled before anything reached the backend still releases the key.
//!
//! MIK-7979 / MIK-7900: a call whose request left the gateway and got no
//! answer (a transport failure, a timeout, a backend stopped by reload while
//! the call was in flight) settles the same way, while the backend's own error
//! answer is replayed as that answer and a pre-send refusal frees the key.
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
    /// Counted as reached, then fail with this error.
    Fail(fn() -> crate::Error),
    /// The backend's own JSON-RPC error answer.
    Refuse(i32, &'static str),
    /// Signal arrival, then fail as a closed stdio response channel does once
    /// the transport is closed under the call.
    ParkUntilClosed,
}

/// A backend whose `tools/call` answers follow a script (the last step
/// repeats) and counts every call that reached it.
struct Scripted {
    steps: Mutex<Vec<Step>>,
    calls: AtomicUsize,
    parked: Arc<Notify>,
    closed: Notify,
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
            Step::Fail(error) => Err(error()),
            Step::Refuse(code, message) => Ok(JsonRpcResponse::error(
                Some(RequestId::Number(1)),
                code,
                message,
            )),
            Step::ParkUntilClosed => {
                self.parked.notify_one();
                self.closed.notified().await;
                Err(crate::Error::Transport(
                    "Response channel closed".to_string(),
                ))
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
        self.closed.notify_one();
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
        closed: Notify::new(),
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

/// Run a keyed call that fails once with `first`, then retry it.
async fn retried_after(first: Step) -> (crate::Result<Value>, crate::Result<Value>, usize) {
    let (meta, wire) = gateway(vec![first, Step::Answer(done())]);
    let client = answering();
    let first = call(&meta, &client).await;
    let retry = call(&meta, &client).await;
    (first, retry, wire.calls.load(Ordering::SeqCst))
}

/// MIK-7979.SETTLE.1: the request left and the transport failed with no
/// answer. The retry is told the outcome is unknown and is not run again.
#[tokio::test]
async fn a_transport_failure_after_send_is_not_executed_again() {
    let (first, retry, calls) = retried_after(Step::Fail(|| {
        crate::Error::Transport("connection reset".into())
    }))
    .await;
    assert!(
        format!("{first:?}").contains("connection reset"),
        "{first:?}"
    );
    assert_eq!(
        calls, 1,
        "the same-key retry reached the backend again: {retry:?}"
    );
    assert!(format!("{retry:?}").contains(UNCERTAIN), "{retry:?}");
}

/// MIK-7979.SETTLE.1: a timeout waiting for the answer is a lost round too.
#[tokio::test]
async fn a_timeout_after_send_is_not_executed_again() {
    let (_, retry, calls) = retried_after(Step::Fail(|| {
        crate::Error::BackendTimeout("timed out".into())
    }))
    .await;
    assert_eq!(
        calls, 1,
        "the same-key retry reached the backend again: {retry:?}"
    );
    assert!(format!("{retry:?}").contains(UNCERTAIN), "{retry:?}");
}

/// MIK-7979.SETTLE.2: the backend answered with its own error. A retry is
/// served that answer, not the uncertain notice, and is not run again.
#[tokio::test]
async fn a_backend_error_answer_is_replayed_as_that_answer() {
    let (_, retry, calls) = retried_after(Step::Refuse(-32050, "quota spent upstream")).await;
    assert_eq!(
        calls, 1,
        "the same-key retry reached the backend again: {retry:?}"
    );
    let served = format!("{retry:?}");
    assert!(served.contains("quota spent upstream"), "{served}");
    assert!(!served.contains(UNCERTAIN), "{served}");
}

/// MIK-7979.SETTLE.3: `BackendUnavailable` is only raised before the request
/// is sent, so it frees the key and the retry runs.
#[tokio::test]
async fn a_backend_unavailable_refusal_frees_the_key() {
    let (_, retry, calls) = retried_after(Step::Fail(|| {
        crate::Error::BackendUnavailable("svc".into())
    }))
    .await;
    assert_eq!(calls, 2, "the retry must run: {retry:?}");
    assert!(format!("{retry:?}").contains("done"), "{retry:?}");
}

/// MIK-7900: a reload stops the backend while its call is in flight. The
/// transport closes under the call, and the retry is told the outcome is
/// unknown rather than replayed a failure or run again.
#[tokio::test]
async fn a_backend_stopped_mid_call_is_not_executed_again() {
    let (meta, wire) = gateway(vec![Step::ParkUntilClosed, Step::Answer(done())]);
    let client = answering();
    let backend = meta.backends.get("svc").expect("svc is registered");
    let (first, ()) = tokio::join!(call(&meta, &client), async {
        wire.parked.notified().await;
        backend.stop().await.expect("stop never fails");
    });
    assert!(
        format!("{first:?}").contains("Response channel closed"),
        "{first:?}"
    );

    let retry = call(&meta, &client).await;
    assert_eq!(
        wire.calls.load(Ordering::SeqCst),
        1,
        "the same-key retry reached the backend again: {retry:?}"
    );
    assert!(format!("{retry:?}").contains(UNCERTAIN), "{retry:?}");
}

/// A lost round that finds its reservation already settled by another path
/// leaves that path's answer in place: it neither reports settling the key nor
/// replaces the stored error with the uncertainty notice.
#[test]
fn a_lost_round_leaves_an_already_settled_key_alone() {
    let cache = Arc::new(IdempotencyCache::new());
    let crate::idempotency::GuardOutcome::Proceed(mut reservation) =
        crate::idempotency::enforce(&cache, KEY, "fp").expect("a fresh key is admitted")
    else {
        panic!("a fresh key must proceed");
    };
    let first = json!({ "code": -32000, "message": "first answer" });
    reservation.fail(&first);

    let settled = super::settle_lost_round(
        &crate::Error::Transport("reset".to_string()),
        Some(&mut reservation),
        super::LostRoundRoute::Meta,
    );

    assert!(!settled, "an already settled key was settled again");
    match crate::idempotency::enforce(&cache, KEY, "fp").expect("the key is stored") {
        crate::idempotency::GuardOutcome::CachedError(stored) => {
            assert_eq!(stored, first, "the first answer was overwritten");
        }
        other => panic!("the stored answer changed: {other:?}"),
    }
}
