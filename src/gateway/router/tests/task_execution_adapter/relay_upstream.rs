// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COLLUDE.1 §13.3 M15 (mutant R9): an upstream-followed task's gated result is
//! recorded as a relay source when the worker settles it.
//!
//! Runs under auth with two principals, on the in-crate upstream fixture: a
//! peer that answers a task-augmented call with a handle, and a recovery
//! adapter that answers the follow-up query with sensitive prose. (The older
//! integration harness cannot mint a key-server identity; this one does not
//! need to.)
use super::super::*;
use super::support::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::gateway::task_service::{UpstreamAnswer, UpstreamHandle, UpstreamRecovery};
use crate::security::firewall::{CollusionAction, CollusionConfig, Firewall, FirewallConfig};

/// What the upstream task finally answers, long enough for several fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// A peer that answers a task-augmented `tools/call` with a task handle and an
/// ordinary one with a short text.
struct Peer;

#[async_trait::async_trait]
impl Transport for Peer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let body = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "mock", "version": "0" }
            }),
            "tools/list" => json!({
                "tools": [{ "name": TOOL, "description": "d", "inputSchema": { "type": "object" } }]
            }),
            "tools/call" => json!({ "content": [{ "type": "text", "text": "ok" }] }),
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), body))
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "tools/call" {
            let handle =
                json!({ "resultType": "task", "taskId": "peer-job-1", "status": "working" });
            return Ok(JsonRpcResponse::success(RequestId::Number(1), handle));
        }
        self.request(method, params).await
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

/// What the recovery adapter's query answers.
type Answering = Arc<dyn Fn() -> UpstreamAnswer + Send + Sync>;

/// The recovery adapter: claims the fixture backend, answers every query from
/// its closure, and counts the queries.
struct Recovery(Arc<AtomicUsize>, Answering);

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    /// This suite asserts nothing about upstream cancels (MIK-7642 PR.D rows do).
    async fn cancel(&self, _handle: &UpstreamHandle, _deadline: Duration) {}

    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        self.0.fetch_add(1, Ordering::SeqCst);
        (self.1)()
    }
}

/// The suite's state with the upstream fixture whose follow-up query answers
/// `answer`, and `key-a`'s task started and queried at least once.
async fn followed(answer: Value) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store, _task) =
        followed_with(Arc::new(move || UpstreamAnswer::Completed(answer.clone()))).await;
    (state, store)
}

/// [`followed`], with the query answering whatever `answering` returns.
async fn followed_with(answering: Answering) -> (Arc<AppState>, tempfile::TempDir, String) {
    let firewall = Arc::new(Firewall::from_config(
        FirewallConfig {
            collusion: CollusionConfig {
                action: CollusionAction::Block,
                sources: vec![format!("{BACKEND}:{TOOL}")],
                ..CollusionConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let (state, store) = super::super::meta_fixture::test_router_app_state_with_meta(
        &two_principal_auth(),
        None,
        |mut meta| {
            meta.set_firewall(Some(firewall));
            meta
        },
    )
    .await;
    let backend = Arc::new(Backend::new(
        BACKEND,
        BackendConfig {
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Peer));
    std::assert!(state.backends.register(backend));
    let queries = Arc::new(AtomicUsize::new(0));
    std::assert!(
        state
            .task_executor
            .install_recovery(Arc::new(Recovery(Arc::clone(&queries), answering)))
    );
    // `key-a` never reads the task: a `tasks/get` would renew the receipt and
    // hide a missing settlement staging.
    let created = post(&state, "key-a", task_invoke(1, "relay-upstream", json!({}))).await;
    let task = task_id(&created);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while queries.load(Ordering::SeqCst) == 0 {
        std::assert!(
            tokio::time::Instant::now() < deadline,
            "base: the worker never queried the peer"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (state, store, task)
}

/// `key-b` sends [`PROSE`] until it is refused as a relay (the worker commits
/// after the answer is stored).
async fn refused_once_recorded(state: &Arc<AppState>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut sends = 100;
    loop {
        let answer = post(state, "key-b", sync_invoke(sends, json!({ "text": PROSE }))).await;
        if answer["error"]["code"] == -32002 {
            return;
        }
        std::assert!(
            tokio::time::Instant::now() < deadline,
            "the upstream result was never recorded: {answer}"
        );
        sends += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// M15: `key-a`'s upstream task completes with [`PROSE`], which `key-a` is
/// owed through `tasks/get`; `key-b` sending it is refused under `block`.
#[tokio::test]
async fn upstream_task_result_is_a_relay_source() {
    let (state, _store) = followed(json!({ "content": [{ "type": "text", "text": PROSE }] })).await;
    refused_once_recorded(&state).await;
}

/// MIK-7887.RECEIPT.4: on the follow path too, the receipt describes the
/// stored result. A backend `cacheScope` the serializer clamps is never
/// delivered, so text stuffed there is not receipted.
#[tokio::test]
async fn a_followed_result_does_not_receipt_a_clamped_cache_scope() {
    use std::fmt::Write as _;
    let stuffing = (0..400).fold(String::new(), |mut text, n| {
        let _ = write!(
            text,
            "The east inventory line {n} lists crate {} of pressed cider. ",
            n * 7 + 3
        );
        text
    });
    let answer = json!({
        "content": [{ "type": "text", "text": PROSE }],
        "cacheScope": stuffing,
    });
    let (state, _store) = followed(answer).await;
    refused_once_recorded(&state).await;
    let piece: String = stuffing.chars().take(400).collect();
    let answer = post(&state, "key-b", sync_invoke(900, json!({ "text": piece }))).await;
    std::assert!(
        answer.get("error").is_none(),
        "undelivered cacheScope text was receipted: {answer}"
    );
}

/// MIK-7887.RECEIPT.1: a followed job that failed with the peer's own error
/// hands that error to the owner, so settlement receipts it. No `tasks/get`
/// runs: the receipt is the settlement's.
#[tokio::test]
async fn a_followed_peer_failure_is_receipted_at_settlement() {
    let (state, _store, _task) = followed_with(Arc::new(|| {
        UpstreamAnswer::Failed(crate::protocol::JsonRpcError {
            code: -32042,
            message: PROSE.to_owned(),
            data: None,
        })
    }))
    .await;
    refused_once_recorded(&state).await;
}

/// MIK-7887.RECEIPT.1: a cancelled job's error is the gateway's own sentence,
/// so settlement receipts nothing and the working stub is dropped.
#[tokio::test]
async fn a_followed_cancellation_receipts_nothing() {
    let (state, _store, task) = followed_with(Arc::new(|| {
        UpstreamAnswer::Substituted(crate::protocol::JsonRpcError {
            code: -32603,
            message: PROSE.to_owned(),
            data: None,
        })
    }))
    .await;
    // Settled first; a read of a gateway error renews nothing either.
    let settled = poll_until_terminal(&state, "key-a", &task).await;
    std::assert!(
        status_of(&settled) == "failed",
        "base: the job failed: {settled}"
    );
    let answer = post(&state, "key-b", sync_invoke(700, json!({ "text": PROSE }))).await;
    std::assert!(
        answer.get("error").is_none(),
        "a gateway substitute was receipted: {answer}"
    );
}
