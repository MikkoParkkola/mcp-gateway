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

/// The recovery adapter: claims the fixture backend, answers every query with
/// [`PROSE`].
struct Recovery;

#[async_trait::async_trait]
impl UpstreamRecovery for Recovery {
    async fn claims(&self, backend: &str) -> bool {
        backend == BACKEND
    }

    async fn query(&self, _handle: &UpstreamHandle, _deadline: Duration) -> UpstreamAnswer {
        UpstreamAnswer::Completed(json!({ "content": [{ "type": "text", "text": PROSE }] }))
    }
}

/// M15: `key-a`'s upstream task completes with [`PROSE`], which `key-a` is
/// owed through `tasks/get`; `key-b` sending it is refused under `block`.
#[tokio::test]
async fn upstream_task_result_is_a_relay_source() {
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
    let (state, _store) = super::super::meta_fixture::test_router_app_state_with_meta(
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
    std::assert!(state.task_executor.install_recovery(Arc::new(Recovery)));

    let created = post(&state, "key-a", task_invoke(1, "relay-upstream", json!({}))).await;
    let id = task_id(&created);
    let settled = poll_until_terminal(&state, "key-a", &id).await;
    std::assert_eq!(status_of(&settled), "completed", "base: {settled}");
    std::assert!(
        settled.to_string().contains("orchard"),
        "base: the upstream answer settled the task: {settled}"
    );

    // The worker commits after the store write a read observes, and a read
    // renews the receipt: keep `key-b` sending without reading the task.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut sends = 100;
    loop {
        let answer = post(
            &state,
            "key-b",
            sync_invoke(sends, json!({ "text": PROSE })),
        )
        .await;
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
