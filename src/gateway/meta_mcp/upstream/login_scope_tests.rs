// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8269: task recovery's query and cancel are background upkeep. They,
//! and the discovery they trigger, never run in a scope that may begin or join
//! a login: one they began would open the browser and end `Cancelled` when the
//! bound fires. A dispatch's claim is not upkeep and keeps its caller's scope.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::NativeUpstreamTasks;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::task_service::{UpstreamHandle, UpstreamRecovery};

/// A peer that declares the tasks extension and records, per method, whether
/// the request ran in a scope allowed to begin a login.
#[derive(Default)]
struct ScopeWitness {
    seen: parking_lot::Mutex<Vec<(String, bool)>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for ScopeWitness {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        self.seen
            .lock()
            .push((method.to_string(), crate::oauth::login_gate::interactive()));
        let result = match method {
            "server/discover" => json!({"capabilities": {"extensions": {
                "io.modelcontextprotocol/tasks": {}
            }}}),
            _ => json!({"taskId": "t1", "status": "working"}),
        };
        Ok(crate::protocol::JsonRpcResponse::success_serialized(
            crate::protocol::RequestId::Number(1),
            result,
        ))
    }
    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
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

/// A trusted, registered `peer` whose transport is `witness`.
fn adapter_over(witness: &Arc<ScopeWitness>) -> NativeUpstreamTasks {
    let backend = Arc::new(Backend::new(
        "peer",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(5),
    ));
    backend.set_transport_for_test(Arc::clone(witness) as Arc<dyn crate::transport::Transport>);
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(backend), "fixture registration");
    NativeUpstreamTasks::new(registry, &["peer".to_string()])
}

#[tokio::test]
async fn task_recovery_requests_never_run_where_a_login_may_begin() {
    let witness = Arc::new(ScopeWitness::default());
    let adapter = adapter_over(&witness);
    let handle = UpstreamHandle {
        backend: "peer".to_string(),
        handle: "t1".to_string(),
    };

    // An ordinary caller's scope, where a login may begin.
    assert!(crate::oauth::login_gate::interactive(), "premise");
    let _ = adapter.query(&handle, Duration::from_secs(5)).await;
    adapter.cancel(&handle, Duration::from_secs(5)).await;

    let seen = witness.seen.lock().clone();
    for method in ["server/discover", "tasks/get", "tasks/cancel"] {
        assert!(
            seen.iter().any(|(m, _)| m == method),
            "{method} was not sent: {seen:?}"
        );
    }
    let interactive: Vec<_> = seen.iter().filter(|(_, i)| *i).collect();
    assert!(
        interactive.is_empty(),
        "task recovery sent these where a login may begin: {interactive:?}"
    );
}

/// The claim a dispatch asks is not upkeep: it runs where the dispatch's own
/// `tools/call` will. Under `non_interactive` it was refused while a start held
/// the backend, and recovery was silently left unarmed for that task.
#[tokio::test]
async fn a_dispatch_claim_discovers_in_its_callers_own_scope() {
    let witness = Arc::new(ScopeWitness::default());
    let adapter = adapter_over(&witness);

    assert!(crate::oauth::login_gate::interactive(), "premise");
    assert!(adapter.claims("peer").await, "a declaring peer is claimed");

    let seen = witness.seen.lock().clone();
    assert_eq!(
        seen,
        [("server/discover".to_string(), true)],
        "the claim's discovery ran outside its caller's scope"
    );
}

/// A restarted gateway's one upstream `tasks/cancel` for an OAuth backend
/// whose start is still in flight (a reconnect with a stored token) waits for
/// that start, then is sent. It used to be refused `AuthorizationRequired`,
/// logged "unclaimed", and never sent: the owner's cancel vanished.
#[tokio::test]
async fn a_cancel_waits_for_an_oauth_backend_start_in_flight() {
    let witness = Arc::new(ScopeWitness::default());
    let config = BackendConfig {
        oauth: Some(crate::config::OAuthConfig {
            shared_account: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let backend = Arc::new(Backend::new(
        "peer",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(5),
    ));
    let registry = Arc::new(BackendRegistry::new());
    assert!(
        registry.register(Arc::clone(&backend)),
        "fixture registration"
    );
    let adapter = NativeUpstreamTasks::new(registry, &["peer".to_string()]);
    let handle = UpstreamHandle {
        backend: "peer".to_string(),
        handle: "t1".to_string(),
    };
    let entry = backend.shared_entry_for_test();
    let start_in_flight = entry.start_lock.lock().await;

    let cancel = tokio::spawn(async move { adapter.cancel(&handle, Duration::from_secs(5)).await });
    // Run the cancel to its first real wait (no I/O before it): a refusal
    // finishes it here; a waiting cancel parks on the start lock.
    for _ in 0..100 {
        if cancel.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    // The start completes.
    backend.set_transport_for_test(Arc::clone(&witness) as Arc<dyn crate::transport::Transport>);
    drop(start_in_flight);
    tokio::time::timeout(Duration::from_secs(10), cancel)
        .await
        .expect("the cancel ends")
        .expect("cancel task");

    let seen = witness.seen.lock().clone();
    assert!(
        seen.iter().any(|(m, _)| m == "tasks/cancel"),
        "the owner's cancel was dropped while the start was in flight: {seen:?}"
    );
    assert!(
        seen.iter().all(|(_, interactive)| !interactive),
        "the cancel ran where a login may begin: {seen:?}"
    );
}
