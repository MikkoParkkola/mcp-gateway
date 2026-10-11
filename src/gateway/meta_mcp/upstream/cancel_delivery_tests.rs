// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8347: what one `tasks/cancel` attempt reports, so the claim holder
//! knows whether to retry and whether the retry spends the bound.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::NativeUpstreamTasks;
use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::task_service::{CancelDelivery, UpstreamHandle, UpstreamRecovery};
use crate::protocol::{JsonRpcError, JsonRpcResponse, RequestId};

/// How the peer answers `tasks/cancel`; it always declares the extension.
#[derive(Clone, Copy)]
enum Answer {
    Result,
    RpcError,
    TransportError,
    LoginRequired,
    LoginPending,
    Hang,
}

struct Peer(Answer);

#[async_trait::async_trait]
impl crate::transport::Transport for Peer {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        if method == "server/discover" {
            return Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"capabilities": {"extensions": {"io.modelcontextprotocol/tasks": {}}}}),
            ));
        }
        match self.0 {
            Answer::Result => Ok(JsonRpcResponse::success_serialized(
                RequestId::Number(1),
                json!({"taskId": "t1", "status": "cancelled"}),
            )),
            Answer::RpcError => {
                let mut response =
                    JsonRpcResponse::success_serialized(RequestId::Number(1), json!({}));
                response.result = None;
                response.error = Some(JsonRpcError {
                    code: -32602,
                    message: "task already terminal".to_owned(),
                    data: None,
                });
                Ok(response)
            }
            Answer::TransportError => Err(crate::Error::BackendUnavailable("peer".to_owned())),
            Answer::LoginRequired => Err(crate::Error::AuthorizationRequired {
                backend: "peer".to_owned(),
            }),
            Answer::LoginPending => Err(crate::Error::AuthorizationPending {
                backend: "peer".to_owned(),
            }),
            Answer::Hang => std::future::pending().await,
        }
    }

    async fn request_with_task_capability(
        &self,
        method: &str,
        params: Option<Value>,
        _extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
    ) -> crate::Result<JsonRpcResponse> {
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

fn handle_on(backend: &str) -> UpstreamHandle {
    UpstreamHandle {
        backend: backend.to_string(),
        handle: "t1".to_string(),
    }
}

fn registered(config: BackendConfig) -> (Arc<Backend>, NativeUpstreamTasks) {
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
    (backend, adapter)
}

async fn delivery(answer: Answer) -> CancelDelivery {
    let (backend, adapter) = registered(BackendConfig::default());
    backend.set_transport_for_test(Arc::new(Peer(answer)) as Arc<dyn crate::transport::Transport>);
    adapter
        .cancel(&handle_on("peer"), Duration::from_secs(1))
        .await
}

/// T4. A peer answer of either kind is `Confirmed`: a JSON-RPC error such as
/// "already terminal" means the peer received it, and resending changes
/// nothing. No answer is `Failed`. Mutants: "an error answer is Failed",
/// "a transport error is Confirmed", "a timeout is Confirmed".
#[tokio::test(start_paused = true)]
async fn a_peer_answer_confirms_and_no_answer_fails() {
    assert_eq!(delivery(Answer::Result).await, CancelDelivery::Confirmed);
    assert_eq!(delivery(Answer::RpcError).await, CancelDelivery::Confirmed);
    assert_eq!(
        delivery(Answer::TransportError).await,
        CancelDelivery::Failed
    );
    assert_eq!(delivery(Answer::Hang).await, CancelDelivery::Failed);
    // An expired token on a connected backend: not sent, so not counted.
    // Mutant: "a login refusal is a failed send".
    assert_eq!(
        delivery(Answer::LoginRequired).await,
        CancelDelivery::NotReady
    );
    assert_eq!(
        delivery(Answer::LoginPending).await,
        CancelDelivery::NotReady
    );
}

/// T1c. Red at base. A cancel that meets a start held past its deadline (an
/// interactive login) is `NotReady`, so the bound is not spent while the
/// login runs; a backend no registry holds is `NotReady` too. Mutant: "a
/// start in flight is reported as a failed send".
#[tokio::test(start_paused = true)]
async fn a_start_held_past_the_deadline_is_not_ready() {
    let config = BackendConfig {
        oauth: Some(crate::config::OAuthConfig {
            shared_account: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let (backend, adapter) = registered(config);
    let entry = backend.shared_entry_for_test();
    let _start_in_flight = entry.start_lock.lock().await;
    assert_eq!(
        adapter
            .cancel(&handle_on("peer"), Duration::from_secs(1))
            .await,
        CancelDelivery::NotReady
    );
    assert_eq!(
        adapter
            .cancel(&handle_on("absent"), Duration::from_secs(1))
            .await,
        CancelDelivery::NotReady
    );
}
