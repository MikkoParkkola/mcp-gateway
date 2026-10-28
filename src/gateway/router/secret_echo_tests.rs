// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend that echoes a secret the gateway injected into its call must not
//! hand that secret back to the caller: the resolved value is the gateway's
//! credential, not part of the backend's answer.
//!
//! The backend here reflects the arguments it received into its result text,
//! as an echo tool or an error message quoting the request would.
use axum::body::to_bytes;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_backend;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};
use crate::protocol::{JsonRpcResponse, RequestId};

/// A value no ordinary answer contains, long enough to be redacted.
const SECRET: &str = "echo-secret-7f3a9c2e51d84b06";

type Calls = Arc<parking_lot::Mutex<Vec<Value>>>;

/// Serves one `echo` tool that answers with the arguments it received.
struct Echo {
    calls: Calls,
}

#[async_trait::async_trait]
impl crate::transport::Transport for Echo {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        let result = match method {
            "tools/list" => json!({"tools": [{
                "name": "echo", "description": "fixture",
                "inputSchema": {"type": "object"}
            }]}),
            "tools/call" => {
                let params = params.unwrap_or(Value::Null);
                self.calls.lock().push(params.clone());
                let received = params["arguments"].to_string();
                json!({"content": [{"type": "text", "text": format!("received {received}")}]})
            }
            _ => json!({}),
        };
        Ok(JsonRpcResponse::success(RequestId::Number(1), result))
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

/// An `echoes` backend whose `api_key` argument the gateway injects.
async fn fixture() -> (axum::Router, Calls, tempfile::TempDir) {
    let calls = Calls::default();
    let backend = Arc::new(Backend::new(
        "echoes",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Echo {
        calls: Arc::clone(&calls),
    }));
    backend
        .get_tools_for_binding(None, &[])
        .await
        .expect("the fixture lists its tools");
    let (mut state, store) = test_router_app_state_with_backend(backend).await;
    let rule: crate::secret_injection::CredentialRule = serde_json::from_value(json!({
        "name": "echo-key", "value": SECRET, "inject_key": "api_key"
    }))
    .expect("rule parses");
    let injector = crate::secret_injection::SecretInjector::new(
        [("echoes".to_string(), vec![rule])].into_iter().collect(),
    );
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    let meta = crate::gateway::test_helpers::MetaMcp::new(Arc::clone(&state_mut.backends));
    state_mut.meta_mcp = Arc::new(meta.with_secret_injector(injector));
    (create_router(state), calls, store)
}

async fn post(router: &axum::Router, body: Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// On the meta route, a backend that echoes the injected secret does not get
/// it into the client's answer.
#[tokio::test]
async fn an_echoed_secret_does_not_reach_the_client_on_the_meta_route() {
    let (router, calls, _store) = fixture().await;
    let body = post(
        &router,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "gateway_invoke",
            "arguments": {"server": "echoes", "tool": "echo", "arguments": {"q": "hi"}}
        }}),
    )
    .await;
    {
        let calls = calls.lock();
        let [call] = calls.as_slice() else {
            panic!("premise: one call reached the backend: {body}");
        };
        assert_eq!(
            call["arguments"]["api_key"], SECRET,
            "premise: the gateway injected the secret"
        );
    }
    assert!(
        body["result"].is_object(),
        "premise: the call was answered: {body}"
    );
    assert!(
        !body.to_string().contains(SECRET),
        "the injected secret reached the client: {body}"
    );
}
