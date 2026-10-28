// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's secret-injection rules deliver the secret where `inject_as`
//! says: a `header` rule as that header on the tool call, and a `query` rule
//! nowhere in the tool call's arguments.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget, SecretInjector};
use crate::transport::ResendPermission;

/// The secret every rule here injects: a literal, so no environment is read.
const SECRET: &str = "injected-secret-value-7f3a";

/// What the backend received on its one `tools/call`.
#[derive(Default)]
struct Received {
    params: Option<Value>,
    headers: Vec<(String, String)>,
}

/// Backend `alpha`: lists `read`, answers every call, records what a
/// `tools/call` carried.
struct Recording(Arc<Mutex<Received>>);

#[async_trait::async_trait]
impl crate::transport::Transport for Recording {
    async fn request(&self, method: &str, params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        self.request_with_headers(method, params, &[], None, ResendPermission::Denied)
            .await
    }
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        _identity_key: Option<&str>,
        _resend: ResendPermission,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            let tool = json!({"name": "read", "description": "A tool.", "inputSchema": {"type": "object"}});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        if method == "tools/call" {
            let mut seen = self.0.lock().expect("recorder");
            seen.params = params;
            seen.headers = extra_headers.to_vec();
        }
        Ok(JsonRpcResponse::success(
            id,
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
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

/// `gateway_invoke read` on `alpha` over stdio, with one rule injecting
/// [`SECRET`] as `inject_as` under `key`; what the backend received.
async fn invoke_with(inject_as: InjectTarget, key: &str) -> Received {
    let received = Arc::new(Mutex::new(Received::default()));
    let registry = Arc::new(BackendRegistry::new());
    let backend = Arc::new(Backend::new(
        "alpha",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Recording(Arc::clone(&received))));
    assert!(registry.register(backend));
    let rule = CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    };
    let injector = SecretInjector::new(std::collections::HashMap::from([(
        "alpha".to_string(),
        vec![rule],
    )]));
    let meta = Arc::new(MetaMcp::new(registry).with_secret_injector(injector));
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}});
    let answer =
        super::super::Gateway::dispatch_single(&meta, &policy, &mtls, &request, "stdio-inject")
            .await
            .expect("a request is answered");
    assert!(
        answer.get("error").is_none(),
        "premise: the call succeeds: {answer}"
    );
    Arc::try_unwrap(received)
        .ok()
        .expect("the recorder is released")
        .into_inner()
        .expect("recorder")
}

/// A `header` rule's secret reaches the backend as that header.
#[tokio::test]
async fn a_header_rule_delivers_the_secret_as_that_header() {
    let seen = invoke_with(InjectTarget::Header, "X-Api-Key").await;
    assert!(
        seen.headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("X-Api-Key") && value == SECRET),
        "no X-Api-Key header carried the secret: {:?}",
        seen.headers
    );
}

/// A `query` rule's secret never travels in the tool call's arguments.
#[tokio::test]
async fn a_query_rule_never_puts_the_secret_in_the_arguments() {
    let seen = invoke_with(InjectTarget::Query, "api_key").await;
    let params = seen.params.expect("the backend received the call");
    assert!(
        !params.to_string().contains(SECRET),
        "the secret reached the backend in the call: {params}"
    );
}
