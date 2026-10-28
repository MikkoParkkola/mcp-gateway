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
    invoke_read(&meta).await;
    // The registry still holds the backend and its recorder: take the record.
    std::mem::take(&mut *received.lock().expect("recorder"))
}

/// `gateway_invoke read` on `alpha` over stdio; the call must succeed.
async fn invoke_read(meta: &Arc<MetaMcp>) {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": "alpha", "tool": "read", "arguments": {}}}});
    let answer =
        super::super::Gateway::dispatch_single(meta, &policy, &mtls, &request, "stdio-inject")
            .await
            .expect("a request is answered");
    assert!(
        answer.get("error").is_none(),
        "premise: the call succeeds: {answer}"
    );
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

/// The secret a backend's rule held before a reload.
const OLD: &str = "reload-old-secret-aa01";
/// The secret a reloaded rule holds.
const NEW: &str = "reload-new-secret-bb02";

/// A backend config with one `argument` rule injecting `value` as `api_key`.
fn with_rule(value: &str) -> BackendConfig {
    BackendConfig {
        secrets: vec![CredentialRule {
            name: "api".to_string(),
            credential_type: CredentialType::ApiKey,
            value: value.to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
        ..BackendConfig::default()
    }
}

/// Builds the backends in `boot` as startup does, applies `patch` as a config
/// reload does, then calls `gateway_invoke read` on `alpha`: what `alpha`,
/// the instance the reload built, received.
async fn after_reload(
    boot: Vec<(&str, BackendConfig)>,
    patch: crate::config_reload::ConfigPatch,
) -> Received {
    let registry = Arc::new(BackendRegistry::new());
    let mut configs = std::collections::HashMap::new();
    for (name, config) in boot {
        let backend = Arc::new(Backend::new(
            name,
            config.clone(),
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(Recording(Arc::default())));
        assert!(registry.register(backend));
        configs.insert(name.to_string(), config);
    }
    let injector = SecretInjector::from_backend_configs(&configs);
    let meta = Arc::new(MetaMcp::new(Arc::clone(&registry)).with_secret_injector(injector));
    let applied = crate::config_reload::apply_patch(
        &patch,
        &registry,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
        &crate::config::RuntimeConfig::default(),
    )
    .await;
    assert!(applied, "premise: the reload applied");
    let received = Arc::new(Mutex::new(Received::default()));
    registry
        .get("alpha")
        .expect("premise: the reload left alpha registered")
        .set_transport_for_test(Arc::new(Recording(Arc::clone(&received))));
    invoke_read(&meta).await;
    std::mem::take(&mut *received.lock().expect("recorder"))
}

/// The `api_key` argument `alpha` received, if any.
fn api_key(seen: &Received) -> Option<Value> {
    seen.params
        .as_ref()
        .and_then(|params| params.pointer("/arguments/api_key"))
        .cloned()
}

/// A backend added by a reload has its rule applied on the next call.
#[tokio::test]
async fn a_reload_that_adds_a_backend_applies_its_rule() {
    let patch = crate::config_reload::ConfigPatch {
        backends_added: vec![("alpha".to_string(), with_rule(NEW))],
        ..Default::default()
    };
    let seen = after_reload(Vec::new(), patch).await;
    assert_eq!(
        api_key(&seen),
        Some(json!(NEW)),
        "the added backend's rule was not applied"
    );
}

/// A reload that changes a rule's value sends the new value, never the old.
#[tokio::test]
async fn a_reload_that_changes_a_rule_sends_the_new_value() {
    let patch = crate::config_reload::ConfigPatch {
        backends_modified: vec![("alpha".to_string(), with_rule(NEW))],
        ..Default::default()
    };
    let seen = after_reload(vec![("alpha", with_rule(OLD))], patch).await;
    let params = seen.params.clone().expect("the backend received the call");
    assert!(
        !params.to_string().contains(OLD),
        "the old secret still went out after the reload: {params}"
    );
    assert_eq!(
        api_key(&seen),
        Some(json!(NEW)),
        "the new value was not sent"
    );
}

/// A reload that removes a rule stops its secret going out.
#[tokio::test]
async fn a_reload_that_removes_a_rule_stops_its_secret() {
    let patch = crate::config_reload::ConfigPatch {
        backends_modified: vec![("alpha".to_string(), BackendConfig::default())],
        ..Default::default()
    };
    let seen = after_reload(vec![("alpha", with_rule(OLD))], patch).await;
    let params = seen.params.expect("the backend received the call");
    assert!(
        !params.to_string().contains(OLD),
        "a removed rule's secret still went out after the reload: {params}"
    );
}
