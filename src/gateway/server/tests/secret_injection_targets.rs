// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's secret-injection rules deliver the secret where `inject_as`
//! says: a `header` rule as that header on the tool call, and a `query` rule
//! nowhere in the tool call's arguments. A config reload's rules apply on the
//! next call.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::backend::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::transport::ResendPermission;

/// The secret every rule here injects: a literal, so no environment is read.
const SECRET: &str = "injected-secret-value-7f3a";

/// What the backend received on its one `tools/call`.
#[derive(Default)]
struct Received {
    params: Option<Value>,
    headers: Vec<(String, String)>,
}

/// Backend `alpha`: lists `read` with `schema`, answers every call, records
/// what a `tools/call` carried.
struct Recording {
    seen: Arc<Mutex<Received>>,
    schema: Value,
}

/// [`Recording`] of a `read` that declares no properties.
fn recording(seen: Arc<Mutex<Received>>) -> Recording {
    Recording {
        seen,
        schema: json!({"type": "object"}),
    }
}

#[async_trait::async_trait]
impl crate::transport::Transport for Recording {
    /// A recording double: these rows check what a call sends, not what its
    /// answer echoes, so it stands in for a transport holding its set
    /// (DELTA-10 refuses an injected call on one that does not).
    fn redacts_injected_values(&self) -> bool {
        true
    }

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
            let tool =
                json!({"name": "read", "description": "A tool.", "inputSchema": self.schema});
            return Ok(JsonRpcResponse::success(id, json!({"tools": [tool]})));
        }
        if method == "tools/call" {
            let mut seen = self.seen.lock().expect("recorder");
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

/// A registry as the gateway builds one: every backend it registers resolves
/// its rules' values with the one shared resolver.
fn gateway_registry() -> Arc<BackendRegistry> {
    registry_resolving_with(crate::secrets::SecretResolver::new())
}

/// [`gateway_registry`] resolving with `resolver`.
fn registry_resolving_with(resolver: crate::secrets::SecretResolver) -> Arc<BackendRegistry> {
    Arc::new(BackendRegistry::with_secret_resolver(Arc::new(resolver)))
}

/// `gateway_invoke read` on `alpha` over stdio, `alpha` holding one rule that
/// injects [`SECRET`] as `inject_as` under `key`: the answer, and what the
/// backend received.
async fn invoke_with(inject_as: InjectTarget, key: &str) -> (Value, Received) {
    let rule = CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    };
    invoke_rules(vec![rule], json!({}), json!({"type": "object"})).await
}

/// `gateway_invoke read` with `arguments` on `alpha`, which holds `rules` and
/// lists `read` with `schema`: the answer, and what the backend received.
async fn invoke_rules(
    rules: Vec<CredentialRule>,
    arguments: Value,
    schema: Value,
) -> (Value, Received) {
    let received = Arc::new(Mutex::new(Received::default()));
    let registry = gateway_registry();
    let config = BackendConfig {
        secrets: rules,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "alpha",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.set_transport_for_test(Arc::new(Recording {
        seen: Arc::clone(&received),
        schema,
    }));
    assert!(registry.register(backend));
    let meta = Arc::new(MetaMcp::new(registry));
    let answer = invoke_read_with(&meta, arguments).await;
    // The registry still holds the backend and its recorder: take the record.
    let seen = std::mem::take(&mut *received.lock().expect("recorder"));
    (answer, seen)
}

/// `gateway_invoke read` on `alpha` over stdio: the answer.
async fn invoke_read(meta: &Arc<MetaMcp>) -> Value {
    invoke_read_with(meta, json!({})).await
}

/// `gateway_invoke read` with `arguments` on `alpha` over stdio: the answer.
async fn invoke_read_with(meta: &Arc<MetaMcp>, arguments: Value) -> Value {
    invoke_read_on(meta, "alpha", arguments).await
}

/// `gateway_invoke read` with `arguments` on `server` over stdio: the answer.
async fn invoke_read_on(meta: &Arc<MetaMcp>, server: &str, arguments: Value) -> Value {
    let policy = Arc::new(crate::security::ToolPolicy::default());
    let mtls = Arc::new(crate::mtls::MtlsPolicy::from_config(
        &crate::mtls::MtlsConfig::default(),
    ));
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "gateway_invoke",
                   "arguments": {"server": server, "tool": "read", "arguments": arguments}}});
    super::super::Gateway::dispatch_single(meta, &policy, &mtls, &request, "stdio-inject")
        .await
        .expect("a request is answered")
}

/// The call answered without an error.
fn assert_succeeded(answer: &Value) {
    assert!(
        answer.get("error").is_none() && answer.pointer("/result/isError") != Some(&json!(true)),
        "premise: the call succeeds: {answer}"
    );
}

/// A `header` rule's secret reaches the backend as that header.
#[tokio::test]
async fn a_header_rule_delivers_the_secret_as_that_header() {
    let (answer, seen) = invoke_with(InjectTarget::Header, "X-Api-Key").await;
    assert_succeeded(&answer);
    assert!(
        seen.headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("X-Api-Key") && value == SECRET),
        "no X-Api-Key header carried the secret: {:?}",
        seen.headers
    );
}

/// A `query` rule's secret never travels in the tool call's arguments. Config
/// load refuses the rule; a backend built in code refuses the call, so nothing
/// carrying the secret is sent.
#[tokio::test]
async fn a_query_rule_never_puts_the_secret_in_the_arguments() {
    let (_, seen) = invoke_with(InjectTarget::Query, "api_key").await;
    if let Some(params) = seen.params {
        assert!(
            !params.to_string().contains(SECRET),
            "the secret reached the backend in the call: {params}"
        );
    }
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
    after_reload_resolving(gateway_registry(), boot, patch).await
}

/// [`after_reload`] over `registry`.
async fn after_reload_resolving(
    registry: Arc<BackendRegistry>,
    boot: Vec<(&str, BackendConfig)>,
    patch: crate::config_reload::ConfigPatch,
) -> Received {
    for (name, config) in boot {
        let backend = Arc::new(Backend::new(
            name,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(recording(Arc::default())));
        assert!(registry.register(backend));
    }
    let meta = Arc::new(MetaMcp::new(Arc::clone(&registry)));
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
        .set_transport_for_test(Arc::new(recording(Arc::clone(&received))));
    assert_succeeded(&invoke_read(&meta).await);
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

/// What a caller sends under a key a rule owns.
const CALLER: &str = "caller-value-ee05";

/// A rule named `name` injecting [`SECRET`] as `inject_as` under `key`.
fn secret_rule(name: &str, inject_as: InjectTarget, key: &str) -> CredentialRule {
    CredentialRule {
        name: name.to_string(),
        credential_type: CredentialType::ApiKey,
        value: SECRET.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    }
}

/// A caller's value under a key a rule owns is overwritten, never sent
/// beside the secret.
#[tokio::test]
async fn a_caller_value_under_a_rule_key_is_overwritten() {
    let schema = json!({"type": "object", "properties": {"api_key": {"type": "string"}}});
    let rule = secret_rule("api", InjectTarget::Argument, "api_key");
    let (answer, seen) = invoke_rules(vec![rule], json!({"api_key": CALLER}), schema).await;
    assert_succeeded(&answer);
    let params = seen.params.expect("the backend received the call");
    assert_eq!(
        params.pointer("/arguments/api_key"),
        Some(&json!(SECRET)),
        "the rule's value was not sent: {params}"
    );
    assert!(
        !params.to_string().contains(CALLER),
        "the caller's value was sent: {params}"
    );
}

/// An argument a rule owns and the schema mirrors onto an `Mcp-Param` header
/// is mirrored with neither the caller's value nor the secret. `region`,
/// which no rule owns, is mirrored: the mirror ran.
#[tokio::test]
async fn a_rule_owned_argument_is_never_mirrored_into_a_header() {
    let schema = json!({"type": "object", "properties": {
        "api_key": {"type": "string", "x-mcp-header": "ApiKey"},
        "region": {"type": "string", "x-mcp-header": "Region"}}});
    let rule = secret_rule("api", InjectTarget::Argument, "api_key");
    let arguments = json!({"api_key": CALLER, "region": "eu"});
    let (answer, seen) = invoke_rules(vec![rule], arguments, schema).await;
    assert_succeeded(&answer);
    assert!(
        seen.headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("Mcp-Param-Region") && value == "eu"),
        "premise: the mirror ran: {:?}",
        seen.headers
    );
    let leaked: Vec<_> = seen
        .headers
        .iter()
        .filter(|(_, value)| value.contains(CALLER) || value.contains(SECRET))
        .collect();
    assert!(leaked.is_empty(), "mirrored: {leaked:?}");
}

/// Each matching rule is audited once per call, naming the rule, and no log
/// record carries its value.
#[test]
fn each_rule_is_audited_once_per_call_and_its_value_is_never_logged() {
    let rules = vec![
        secret_rule("first", InjectTarget::Argument, "api_key"),
        secret_rule("second", InjectTarget::Header, "X-Api-Key"),
    ];
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let (answer, seen) =
            runtime.block_on(invoke_rules(rules, json!({}), json!({"type": "object"})));
        assert_succeeded(&answer);
        assert!(seen.params.is_some(), "premise: the backend was called");
    });
    assert_eq!(
        crate::test_log_capture::count(&records, "INFO", "Secret injected"),
        2,
        "one audit line per rule per call"
    );
    let logged = serde_json::to_string(&records).expect("records serialise");
    assert!(!logged.contains(SECRET), "a log record carried the secret");
}

/// A reload whose only change is a rule's value is a modified backend, as the
/// config diff computes it, and its new value is sent.
#[tokio::test]
async fn a_secrets_only_reload_is_diffed_as_a_change_and_applied() {
    let config = |value: &str| {
        let mut config = crate::config::Config::default();
        config
            .backends
            .insert("alpha".to_string(), with_rule(value));
        config
    };
    let patch = crate::config_reload::compute_diff(&config(OLD), &config(NEW));
    assert!(
        patch
            .backends_modified
            .iter()
            .any(|(name, _)| name == "alpha"),
        "premise: the diff marks the secrets-only change: {patch:?}"
    );
    let seen = after_reload(vec![("alpha", with_rule(OLD))], patch).await;
    assert_eq!(
        api_key(&seen),
        Some(json!(NEW)),
        "the new value was not sent"
    );
}

/// A rule a reload adds resolves through the gateway's env files: the value
/// only an env file assigns is sent, so the reloaded backend was handed the
/// gateway's resolver.
#[tokio::test]
async fn a_reloaded_rule_resolves_a_value_only_an_env_file_assigns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join("keys.env");
    crate::gateway::test_helpers::write_owner_only(
        &env_file,
        "RELOAD_FILE_ONLY_KEY=from-the-file-ff06\n",
    )
    .expect("env file");
    let overlay = Arc::new(crate::config::EnvOverlay::from_paths(&[env_file]));
    let env = Arc::new(crate::config::LiveEnv::new(
        overlay,
        crate::config::ResolvedEnvFiles::default(),
    ));
    let registry = registry_resolving_with(crate::secrets::SecretResolver::new().with_env(env));
    let patch = crate::config_reload::ConfigPatch {
        backends_modified: vec![("alpha".to_string(), with_rule("{env.RELOAD_FILE_ONLY_KEY}"))],
        ..Default::default()
    };
    let seen =
        after_reload_resolving(registry, vec![("alpha", BackendConfig::default())], patch).await;
    assert_eq!(
        api_key(&seen),
        Some(json!("from-the-file-ff06")),
        "the env file's value was not sent"
    );
}

/// A backend's rules are its own: `beta`, which holds no rule, is sent its
/// call untouched, a caller's own `api_key` included, while `alpha`,
/// registered beside it in the same registry with an argument rule, gets the
/// secret. A coverage row: each backend reads only its own `secrets:`, so it
/// holds on the line; it fails if a backend without rules applied another
/// backend's, such as rules read from one shared table.
#[tokio::test]
async fn a_backend_without_a_rule_gets_none_of_another_backends_secret() {
    let registry = gateway_registry();
    let mut recorders = Vec::new();
    for (name, secrets) in [
        (
            "alpha",
            vec![CredentialRule {
                name: "api".to_string(),
                credential_type: CredentialType::ApiKey,
                value: SECRET.to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "api_key".to_string(),
                tools: vec!["*".to_string()],
            }],
        ),
        ("beta", Vec::new()),
    ] {
        let seen = Arc::new(Mutex::new(Received::default()));
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig {
                secrets,
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            Duration::from_secs(300),
        ));
        backend.set_transport_for_test(Arc::new(recording(Arc::clone(&seen))));
        assert!(registry.register(backend));
        recorders.push(seen);
    }
    let meta = Arc::new(MetaMcp::new(registry));
    let caller = json!({"q": 1, "api_key": "the-callers-own"});

    // beta is called before and after alpha, so neither a rule shared at
    // registration nor a value left over from alpha's send can pass.
    for round in ["before alpha", "after alpha"] {
        if round == "after alpha" {
            // Control: the same registry applies alpha's own rule to alpha.
            let answer = invoke_read_on(&meta, "alpha", json!({"q": 1})).await;
            assert_succeeded(&answer);
            let alpha = std::mem::take(&mut *recorders[0].lock().expect("recorder"));
            let sent = alpha.params.expect("premise: alpha received its call");
            assert_eq!(
                sent["arguments"],
                json!({"q": 1, "api_key": SECRET}),
                "control: alpha's rule applies to the same call shape: {sent}"
            );
        }
        let answer = invoke_read_on(&meta, "beta", caller.clone()).await;
        assert_succeeded(&answer);
        let beta = std::mem::take(&mut *recorders[1].lock().expect("recorder"));
        let sent = beta.params.expect("premise: beta received its call");
        assert_eq!(
            sent["arguments"], caller,
            "{round}: beta's arguments were changed: {sent}"
        );
        assert!(
            !sent.to_string().contains(SECRET)
                && !beta
                    .headers
                    .iter()
                    .any(|(name, value)| name.contains(SECRET) || value.contains(SECRET)),
            "{round}: beta received alpha's secret: {sent} {:?}",
            beta.headers
        );
    }
}
