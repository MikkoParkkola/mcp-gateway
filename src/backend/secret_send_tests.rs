// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's own rules on its send: where each target goes, and what the
//! send refuses for a backend built in code, which config load never saw.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

use super::Backend;
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};
use crate::secrets::SecretResolver;

/// The value every rule here holds unless a row says otherwise.
const SECRET: &str = "send-side-secret-ab07";

fn rule(inject_as: InjectTarget, key: &str, value: &str) -> CredentialRule {
    CredentialRule {
        name: "api".to_string(),
        credential_type: CredentialType::ApiKey,
        value: value.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    }
}

/// Backend `svc` over `transport` holding `rules`, stamped with a resolver
/// when `resolved` (as the gateway's registry stamps every backend).
fn backend(transport: TransportConfig, rules: Vec<CredentialRule>, resolved: bool) -> Backend {
    let backend = Backend::new(
        "svc",
        BackendConfig {
            transport,
            secrets: rules,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    if resolved {
        backend.stamp_secret_resolver(Arc::new(SecretResolver::new()));
    }
    backend
}

fn http() -> TransportConfig {
    TransportConfig::default()
}

/// The params and headers `backend` sends for `params`, given `headers`.
fn send(
    backend: &Backend,
    params: Value,
    headers: Vec<(String, String)>,
) -> crate::Result<(Option<Value>, Vec<(String, String)>)> {
    Ok(backend
        .prepare_secrets("tools/call", Some(params))?
        .apply(headers))
}

#[test]
fn a_call_with_no_arguments_member_still_gets_the_argument() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        true,
    );
    let (params, _) = send(&backend, json!({"name": "read"}), Vec::new()).expect("sent");
    assert_eq!(
        params.and_then(|p| p.pointer("/arguments/api_key").cloned()),
        Some(json!(SECRET))
    );
}

#[test]
fn a_header_replaces_one_of_the_same_name_whatever_its_case() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    let held = vec![
        ("x-api-key".to_string(), "caller-held".to_string()),
        ("X-Other".to_string(), "kept".to_string()),
    ];
    let (_, headers) =
        send(&backend, json!({"name": "read", "arguments": {}}), held).expect("sent");
    let named: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("X-Api-Key"))
        .collect();
    assert_eq!(
        named,
        [&("X-Api-Key".to_string(), SECRET.to_string())],
        "{headers:?}"
    );
    assert!(
        headers
            .iter()
            .any(|(name, value)| name == "X-Other" && value == "kept")
    );
}

#[test]
fn a_rule_that_resolves_empty_injects_nothing_and_still_drops_the_caller_value() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", "")],
        true,
    );
    let params = json!({"name": "read", "arguments": {"api_key": "caller-chosen", "q": 1}});
    let (params, _) = send(&backend, params, Vec::new()).expect("sent");
    let arguments = params.expect("params").pointer("/arguments").cloned();
    assert_eq!(arguments, Some(json!({"q": 1})));
}

/// The refusal: a configuration error naming the backend and the rule, and
/// never the value.
fn refused(backend: &Backend, why: &str) {
    let error = send(
        backend,
        json!({"name": "read", "arguments": {}}),
        Vec::new(),
    )
    .expect_err("the call is refused")
    .to_string();
    assert!(
        error.contains("backend 'svc' secret rule 'api'") && error.contains(why),
        "{error}"
    );
    assert!(
        !error.contains(SECRET),
        "the refusal echoed the value: {error}"
    );
}

#[test]
fn a_backend_no_registry_stamped_refuses_rather_than_resolve_the_process_environment() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        false,
    );
    refused(&backend, "has no secret resolver");
}

#[test]
fn a_query_rule_is_refused_on_the_send() {
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Query, "api_key", SECRET)],
        true,
    );
    refused(&backend, "URL query parameter");
}

#[test]
fn a_header_rule_on_a_transport_without_request_headers_is_refused_on_the_send() {
    let stdio = TransportConfig::Stdio {
        command: "/bin/true".to_string(),
        cwd: None,
        protocol_version: None,
    };
    let backend = backend(
        stdio,
        vec![rule(InjectTarget::Header, "X-Api-Key", SECRET)],
        true,
    );
    refused(&backend, "sends no request headers");
}

#[cfg(feature = "a2a")]
#[test]
fn any_rule_on_an_a2a_backend_is_refused_on_the_send() {
    let a2a = TransportConfig::A2a {
        a2a_url: "https://agent.example.com".to_string(),
        a2a_agent_card_path: None,
    };
    let backend = backend(
        a2a,
        vec![rule(InjectTarget::Argument, "api_key", SECRET)],
        true,
    );
    refused(&backend, "A2A backend");
}

#[test]
fn a_header_value_that_is_not_a_valid_header_value_is_refused_without_echoing_it() {
    let value = "line-one\nline-two-cd08";
    let backend = backend(
        http(),
        vec![rule(InjectTarget::Header, "X-Api-Key", value)],
        true,
    );
    let error = send(
        &backend,
        json!({"name": "read", "arguments": {}}),
        Vec::new(),
    )
    .expect_err("the call is refused")
    .to_string();
    assert!(
        error.contains("secret rule 'api'") && error.contains("not a valid HTTP header value"),
        "{error}"
    );
    assert!(
        !error.contains("line-two-cd08"),
        "the refusal echoed the value: {error}"
    );
}

#[test]
fn a_call_no_rule_matches_is_sent_untouched() {
    let mut scoped = rule(InjectTarget::Argument, "api_key", SECRET);
    scoped.tools = vec!["write_*".to_string()];
    let backend = backend(http(), vec![scoped], false);
    let params = json!({"name": "read", "arguments": {"api_key": "caller"}});
    let (sent, _) = send(&backend, params.clone(), Vec::new()).expect("sent");
    assert_eq!(sent, Some(params));
}
