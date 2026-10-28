// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Each refusal fires at config load with its exact text, and that text is the
//! one the upgrade guide quotes.

use std::collections::HashMap;

use super::{Refusal, refusal};
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::secret_injection::{CredentialRule, CredentialType, InjectTarget};

/// Every kind, so a kind added later is quoted or this list fails review.
const KINDS: [Refusal; 8] = [
    Refusal::Query,
    Refusal::StdioHeader,
    Refusal::RequiredBinding,
    Refusal::OwnedHeader,
    Refusal::InvalidHeaderName,
    Refusal::DuplicateHeader,
    Refusal::A2a,
    Refusal::A2aMessage,
];

/// The value every rule here holds: never echoed by a refusal.
const VALUE: &str = "plain-rule-value-dd04";

fn rule(name: &str, inject_as: InjectTarget, key: &str) -> CredentialRule {
    CredentialRule {
        name: name.to_string(),
        credential_type: CredentialType::ApiKey,
        value: VALUE.to_string(),
        inject_as,
        inject_key: key.to_string(),
        tools: vec!["*".to_string()],
    }
}

fn http(url: &str, secrets: Vec<CredentialRule>) -> BackendConfig {
    BackendConfig {
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: None,
            protocol_version: None,
        },
        secrets,
        ..BackendConfig::default()
    }
}

fn validate(backend: BackendConfig) -> crate::Result<()> {
    let mut config = Config::default();
    config.backends.insert("svc".to_string(), backend);
    config.validate()
}

/// The load refuses `backend` with exactly `kind`'s text for rule `rule`
/// injecting `header`.
fn assert_refused(backend: BackendConfig, kind: Refusal, rule: &str, header: &str) {
    let message = match validate(backend) {
        Err(e) => e.to_string(),
        Ok(()) => panic!("{kind:?}: the config loaded"),
    };
    assert!(
        message.contains(&refusal(kind, "svc", rule, header)),
        "{kind:?}: {message}"
    );
    assert!(
        !message.contains(VALUE),
        "{kind:?} echoed the value: {message}"
    );
}

/// The upgrade guide as it ships: the numbered document and every pending
/// `upgrading.d` fragment, which release preparation folds into it.
fn upgrading_guide() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut guide = std::fs::read_to_string(root.join("docs/UPGRADING-4.0.md")).expect("guide");
    let fragments = std::fs::read_dir(root.join("upgrading.d")).expect("upgrading.d");
    for fragment in fragments.flatten() {
        if fragment.path().extension().is_some_and(|ext| ext == "md") {
            guide.push_str(&std::fs::read_to_string(fragment.path()).expect("fragment"));
        }
    }
    guide.replace("\r\n", "\n")
}

#[test]
fn every_refusal_is_quoted_in_upgrading() {
    let doc = upgrading_guide();
    for kind in KINDS {
        let text = refusal(kind, "<b>", "<r>", "<h>");
        assert!(
            doc.contains(&format!("`{text}`")),
            "the upgrade guide does not quote {kind:?}: {text}"
        );
    }
}

#[test]
fn a_query_rule_is_refused() {
    let backend = http(
        "https://svc.example.com/mcp",
        vec![rule("q", InjectTarget::Query, "api_key")],
    );
    assert_refused(backend, Refusal::Query, "q", "api_key");
}

#[test]
fn a_header_rule_on_stdio_is_refused() {
    let backend = BackendConfig {
        transport: TransportConfig::Stdio {
            command: "/bin/true".to_string(),
            cwd: None,
            protocol_version: None,
        },
        secrets: vec![rule("h", InjectTarget::Header, "X-Api-Key")],
        ..BackendConfig::default()
    };
    assert_refused(backend, Refusal::StdioHeader, "h", "X-Api-Key");
}

fn binding(required: bool) -> IdentityPropagationConfig {
    IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "aud-svc".to_string(),
        required,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    }
}

#[test]
fn a_header_rule_on_a_required_binding_is_refused() {
    let mut backend = http(
        "https://svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "X-Api-Key")],
    );
    backend.identity_propagation = Some(binding(true));
    assert_refused(backend, Refusal::RequiredBinding, "h", "X-Api-Key");
}

#[test]
fn a_header_rule_on_an_optional_binding_loads() {
    let mut backend = http(
        "https://svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "X-Api-Key")],
    );
    backend.identity_propagation = Some(binding(false));
    validate(backend).expect("an optional binding keeps its header rules");
}

#[test]
fn an_argument_rule_loads() {
    let backend = http(
        "https://svc.example.com/mcp",
        vec![rule("a", InjectTarget::Argument, "api_key")],
    );
    validate(backend).expect("an argument rule is delivered as written");
}

#[test]
fn a_header_the_gateway_or_the_backend_sets_is_refused() {
    let protocol = http(
        "https://svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "mcp-session-id")],
    );
    assert_refused(protocol, Refusal::OwnedHeader, "h", "mcp-session-id");

    let mut configured = http(
        "https://svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "X-API-KEY")],
    );
    configured.headers = HashMap::from([("x-api-key".to_string(), "static".to_string())]);
    assert_refused(configured, Refusal::OwnedHeader, "h", "X-API-KEY");

    let userinfo = http(
        "https://user:pw@svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "Authorization")],
    );
    assert_refused(userinfo, Refusal::OwnedHeader, "h", "Authorization");
}

#[test]
fn two_rules_for_one_header_are_refused() {
    let backend = http(
        "https://svc.example.com/mcp",
        vec![
            rule("first", InjectTarget::Header, "X-Api-Key"),
            rule("second", InjectTarget::Header, "x-api-key"),
        ],
    );
    assert_refused(backend, Refusal::DuplicateHeader, "second", "x-api-key");
}

#[test]
fn an_invalid_header_name_is_refused() {
    let backend = http(
        "https://svc.example.com/mcp",
        vec![rule("h", InjectTarget::Header, "Bad Header")],
    );
    assert_refused(backend, Refusal::InvalidHeaderName, "h", "Bad Header");
}

#[cfg(feature = "a2a")]
#[test]
fn any_rule_on_an_a2a_backend_is_refused() {
    let a2a = |secrets| BackendConfig {
        transport: TransportConfig::A2a {
            a2a_url: "https://agent.example.com".to_string(),
            a2a_agent_card_path: None,
        },
        secrets,
        ..BackendConfig::default()
    };
    assert_refused(
        a2a(vec![rule("h", InjectTarget::Header, "X-Api-Key")]),
        Refusal::A2a,
        "h",
        "X-Api-Key",
    );
    assert_refused(
        a2a(vec![rule("m", InjectTarget::Argument, "message")]),
        Refusal::A2aMessage,
        "m",
        "message",
    );
}
