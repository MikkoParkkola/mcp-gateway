//! Tests for secret injection — extracted from `src/secret_injection.rs`.

#![allow(unsafe_code)] // Tests use set_var/remove_var which are unsafe in edition 2024

use std::collections::HashMap;

use mcp_gateway::secret_injection::{
    glob_match, tool_matches_rule, CredentialRule, CredentialType, InjectTarget, SecretInjector,
};
use serde_json::json;

// ── glob matching ────────────────────────────────────────────────────

#[test]
fn glob_match_exact() {
    assert!(glob_match("get_weather", "get_weather"));
    assert!(!glob_match("get_weather", "get_forecast"));
}

#[test]
fn glob_match_star() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*", ""));
}

#[test]
fn glob_match_prefix_wildcard() {
    assert!(glob_match("get_*", "get_weather"));
    assert!(glob_match("get_*", "get_forecast"));
    assert!(!glob_match("get_*", "set_weather"));
}

#[test]
fn glob_match_suffix_wildcard() {
    assert!(glob_match("*_weather", "get_weather"));
    assert!(glob_match("*_weather", "set_weather"));
    assert!(!glob_match("*_weather", "get_forecast"));
}

#[test]
fn glob_match_contains_wildcard() {
    assert!(glob_match("get_*_v2", "get_weather_v2"));
    assert!(!glob_match("get_*_v2", "get_weather_v3"));
}

// ── tool_matches_rule ─────────────────────────────────────────────────

#[test]
fn matches_rule_empty_patterns_matches_all() {
    assert!(tool_matches_rule("any_tool", &[]));
}

#[test]
fn matches_rule_wildcard_matches_all() {
    assert!(tool_matches_rule("any_tool", &["*".to_string()]));
}

#[test]
fn matches_rule_specific_pattern() {
    assert!(tool_matches_rule(
        "weather_forecast",
        &["weather_*".to_string()]
    ));
    assert!(!tool_matches_rule(
        "search_web",
        &["weather_*".to_string()]
    ));
}

// ── inject ────────────────────────────────────────────────────────────

#[test]
fn inject_no_rules_returns_unchanged() {
    let injector = SecretInjector::empty();
    let args = json!({"city": "Helsinki"});
    let result = injector.inject("weather", "get_forecast", args.clone()).unwrap();
    assert_eq!(result.arguments, args);
    assert_eq!(result.injected_count, 0);
    assert!(result.headers.is_empty());
}

#[test]
fn inject_argument_type() {
    // Set a test env var
    unsafe { std::env::set_var("TEST_SECRET_KEY_88", "sk-test-12345") };

    let rules = HashMap::from([(
        "weather".to_string(),
        vec![CredentialRule {
            name: "api_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "{env.TEST_SECRET_KEY_88}".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let args = json!({"city": "Helsinki"});
    let result = injector.inject("weather", "get_forecast", args).unwrap();

    assert_eq!(result.arguments["city"], "Helsinki");
    assert_eq!(result.arguments["api_key"], "sk-test-12345");
    assert_eq!(result.injected_count, 1);
    assert_eq!(result.injected_names, vec!["api_key"]);

    unsafe { std::env::remove_var("TEST_SECRET_KEY_88") };
}

#[test]
fn inject_header_type() {
    unsafe { std::env::set_var("TEST_BEARER_TOKEN_88", "bearer-abc-123") };

    let rules = HashMap::from([(
        "linear".to_string(),
        vec![CredentialRule {
            name: "linear_token".to_string(),
            credential_type: CredentialType::Bearer,
            value: "Bearer {env.TEST_BEARER_TOKEN_88}".to_string(),
            inject_as: InjectTarget::Header,
            inject_key: "Authorization".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let args = json!({"title": "Bug report"});
    let result = injector.inject("linear", "create_issue", args).unwrap();

    // Arguments unchanged (injection goes to headers)
    assert_eq!(result.arguments["title"], "Bug report");
    assert!(!result.arguments.as_object().unwrap().contains_key("Authorization"));

    // Header injected
    assert_eq!(
        result.headers.get("Authorization").unwrap(),
        "Bearer bearer-abc-123"
    );
    assert_eq!(result.injected_count, 1);

    unsafe { std::env::remove_var("TEST_BEARER_TOKEN_88") };
}

#[test]
fn inject_tool_pattern_filtering() {
    unsafe { std::env::set_var("TEST_WRITE_KEY_88", "write-secret") };

    let rules = HashMap::from([(
        "api".to_string(),
        vec![CredentialRule {
            name: "write_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "{env.TEST_WRITE_KEY_88}".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "auth_token".to_string(),
            tools: vec!["create_*".to_string(), "update_*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);

    // Matching tool: should inject
    let result = injector
        .inject("api", "create_item", json!({}))
        .unwrap();
    assert_eq!(result.injected_count, 1);
    assert_eq!(result.arguments["auth_token"], "write-secret");

    // Non-matching tool: should NOT inject
    let result = injector
        .inject("api", "list_items", json!({}))
        .unwrap();
    assert_eq!(result.injected_count, 0);
    assert!(result.arguments.as_object().unwrap().is_empty());

    unsafe { std::env::remove_var("TEST_WRITE_KEY_88") };
}

#[test]
fn inject_multiple_rules() {
    unsafe { std::env::set_var("TEST_KEY_A_88", "key-a") };
    unsafe { std::env::set_var("TEST_KEY_B_88", "key-b") };

    let rules = HashMap::from([(
        "multi".to_string(),
        vec![
            CredentialRule {
                name: "key_a".to_string(),
                credential_type: CredentialType::ApiKey,
                value: "{env.TEST_KEY_A_88}".to_string(),
                inject_as: InjectTarget::Argument,
                inject_key: "key_a".to_string(),
                tools: vec!["*".to_string()],
            },
            CredentialRule {
                name: "key_b".to_string(),
                credential_type: CredentialType::Bearer,
                value: "Bearer {env.TEST_KEY_B_88}".to_string(),
                inject_as: InjectTarget::Header,
                inject_key: "Authorization".to_string(),
                tools: vec!["*".to_string()],
            },
        ],
    )]);

    let injector = SecretInjector::new(rules);
    let result = injector
        .inject("multi", "some_tool", json!({"data": 42}))
        .unwrap();

    assert_eq!(result.injected_count, 2);
    assert_eq!(result.arguments["key_a"], "key-a");
    assert_eq!(result.arguments["data"], 42);
    assert_eq!(
        result.headers.get("Authorization").unwrap(),
        "Bearer key-b"
    );

    unsafe { std::env::remove_var("TEST_KEY_A_88") };
    unsafe { std::env::remove_var("TEST_KEY_B_88") };
}

#[test]
fn inject_overwrite_protection() {
    // Agent tries to set their own api_key — injector should overwrite it
    unsafe { std::env::set_var("TEST_REAL_KEY_88", "real-secret") };

    let rules = HashMap::from([(
        "backend".to_string(),
        vec![CredentialRule {
            name: "api_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "{env.TEST_REAL_KEY_88}".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    // Agent supplies a fake api_key
    let args = json!({"api_key": "agent-supplied-fake", "query": "test"});
    let result = injector.inject("backend", "search", args).unwrap();

    // Gateway-injected value must win
    assert_eq!(result.arguments["api_key"], "real-secret");
    assert_eq!(result.arguments["query"], "test");

    unsafe { std::env::remove_var("TEST_REAL_KEY_88") };
}

#[test]
fn inject_empty_resolved_value_skipped() {
    // Missing env var resolves to empty string — should be skipped
    let rules = HashMap::from([(
        "backend".to_string(),
        vec![CredentialRule {
            name: "missing_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "{env.NONEXISTENT_VAR_SECRET_INJ_88}".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let args = json!({"query": "test"});
    let result = injector.inject("backend", "search", args).unwrap();

    assert_eq!(result.injected_count, 0);
    assert!(!result.arguments.as_object().unwrap().contains_key("api_key"));
}

#[test]
fn inject_wrong_backend_returns_unchanged() {
    let rules = HashMap::from([(
        "weather".to_string(),
        vec![CredentialRule {
            name: "key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "secret".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let args = json!({"query": "test"});
    let result = injector.inject("other_backend", "search", args.clone()).unwrap();

    assert_eq!(result.arguments, args);
    assert_eq!(result.injected_count, 0);
}

// ── from_backend_configs ──────────────────────────────────────────────

#[test]
fn from_backend_configs_empty() {
    let backends: HashMap<String, mcp_gateway::config::BackendConfig> = HashMap::new();
    let injector = SecretInjector::from_backend_configs(&backends);
    assert!(!injector.has_rules());
}

#[test]
fn from_backend_configs_with_rules() {
    let backend = mcp_gateway::config::BackendConfig {
        secrets: vec![CredentialRule {
            name: "test_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "test-value".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "api_key".to_string(),
            tools: vec!["*".to_string()],
        }],
        ..Default::default()
    };

    let backends = HashMap::from([("test_backend".to_string(), backend)]);
    let injector = SecretInjector::from_backend_configs(&backends);

    assert!(injector.has_rules());
    assert_eq!(injector.rule_count("test_backend"), 1);
    assert_eq!(injector.rule_count("nonexistent"), 0);
}

// ── redacted_rules ────────────────────────────────────────────────────

#[test]
fn redacted_rules_does_not_contain_value() {
    let rules = HashMap::from([(
        "backend".to_string(),
        vec![CredentialRule {
            name: "secret".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "super-secret-value".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "key".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let redacted = injector.redacted_rules("backend");

    assert_eq!(redacted.len(), 1);
    assert_eq!(redacted[0].name, "secret");
    // The redacted struct should NOT have a `value` field
    let json = serde_json::to_string(&redacted[0]).unwrap();
    assert!(!json.contains("super-secret-value"));
}

// ── update_rules ──────────────────────────────────────────────────────

#[test]
fn update_rules_adds_and_removes() {
    let mut injector = SecretInjector::empty();
    assert!(!injector.has_rules());

    injector.update_rules(
        "new_backend",
        vec![CredentialRule {
            name: "key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "val".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "k".to_string(),
            tools: vec![],
        }],
    );
    assert!(injector.has_rules());
    assert_eq!(injector.rule_count("new_backend"), 1);

    // Remove by passing empty rules
    injector.update_rules("new_backend", vec![]);
    assert!(!injector.has_rules());
}

// ── configured_backends ───────────────────────────────────────────────

#[test]
fn configured_backends_lists_names() {
    let rules = HashMap::from([
        ("alpha".to_string(), vec![]),
        ("beta".to_string(), vec![]),
    ]);
    let injector = SecretInjector::new(rules);
    let mut backends = injector.configured_backends();
    backends.sort_unstable();
    assert_eq!(backends, vec!["alpha", "beta"]);
}

// ── serialization roundtrip ──────────────────────────────────────────

#[test]
fn credential_rule_yaml_roundtrip() {
    let yaml = r#"
name: weather_key
credential_type: api_key
value: "{env.WEATHER_KEY}"
inject_as: argument
inject_key: api_key
tools: ["get_*", "search_*"]
"#;

    let rule: CredentialRule = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(rule.name, "weather_key");
    assert_eq!(rule.credential_type, CredentialType::ApiKey);
    assert_eq!(rule.inject_as, InjectTarget::Argument);
    assert_eq!(rule.tools, vec!["get_*", "search_*"]);

    // Roundtrip
    let serialized = serde_yaml::to_string(&rule).unwrap();
    let deserialized: CredentialRule = serde_yaml::from_str(&serialized).unwrap();
    assert_eq!(deserialized.name, "weather_key");
}

#[test]
fn credential_rule_default_values() {
    let yaml = r#"
name: simple
value: "literal-secret"
inject_key: token
"#;

    let rule: CredentialRule = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(rule.credential_type, CredentialType::ApiKey); // default
    assert_eq!(rule.inject_as, InjectTarget::Argument); // default
    assert_eq!(rule.tools, vec!["*"]); // default
}

// ── query injection ───────────────────────────────────────────────────

#[test]
fn inject_query_type() {
    let rules = HashMap::from([(
        "api".to_string(),
        vec![CredentialRule {
            name: "api_key".to_string(),
            credential_type: CredentialType::ApiKey,
            value: "query-key-123".to_string(),
            inject_as: InjectTarget::Query,
            inject_key: "apikey".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let result = injector.inject("api", "search", json!({})).unwrap();

    // Query params injected as __query_ prefixed argument
    assert_eq!(result.arguments["__query_apikey"], "query-key-123");
    assert_eq!(result.injected_count, 1);
}

// ── literal value (no env/keychain) ───────────────────────────────────

#[test]
fn inject_literal_value() {
    let rules = HashMap::from([(
        "backend".to_string(),
        vec![CredentialRule {
            name: "static_key".to_string(),
            credential_type: CredentialType::Custom,
            value: "literal-api-key-abc123".to_string(),
            inject_as: InjectTarget::Argument,
            inject_key: "token".to_string(),
            tools: vec!["*".to_string()],
        }],
    )]);

    let injector = SecretInjector::new(rules);
    let result = injector.inject("backend", "test", json!({})).unwrap();
    assert_eq!(result.arguments["token"], "literal-api-key-abc123");
}
