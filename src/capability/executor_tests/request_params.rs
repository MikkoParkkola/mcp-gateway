// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! URL building, path selection, parameter substitution and personal auth.

use super::*;

#[test]
fn test_build_url() {
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/users/{id}/posts/{post_id}".to_string(),
        ..Default::default()
    };

    let params = serde_json::json!({
        "id": "123",
        "post_id": 456
    });

    let url = executor.build_url(&config, &params).unwrap();
    assert_eq!(url, "https://api.example.com/users/123/posts/456");
}

fn socialdeal_path_selector_config() -> RestConfig {
    serde_yaml::from_str(
        r"
base_url: https://www.socialdeal.nl
path: /sitemap/deals/lmd/{city}/deals.xml
path_selector:
  parameter: category
  default: deals
  paths:
    deals: /sitemap/deals/lmd/{city}/deals.xml
    all: /sitemap/deals/{city}/deals-and-companies.xml
    expired: /sitemap/deals/lmd/{city}/expired-deals.xml
",
    )
    .unwrap()
}

#[test]
fn path_selector_routes_each_declared_value_to_its_path_template() {
    let executor = CapabilityExecutor::new();
    let config = socialdeal_path_selector_config();

    let cases = [
        (
            "deals",
            "https://www.socialdeal.nl/sitemap/deals/lmd/amsterdam/deals.xml",
        ),
        (
            "all",
            "https://www.socialdeal.nl/sitemap/deals/amsterdam/deals-and-companies.xml",
        ),
        (
            "expired",
            "https://www.socialdeal.nl/sitemap/deals/lmd/amsterdam/expired-deals.xml",
        ),
    ];

    for (category, expected) in cases {
        let params = serde_json::json!({"city": "amsterdam", "category": category});
        assert_eq!(executor.build_url(&config, &params).unwrap(), expected);
    }
}

#[test]
fn path_selector_uses_declared_default_when_parameter_is_absent() {
    let executor = CapabilityExecutor::new();
    let config = socialdeal_path_selector_config();
    let params = serde_json::json!({"city": "haarlem"});

    assert_eq!(
        executor.build_url(&config, &params).unwrap(),
        "https://www.socialdeal.nl/sitemap/deals/lmd/haarlem/deals.xml"
    );
}

#[test]
fn path_selector_substitutes_selected_default_into_its_own_placeholder() {
    let executor = CapabilityExecutor::new();
    let config: RestConfig = serde_yaml::from_str(
        r"
base_url: https://api.example.com
path: /feeds/current/{city}
path_selector:
  parameter: category
  default: current
  paths:
    current: /feeds/{category}/{city}
    archive: /feeds/{category}/{city}
",
    )
    .unwrap();

    for params in [
        serde_json::json!({"city": "amsterdam"}),
        serde_json::json!({"city": "amsterdam", "category": null}),
    ] {
        assert_eq!(
            executor.build_url(&config, &params).unwrap(),
            "https://api.example.com/feeds/current/amsterdam"
        );
    }
}

#[test]
fn path_selector_rejects_values_without_a_declared_path() {
    let executor = CapabilityExecutor::new();
    let config = socialdeal_path_selector_config();
    let params = serde_json::json!({"city": "utrecht", "category": "restaurants"});

    let error = executor
        .build_url(&config, &params)
        .unwrap_err()
        .to_string();
    assert!(error.contains("category"), "{error}");
    assert!(error.contains("path selector"), "{error}");
}

#[test]
fn test_substitute_string() {
    let executor = CapabilityExecutor::new();
    let template = "Hello {name}, your score is {score}";
    let params = serde_json::json!({
        "name": "World",
        "score": 100
    });

    let result = executor.substitute_string(template, &params).unwrap();
    assert_eq!(result, "Hello World, your score is 100");
}

#[test]
fn test_extract_path() {
    let executor = CapabilityExecutor::new();
    let value = serde_json::json!({
        "data": {
            "users": [
                {"name": "Alice"},
                {"name": "Bob"}
            ]
        }
    });

    let result = executor.extract_path(&value, "data.users").unwrap();
    assert!(result.is_array());
    assert_eq!(result.as_array().unwrap().len(), 2);

    let result = executor.extract_path(&value, "data.users.0.name").unwrap();
    assert_eq!(result, "Alice");
}

#[test]
fn test_cache() {
    let cache = ResponseCache::new();
    let value = serde_json::json!({"test": true});

    cache.set("key1", &value, None, 60);
    assert_eq!(cache.get("key1"), Some(value));

    assert_eq!(cache.get("nonexistent"), None);
}

#[test]
fn test_fetch_from_file_simple() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tokens.json");
    crate::gateway::test_helpers::write_owner_only(
        &file,
        r#"{"access_token": "test-token-123", "refresh_token": "refresh-456"}"#,
    )
    .unwrap();

    let spec = format!("{}:access_token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "test-token-123");

    let spec = format!("{}:refresh_token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "refresh-456");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_nested() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred-nested");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("config.json");
    crate::gateway::test_helpers::write_owner_only(
        &file,
        r#"{"auth": {"google": {"token": "nested-token"}, "count": 42}}"#,
    )
    .unwrap();

    let spec = format!("{}:auth.google.token", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "nested-token");

    // Numeric values work too
    let spec = format!("{}:auth.count", file.display());
    let result = executor.fetch_from_file(&spec).unwrap();
    assert_eq!(result, "42");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_missing_field() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred-missing");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tokens.json");
    crate::gateway::test_helpers::write_owner_only(&file, r#"{"access_token": "value"}"#).unwrap();

    let spec = format!("{}:nonexistent", file.display());
    let result = executor.fetch_from_file(&spec);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_fetch_from_file_missing_file() {
    let executor = CapabilityExecutor::new();
    let result = executor.fetch_from_file("/nonexistent/path/tokens.json:field");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Cannot read credential file"), "{err}");
}

#[test]
fn test_fetch_from_file_invalid_format() {
    let executor = CapabilityExecutor::new();
    // No colon separator for field
    let result = executor.fetch_from_file("/path/to/file.json");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Invalid file credential format")
    );
}

#[test]
fn test_substitute_params_skips_unresolved_placeholders() {
    let executor = CapabilityExecutor::new();
    let mut template = std::collections::HashMap::new();
    template.insert("resolved".to_string(), "{name}".to_string());
    template.insert("unresolved".to_string(), "{missing_param}".to_string());
    template.insert("static_val".to_string(), "hello".to_string());

    let params = serde_json::json!({"name": "world"});
    let result = executor.substitute_params(&template, &params).unwrap();

    // resolved and static_val should be present, unresolved should be filtered
    let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
    assert!(keys.contains(&"resolved"));
    assert!(keys.contains(&"static_val"));
    assert!(!keys.contains(&"unresolved"));
}

fn personal_auth_capability() -> CapabilityDefinition {
    crate::capability::parse_capability(
        r"
name: personal_calendar
description: Personal calendar read
auth:
  required: true
  type: bearer
  key: env:MIK6553_SHOULD_NOT_BE_READ
metadata:
  exposure: personal
  identity_owner:
    authority: cloudflare_access
    subject: owner-1
    label: owner@example.com
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /calendar
      method: GET
",
    )
    .unwrap()
}

#[tokio::test]
async fn personal_capability_missing_identity_denies_before_auth_lookup() {
    let executor = CapabilityExecutor::new();
    let cap = personal_auth_capability();

    let err = executor
        .execute_with_context(
            &cap,
            serde_json::json!({}),
            CapabilityExecutionContext::default(),
        )
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("caller identity is required"), "{err}");
    assert!(!err.contains("MIK6553_SHOULD_NOT_BE_READ"), "{err}");
}

#[tokio::test]
async fn personal_capability_owner_mismatch_denies_before_auth_lookup() {
    let executor = CapabilityExecutor::new();
    let cap = personal_auth_capability();
    let context = CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
        "cloudflare_access",
        "other-user",
        Some("other@example.com".to_string()),
    ));

    let err = executor
        .execute_with_context(&cap, serde_json::json!({}), context)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("does not match owner"), "{err}");
    assert!(!err.contains("MIK6553_SHOULD_NOT_BE_READ"), "{err}");
}

#[tokio::test]
async fn personal_capability_matching_owner_reaches_auth_lookup() {
    let executor = CapabilityExecutor::new();
    let cap = personal_auth_capability();
    let context = CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
        "cloudflare_access",
        "owner-1",
        Some("owner@example.com".to_string()),
    ));

    let err = executor
        .execute_with_context(&cap, serde_json::json!({}), context)
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("MIK6553_SHOULD_NOT_BE_READ"), "{err}");
    assert!(!err.contains("access denied"), "{err}");
}

#[tokio::test]
async fn shared_required_auth_preserves_legacy_auth_lookup() {
    let executor = CapabilityExecutor::new();
    let cap = crate::capability::parse_capability(
        r"
name: shared_weather
description: Shared weather lookup
auth:
  required: true
  type: bearer
  key: env:MIK6553_SHARED_AUTH_LOOKUP
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /weather
      method: GET
",
    )
    .unwrap();

    let err = executor
        .execute_with_context(
            &cap,
            serde_json::json!({}),
            CapabilityExecutionContext::default(),
        )
        .await
        .unwrap_err()
        .to_string();

    assert!(err.contains("MIK6553_SHARED_AUTH_LOOKUP"), "{err}");
    assert!(!err.contains("access denied"), "{err}");
}
