// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for `CapabilityExecutor` and `ResponseCache`

use super::*;
use crate::capability::CapabilityExecutionContext;
use crate::capability::response_cache::ResponseCache;
use crate::identity_grants::GrantSubject;
use axum::{
    Json, Router,
    body::Body,
    http::header,
    response::Response as AxumResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

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

    cache.set("key1", &value, 60);
    assert_eq!(cache.get("key1"), Some(value));

    assert_eq!(cache.get("nonexistent"), None);
}

#[test]
fn test_fetch_from_file_simple() {
    let executor = CapabilityExecutor::new();
    let dir = std::env::temp_dir().join("mcp-gateway-test-cred");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tokens.json");
    std::fs::write(
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
    std::fs::write(
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
    std::fs::write(&file, r#"{"access_token": "value"}"#).unwrap();

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
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Failed to read"));
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

// ── static_params integration tests ──────────────────────────────────────────

#[test]
fn static_params_flow_into_url_substitution() {
    // GIVEN: RestConfig with static_params containing a path placeholder value
    // WHEN: build_url is called with empty caller params
    // THEN: static_params are substituted into the URL path
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/v1/forecast/{format}".to_string(),
        static_params: [("format".to_string(), serde_json::json!("json"))]
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let caller_params = serde_json::json!({});
    let effective = config.merge_with_static_params(&caller_params);
    let url = executor.build_url(&config, &effective).unwrap();
    assert_eq!(url, "https://api.example.com/v1/forecast/json");
}

#[test]
fn static_params_flow_into_query_params() {
    // GIVEN: RestConfig with static_params and a query params template referencing them
    // WHEN: substitute_params is called with merged effective params
    // THEN: static values appear in the resolved query parameters
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/forecast".to_string(),
        params: [
            ("current".to_string(), "{current}".to_string()),
            ("timezone".to_string(), "{timezone}".to_string()),
        ]
        .into_iter()
        .collect(),
        static_params: [
            (
                "current".to_string(),
                serde_json::json!("temperature_2m,weather_code"),
            ),
            ("timezone".to_string(), serde_json::json!("auto")),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let caller_params = serde_json::json!({});
    let effective = config.merge_with_static_params(&caller_params);
    let resolved = executor
        .substitute_params(&config.params, &effective)
        .unwrap();

    let map: std::collections::HashMap<_, _> = resolved.into_iter().collect();
    assert_eq!(map["current"], "temperature_2m,weather_code");
    assert_eq!(map["timezone"], "auto");
}

#[test]
fn caller_params_override_static_params_on_collision() {
    // GIVEN: static_params defines "timezone" = "auto"
    // WHEN: caller supplies "timezone" = "America/New_York"
    // THEN: caller value wins
    let config = RestConfig {
        static_params: [("timezone".to_string(), serde_json::json!("auto"))]
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let caller_params = serde_json::json!({ "timezone": "America/New_York" });
    let effective = config.merge_with_static_params(&caller_params);
    assert_eq!(effective["timezone"], "America/New_York");
}

#[test]
fn static_params_preserved_when_caller_provides_no_collision() {
    // GIVEN: static_params has "format" key, caller provides "lat" key
    // WHEN: merging
    // THEN: both keys are present in the effective params
    let config = RestConfig {
        static_params: [("format".to_string(), serde_json::json!("json"))]
            .into_iter()
            .collect(),
        ..Default::default()
    };

    let caller_params = serde_json::json!({ "lat": 60.17 });
    let effective = config.merge_with_static_params(&caller_params);
    assert_eq!(effective["format"], "json");
    assert!((effective["lat"].as_f64().unwrap() - 60.17).abs() < f64::EPSILON);
}

#[test]
fn empty_static_params_returns_borrowed_caller_params() {
    // GIVEN: RestConfig with no static_params
    // WHEN: merging with caller params
    // THEN: returned Cow is Borrowed (zero allocation)
    let config = RestConfig::default();
    let caller_params = serde_json::json!({ "q": "rust" });
    let effective = config.merge_with_static_params(&caller_params);
    assert!(matches!(effective, std::borrow::Cow::Borrowed(_)));
    assert_eq!(effective["q"], "rust");
}

#[test]
fn static_params_support_numeric_and_boolean_values() {
    // GIVEN: static_params with integer, float, and boolean values
    // WHEN: merging with empty caller params
    // THEN: all typed values are preserved
    let config = RestConfig {
        static_params: [
            ("count".to_string(), serde_json::json!(10)),
            ("ratio".to_string(), serde_json::json!(0.5)),
            ("enabled".to_string(), serde_json::json!(true)),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let empty = serde_json::json!({});
    let effective = config.merge_with_static_params(&empty);
    assert_eq!(effective["count"], serde_json::json!(10));
    assert!((effective["ratio"].as_f64().unwrap() - 0.5).abs() < f64::EPSILON);
    assert_eq!(effective["enabled"], serde_json::json!(true));
}

#[test]
fn static_params_deserialization_from_yaml() {
    // GIVEN: YAML config with static_params containing mixed types
    // WHEN: deserializing RestConfig
    // THEN: all static_params are correctly parsed
    let yaml = r"
base_url: https://api.open-meteo.com
path: /v1/forecast
static_params:
  current: 'temperature_2m,weather_code'
  timezone: auto
  forecast_days: 7
";
    let config: RestConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
        config.static_params["current"],
        "temperature_2m,weather_code"
    );
    assert_eq!(config.static_params["timezone"], "auto");
    assert_eq!(config.static_params["forecast_days"], serde_json::json!(7));
}

#[test]
fn static_params_serialization_round_trips() {
    // GIVEN: RestConfig with static_params
    // WHEN: serialized to JSON and back
    // THEN: static_params are preserved exactly
    let mut static_params = std::collections::HashMap::new();
    static_params.insert("key".to_string(), serde_json::json!("value"));
    static_params.insert("num".to_string(), serde_json::json!(42));

    let config = RestConfig {
        base_url: "https://example.com".to_string(),
        static_params,
        ..Default::default()
    };

    let json = serde_json::to_string(&config).unwrap();
    let restored: RestConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.static_params["key"], "value");
    assert_eq!(restored.static_params["num"], serde_json::json!(42));
}

#[test]
fn static_params_with_array_value_preserved() {
    // GIVEN: static_params containing a JSON array value
    // WHEN: merging
    // THEN: array is preserved in the effective params
    let config = RestConfig {
        static_params: [(
            "fields".to_string(),
            serde_json::json!(["id", "name", "email"]),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let empty = serde_json::json!({});
    let effective = config.merge_with_static_params(&empty);
    assert_eq!(
        effective["fields"],
        serde_json::json!(["id", "name", "email"])
    );
}

#[test]
fn build_url_with_static_params_substitution_in_endpoint() {
    // GIVEN: endpoint-style URL with static params embedded as placeholders
    // WHEN: merged with empty caller params and URL built
    // THEN: static values are substituted into the endpoint URL
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        endpoint: "https://api.example.com/v1/data?format={fmt}&version={ver}".to_string(),
        static_params: [
            ("fmt".to_string(), serde_json::json!("json")),
            ("ver".to_string(), serde_json::json!("2")),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    let caller_params = serde_json::json!({});
    let effective = config.merge_with_static_params(&caller_params);
    let url = executor.build_url(&config, &effective).unwrap();
    assert!(
        url.contains("format=json"),
        "URL should contain format=json"
    );
    assert!(url.contains("version=2"), "URL should contain version=2");
}

// ── body_content_type tests ──────────────────────────────────────────────────

#[test]
fn body_content_type_text_plain_uses_raw_string_body() {
    // Verify that when body_content_type = "text/plain" and the body template
    // is a JSON string, attach_request_body builds a raw-string request (not
    // JSON-encoded).  We can't easily inspect the built request in a unit test
    // without a live HTTP server, so we at least verify that the RestConfig
    // deserialises correctly from YAML and that substitute_string works.
    let executor = CapabilityExecutor::new();
    let config = RestConfig {
        body: Some(serde_json::Value::String(
            "SELECT * FROM bus_msg WHERE topic = '{topic}' LIMIT {max_msg}".to_string(),
        )),
        body_content_type: "text/plain".to_string(),
        ..Default::default()
    };

    let params = serde_json::json!({"topic": "bus.demo.test", "max_msg": 50});

    // substitute_string is the path taken for plain-text bodies.
    let sql = executor
        .substitute_string(config.body.as_ref().unwrap().as_str().unwrap(), &params)
        .unwrap();

    assert!(
        sql.contains("bus.demo.test"),
        "SQL should contain topic: {sql}"
    );
    assert!(sql.contains("50"), "SQL should contain max_msg: {sql}");
    assert!(
        !sql.contains('{'),
        "All placeholders should be resolved: {sql}"
    );
}

#[tokio::test]
async fn handle_response_binary_returns_base64_payload() {
    async fn binary_handler() -> AxumResponse {
        AxumResponse::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "video/mp4")
            .body(Body::from(vec![0_u8, 1, 2, 3, 4, 5]))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/video", get(binary_handler)))
            .await
            .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .get(format!("http://{addr}/video"))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_format: "binary".to_string(),
        ..Default::default()
    };

    let body = executor.handle_response(response, &config).await.unwrap();
    assert_eq!(body["mime_type"], "video/mp4");
    assert_eq!(body["size"], 6);
    assert_eq!(body["data"], STANDARD.encode([0_u8, 1, 2, 3, 4, 5]));
}

#[tokio::test]
async fn handle_response_graphql_error_with_null_projection_returns_error() {
    async fn graphql_error_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "data": null,
            "errors": [
                { "message": "Field \"createAsUser\" is not defined by type \"IssueCreateInput\"." },
                { "message": "Field \"displayIconUrl\" is not defined by type \"IssueCreateInput\"." }
            ]
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", post(graphql_error_handler)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .post(format!("http://{addr}/graphql"))
        .json(&serde_json::json!({ "query": "mutation Broken { issueCreate { success } }" }))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_path: Some("data.issueCreate".to_string()),
        ..Default::default()
    };

    let err = executor
        .handle_response(response, &config)
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("GraphQL error"), "{message}");
    assert!(message.contains("createAsUser"), "{message}");
    assert!(message.contains("displayIconUrl"), "{message}");
}

#[tokio::test]
async fn handle_response_graphql_success_with_response_path_is_unchanged() {
    async fn graphql_success_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "data": {
                "issueCreate": {
                    "success": true,
                    "issue": {
                        "id": "lin-123",
                        "identifier": "MIK-3181"
                    }
                }
            }
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route("/graphql", post(graphql_success_handler)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let response = executor
        .client
        .post(format!("http://{addr}/graphql"))
        .json(&serde_json::json!({ "query": "mutation Ok { issueCreate { success } }" }))
        .send()
        .await
        .unwrap();
    let config = RestConfig {
        response_path: Some("data.issueCreate".to_string()),
        ..Default::default()
    };

    let body = executor.handle_response(response, &config).await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["issue"]["identifier"], "MIK-3181");
}

#[test]
fn body_content_type_empty_defaults_to_json() {
    // Default behaviour: body_content_type is empty → use JSON body.
    // RestConfig::default() should produce empty body_content_type.
    let config = RestConfig::default();
    assert!(
        config.body_content_type.is_empty(),
        "Default body_content_type must be empty (→ JSON)"
    );
}

#[test]
fn body_content_type_deserialises_from_yaml() {
    let yaml = r#"
base_url: "http://127.0.0.1:8000"
path: "/sql"
method: "POST"
body_content_type: "text/plain"
body: "SELECT * FROM bus_msg LIMIT 10"
"#;
    let config: RestConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.body_content_type, "text/plain");
    assert_eq!(
        config.body.unwrap().as_str().unwrap(),
        "SELECT * FROM bus_msg LIMIT 10"
    );
}

#[tokio::test]
async fn send_with_retry_recovers_from_transient_timeouts() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Local server: the first two connections hang past the client's per-attempt
    // timeout (a transient timeout -> retry); the third responds 200 at once.
    // Verifies MIK-5081: transient outbound failures are retried with backoff
    // instead of surfacing as an immediate BACKEND_ERROR.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_srv = Arc::clone(&counter);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let n = counter_srv.fetch_add(1, Ordering::SeqCst);
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                if n < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                } else {
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
                    let _ = stream.flush();
                }
            });
        }
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let req = client
        .get(&url)
        .timeout(std::time::Duration::from_millis(120));

    // Idempotent (retry_timeouts = true): timeouts are retried.
    let health = crate::failsafe::HealthTracker::new("test");
    let resp = send_with_retry(req, "test", true, &health).await;
    assert!(
        resp.is_ok(),
        "retry should recover from transient timeouts, got {resp:?}"
    );
    assert_eq!(resp.unwrap().status(), 200);
    assert!(
        health.is_healthy(),
        "a recovered call records transport success"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        3,
        "should have taken exactly 3 attempts (2 transient + 1 success)"
    );
}

#[tokio::test]
async fn send_with_retry_records_transport_failures() {
    // A refused port (listener bound then dropped) yields connection errors,
    // which are always retried and recorded as transport failures. After
    // enough consecutive failures the health tracker flips unhealthy (MIK-5080).
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().unwrap()
        // listener dropped here -> port now refuses connections
    };

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let health = crate::failsafe::HealthTracker::new("test");

    assert!(health.is_healthy(), "fresh tracker is healthy");
    for _ in 0..3 {
        let req = client
            .get(&url)
            .timeout(std::time::Duration::from_millis(200));
        let resp = send_with_retry(req, "test", false, &health).await;
        assert!(resp.is_err(), "connect to a refused port must fail");
    }
    assert!(
        !health.is_healthy(),
        "consecutive transport failures should flip the tracker unhealthy"
    );
}

#[tokio::test]
async fn send_with_retry_does_not_retry_timeouts_when_not_idempotent() {
    // A server that always hangs past the client timeout. With retry_timeouts
    // = false (non-idempotent), the timeout is NOT retried: exactly one
    // connection attempt is made. Protects against duplicate side effects.
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_srv = Arc::clone(&counter);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            counter_srv.fetch_add(1, Ordering::SeqCst);
            // Hold the connection open and never respond.
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(500));
                drop(stream);
            });
        }
    });

    let client = reqwest::Client::new();
    let url = format!("http://{addr}/");
    let health = crate::failsafe::HealthTracker::new("test");
    let req = client
        .post(&url)
        .timeout(std::time::Duration::from_millis(120));

    let resp = send_with_retry(req, "test", false, &health).await;
    assert!(resp.is_err(), "the hung request should time out");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "a non-idempotent timeout must NOT be retried (single attempt)"
    );
}

/// A backend URL carrying a query-string credential must not survive into the
/// text of an outbound transport error.
///
/// Both assertions matter: the first pins what `reqwest` does on its own, so a
/// future release that starts redacting turns this test red rather than leaving
/// it passing vacuously; the second pins what `redact_url` adds.
#[tokio::test]
async fn redact_url_strips_a_credential_bearing_backend_url() {
    let url = "http://127.0.0.1:1/spec?api_key=SECRET-QUERY-VALUE";
    let raw = reqwest::Client::new().get(url).send().await.unwrap_err();

    assert!(
        raw.to_string().contains("SECRET-QUERY-VALUE"),
        "reqwest no longer embeds the URL; redact_url may be obsolete: {raw}"
    );
    let redacted = super::redact_url(raw);
    assert!(
        !redacted.to_string().contains("SECRET-QUERY-VALUE"),
        "credential survived redaction: {redacted}"
    );
}

/// GH475.RL.10 — the linkage between a capability backend's *real* HTTP 429
/// and the shared predicate that must exclude it from failure accounting.
///
/// PINNED OBSERVABLE: the circuit state after one dispatch failure. A real
/// throttled response leaves the circuit closed; a real server error opens it.
/// The two responses differ **only in the status line** — same body, same
/// route shape — so the thing being pinned is that the status reaches the
/// accounting at all, not that some word in the payload happened to.
///
/// WHICH ACCOUNTING, precisely: capability dispatch never reaches `Failsafe`.
/// Its `Err` goes to `BudgetOutcome::of` (`gateway/meta_mcp/invoke.rs:1384`),
/// whose recorder is private to that module. `Failsafe::record_dispatch_failure`
/// is the only *public* consumer of the same `is_rate_limited` predicate
/// (`gateway/recovery.rs:286`), so it is what this test drives. What is pinned
/// is the classification of a real capability error string by that predicate —
/// not the capability path's own budget accounting.
///
/// The error text is produced by the production formatter in
/// `executor/params.rs` (`handle_response`), not composed here: a test that
/// writes its own `"429 Too Many Requests"` string pins a copy of the format
/// and stays green when the format changes.
///
/// FALSIFIER: a mutation probe, not a pre-fix ref — the exclusion and this
/// test arrived together, so §P2's retrofit probe does not apply. Dropping the
/// status from the `"API returned {}: {}"` literal makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
///
/// PINNED SEPARATELY: the same format site in `executor/jsonrpc.rs` and
/// `executor/graphql.rs` — each formats its own status text, and each is driven
/// by its own sibling test below. STILL NOT PINNED here or there: the
/// meta-MCP error-budget effect — `record_error_budget` is private to
/// `gateway::meta_mcp::invoke`, where `error_budget_tests` pins it against the
/// same `is_rate_limited` predicate this path uses.
#[tokio::test]
async fn a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use crate::failsafe::Failsafe;
    use std::time::Duration;

    // Same body on both routes: the status line is the only discriminator.
    async fn throttled() -> AxumResponse {
        AxumResponse::builder()
            .status(429)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }
    async fn broken() -> AxumResponse {
        AxumResponse::builder()
            .status(500)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/throttled", get(throttled))
                .route("/broken", get(broken)),
        )
        .await
        .unwrap();
    });

    let executor = CapabilityExecutor::new();
    let config = RestConfig::default();
    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .get(format!("http://{addr}{route}"))
            .send()
            .await
            .unwrap();
        errors.push(
            executor
                .handle_response(response, &config)
                .await
                .unwrap_err()
                .to_string(),
        );
    }

    let failsafe_config = FailsafeConfig {
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let latency = Duration::from_millis(1);

    let throttled_backend = Failsafe::new("throttled-capability", &failsafe_config);
    throttled_backend.record_dispatch_failure(&errors[0], latency);
    assert!(
        throttled_backend.circuit_breaker.can_proceed(),
        "a real 429 must not trip the breaker; error text was: {}",
        errors[0]
    );

    let broken_backend = Failsafe::new("broken-capability", &failsafe_config);
    broken_backend.record_dispatch_failure(&errors[1], latency);
    assert!(
        !broken_backend.circuit_breaker.can_proceed(),
        "the control must still trip: same body, only the status differs; error text was: {}",
        errors[1]
    );
}

/// A loopback backend answering 429 on `/throttled` and 500 on `/broken`, with
/// an executor whose HTTP client can actually reach it.
///
/// The sibling REST test above reaches its server with the production client
/// because `handle_response` is called directly, past every guard. The protocol
/// executors are entered at `execute()`, which runs the guards first: an IP
/// literal is rejected outright (`security/ssrf/mod.rs:164`) and a domain name,
/// which does pass (`security/ssrf/mod.rs:185`), is then stopped at DNS by the
/// production client's `PinningResolver` (`executor/mod.rs:175`). A plain
/// client plus a domain host clears both.
///
/// LIMIT: swapping the client means the production client's own SSRF and
/// redirect posture is not exercised here. What the two tests below pin is
/// their format site and the classification of what it produces — nothing more.
async fn loopback_status_backend() -> (CapabilityExecutor, String) {
    // Same body on both routes: the status line is the only discriminator.
    async fn throttled() -> AxumResponse {
        AxumResponse::builder()
            .status(429)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }
    async fn broken() -> AxumResponse {
        AxumResponse::builder()
            .status(500)
            .body(Body::from(r#"{"detail":"slow down"}"#))
            .unwrap()
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/throttled", post(throttled))
                .route("/broken", post(broken)),
        )
        .await
        .unwrap();
    });

    let mut executor = CapabilityExecutor::new();
    executor.client = reqwest::Client::new();
    (executor, format!("http://localhost:{port}"))
}

/// A capability the protocol executors will dispatch without prerequisites:
/// not `personal`, so the identity check passes, and no auth to inject.
fn unauthenticated_capability() -> CapabilityDefinition {
    crate::capability::parse_capability(
        r"
name: throttled_backend
description: Backend used to observe a real 429
providers:
  primary:
    service: rest
    config:
      base_url: https://backend.invalid
      path: /
      method: POST
",
    )
    .unwrap()
}

/// Drive the same predicate the sibling REST test drives: `errors[0]` came from
/// the 429 route and must not trip the breaker, `errors[1]` from the 500 route
/// and must.
fn assert_only_the_500_trips_the_breaker(errors: &[String]) {
    use crate::config::{CircuitBreakerConfig, FailsafeConfig};
    use crate::failsafe::Failsafe;
    use std::time::Duration;

    let failsafe_config = FailsafeConfig {
        circuit_breaker: CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let latency = Duration::from_millis(1);

    let throttled_backend = Failsafe::new("throttled-capability", &failsafe_config);
    throttled_backend.record_dispatch_failure(&errors[0], latency);
    assert!(
        throttled_backend.circuit_breaker.can_proceed(),
        "a real 429 must not trip the breaker; error text was: {}",
        errors[0]
    );

    let broken_backend = Failsafe::new("broken-capability", &failsafe_config);
    broken_backend.record_dispatch_failure(&errors[1], latency);
    assert!(
        !broken_backend.circuit_breaker.can_proceed(),
        "the control must still trip: same body, only the status differs; error text was: {}",
        errors[1]
    );
}

/// The JSON-RPC half of the site pinned by
/// `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`,
/// which that test names as NOT PINNED.
///
/// The error text is produced by the production formatter at
/// `executor/jsonrpc.rs` (`"JSON-RPC endpoint returned {}: {}"`), not composed
/// here — a test writing its own status string pins a copy of the format and
/// stays green when the format changes.
///
/// FALSIFIER: a mutation probe. Dropping the status from that literal
/// (`"JSON-RPC endpoint returned: {}", error_text`) makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
#[tokio::test]
async fn a_real_jsonrpc_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, JsonRpcConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let config = ProtocolConfig::Jsonrpc(JsonRpcConfig {
            endpoint: format!("{base}{route}"),
            method: "eth_blockNumber".to_string(),
            ..Default::default()
        });
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        errors.push(
            jsonrpc::JsonRpcExecutor {
                executor: &executor,
            }
            .execute(&config, serde_json::json!({}), &ctx)
            .await
            .unwrap_err()
            .to_string(),
        );
    }

    assert_only_the_500_trips_the_breaker(&errors);
}

/// The GraphQL half of the site pinned by
/// `a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`,
/// which that test names as NOT PINNED.
///
/// The error text is produced by the production formatter at
/// `executor/graphql.rs` (`"GraphQL endpoint returned {}: {}"`), not composed
/// here, for the same reason.
///
/// FALSIFIER: a mutation probe. Dropping the status from that literal
/// (`"GraphQL endpoint returned: {}", error_text`) makes the throttled case
/// count as an ordinary failure and this test fails on its first assertion.
#[tokio::test]
async fn a_real_graphql_429_is_excluded_by_the_shared_rate_limit_predicate() {
    use crate::capability::{ExecutionContext, GraphqlConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    let mut errors = Vec::new();
    for route in ["/throttled", "/broken"] {
        let config = ProtocolConfig::Graphql(GraphqlConfig {
            endpoint: format!("{base}{route}"),
            query: Some("query { viewer { login } }".to_string()),
            ..Default::default()
        });
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        errors.push(
            graphql::GraphqlExecutor {
                executor: &executor,
            }
            .execute(&config, serde_json::json!({}), &ctx)
            .await
            .unwrap_err()
            .to_string(),
        );
    }

    assert_only_the_500_trips_the_breaker(&errors);
}

/// RL.10 — the rate-limit outcome is TYPED, and every other status is not.
///
/// The three sibling tests above prove a 429 is *recognised*; they do it by
/// reading a formatted string, so the property they pin is "the status text
/// survives formatting", not "a rate limit has a type". This one pins the
/// type: `Error::Http` carrying `StatusCode::TOO_MANY_REQUESTS`, which
/// `BudgetOutcome::of` can match without reading a byte of prose.
///
/// THE CONTROL IS THE OTHER HALF OF THE TEST: 500 must still arrive as
/// `Error::Protocol` with its status and its body fragment intact. The gate is
/// `status == 429` alone — not `error_for_status_ref()`'s `Err`, which would
/// flatten 504 into a typed error and change how the dispatch classifier reads
/// it.
///
/// URL CANARY: the REST leg is driven through a query string carrying
/// `api_key=CANARY`. A `reqwest::Error` prints its URL by default, so the typed
/// error is stripped with `without_url()` before it is wrapped; the assertions
/// below fail if either the credential, the host or the path reaches `Display`.
///
/// STILL NOT PINNED here: that the relocated body reaches the `warn!` record —
/// only that it leaves the error. Capturing a tracing event needs a subscriber
/// this module does not install.
/// A typed 429 must still reach the caller as a backend fault (GH475.RL.10).
///
/// `to_rpc_code` reported `Error::Protocol` as `-32600` and every other variant
/// as `-32603`. Making a 429 typed moved it from the first bucket to the
/// second, which tells a JSON-RPC client the *gateway* failed. The guarded arm
/// puts it in `-32000` beside the other backend-side refusals; the 500 control
/// proves the move is scoped to 429 and did not drag the untyped path with it.
#[tokio::test]
async fn a_typed_429_reports_a_backend_fault_rpc_code() {
    let (executor, base) = loopback_status_backend().await;
    let rest_config = RestConfig::default();

    let mut codes = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .post(format!("{base}{route}"))
            .send()
            .await
            .unwrap();
        codes.push(
            executor
                .handle_response(response, &rest_config)
                .await
                .unwrap_err()
                .to_rpc_code(),
        );
    }

    assert_eq!(
        codes[0], -32000,
        "a throttled backend is a backend fault, not a gateway one"
    );
    assert_eq!(
        codes[1], -32600,
        "the untyped 500 must keep the code it always had"
    );
}

#[tokio::test]
async fn a_capability_429_is_a_typed_http_error_at_every_protocol_site() {
    use crate::capability::{ExecutionContext, GraphqlConfig, JsonRpcConfig, ProtocolConfig};
    use rest::ProtocolExecutor;

    fn assert_typed_429(error: &Error, site: &str) {
        match error {
            Error::Http(inner) => assert_eq!(
                inner.status(),
                Some(reqwest::StatusCode::TOO_MANY_REQUESTS),
                "{site}: the typed error must carry the throttling status"
            ),
            other => panic!("{site}: a 429 must be a typed Http error, got: {other}"),
        }
    }

    fn assert_untyped_500(error: &Error, site: &str) {
        match error {
            Error::Protocol(text) => {
                assert!(
                    text.contains("500"),
                    "{site}: the control must keep its status in the message: {text}"
                );
                assert!(
                    text.contains("slow down"),
                    "{site}: the control must keep its body fragment: {text}"
                );
            }
            other => panic!("{site}: only 429 is typed; 500 must stay Protocol, got: {other}"),
        }
    }

    let (executor, base) = loopback_status_backend().await;
    let capability = unauthenticated_capability();

    // REST — driven at `handle_response`, the production formatter, with a
    // credential in the query string as the leak canary.
    let rest_config = RestConfig::default();
    let mut rest = Vec::new();
    for route in ["/throttled", "/broken"] {
        let response = executor
            .client
            .post(format!("{base}{route}?api_key=CANARY"))
            .send()
            .await
            .unwrap();
        rest.push(
            executor
                .handle_response(response, &rest_config)
                .await
                .unwrap_err(),
        );
    }
    assert_typed_429(&rest[0], "REST");
    assert_untyped_500(&rest[1], "REST");

    let leaked = rest[0].to_string();
    for secret in ["CANARY", "api_key", "localhost", "/throttled", "slow down"] {
        assert!(
            !leaked.contains(secret),
            "the typed error leaked {secret:?}: {leaked}"
        );
    }
    match &rest[0] {
        Error::Http(inner) => assert!(
            inner.url().is_none(),
            "the URL must be stripped from the error, not merely absent from its Display"
        ),
        other => panic!("expected a typed Http error, got: {other}"),
    }

    // JSON-RPC and GraphQL — driven through `execute`, as their sibling
    // detection tests are.
    let mut jsonrpc = Vec::new();
    let mut graphql = Vec::new();
    for route in ["/throttled", "/broken"] {
        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        jsonrpc.push(
            jsonrpc::JsonRpcExecutor {
                executor: &executor,
            }
            .execute(
                &ProtocolConfig::Jsonrpc(JsonRpcConfig {
                    endpoint: format!("{base}{route}"),
                    method: "eth_blockNumber".to_string(),
                    ..Default::default()
                }),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap_err(),
        );

        let ctx = ExecutionContext {
            capability: &capability,
            timeout_secs: 5,
            context: CapabilityExecutionContext::default(),
        };
        graphql.push(
            graphql::GraphqlExecutor {
                executor: &executor,
            }
            .execute(
                &ProtocolConfig::Graphql(GraphqlConfig {
                    endpoint: format!("{base}{route}"),
                    query: Some("query { viewer { login } }".to_string()),
                    ..Default::default()
                }),
                serde_json::json!({}),
                &ctx,
            )
            .await
            .unwrap_err(),
        );
    }
    assert_typed_429(&jsonrpc[0], "JSON-RPC");
    assert_untyped_500(&jsonrpc[1], "JSON-RPC");
    assert_typed_429(&graphql[0], "GraphQL");
    assert_untyped_500(&graphql[1], "GraphQL");
}
