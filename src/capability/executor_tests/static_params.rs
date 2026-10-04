// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Static parameters merged into the request.

use super::*;

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
