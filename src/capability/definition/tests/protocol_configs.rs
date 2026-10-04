// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! REST, GraphQL and JSON-RPC protocol configs and the provider bridge.

use super::*;

// ── ProtocolConfig tests ─────────────────────────────────────────────

#[test]
fn protocol_config_rest_round_trips_through_serde_json() {
    // GIVEN: a ProtocolConfig::Rest with populated fields
    // WHEN: serialized to JSON and back
    // THEN: all fields preserved
    let config = ProtocolConfig::Rest(Box::new(RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/v1/users".to_string(),
        method: "POST".to_string(),
        ..Default::default()
    }));

    let json = serde_json::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.protocol_name(), "rest");
    let rest = restored.as_rest().unwrap();
    assert_eq!(rest.base_url, "https://api.example.com");
    assert_eq!(rest.path, "/v1/users");
    assert_eq!(rest.method, "POST");
}

#[test]
fn protocol_config_rest_round_trips_through_serde_yaml() {
    // GIVEN: a ProtocolConfig::Rest
    // WHEN: serialized to YAML and back
    // THEN: all fields preserved
    let config = ProtocolConfig::Rest(Box::new(RestConfig {
        base_url: "https://api.weather.com".to_string(),
        path: "/forecast".to_string(),
        method: "GET".to_string(),
        ..Default::default()
    }));

    let yaml = serde_yaml::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(restored.protocol_name(), "rest");
    let rest = restored.as_rest().unwrap();
    assert_eq!(rest.base_url, "https://api.weather.com");
}

#[test]
fn protocol_config_protocol_name_returns_rest() {
    let config = ProtocolConfig::Rest(Box::default());
    assert_eq!(config.protocol_name(), "rest");
}

#[test]
fn protocol_config_as_rest_returns_some_for_rest_variant() {
    let inner = RestConfig {
        base_url: "https://example.com".to_string(),
        ..Default::default()
    };
    let config = ProtocolConfig::Rest(Box::new(inner.clone()));
    let extracted = config.as_rest().unwrap();
    assert_eq!(extracted.base_url, inner.base_url);
}

// ── ProviderConfig::protocol_config() bridge tests ──────────────────

#[test]
fn provider_config_protocol_config_maps_rest_service() {
    // GIVEN: ProviderConfig with service = "rest"
    // WHEN: calling protocol_config()
    // THEN: returns ProtocolConfig::Rest with the same RestConfig
    let provider = ProviderConfig {
        service: "rest".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            base_url: "https://api.example.com".to_string(),
            path: "/users".to_string(),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "rest");
    let rest = proto.as_rest().unwrap();
    assert_eq!(rest.base_url, "https://api.example.com");
    assert_eq!(rest.path, "/users");
}

#[test]
fn provider_config_protocol_config_defaults_empty_service_to_rest() {
    // GIVEN: ProviderConfig with empty service string
    // WHEN: calling protocol_config()
    // THEN: falls back to REST
    let provider = ProviderConfig {
        service: String::new(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            base_url: "https://fallback.example.com".to_string(),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "rest");
    assert_eq!(
        proto.as_rest().unwrap().base_url,
        "https://fallback.example.com"
    );
}

#[test]
fn provider_config_protocol_config_unknown_service_falls_back_to_rest() {
    // GIVEN: ProviderConfig with unknown service = "grpc"
    // WHEN: calling protocol_config()
    // THEN: falls back to REST (backward compat)
    let provider = ProviderConfig {
        service: "grpc".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            base_url: "https://grpc.example.com".to_string(),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "rest");
    assert_eq!(
        proto.as_rest().unwrap().base_url,
        "https://grpc.example.com"
    );
}

#[test]
fn provider_config_deserialized_from_yaml_maps_to_protocol_config() {
    // GIVEN: YAML matching the existing capability format
    // WHEN: deserialized to ProviderConfig and mapped
    // THEN: protocol_config() produces correct REST config
    let yaml = r"
service: rest
timeout: 15
config:
  base_url: https://api.open-meteo.com
  path: /v1/forecast
  method: GET
";
    let provider: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(provider.service, "rest");
    assert_eq!(provider.timeout, 15);

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "rest");
    let rest = proto.as_rest().unwrap();
    assert_eq!(rest.base_url, "https://api.open-meteo.com");
    assert_eq!(rest.path, "/v1/forecast");
    assert_eq!(rest.method, "GET");
}

#[test]
fn provider_config_default_service_is_rest() {
    // GIVEN: YAML without explicit service field
    // WHEN: deserialized
    // THEN: service defaults to "rest"
    let yaml = r"
config:
  base_url: https://api.example.com
";
    let provider: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(provider.service, "rest");
    assert_eq!(provider.protocol_config().protocol_name(), "rest");
}

// ── ProtocolConfig::Graphql tests ───────────────────────────────────

#[test]
fn protocol_config_graphql_round_trips_through_serde_json() {
    // GIVEN: a ProtocolConfig::Graphql with populated fields
    // WHEN: serialized to JSON and back
    // THEN: all fields preserved
    let config = ProtocolConfig::Graphql(GraphqlConfig {
        endpoint: "https://api.github.com/graphql".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("Authorization".to_string(), "Bearer token123".to_string());
            h
        },
        query: Some("{ viewer { login } }".to_string()),
        variables: {
            let mut v = HashMap::new();
            v.insert("first".to_string(), serde_json::json!(10));
            v
        },
        response_path: Some("data.viewer".to_string()),
    });

    let json = serde_json::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.protocol_name(), "graphql");
    let gql = restored.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.github.com/graphql");
    assert_eq!(gql.query.as_deref(), Some("{ viewer { login } }"));
    assert_eq!(gql.variables.get("first"), Some(&serde_json::json!(10)));
    assert_eq!(gql.response_path.as_deref(), Some("data.viewer"));
    assert_eq!(gql.headers.get("Authorization").unwrap(), "Bearer token123");
}

#[test]
fn protocol_config_graphql_round_trips_through_serde_yaml() {
    let config = ProtocolConfig::Graphql(GraphqlConfig {
        endpoint: "https://api.example.com/graphql".to_string(),
        query: Some("{ users { id } }".to_string()),
        ..Default::default()
    });

    let yaml = serde_yaml::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(restored.protocol_name(), "graphql");
    let gql = restored.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.example.com/graphql");
}

#[test]
fn protocol_config_graphql_protocol_name_returns_graphql() {
    let config = ProtocolConfig::Graphql(GraphqlConfig::default());
    assert_eq!(config.protocol_name(), "graphql");
}

#[test]
fn protocol_config_as_graphql_returns_some_for_graphql_variant() {
    let config = ProtocolConfig::Graphql(GraphqlConfig {
        endpoint: "https://example.com/graphql".to_string(),
        ..Default::default()
    });
    assert!(config.as_graphql().is_some());
    assert!(config.as_rest().is_none());
}

#[test]
fn protocol_config_as_rest_returns_none_for_graphql_variant() {
    let config = ProtocolConfig::Graphql(GraphqlConfig::default());
    assert!(config.as_rest().is_none());
}

#[test]
fn protocol_config_as_graphql_returns_none_for_rest_variant() {
    let config = ProtocolConfig::Rest(Box::default());
    assert!(config.as_graphql().is_none());
}

// ── ProviderConfig::protocol_config() bridge for GraphQL ────────────

#[test]
fn provider_config_graphql_service_maps_to_graphql_protocol() {
    // GIVEN: ProviderConfig with service = "graphql"
    // WHEN: calling protocol_config()
    // THEN: returns ProtocolConfig::Graphql
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            endpoint: "https://api.github.com/graphql".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Accept".to_string(), "application/json".to_string());
                h
            },
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "graphql");
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.github.com/graphql");
    assert_eq!(gql.headers.get("Accept").unwrap(), "application/json");
}

#[test]
fn provider_config_graphql_uses_base_url_plus_path_when_no_endpoint() {
    // GIVEN: ProviderConfig with service = "graphql" and base_url+path
    // WHEN: calling protocol_config()
    // THEN: endpoint is base_url + path
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            base_url: "https://api.example.com".to_string(),
            path: "/graphql".to_string(),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.example.com/graphql");
}

#[test]
fn provider_config_graphql_extracts_query_from_body_string() {
    // GIVEN: ProviderConfig with body as a string (the query)
    // WHEN: calling protocol_config()
    // THEN: query is extracted from body
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            endpoint: "https://api.example.com/graphql".to_string(),
            body: Some(serde_json::json!("{ viewer { login } }")),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.query.as_deref(), Some("{ viewer { login } }"));
}

#[test]
fn provider_config_graphql_extracts_query_from_body_object() {
    // GIVEN: ProviderConfig with body as { query: "..." }
    // WHEN: calling protocol_config()
    // THEN: query is extracted from body.query
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            endpoint: "https://api.example.com/graphql".to_string(),
            body: Some(serde_json::json!({ "query": "{ users { id } }" })),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.query.as_deref(), Some("{ users { id } }"));
}

#[test]
fn provider_config_graphql_maps_static_params_to_variables() {
    // GIVEN: ProviderConfig with static_params
    // WHEN: calling protocol_config()
    // THEN: static_params become graphql variables
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            endpoint: "https://api.example.com/graphql".to_string(),
            static_params: {
                let mut m = HashMap::new();
                m.insert("first".to_string(), serde_json::json!(5));
                m
            },
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.variables.get("first"), Some(&serde_json::json!(5)));
}

#[test]
fn provider_config_graphql_preserves_response_path() {
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            endpoint: "https://api.example.com/graphql".to_string(),
            response_path: Some("data.viewer".to_string()),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.response_path.as_deref(), Some("data.viewer"));
}

#[test]
fn provider_config_graphql_deserialized_from_yaml() {
    // GIVEN: YAML with service: graphql
    // WHEN: deserialized and mapped
    // THEN: produces correct GraphqlConfig
    let yaml = r#"
service: graphql
timeout: 15
config:
  endpoint: https://api.github.com/graphql
  headers:
    Accept: application/json
    User-Agent: mcp-gateway
  body:
    query: "query { viewer { login name } }"
"#;
    let provider: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(provider.service, "graphql");

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "graphql");
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.github.com/graphql");
    assert_eq!(
        gql.query.as_deref(),
        Some("query { viewer { login name } }")
    );
    assert_eq!(gql.headers.get("Accept").unwrap(), "application/json");
}

// ── JSON-RPC ProtocolConfig tests ──────────────────────────────────

#[test]
fn protocol_config_jsonrpc_round_trips_through_serde_json() {
    let config = ProtocolConfig::Jsonrpc(JsonRpcConfig {
        endpoint: "http://localhost:8545".to_string(),
        method: "eth_blockNumber".to_string(),
        headers: {
            let mut h = HashMap::new();
            h.insert("Authorization".to_string(), "Bearer token123".to_string());
            h
        },
        default_params: serde_json::json!({"tag": "latest"}),
    });

    let json = serde_json::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.protocol_name(), "jsonrpc");
    let jrpc = restored.as_jsonrpc().unwrap();
    assert_eq!(jrpc.endpoint, "http://localhost:8545");
    assert_eq!(jrpc.method, "eth_blockNumber");
    assert_eq!(jrpc.default_params["tag"], "latest");
    assert_eq!(
        jrpc.headers.get("Authorization").unwrap(),
        "Bearer token123"
    );
}

#[test]
fn protocol_config_jsonrpc_round_trips_through_serde_yaml() {
    let config = ProtocolConfig::Jsonrpc(JsonRpcConfig {
        endpoint: "http://localhost:8080/rpc".to_string(),
        method: "system.listMethods".to_string(),
        ..Default::default()
    });

    let yaml = serde_yaml::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(restored.protocol_name(), "jsonrpc");
    let jrpc = restored.as_jsonrpc().unwrap();
    assert_eq!(jrpc.endpoint, "http://localhost:8080/rpc");
    assert_eq!(jrpc.method, "system.listMethods");
}

#[test]
fn protocol_config_as_jsonrpc_returns_none_for_non_jsonrpc() {
    let rest = ProtocolConfig::Rest(Box::default());
    assert!(rest.as_jsonrpc().is_none());

    let gql = ProtocolConfig::Graphql(GraphqlConfig::default());
    assert!(gql.as_jsonrpc().is_none());
}

// ── ProviderConfig::protocol_config() bridge for JSON-RPC ─────────

#[test]
fn provider_config_jsonrpc_service_maps_to_jsonrpc_protocol() {
    let provider = ProviderConfig {
        service: "jsonrpc".to_string(),
        cost_per_call: 0.0,
        timeout: 10,
        config: RestConfig {
            endpoint: "http://localhost:8545".to_string(),
            method: "eth_getBalance".to_string(),
            headers: {
                let mut h = HashMap::new();
                h.insert("Accept".to_string(), "application/json".to_string());
                h
            },
            static_params: {
                let mut m = HashMap::new();
                m.insert("tag".to_string(), serde_json::json!("latest"));
                m
            },
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "jsonrpc");
    let jrpc = proto.as_jsonrpc().unwrap();
    assert_eq!(jrpc.endpoint, "http://localhost:8545");
    assert_eq!(jrpc.method, "eth_getBalance");
    assert_eq!(jrpc.headers.get("Accept").unwrap(), "application/json");
    assert_eq!(jrpc.default_params["tag"], "latest");
}

#[test]
fn provider_config_jsonrpc_deserialized_from_yaml() {
    let yaml = r#"
service: jsonrpc
timeout: 10
config:
  endpoint: http://localhost:8545
  method: eth_blockNumber
  headers:
    Accept: application/json
  static_params:
    tag: "latest"
"#;
    let provider: ProviderConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(provider.service, "jsonrpc");

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "jsonrpc");
    let jrpc = proto.as_jsonrpc().unwrap();
    assert_eq!(jrpc.endpoint, "http://localhost:8545");
    assert_eq!(jrpc.method, "eth_blockNumber");
    assert_eq!(jrpc.default_params["tag"], "latest");
}
