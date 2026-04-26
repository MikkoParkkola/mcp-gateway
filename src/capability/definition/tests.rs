use super::*;

#[test]
fn test_default_values() {
    let config: AuthConfig = serde_json::from_str("{}").unwrap();
    assert!(!config.required);
    assert!(config.auth_type.is_empty());
}

fn make_capability(name: &str, description: &str, tags: Vec<&str>) -> CapabilityDefinition {
    CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: description.to_string(),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            tags: tags.into_iter().map(ToString::to_string).collect(),
            ..CapabilityMetadata::default()
        },
        transform: TransformConfig::default(),
        response_transform: TransformConfig::default(),
        webhooks: HashMap::new(),
        sha256: None,
        visible_in_states: vec![],
    }
}

#[test]
fn to_mcp_tool_without_tags_uses_plain_description() {
    let cap = make_capability("test_tool", "A test tool", vec![]);
    let tool = cap.to_mcp_tool();
    assert_eq!(tool.name, "test_tool");
    assert_eq!(tool.description, Some("A test tool".to_string()));
}

#[test]
fn to_mcp_tool_with_tags_appends_keywords_suffix() {
    let cap = make_capability("search_tool", "Web search", vec!["search", "web", "brave"]);
    let tool = cap.to_mcp_tool();
    let desc = tool.description.unwrap();
    assert!(desc.starts_with("Web search"));
    assert!(desc.contains("[keywords: search, web, brave]"));
}

#[test]
fn to_mcp_tool_single_tag_formats_correctly() {
    let cap = make_capability("weather", "Get weather", vec!["forecast"]);
    let tool = cap.to_mcp_tool();
    assert_eq!(
        tool.description,
        Some("Get weather [keywords: forecast]".to_string())
    );
}

#[test]
fn to_mcp_tool_read_only_capability_has_protocol_annotations() {
    let mut cap = make_capability("weather", "Get weather", vec!["forecast"]);
    cap.metadata.read_only = true;

    let annotations = cap
        .to_mcp_tool()
        .annotations
        .expect("capability tools should be annotated");

    assert_eq!(annotations.read_only_hint, Some(true));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(true));
    assert_eq!(annotations.open_world_hint, Some(true));
}

#[test]
fn to_mcp_tool_write_capability_uses_conservative_defaults() {
    let cap = make_capability("submit_form", "Submit a form", vec!["form"]);

    let annotations = cap
        .to_mcp_tool()
        .annotations
        .expect("capability tools should be annotated");

    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(true));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(true));
}

#[test]
fn to_mcp_tool_capability_metadata_can_override_annotation_defaults() {
    let mut cap = make_capability("start_scan", "Start a scan", vec!["security"]);
    cap.metadata.destructive = Some(false);
    cap.metadata.idempotent = Some(false);
    cap.metadata.open_world = Some(false);

    let annotations = cap
        .to_mcp_tool()
        .annotations
        .expect("capability tools should be annotated");

    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(false));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(false));
}

#[test]
fn build_description_with_empty_tags_is_plain() {
    let cap = make_capability("no_tags", "Plain description", vec![]);
    assert_eq!(cap.build_description(), "Plain description");
}

#[test]
fn build_description_with_tags_includes_all_tags() {
    let cap = make_capability("multi", "Desc", vec!["a", "b", "c"]);
    assert_eq!(cap.build_description(), "Desc [keywords: a, b, c]");
}

// ── extract_schema_fields ─────────────────────────────────────────────

#[test]
fn extract_schema_fields_returns_empty_for_null_schema() {
    // GIVEN: null JSON value (default schema)
    // WHEN: extracting fields
    // THEN: empty vec
    let fields = extract_schema_fields(&serde_json::Value::Null);
    assert!(fields.is_empty());
}

#[test]
fn extract_schema_fields_extracts_property_names() {
    // GIVEN: schema with `symbol` and `exchange` properties
    // WHEN: extracting fields
    // THEN: both property names are present
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string" },
            "exchange": { "type": "string" }
        }
    });
    let fields = extract_schema_fields(&schema);
    assert!(fields.contains(&"symbol".to_string()));
    assert!(fields.contains(&"exchange".to_string()));
}

#[test]
fn extract_schema_fields_includes_property_description_words() {
    // GIVEN: schema where property has a description
    // WHEN: extracting fields
    // THEN: words from property description are included
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string", "description": "Stock ticker symbol" }
        }
    });
    let fields = extract_schema_fields(&schema);
    assert!(fields.contains(&"symbol".to_string()));
    assert!(fields.contains(&"stock".to_string()));
    assert!(fields.contains(&"ticker".to_string()));
}

#[test]
fn extract_schema_fields_includes_top_level_description_words() {
    // GIVEN: schema with a top-level description
    // WHEN: extracting fields
    // THEN: words from the top-level description are included
    let schema = serde_json::json!({
        "type": "object",
        "description": "Market data query",
        "properties": {}
    });
    let fields = extract_schema_fields(&schema);
    assert!(fields.contains(&"market".to_string()));
    assert!(fields.contains(&"data".to_string()));
    assert!(fields.contains(&"query".to_string()));
}

#[test]
fn extract_schema_fields_deduplicates_tokens() {
    // GIVEN: schema where "symbol" appears as property name AND in description
    // WHEN: extracting fields
    // THEN: "symbol" appears only once
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string", "description": "The symbol to look up" }
        }
    });
    let fields = extract_schema_fields(&schema);
    let count = fields.iter().filter(|f| f.as_str() == "symbol").count();
    assert_eq!(count, 1, "symbol should appear exactly once");
}

#[test]
fn extract_schema_fields_lowercases_tokens() {
    // GIVEN: schema with mixed-case property name
    // WHEN: extracting fields
    // THEN: all tokens are lowercase
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "StockSymbol": { "type": "string", "description": "A TICKER value" }
        }
    });
    let fields = extract_schema_fields(&schema);
    assert!(fields.iter().all(|f| f == &f.to_lowercase()));
    assert!(fields.contains(&"stocksymbol".to_string()));
    assert!(fields.contains(&"ticker".to_string()));
    assert!(fields.contains(&"value".to_string()));
}

// ── build_description with schema ─────────────────────────────────────

fn make_capability_with_schema(
    name: &str,
    description: &str,
    tags: Vec<&str>,
    input: serde_json::Value,
) -> CapabilityDefinition {
    CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: description.to_string(),
        schema: SchemaDefinition {
            input,
            output: serde_json::Value::Null,
        },
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            tags: tags.into_iter().map(ToString::to_string).collect(),
            ..CapabilityMetadata::default()
        },
        transform: crate::transform::TransformConfig::default(),
        response_transform: crate::transform::TransformConfig::default(),
        webhooks: HashMap::new(),
        sha256: None,
        visible_in_states: vec![],
    }
}

#[test]
fn build_description_with_schema_appends_schema_suffix() {
    // GIVEN: capability with schema containing symbol and exchange
    // WHEN: building description
    // THEN: [schema: ...] suffix is appended
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string" },
            "exchange": { "type": "string" }
        }
    });
    let cap = make_capability_with_schema("stock_tool", "Get stock data", vec![], schema);
    let desc = cap.build_description();
    assert!(desc.starts_with("Get stock data"));
    assert!(desc.contains("[schema:"));
    assert!(desc.contains("symbol"));
    assert!(desc.contains("exchange"));
}

#[test]
fn build_description_with_tags_and_schema_includes_both_suffixes() {
    // GIVEN: capability with both tags and schema fields
    // WHEN: building description
    // THEN: [keywords: ...] and [schema: ...] both appear
    let schema = serde_json::json!({
        "type": "object",
        "properties": { "symbol": { "type": "string" } }
    });
    let cap = make_capability_with_schema(
        "stock_tool",
        "Get stock data",
        vec!["finance", "market"],
        schema,
    );
    let desc = cap.build_description();
    assert!(desc.contains("[keywords: finance, market]"));
    assert!(desc.contains("[schema:"));
    assert!(desc.contains("symbol"));
}

#[test]
fn build_description_without_schema_omits_schema_suffix() {
    // GIVEN: capability with tags but no schema properties
    // WHEN: building description
    // THEN: no [schema: ...] suffix
    let cap = make_capability("search", "Search tool", vec!["web"]);
    let desc = cap.build_description();
    assert!(!desc.contains("[schema:"));
}

#[test]
fn to_mcp_tool_with_schema_includes_schema_fields_in_description() {
    // GIVEN: capability with a rich input schema
    // WHEN: converting to MCP tool
    // THEN: description contains searchable schema fields
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "symbol": { "type": "string", "description": "Stock ticker symbol" },
            "exchange": { "type": "string" },
            "price": { "type": "number" },
            "volume": { "type": "integer" }
        }
    });
    let cap = make_capability_with_schema("market_data", "Fetch market data", vec![], schema);
    let tool = cap.to_mcp_tool();
    let desc = tool.description.unwrap();
    assert!(desc.contains("symbol"), "description must contain 'symbol'");
    assert!(
        desc.contains("exchange"),
        "description must contain 'exchange'"
    );
    assert!(desc.contains("price"), "description must contain 'price'");
    assert!(desc.contains("volume"), "description must contain 'volume'");
}

#[test]
fn test_providers_with_fallback_array() {
    let yaml = r"
primary:
  service: openai
  config:
    endpoint: https://api.openai.com/v1/chat
fallback:
  - service: anthropic
    config:
      endpoint: https://api.anthropic.com/v1/messages
  - service: groq
    config:
      endpoint: https://api.groq.com/v1/chat
";
    let providers: ProvidersConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(providers.named.contains_key("primary"));
    assert_eq!(providers.fallback.len(), 2);
    assert_eq!(providers.fallback[0].service, "anthropic");
    assert_eq!(providers.fallback[1].service, "groq");
}

#[test]
fn capability_metadata_produces_consumes_chains_with_default_empty() {
    // GIVEN: no composition fields in JSON
    // WHEN: deserializing CapabilityMetadata
    // THEN: produces, consumes, chains_with all default to empty
    let meta: CapabilityMetadata = serde_json::from_str("{}").unwrap();
    assert!(meta.produces.is_empty());
    assert!(meta.consumes.is_empty());
    assert!(meta.chains_with.is_empty());
}

#[test]
fn capability_metadata_deserializes_all_composition_fields() {
    // GIVEN: JSON with all three composition fields
    // WHEN: deserializing
    // THEN: fields populated correctly
    let json = r#"{
        "produces": ["teamId"],
        "consumes": ["userId"],
        "chains_with": ["linear_create_issue"]
    }"#;
    let meta: CapabilityMetadata = serde_json::from_str(json).unwrap();
    assert_eq!(meta.produces, vec!["teamId"]);
    assert_eq!(meta.consumes, vec!["userId"]);
    assert_eq!(meta.chains_with, vec!["linear_create_issue"]);
}

#[test]
fn capability_metadata_serializes_composition_fields() {
    // GIVEN: CapabilityMetadata with composition data
    // WHEN: serializing to JSON
    // THEN: all fields present
    let meta = CapabilityMetadata {
        produces: vec!["teamId".to_string()],
        consumes: vec!["userId".to_string()],
        chains_with: vec!["next_tool".to_string()],
        ..CapabilityMetadata::default()
    };
    let json = serde_json::to_value(&meta).unwrap();
    assert_eq!(json["produces"][0], "teamId");
    assert_eq!(json["consumes"][0], "userId");
    assert_eq!(json["chains_with"][0], "next_tool");
}

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

// ── Sample capability YAML loads correctly ──────────────────────────

#[test]
fn github_graphql_sample_capability_loads() {
    // GIVEN: the github_graphql.yaml sample capability
    // WHEN: parsed as CapabilityDefinition
    // THEN: all fields are correct and service maps to graphql
    let yaml = include_str!("../../../capabilities/examples/github_graphql.yaml");
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(cap.name, "github_graphql_viewer");
    assert!(cap.description.contains("GraphQL"));
    assert!(cap.auth.required);
    assert_eq!(cap.auth.key, "env:GITHUB_TOKEN");

    let provider = cap.providers.get("primary").unwrap();
    assert_eq!(provider.service, "graphql");

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "graphql");
    let gql = proto.as_graphql().unwrap();
    assert_eq!(gql.endpoint, "https://api.github.com/graphql");
    assert!(gql.query.as_deref().unwrap().contains("viewer"));
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

// ── Sample JSON-RPC capability YAML loads correctly ────────────────

#[test]
fn jsonrpc_sample_capability_loads() {
    let yaml = include_str!("../../../capabilities/examples/jsonrpc_example.yaml");
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();

    assert_eq!(cap.name, "jsonrpc_eth_block_number");
    assert!(cap.description.contains("block number"));
    assert!(!cap.auth.required);

    let provider = cap.providers.get("primary").unwrap();
    assert_eq!(provider.service, "jsonrpc");
    assert_eq!(provider.timeout, 10);

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "jsonrpc");
    let jrpc = proto.as_jsonrpc().unwrap();
    assert_eq!(jrpc.endpoint, "http://localhost:8545");
    assert_eq!(jrpc.method, "eth_blockNumber");
    assert_eq!(jrpc.default_params["tag"], "latest");
}

// ── response_transform field ──────────────────────────────────────────────────

#[test]
fn response_transform_defaults_to_empty_when_absent_from_yaml() {
    // GIVEN: a capability YAML with no response_transform section
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: response_transform is empty / noop
    assert!(cap.response_transform.project.is_empty());
    assert!(cap.response_transform.rename.is_empty());
    assert!(cap.response_transform.redact.is_empty());
    assert!(cap.response_transform.format.is_none());
    assert!(cap.response_transform.is_empty());
}

#[test]
fn response_transform_project_deserializes_from_yaml() {
    // GIVEN: a capability YAML with response_transform.project
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
response_transform:
  project:
    - id
    - name
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: project fields are populated
    assert_eq!(cap.response_transform.project, vec!["id", "name"]);
    assert!(!cap.response_transform.is_empty());
}

#[test]
fn response_transform_redact_deserializes_from_yaml() {
    // GIVEN: a capability YAML with response_transform.redact
    let yaml = r"
name: my_tool
description: A tool
providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /v1/test
response_transform:
  redact:
    - pattern: '\bsecret\b'
      replacement: '[REDACTED]'
";
    // WHEN: deserializing
    let cap: CapabilityDefinition = serde_yaml::from_str(yaml).unwrap();
    // THEN: redact rules are populated
    assert_eq!(cap.response_transform.redact.len(), 1);
    assert_eq!(cap.response_transform.redact[0].pattern, r"\bsecret\b");
    assert_eq!(cap.response_transform.redact[0].replacement, "[REDACTED]");
    assert!(!cap.response_transform.is_empty());
}

// ── TransformConfig::is_empty ─────────────────────────────────────────────────

#[test]
fn transform_config_is_empty_on_default() {
    // GIVEN: default TransformConfig
    // WHEN: checking is_empty
    // THEN: returns true
    assert!(crate::transform::TransformConfig::default().is_empty());
}

#[test]
fn transform_config_is_not_empty_when_project_set() {
    // GIVEN: TransformConfig with project fields
    let config = crate::transform::TransformConfig {
        project: vec!["id".to_string()],
        ..Default::default()
    };
    // WHEN: checking is_empty
    // THEN: returns false
    assert!(!config.is_empty());
}

#[test]
fn response_transform_skipped_in_serialization_when_empty() {
    // GIVEN: a capability with empty response_transform
    let cap = make_capability("test_tool", "Test", vec![]);
    // WHEN: serializing to YAML
    let yaml = serde_yaml::to_string(&cap).unwrap();
    // THEN: response_transform key is absent (skip_serializing_if)
    assert!(!yaml.contains("response_transform"));
}

#[test]
fn response_transform_included_in_serialization_when_non_empty() {
    // GIVEN: a capability with non-empty response_transform
    let mut cap = make_capability("test_tool", "Test", vec![]);
    cap.response_transform.project = vec!["id".to_string()];
    // WHEN: serializing to YAML
    let yaml = serde_yaml::to_string(&cap).unwrap();
    // THEN: response_transform key is present
    assert!(yaml.contains("response_transform"));
}
