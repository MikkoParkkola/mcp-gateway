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
        webhooks: HashMap::new(),
        sha256: None,
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
        webhooks: HashMap::new(),
        sha256: None,
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
    let config = ProtocolConfig::Rest(RestConfig {
        base_url: "https://api.example.com".to_string(),
        path: "/v1/users".to_string(),
        method: "POST".to_string(),
        ..Default::default()
    });

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
    let config = ProtocolConfig::Rest(RestConfig {
        base_url: "https://api.weather.com".to_string(),
        path: "/forecast".to_string(),
        method: "GET".to_string(),
        ..Default::default()
    });

    let yaml = serde_yaml::to_string(&config).unwrap();
    let restored: ProtocolConfig = serde_yaml::from_str(&yaml).unwrap();

    assert_eq!(restored.protocol_name(), "rest");
    let rest = restored.as_rest().unwrap();
    assert_eq!(rest.base_url, "https://api.weather.com");
}

#[test]
fn protocol_config_protocol_name_returns_rest() {
    let config = ProtocolConfig::Rest(RestConfig::default());
    assert_eq!(config.protocol_name(), "rest");
}

#[test]
fn protocol_config_as_rest_returns_some_for_rest_variant() {
    let inner = RestConfig {
        base_url: "https://example.com".to_string(),
        ..Default::default()
    };
    let config = ProtocolConfig::Rest(inner.clone());
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
    // GIVEN: ProviderConfig with unknown service = "graphql"
    // WHEN: calling protocol_config()
    // THEN: falls back to REST (backward compat)
    let provider = ProviderConfig {
        service: "graphql".to_string(),
        cost_per_call: 0.0,
        timeout: 30,
        config: RestConfig {
            base_url: "https://graphql.example.com".to_string(),
            ..Default::default()
        },
    };

    let proto = provider.protocol_config();
    assert_eq!(proto.protocol_name(), "rest");
    assert_eq!(
        proto.as_rest().unwrap().base_url,
        "https://graphql.example.com"
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
