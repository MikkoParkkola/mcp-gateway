// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

mod descriptions;
mod protocol_configs;
mod repo_capabilities;
mod transforms;

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
        projection: None,
        webhooks: HashMap::new(),
        sha256: None,
        visible_in_states: vec![],
    }
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
