// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The routing instructions the gateway advertises at initialize.

use super::*;

// ── build_routing_instructions ──────────────────────────────────────

fn make_capability_def(
    name: &str,
    category: &str,
    tags: &[&str],
) -> crate::capability::CapabilityDefinition {
    use crate::capability::{
        AuthConfig, CacheConfig, CapabilityMetadata, ProvidersConfig, SchemaDefinition,
    };
    use crate::transform::TransformConfig;

    crate::capability::CapabilityDefinition {
        fulcrum: "1.0".to_string(),
        name: name.to_string(),
        description: format!("{name} description"),
        schema: SchemaDefinition::default(),
        providers: ProvidersConfig::default(),
        auth: AuthConfig::default(),
        cache: CacheConfig::default(),
        metadata: CapabilityMetadata {
            category: category.to_string(),
            tags: tags.iter().map(ToString::to_string).collect(),
            ..CapabilityMetadata::default()
        },
        transform: TransformConfig::default(),
        response_transform: TransformConfig::default(),
        projection: None,
        visible_in_states: vec![],
        webhooks: std::collections::HashMap::new(),
        sha256: None,
    }
}

#[test]
fn routing_instructions_empty_for_no_capabilities() {
    let result = build_routing_instructions(&[], "fulcrum");
    assert!(result.is_empty());
}

#[test]
fn routing_instructions_groups_by_category() {
    let caps = vec![
        make_capability_def("brave_search", "search", &["search", "web"]),
        make_capability_def("brave_news", "search", &["news"]),
        make_capability_def("uuid_generate", "utility", &["uuid"]),
    ];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("search"));
    assert!(result.contains("utility"));
    assert!(result.contains("fulcrum/brave_search"));
    assert!(result.contains("fulcrum/uuid_generate"));
}

#[test]
fn routing_instructions_omits_per_category_search_keywords() {
    let caps = vec![make_capability_def(
        "brave_search",
        "search",
        &["search", "web", "brave"],
    )];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("search"));
    assert!(result.contains("fulcrum/brave_search"));
    assert!(!result.contains("Search keywords:"));
    assert!(!result.contains("web"));
}

#[test]
fn routing_instructions_dense_catalog_stays_below_initialize_budget() {
    let mut caps = Vec::new();
    for category_index in 0..40 {
        for tool_index in 0..10 {
            caps.push(make_capability_def(
                &format!("tool_{category_index}_{tool_index}_with_long_descriptive_name"),
                &format!("category_{category_index}"),
                &[
                    "aggregator",
                    "astronomy",
                    "biodiversity",
                    "climate",
                    "forecast",
                    "historical",
                    "observation",
                    "temperature",
                    "weather",
                    "workflow",
                ],
            ));
        }
    }

    let result = build_routing_instructions(&caps, "fulcrum");

    assert!(
        result.len() < 6_000,
        "routing guide was {} bytes",
        result.len()
    );
    assert!(!result.contains("Search keywords:"));
}

#[test]
fn routing_instructions_truncates_tools_to_two_per_category() {
    let caps = vec![
        make_capability_def("tool_a", "search", &[]),
        make_capability_def("tool_b", "search", &[]),
        make_capability_def("tool_c", "search", &[]),
        make_capability_def("tool_d", "search", &[]),
    ];
    let result = build_routing_instructions(&caps, "fulcrum");
    assert!(result.contains("(+2)"), "Should show overflow count");
}

#[test]
fn routing_instructions_uses_general_for_empty_category() {
    let caps = vec![make_capability_def("my_tool", "", &[])];
    let result = build_routing_instructions(&caps, "backend");
    assert!(result.contains("general"));
}
