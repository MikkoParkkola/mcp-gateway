// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6865.SCHEMA.1 — Meta-MCP tool schemas MUST remain valid under JSON
//! Schema 2020-12.
//!
//! Enumerates every `inputSchema` the gateway's Meta-MCP surface can produce
//! — Traditional mode (all optional meta-tools enabled) and Code Mode — via
//! the real `tools/list` handler (`MetaMcp::handle_tools_list`), and
//! validates each one against the JSON Schema 2020-12 meta-schema using the
//! `jsonschema` crate (a real validator, not a hand-rolled key check).

use std::{sync::Arc, time::Duration};

use mcp_gateway::{
    backend::BackendRegistry,
    config::{Config, FailsafeConfig, WebhookConfig},
    config_reload::{LiveConfig, ReloadContext},
    gateway::{WebhookRegistry, test_helpers::MetaMcp},
    protocol::{JsonRpcResponse, RequestId, ToolsListResult},
    stats::UsageStats,
};

fn repo_file(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn decode_tools_list(response: JsonRpcResponse) -> ToolsListResult {
    serde_json::from_value(response.result.expect("tools/list should return a result"))
        .expect("tools/list result should deserialize")
}

fn make_reload_context(backends: Arc<BackendRegistry>) -> Arc<ReloadContext> {
    Arc::new(ReloadContext::new(
        repo_file("examples/gateway-full.yaml"),
        Arc::new(LiveConfig::new(Config::default())),
        backends,
        FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// Traditional-mode `MetaMcp` with every optional meta-tool switched on
/// (stats, cost report, webhooks, reload) so its `tools/list` response
/// includes the maximum schema surface — the same construction
/// `public_claims_validation.rs` uses for its "operational" scenario.
fn operational_meta_mcp() -> MetaMcp {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = MetaMcp::with_features(
        Arc::clone(&backends),
        None,
        Some(Arc::new(UsageStats::new())),
        None,
        Duration::from_secs(60),
    );
    meta_mcp.set_reload_context(make_reload_context(Arc::clone(&backends)));
    meta_mcp.set_webhook_registry(Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        WebhookConfig::default(),
    ))));
    meta_mcp
}

fn code_mode_meta_mcp() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new())).with_code_mode(true)
}

/// Every `inputSchema` the gateway can hand a client across both tool
/// surfaces, tagged with `"<mode>/<tool name>"` for failure messages.
fn all_meta_tool_schemas() -> Vec<(String, serde_json::Value)> {
    let mut schemas = Vec::new();
    let mut names = Vec::new();
    for (mode, meta_mcp) in [
        ("traditional", operational_meta_mcp()),
        ("code_mode", code_mode_meta_mcp()),
    ] {
        let tools = decode_tools_list(meta_mcp.handle_tools_list(RequestId::Number(1))).tools;
        assert!(
            !tools.is_empty(),
            "{mode} tools/list returned zero tools — fixture is not exercising real schemas"
        );
        for tool in tools {
            names.push(format!("{mode}/{}", tool.name));
            schemas.push((format!("{mode}/{}", tool.name), tool.input_schema));
            // Both schema fields are published to a client, so both are in the
            // population. Only some tools declare an `outputSchema`.
            if let Some(output) = tool.output_schema {
                schemas.push((format!("{mode}/{} [outputSchema]", tool.name), output));
            }
        }
    }

    // Population floor. Without it an `all_meta_tool_schemas()` that silently
    // returned a near-empty set would make every check above it pass while
    // walking nothing — the failure mode the per-mode non-empty assert alone
    // does not catch (one tool per mode satisfies it).
    let traditional = names
        .iter()
        .filter(|n| n.starts_with("traditional/"))
        .count();
    assert!(
        traditional >= 14,
        "traditional mode published {traditional} tools; the documented floor for the \
         Meta-MCP surface is 14 — the fixture is not enabling the real surface: {names:?}"
    );
    for expected in [
        "traditional/gateway_search_tools",
        "traditional/gateway_invoke",
        "traditional/gateway_list_servers",
        "traditional/gateway_get_stats",
        "code_mode/gateway_search",
        "code_mode/gateway_execute",
    ] {
        assert!(
            names.iter().any(|n| n == expected),
            "`{expected}` is missing from the enumerated surface: {names:?}"
        );
    }
    assert!(
        schemas.iter().any(|(n, _)| n.ends_with("[outputSchema]")),
        "no tool published an outputSchema — the outputSchema arm of this walk covers nothing"
    );

    schemas
}

/// Asserts every enumerated Meta-MCP `inputSchema` is a structurally valid
/// JSON Schema 2020-12 document per the official meta-schema.
#[test]
fn meta_mcp_tool_schemas_are_valid_json_schema_2020_12() {
    let schemas = all_meta_tool_schemas();
    for (name, schema) in &schemas {
        if let Err(err) = jsonschema::meta::validate(schema) {
            panic!("tool `{name}` has an invalid JSON Schema 2020-12 inputSchema: {err}");
        }
    }
}

/// Falsifier: proves the validator above can actually fail, not just pass by
/// construction. `minLength` MUST be a non-negative integer under 2020-12;
/// a string value is structurally invalid and must be rejected.
#[test]
fn falsifier_invalid_schema_is_rejected_by_the_same_validator() {
    let broken = serde_json::json!({
        "type": "object",
        "properties": {
            "query": { "type": "string", "minLength": "not-a-number" }
        },
        "required": ["query"]
    });
    let result = jsonschema::meta::validate(&broken);
    assert!(
        result.is_err(),
        "validator accepted a schema with minLength as a string — it cannot distinguish valid from invalid, so the passing test above proves nothing"
    );
}

/// MIK-6865.SCHEMA.1c, clause C — plan row P12a. Every `$ref` in a published
/// schema must resolve to a target that exists in the SAME document.
///
/// Meta-validation cannot answer this: a schema pointing at a `$defs` entry
/// that was never written is structurally well-formed and validates cleanly.
/// Well-formedness and resolution are different questions, and the second is
/// the one a client hits.
///
/// Returns each unresolvable pointer, so the surface test and its falsifier
/// exercise the same code.
fn dangling_refs(schema: &serde_json::Value) -> Vec<String> {
    fn resolve(root: &serde_json::Value, pointer: &str) -> bool {
        // Only local pointers can resolve in-document. An external `$ref` is a
        // fetch this gateway must never make (the `jsonschema` dependency is
        // built `default-features = false` precisely to disable remote
        // resolution), so it cannot resolve here and is reported.
        // ponytail: JSON-pointer fragments only. A plain-name fragment
        // (`#name`, resolved against `$anchor`) and an `$id`-relative base are
        // both legal 2020-12 and would be reported here as dangling. No
        // published schema uses either today — the surface has no `$ref` at
        // all — so the walker stays a pointer walker; teach it `$anchor` and
        // `$id` bases the day one appears, rather than editing the schema to
        // suit the check.
        let Some(rest) = pointer.strip_prefix('#') else {
            return false;
        };
        if rest.is_empty() {
            return true;
        }
        let Some(path) = rest.strip_prefix('/') else {
            return false;
        };
        let mut node = root;
        for raw in path.split('/') {
            // RFC 6901 escaping: `~1` is `/` and `~0` is `~`, in that order.
            let token = raw.replace("~1", "/").replace("~0", "~");
            node = match node {
                serde_json::Value::Object(map) => match map.get(&token) {
                    Some(child) => child,
                    None => return false,
                },
                serde_json::Value::Array(items) => match token.parse::<usize>() {
                    Ok(i) if i < items.len() => &items[i],
                    _ => return false,
                },
                _ => return false,
            };
        }
        true
    }

    fn walk(root: &serde_json::Value, node: &serde_json::Value, found: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(pointer)) = map.get("$ref")
                    && !resolve(root, pointer)
                {
                    found.push(pointer.clone());
                }
                for child in map.values() {
                    walk(root, child, found);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(root, child, found);
                }
            }
            _ => {}
        }
    }

    let mut found = Vec::new();
    walk(schema, schema, &mut found);
    found
}

#[test]
fn every_ref_in_a_published_schema_resolves_within_its_own_document() {
    for (name, schema) in all_meta_tool_schemas() {
        let dangling = dangling_refs(&schema);
        assert!(
            dangling.is_empty(),
            "tool `{name}` publishes {} unresolvable $ref(s): {dangling:?}",
            dangling.len()
        );
    }
}

/// Falsifier for the row above, and it is load-bearing: the surface carries no
/// `$ref` today, so the assertion passes over an empty set and would pass
/// identically if `dangling_refs` returned nothing for every input. This is
/// what makes the passing test a regression guard rather than a tautology.
#[test]
fn falsifier_a_ref_to_a_missing_definition_is_reported_by_the_same_walker() {
    let present = serde_json::json!({
        "type": "object",
        "properties": { "who": { "$ref": "#/$defs/Actor" } },
        "$defs": { "Actor": { "type": "string" } }
    });
    assert!(
        dangling_refs(&present).is_empty(),
        "a $ref whose target exists must not be reported, or the check flags everything"
    );

    let missing = serde_json::json!({
        "type": "object",
        "properties": { "who": { "$ref": "#/$defs/Actor" } },
        "$defs": { "Principal": { "type": "string" } }
    });
    assert_eq!(
        dangling_refs(&missing),
        vec!["#/$defs/Actor".to_string()],
        "a $ref to a definition that was never written must be reported"
    );

    // Nested, and external: neither position may hide from the walker.
    let nested_external = serde_json::json!({
        "type": "object",
        "properties": {
            "items": { "type": "array", "items": { "$ref": "https://json-schema.org/draft/2020-12/schema" } }
        }
    });
    assert_eq!(
        dangling_refs(&nested_external),
        vec!["https://json-schema.org/draft/2020-12/schema".to_string()],
        "an external $ref cannot resolve in-document and must be reported"
    );
}

/// The published surface is not only the 19 `gateway_*` definitions: every
/// capability YAML the loader reads becomes a tool whose `inputSchema` and
/// `outputSchema` reach the same client. Enumerating them through the real
/// load path (`CapabilityLoader::load_directory` → `to_mcp_tool`) is what
/// makes the population the criterion's population rather than a subset.
#[tokio::test]
async fn capability_schemas_are_valid_2020_12_and_resolve_their_own_refs() {
    let dir = repo_file("capabilities");
    let definitions = mcp_gateway::capability::CapabilityLoader::load_directory(
        dir.to_str().expect("capabilities path is UTF-8"),
    )
    .await
    .expect("the repo's capability directory must load");

    assert!(
        definitions.len() >= 100,
        "loaded only {} capability definitions; the catalogue is 110+, so the load path is \
         not being exercised",
        definitions.len()
    );

    for definition in &definitions {
        let tool = definition.to_mcp_tool();
        let mut published = vec![(tool.name.clone(), tool.input_schema)];
        if let Some(output) = tool.output_schema {
            published.push((format!("{} [outputSchema]", tool.name), output));
        }
        for (name, schema) in published {
            if let Err(err) = jsonschema::meta::validate(&schema) {
                panic!("capability tool `{name}` publishes an invalid 2020-12 schema: {err}");
            }
            let dangling = dangling_refs(&schema);
            assert!(
                dangling.is_empty(),
                "capability tool `{name}` publishes {} unresolvable $ref(s): {dangling:?}",
                dangling.len()
            );
        }
    }
}
