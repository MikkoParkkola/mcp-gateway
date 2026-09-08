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
            schemas.push((
                format!("{mode}/{} [inputSchema]", tool.name),
                tool.input_schema,
            ));
            // Both schema fields are published to a client, so both are in the
            // population. Only some tools declare an `outputSchema`.
            if let Some(output) = tool.output_schema {
                schemas.push((format!("{mode}/{} [outputSchema]", tool.name), output));
            }
        }
    }

    // Enumerate all 19 published names across both modes, including webhook
    // status when the operational fixture attaches its registry. Equality
    // prevents a newly published schema from silently escaping validation.
    let mut published: Vec<&str> = names.iter().map(String::as_str).collect();
    published.sort_unstable();
    assert_eq!(
        published,
        [
            "code_mode/gateway_execute",
            "code_mode/gateway_search",
            "traditional/gateway_cost_report",
            "traditional/gateway_get_profile",
            "traditional/gateway_get_stats",
            "traditional/gateway_invoke",
            "traditional/gateway_kill_server",
            "traditional/gateway_list_disabled_capabilities",
            "traditional/gateway_list_profiles",
            "traditional/gateway_list_servers",
            "traditional/gateway_list_tools",
            "traditional/gateway_reload_capabilities",
            "traditional/gateway_reload_config",
            "traditional/gateway_revive_server",
            "traditional/gateway_run_playbook",
            "traditional/gateway_search_tools",
            "traditional/gateway_set_profile",
            "traditional/gateway_set_state",
            "traditional/gateway_webhook_status",
        ],
        "the enumerated surface is not the 19 published `gateway_*` \
         definitions: either the fixture stopped enabling the real surface, or \
         a published definition was added or retired without updating this list"
    );

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
///
/// The walk itself lives in `src/trust/schema_bounds.rs` and is the SAME code
/// the gateway runs while publishing a descriptor. One walker decides for both,
/// so a schema these tests call bounded cannot be one the gateway publishes
/// unbounded.
fn dangling_refs(schema: &serde_json::Value) -> Vec<String> {
    mcp_gateway::trust::unresolved_refs(schema)
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
        let mut published = vec![(format!("{} [inputSchema]", tool.name), tool.input_schema)];
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

/// The keywords by which a schema is built out of subschemas. The criterion's
/// own evidence names `allOf`, `anyOf` and `oneOf`; `not` and the
/// `if`/`then`/`else` trio compose in exactly the same way, so the walk covers
/// the family rather than the three the sentence happened to list. Widening it
/// costs nothing while the observed count is zero, and a narrower list would
/// have to be widened by whoever first meets a conditional schema.
const COMPOSITION_KEYWORDS: [&str; 7] = ["allOf", "anyOf", "oneOf", "not", "if", "then", "else"];

/// Returns the JSON-pointer position of every composition keyword in `schema`,
/// at any depth. An empty result means the document is a flat schema: its
/// constraints are stated directly, not assembled from subschemas.
fn composition_sites(schema: &serde_json::Value) -> Vec<String> {
    fn walk(node: &serde_json::Value, at: &str, found: &mut Vec<String>) {
        match node {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let here = format!("{at}/{}", key.replace('~', "~0").replace('/', "~1"));
                    if COMPOSITION_KEYWORDS.contains(&key.as_str()) {
                        found.push(here.clone());
                    }
                    walk(child, &here, found);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{at}/{i}"), found);
                }
            }
            _ => {}
        }
    }

    let mut found = Vec::new();
    walk(schema, "", &mut found);
    found
}

/// Records what the emitted first-party surface actually contains, and guards
/// it.
///
/// This asserts an OBSERVATION, not a bound. What "the revision's $ref and
/// composition bounds" permits is an open question (U9 in the cluster-G test
/// plan under `docs/design/`), and a test that answered it would be settling a
/// scheduled unknown by assertion. What is checkable today is that no
/// published Meta-MCP schema composes at all — so 2020-12 validity plus `$ref`
/// resolution is the whole of the surface this criterion can currently
/// observe. The day this row goes red, U9 has to be answered before that
/// schema ships.
#[test]
fn no_meta_mcp_schema_composes_subschemas_today() {
    for (name, schema) in all_meta_tool_schemas() {
        let sites = composition_sites(&schema);
        assert!(
            sites.is_empty(),
            "tool `{name}` composes subschemas at {sites:?}; the bound this must stay within \
             is unresolved (U9), so this schema cannot be published until it is answered"
        );
    }
}

/// The capability catalogue is the other half of the first-party population,
/// and it is the larger half: 110+ definitions against 19 hand-written ones.
#[tokio::test]
async fn no_capability_schema_composes_subschemas_today() {
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
        let mut published = vec![(format!("{} [inputSchema]", tool.name), tool.input_schema)];
        if let Some(output) = tool.output_schema {
            published.push((format!("{} [outputSchema]", tool.name), output));
        }
        for (name, schema) in published {
            let sites = composition_sites(&schema);
            assert!(
                sites.is_empty(),
                "capability tool `{name}` composes subschemas at {sites:?}; the bound this \
                 must stay within is unresolved (U9)"
            );
        }
    }
}

/// Falsifier for the two rows above, and it is load-bearing for the same
/// reason the `$ref` falsifier is: both assertions pass over an empty set
/// today, so a walker that reported nothing for every input would look
/// identical.
#[test]
fn falsifier_a_composed_subschema_is_reported_by_the_same_walker() {
    let flat = serde_json::json!({
        "type": "object",
        "properties": { "query": { "type": "string" } }
    });
    assert!(
        composition_sites(&flat).is_empty(),
        "a flat schema must not be reported, or the check flags everything"
    );

    // Nested: a schema that composes below the root is the shape a hand-edit
    // would most plausibly introduce.
    let composed = serde_json::json!({
        "type": "object",
        "properties": {
            "target": { "allOf": [{ "type": "string" }, { "minLength": 1 }] }
        }
    });
    assert_eq!(
        composition_sites(&composed),
        vec!["/properties/target/allOf".to_string()],
        "a nested `allOf` must be reported, at its position"
    );

    for keyword in COMPOSITION_KEYWORDS {
        let one = serde_json::json!({ keyword: { "type": "string" } });
        assert_eq!(
            composition_sites(&one),
            vec![format!("/{keyword}")],
            "`{keyword}` is in the keyword set but the walker does not report it"
        );
    }
}

/// The population is closed at the projection, and this is what says so.
///
/// `MetaMcp::handle_tools_list_for_session` appends every configured surfaced
/// tool to the emitted list, resolving it through `Backend::get_cached_tool`
/// (see `src/gateway/meta_mcp/surfaced.rs`) — a `Tool` deserialized verbatim
/// from a connected MCP server's own `tools/list` reply — and projects it with
/// the same `project_tool_descriptor_trust_card` used for the gateway's own
/// definitions, as does the direct backend proxy
/// (`src/gateway/router/backend_handlers.rs`). The two rows above can only
/// constrain the schemas this repository WRITES; searching the tree cannot
/// find the FORWARDED population, because it does not exist in the tree. So
/// the bound is established where every route passes: the projection inspects
/// the schema it is about to publish and records the verdict beside it.
///
/// AC1 (an unresolved local `$ref` from a backend is reported) and AC3 (the
/// published schema is judged, never altered) of
/// `docs/design/2026-09-07-schema-1c-forwarded-schema-bounds-test-plan.md`.
#[test]
fn a_backend_forwarded_schema_is_inspected_before_it_reaches_the_client() {
    // Exactly what a remote server sends, deserialized the way the backend
    // tool cache deserializes it.
    let from_backend: mcp_gateway::protocol::Tool = serde_json::from_value(serde_json::json!({
        "name": "remote_tool",
        "description": "a tool this repository did not write",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "allOf": [{ "$ref": "#/$defs/Absent" }, { "type": "string" }]
                }
            }
        }
    }))
    .expect("a backend tool descriptor must deserialize");

    let emitted = mcp_gateway::trust::project_tool_descriptor_trust_card(
        "backend:remote",
        "remote",
        &from_backend,
    );
    let schema = emitted
        .get("inputSchema")
        .expect("the projection must publish the tool's inputSchema");

    assert_eq!(
        emitted["trustCard"]["schemaBounds"],
        serde_json::json!({
            "status": "outOfBounds",
            "unresolvedRefs": ["#/$defs/Absent"],
        }),
        "the projection must name the backend's unresolvable $ref on the descriptor it publishes"
    );

    // AC3: judged, not altered. The backend's own schema still reaches the
    // client byte for byte — composition included, which is legal 2020-12 and
    // is observed here, never bounded.
    assert_eq!(
        composition_sites(schema),
        vec!["/properties/target/allOf".to_string()],
        "the composition the backend sent must reach the client untouched"
    );
    assert_eq!(
        dangling_refs(schema),
        vec!["#/$defs/Absent".to_string()],
        "the inspection must not drop, rewrite or sanitize the forwarded schema"
    );
}

/// AC2: the inspector reports UNRESOLVED pointers, not every pointer.
///
/// Without this row a walker that flagged each `$ref` it met would satisfy the
/// row above and be wrong about every legitimate backend that uses `$defs`.
#[test]
fn a_forwarded_schema_whose_local_ref_resolves_is_within_bounds() {
    let from_backend: mcp_gateway::protocol::Tool = serde_json::from_value(serde_json::json!({
        "name": "remote_tool",
        "description": "a tool this repository did not write",
        "inputSchema": {
            "type": "object",
            "$defs": { "Target": { "type": "string" } },
            "properties": { "target": { "$ref": "#/$defs/Target" } }
        }
    }))
    .expect("a backend tool descriptor must deserialize");

    let emitted = mcp_gateway::trust::project_tool_descriptor_trust_card(
        "backend:remote",
        "remote",
        &from_backend,
    );

    assert_eq!(
        emitted["trustCard"]["schemaBounds"],
        serde_json::json!({ "status": "within" }),
        "a $ref that resolves in its own document is within the revision's bounds"
    );
}
