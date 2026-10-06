// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustCard` projection helpers for live MCP tool descriptors.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    hashing::canonical_json_sha256,
    protocol::Tool,
    trust::{SchemaBounds, TrustCard, TrustEvaluationStatus},
};

/// Wire key for the additive MCP tool descriptor extension.
pub const TOOL_DESCRIPTOR_TRUST_CARD_KEY: &str = "trustCard";

/// Digest-only `TrustCard` reference embedded into live tool descriptors.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptorTrustCard {
    /// `TrustCard` schema version used to compute the digest.
    pub schema_version: String,
    /// Stable gateway-local server identifier.
    pub server_id: String,
    /// Tool name from the live descriptor.
    pub tool_name: String,
    /// Canonical SHA-256 digest of the validated `TrustCard` JSON.
    pub trust_card_digest_sha256: String,
    /// Canonical SHA-256 digest of the CBOM section.
    pub cbom_digest_sha256: String,
    /// Validation status for the generated local `TrustCard`.
    pub evaluation_status: TrustEvaluationStatus,
    /// Whether every `$ref` in the published `inputSchema` resolves inside it.
    ///
    /// Inspected, never enforced: the descriptor is published exactly as the
    /// backend sent it and the verdict travels beside it. Bounds `$ref`
    /// resolution ONLY — see [`SchemaBounds`] for what is deliberately not
    /// checked.
    pub schema_bounds: SchemaBounds,
}

impl ToolDescriptorTrustCard {
    /// Build a descriptor reference from one live protocol tool.
    #[must_use]
    pub fn from_tool(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        tool: &Tool,
    ) -> Self {
        let card = TrustCard::from_tool(server_name, tool).with_validation();
        Self {
            schema_version: card.schema_version.clone(),
            server_id: server_id.into(),
            tool_name: tool.name.clone(),
            trust_card_digest_sha256: trust_card_digest_sha256(&card),
            cbom_digest_sha256: cbom_digest_sha256(&card),
            evaluation_status: card.evaluation_status,
            schema_bounds: SchemaBounds::inspect_descriptor(
                &tool.input_schema,
                tool.output_schema.as_ref(),
            ),
        }
    }
}

/// Return the canonical digest used by descriptor and control-plane references.
#[must_use]
pub fn trust_card_digest_sha256(card: &TrustCard) -> String {
    let json_value = serde_json::to_value(card).unwrap_or(Value::Null);
    canonical_json_sha256(&json_value)
}

/// Return the canonical digest of the CBOM section.
#[must_use]
pub fn cbom_digest_sha256(card: &TrustCard) -> String {
    let json_value = serde_json::to_value(&card.cbom).unwrap_or(Value::Null);
    canonical_json_sha256(&json_value)
}

/// Project a `TrustCard` reference into one live MCP tool descriptor.
#[must_use]
pub fn project_tool_descriptor_trust_card(
    server_id: impl Into<String>,
    server_name: impl Into<String>,
    tool: &Tool,
) -> Value {
    with_card(
        descriptor_of(tool),
        computed_card(server_id, server_name, tool),
    )
}

/// The tool as published; the fallback keeps the two required fields when
/// the tool cannot be serialised whole.
fn descriptor_of(tool: &Tool) -> Value {
    serde_json::to_value(tool).unwrap_or_else(|_| {
        json!({
            "name": tool.name.clone(),
            "inputSchema": tool.input_schema.clone(),
        })
    })
}

fn computed_card(
    server_id: impl Into<String>,
    server_name: impl Into<String>,
    tool: &Tool,
) -> Value {
    #[cfg(test)]
    CARD_COMPUTATIONS.with(|n| n.set(n.get() + 1));
    let trust_card = ToolDescriptorTrustCard::from_tool(server_id, server_name, tool);
    serde_json::to_value(trust_card).unwrap_or(Value::Null)
}

fn with_card(mut descriptor: Value, card: Value) -> Value {
    if let Value::Object(object) = &mut descriptor {
        object.insert(TOOL_DESCRIPTOR_TRUST_CARD_KEY.to_string(), card);
    }
    descriptor
}

/// Computed references by server identity, then tool name. A reference is a
/// pure function of the server identity and the tool, and an entry is reused
/// only while the tool serialises to exactly the descriptor it was computed
/// from, so a tool changed under the same name is recomputed, never served
/// stale (MIK-7916).
type CardMemo = HashMap<(String, String), HashMap<String, (Value, Value)>>;

// ponytail: a full map keeps its residents and computes newcomers uncached,
// so a churning catalog can lose its saving; an LRU if that ever shows.
const MEMO_SERVERS: usize = 1024;
const MEMO_TOOLS_PER_SERVER: usize = 8192;

fn card_memo() -> &'static Mutex<CardMemo> {
    static MEMO: OnceLock<Mutex<CardMemo>> = OnceLock::new();
    MEMO.get_or_init(Mutex::default)
}

/// Project `TrustCard` references into a list of live MCP tool descriptors.
///
/// Every `tools/list` lists the same catalog, so each reference is computed
/// once per tool version rather than once per request.
#[must_use]
pub fn project_tool_descriptors_trust_cards(
    server_id: &str,
    server_name: &str,
    tools: &[Tool],
) -> Vec<Value> {
    let mut memo = card_memo().lock().unwrap_or_else(PoisonError::into_inner);
    let key = (server_id.to_string(), server_name.to_string());
    if memo.len() >= MEMO_SERVERS && !memo.contains_key(&key) {
        return tools
            .iter()
            .map(|tool| project_tool_descriptor_trust_card(server_id, server_name, tool))
            .collect();
    }
    let cards = memo.entry(key).or_default();
    tools
        .iter()
        .map(|tool| {
            let Ok(descriptor) = serde_json::to_value(tool) else {
                return project_tool_descriptor_trust_card(server_id, server_name, tool);
            };
            let card = match cards.get(&tool.name) {
                Some((seen, card)) if *seen == descriptor => card.clone(),
                _ => {
                    let card = computed_card(server_id, server_name, tool);
                    if cards.len() < MEMO_TOOLS_PER_SERVER || cards.contains_key(&tool.name) {
                        cards.insert(tool.name.clone(), (descriptor.clone(), card.clone()));
                    }
                    card
                }
            };
            with_card(descriptor, card)
        })
        .collect()
}

/// Build a JSON-RPC `tools/list` result with projected `TrustCard` references.
#[must_use]
pub fn tools_list_result_with_trust_cards(tools: Vec<Value>) -> Value {
    let mut result = serde_json::Map::new();
    result.insert("tools".to_string(), Value::Array(tools));
    Value::Object(result)
}

#[cfg(test)]
thread_local! {
    /// Test-only: `TrustCard` references computed on this thread.
    static CARD_COMPUTATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn computations() -> usize {
        CARD_COMPUTATIONS.with(std::cell::Cell::get)
    }

    /// A catalog under a server identity no other test uses, so a shared
    /// memo cannot have seen it.
    fn catalog(server: &str) -> Vec<Tool> {
        (0..3)
            .map(|i| Tool {
                name: format!("{server}_tool_{i}"),
                description: Some(format!("tool {i}")),
                ..tool()
            })
            .collect()
    }

    /// MIK-7916 AC1: an unchanged catalog computes each reference once; a
    /// changed tool is recomputed, and only that one.
    #[test]
    fn unchanged_catalog_computes_each_card_once() {
        let (id, name) = ("backend:memo-once", "memo-once");
        let mut tools = catalog(name);
        let start = computations();
        let first = project_tool_descriptors_trust_cards(id, name, &tools);
        let second = project_tool_descriptors_trust_cards(id, name, &tools);
        assert_eq!(first, second);
        assert_eq!(
            computations() - start,
            tools.len(),
            "one computation per tool, not per list"
        );

        tools[1].description = Some("changed".to_string());
        let third = project_tool_descriptors_trust_cards(id, name, &tools);
        assert_eq!(
            computations() - start,
            tools.len() + 1,
            "only the changed tool is recomputed"
        );
        assert_ne!(
            third[1]["trustCard"], first[1]["trustCard"],
            "a changed tool gets a new card"
        );
        assert_eq!(third[0], first[0]);
    }

    /// MIK-7916 AC2: whatever is reused, the projection equals a fresh
    /// per-tool computation, digests included.
    #[test]
    fn memoised_projection_equals_a_fresh_one() {
        let (id, name) = ("backend:memo-fresh", "memo-fresh");
        let tools = catalog(name);
        for _ in 0..2 {
            let listed = project_tool_descriptors_trust_cards(id, name, &tools);
            for (descriptor, tool) in listed.iter().zip(&tools) {
                assert_eq!(
                    descriptor,
                    &project_tool_descriptor_trust_card(id, name, tool)
                );
            }
        }
    }

    /// MIK-7916 review: a server over the per-server bound keeps its resident
    /// cards; an unchanged list recomputes only the tools that did not fit.
    #[test]
    fn a_catalog_over_the_bound_recomputes_only_the_overflow() {
        let (id, name) = ("backend:memo-overflow", "memo-overflow");
        let tools: Vec<Tool> = (0..=MEMO_TOOLS_PER_SERVER)
            .map(|i| Tool {
                name: format!("{name}_tool_{i}"),
                ..tool()
            })
            .collect();
        let _ = project_tool_descriptors_trust_cards(id, name, &tools);
        let start = computations();
        let _ = project_tool_descriptors_trust_cards(id, name, &tools);
        assert_eq!(computations() - start, 1, "only the overflow tool");
    }

    /// MIK-7916 review: identities that concatenate alike stay apart; a NUL
    /// inside one must not let another server's card be reused.
    #[test]
    fn identities_that_join_alike_do_not_share_a_card() {
        let tools = catalog("memo-nul");
        let _ = project_tool_descriptors_trust_cards("backend:x\0y", "memo-nul", &tools);
        let other = project_tool_descriptors_trust_cards("backend:x", "y\0memo-nul", &tools);
        assert_eq!(
            other[0],
            project_tool_descriptor_trust_card("backend:x", "y\0memo-nul", &tools[0])
        );
    }

    /// MIK-7916 AC3: the memo is keyed on the whole tool. A change to any one
    /// field, however small, misses and re-projects; a hand-picked subset of
    /// fields would serve a card computed for other content.
    #[test]
    fn a_change_to_any_single_field_misses_the_memo() {
        use crate::projection::{ActorSpec, ProjectionSpec, Role};
        use crate::protocol::ToolAnnotations;

        type Change = fn(&mut Tool);
        let changes: [(&str, Change); 7] = [
            ("title", |t| t.title = Some("Other title".to_string())),
            ("description count", |t| {
                t.description = Some("Search local docs (3 servers)".to_string());
            }),
            ("input schema", |t| {
                t.input_schema["properties"]["limit"] = json!({"type": "integer"});
            }),
            ("output schema", |t| {
                t.output_schema = Some(json!({"type": "object"}))
            }),
            ("annotations hint", |t| {
                t.annotations = Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    ..ToolAnnotations::default()
                });
            }),
            ("role", |t| t.role = Some(Role::Selector)),
            ("projection", |t| {
                t.projection = Some(ProjectionSpec {
                    actor: Some(ActorSpec::default()),
                    ..ProjectionSpec::default()
                });
            }),
        ];
        for (field, change) in changes {
            let (id, name) = (
                format!("backend:memo-field-{field}"),
                format!("memo-field-{field}"),
            );
            let original = tool();
            let _ =
                project_tool_descriptors_trust_cards(&id, &name, std::slice::from_ref(&original));
            let mut changed = original.clone();
            change(&mut changed);
            let start = computations();
            let listed =
                project_tool_descriptors_trust_cards(&id, &name, std::slice::from_ref(&changed));
            assert_eq!(
                computations() - start,
                1,
                "{field}: a changed tool must re-project"
            );
            assert_eq!(
                listed[0],
                project_tool_descriptor_trust_card(id.as_str(), name.as_str(), &changed),
                "{field}: the listing must describe the changed tool"
            );
        }
    }

    /// The same tool under another server identity is a different card.
    #[test]
    fn server_identity_is_part_of_the_key() {
        let tools = catalog("memo-identity");
        let a = project_tool_descriptors_trust_cards("backend:a", "memo-identity-a", &tools);
        let b = project_tool_descriptors_trust_cards("backend:b", "memo-identity-b", &tools);
        assert_ne!(a[0]["trustCard"]["serverId"], b[0]["trustCard"]["serverId"]);
        assert_eq!(
            b[0],
            project_tool_descriptor_trust_card("backend:b", "memo-identity-b", &tools[0])
        );
    }

    fn tool() -> Tool {
        Tool {
            name: "search_docs".to_string(),
            title: Some("Search docs".to_string()),
            description: Some("Search local docs".to_string()),
            input_schema: json!({"type": "object", "properties": {"query": {"type": "string"}}}),
            output_schema: None,
            annotations: None,
            role: None,
            projection: None,
        }
    }

    #[test]
    fn project_tool_descriptor_adds_digest_only_trust_card_ref() {
        let descriptor = project_tool_descriptor_trust_card("backend:docs", "docs", &tool());

        assert_eq!(descriptor["name"], "search_docs");
        assert_eq!(descriptor["trustCard"]["schemaVersion"], "trust_card.v1");
        assert_eq!(descriptor["trustCard"]["serverId"], "backend:docs");
        assert_eq!(descriptor["trustCard"]["toolName"], "search_docs");
        assert_eq!(
            descriptor["trustCard"]["trustCardDigestSha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            descriptor["trustCard"]["cbomDigestSha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
}
