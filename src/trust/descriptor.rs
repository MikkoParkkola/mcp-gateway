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
/// the tool cannot be serialised whole. Every serialisation of a tool in this
/// module goes through here, so the test counter sees each one.
fn descriptor_of(tool: &Tool) -> Value {
    #[cfg(test)]
    TOOL_SERIALISATIONS.with(|n| n.set(n.get() + 1));
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

/// Projected descriptors by server id, then server name, then tool name. A
/// projection is a pure function of the server identity and the tool, and an
/// entry is reused only while the tool equals, field for field through the
/// derive, the one it was projected from. A tool changed under the same name
/// is re-projected, never served stale (MIK-7916). The identity is the whole
/// tool, not a hash: a collision would serve another tool's card.
#[derive(Default)]
struct CardMemo {
    /// (server id, server name) pairs held, bounded by `MEMO_SERVERS`.
    servers: usize,
    by_id: HashMap<String, HashMap<String, ToolCards>>,
}

/// One server identity's memo: tool name to (tool as projected, descriptor).
type ToolCards = HashMap<String, (Tool, Value)>;

// ponytail: a full map keeps its residents and computes newcomers uncached,
// so a churning catalog can lose its saving; an LRU if that ever shows.
const MEMO_SERVERS: usize = 1024;
const MEMO_TOOLS_PER_SERVER: usize = 8192;

fn card_memo() -> &'static Mutex<CardMemo> {
    static MEMO: OnceLock<Mutex<CardMemo>> = OnceLock::new();
    MEMO.get_or_init(Mutex::default)
}

impl CardMemo {
    /// The cards held for one server identity, made room for if the
    /// `MEMO_SERVERS` bound on (id, name) pairs allows; `None` when it is
    /// full and the identity is new. Looked up by `&str`, so a held identity
    /// allocates no key.
    fn cards_for(&mut self, server_id: &str, server_name: &str) -> Option<&mut ToolCards> {
        let held = self
            .by_id
            .get(server_id)
            .is_some_and(|names| names.contains_key(server_name));
        if !held {
            if self.servers >= MEMO_SERVERS {
                return None;
            }
            self.servers += 1;
        }
        let names = held_or_default(&mut self.by_id, server_id);
        Some(held_or_default(names, server_name))
    }
}

/// Project `TrustCard` references into a list of live MCP tool descriptors.
///
/// Every `tools/list` lists the same catalog, so each descriptor is projected
/// once per tool version; a repeat list compares each tool and hands back a
/// copy, with no serialisation.
#[must_use]
pub fn project_tool_descriptors_trust_cards(
    server_id: &str,
    server_name: &str,
    tools: &[Tool],
) -> Vec<Value> {
    let mut memo = card_memo().lock().unwrap_or_else(PoisonError::into_inner);
    let Some(cards) = memo.cards_for(server_id, server_name) else {
        return tools
            .iter()
            .map(|tool| project_tool_descriptor_trust_card(server_id, server_name, tool))
            .collect();
    };
    tools
        .iter()
        .map(|tool| match cards.get(&tool.name) {
            Some((seen, projected)) if same_tool(seen, tool) => projected.clone(),
            _ => {
                let projected = project_tool_descriptor_trust_card(server_id, server_name, tool);
                if cards.len() < MEMO_TOOLS_PER_SERVER || cards.contains_key(&tool.name) {
                    cards.insert(tool.name.clone(), (tool.clone(), projected.clone()));
                }
                projected
            }
        })
        .collect()
}

/// Whether a memoised projection of `seen` describes `tool`: the whole tool
/// through the derive, then the two schemas again with the sign of zero
/// compared, because `serde_json` holds `-0.0 == 0.0` while serialising and
/// digesting them apart. Maps are `BTreeMap`s (no `preserve_order`), so equal
/// maps serialise alike and need no further check.
fn same_tool(seen: &Tool, tool: &Tool) -> bool {
    seen == tool
        && same_json(&seen.input_schema, &tool.input_schema)
        && match (&seen.output_schema, &tool.output_schema) {
            (Some(a), Some(b)) => same_json(a, b),
            _ => true,
        }
}

/// `==` that also tells `-0.0` from `0.0`.
fn same_json(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            x == y && x.as_f64().map(f64::is_sign_negative) == y.as_f64().map(f64::is_sign_negative)
        }
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same_json(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, x)| y.get(key).is_some_and(|y| same_json(x, y)))
        }
        _ => a == b,
    }
}

/// `entry(key.to_owned()).or_default()` that allocates the key only when it
/// is absent, so finding a held key costs no allocation.
fn held_or_default<'a, V: Default>(map: &'a mut HashMap<String, V>, key: &str) -> &'a mut V {
    if !map.contains_key(key) {
        map.insert(key.to_owned(), V::default());
    }
    map.get_mut(key)
        .expect("present: inserted above when absent")
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
    /// Test-only: tools serialised into a descriptor on this thread.
    static TOOL_SERIALISATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn computations() -> usize {
        CARD_COMPUTATIONS.with(std::cell::Cell::get)
    }

    fn serialisations() -> usize {
        TOOL_SERIALISATIONS.with(std::cell::Cell::get)
    }

    /// MIK-7916 AC3: a repeat list serialises no tool; a changed tool is
    /// serialised exactly once. The second half keeps the first honest: a
    /// projection that never serialised anything would pass "zero" alone.
    #[test]
    fn a_hit_serialises_no_tool_and_a_miss_exactly_one() {
        let (id, name) = ("backend:memo-serialise", "memo-serialise");
        let mut tools = catalog(name);
        let _ = project_tool_descriptors_trust_cards(id, name, &tools);
        let start = serialisations();
        let _ = project_tool_descriptors_trust_cards(id, name, &tools);
        assert_eq!(serialisations() - start, 0, "a hit list serialised a tool");

        tools[2].description = Some("changed".to_string());
        let start = serialisations();
        let _ = project_tool_descriptors_trust_cards(id, name, &tools);
        assert_eq!(
            serialisations() - start,
            1,
            "one changed tool, one serialisation"
        );
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

    /// MIK-7916 review: `serde_json` numbers compare `-0.0 == 0.0` yet
    /// serialise apart, so an equality hit on that change would publish the
    /// old schema. A schema whose only change is the sign of a zero re-projects.
    #[test]
    fn a_schema_changed_only_in_the_sign_of_zero_misses_the_memo() {
        let (id, name) = ("backend:memo-signed-zero", "memo-signed-zero");
        let mut zero = tool();
        zero.input_schema["properties"]["query"]["default"] = json!(0.0);
        let mut negative = zero.clone();
        negative.input_schema["properties"]["query"]["default"] = json!(-0.0);
        let _ = project_tool_descriptors_trust_cards(id, name, std::slice::from_ref(&zero));
        let listed =
            project_tool_descriptors_trust_cards(id, name, std::slice::from_ref(&negative));
        assert_eq!(
            serde_json::to_string(&listed[0]).unwrap(),
            serde_json::to_string(&project_tool_descriptor_trust_card(id, name, &negative))
                .unwrap(),
            "the listing must serialise exactly as a fresh projection of the changed tool"
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
        let edits: [(&str, Change); 7] = [
            ("title", |t| {
                t.title = Some("Other title".to_string());
            }),
            ("description count", |t| {
                t.description = Some("Search local docs (3 servers)".to_string());
            }),
            ("input schema", |t| {
                t.input_schema["properties"]["limit"] = json!({"type": "integer"});
            }),
            ("output schema", |t| {
                t.output_schema = Some(json!({"type": "object"}));
            }),
            ("annotations hint", |t| {
                t.annotations = Some(ToolAnnotations {
                    read_only_hint: Some(true),
                    ..ToolAnnotations::default()
                });
            }),
            ("role", |t| {
                t.role = Some(Role::Selector);
            }),
            ("projection", |t| {
                t.projection = Some(ProjectionSpec {
                    actor: Some(ActorSpec::default()),
                    ..ProjectionSpec::default()
                });
            }),
        ];
        for (field, change) in edits {
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

    /// MIK-7916 review: the server bound counts (id, name) pairs, not ids,
    /// and a full memo still serves the pairs it holds. A local memo, so no
    /// other test's identities share the count.
    #[test]
    fn the_server_bound_counts_identity_pairs() {
        let mut memo = CardMemo::default();
        for i in 0..MEMO_SERVERS {
            assert!(
                memo.cards_for("backend:shared", &format!("name-{i}"))
                    .is_some(),
                "pair {i} is under the bound"
            );
        }
        assert!(
            memo.cards_for("backend:shared", "one-more").is_none(),
            "a new name under a held id is a new pair"
        );
        assert!(
            memo.cards_for("backend:other", "name-0").is_none(),
            "a new id is a new pair"
        );
        assert!(
            memo.cards_for("backend:shared", "name-0").is_some(),
            "a held pair is still served when full"
        );
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
