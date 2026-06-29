//! `TrustCard` projection helpers for live MCP tool descriptors.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    hashing::canonical_json_sha256,
    protocol::Tool,
    trust::{TrustCard, TrustEvaluationStatus},
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
    let trust_card = ToolDescriptorTrustCard::from_tool(server_id, server_name, tool);
    let mut descriptor = serde_json::to_value(tool).unwrap_or_else(|_| {
        json!({
            "name": tool.name.clone(),
            "inputSchema": tool.input_schema.clone(),
        })
    });

    if let Value::Object(object) = &mut descriptor {
        object.insert(
            TOOL_DESCRIPTOR_TRUST_CARD_KEY.to_string(),
            serde_json::to_value(trust_card).unwrap_or(Value::Null),
        );
    }

    descriptor
}

/// Project `TrustCard` references into a list of live MCP tool descriptors.
#[must_use]
pub fn project_tool_descriptors_trust_cards(
    server_id: &str,
    server_name: &str,
    tools: &[Tool],
) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| project_tool_descriptor_trust_card(server_id, server_name, tool))
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
mod tests {
    use serde_json::json;

    use super::*;

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
