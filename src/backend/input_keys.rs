// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Undeclared tool-call argument keys, judged against the caller's own
//! catalogue slot (MIK-7570.SCHEMA.1, R2).

use serde_json::Value;

use super::Backend;
use crate::config::InputSchemaEnforcement;

impl Backend {
    /// Refusal text for a `tools/call` whose arguments carry keys the tool's
    /// `inputSchema` does not declare, or `None` when the call may proceed.
    ///
    /// The schema comes from THIS caller's slot only: a "valid parameters"
    /// list built from another caller's catalogue would disclose it. A tool
    /// the slot does not hold is forwarded unchecked and counted, because the
    /// gateway cannot enforce a contract it has not been shown, and fetching
    /// `tools/list` under a request is ruled out (`ops.rs`).
    #[must_use]
    pub(crate) fn undeclared_key_refusal(
        &self,
        identity_key: Option<&str>,
        tool: &str,
        arguments: &Value,
    ) -> Option<String> {
        let mode = self.config.input_schema_enforcement;
        if mode == InputSchemaEnforcement::Off {
            return None;
        }
        let Some(cached) = self.get_cached_tool_for(identity_key, tool) else {
            crate::trust::closed_keys::count("input_schema_unknown");
            return Some("schema unknown".to_owned());
        };
        let empty = Value::Object(serde_json::Map::new());
        let arguments = if arguments.is_null() {
            &empty
        } else {
            arguments
        };
        let refusal =
            crate::capability::undeclared_key_refusal(arguments, &cached.input_schema, mode)?;
        tracing::warn!(
            backend = %self.name,
            tool = %tool,
            "tool call refused: undeclared argument keys"
        );
        Some(refusal)
    }
}
