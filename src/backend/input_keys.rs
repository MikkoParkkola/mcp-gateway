// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Undeclared tool-call argument keys, judged against the caller's own
//! catalogue slot (MIK-7570.SCHEMA.1, R2).

use std::sync::Arc;

use serde_json::Value;

use super::{Backend, PoolKey};
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
            return None;
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

    /// Fill this caller's catalogue slot from a `tools/list` the direct route
    /// already drained, so the caller's later `tools/call`s are judged against
    /// what it was shown. Without this, a caller that lists only on the direct
    /// route reads a cold slot on every call and is forwarded unchecked.
    ///
    /// Fills an empty or stale slot only; a fresher discovery fill stands. A
    /// page fetched under a caller's own credential never lands in the shared
    /// slot, which every caller reads.
    pub(crate) async fn remember_listed_tools(
        &self,
        identity_key: Option<&str>,
        sent_caller_credential: bool,
        tools: &[Value],
    ) {
        let key = self.pool_key_for(identity_key);
        if matches!(key, PoolKey::Shared) && sent_caller_credential {
            return;
        }
        // Entry by entry, as `normalize_tools_list_response` reads them: one
        // malformed tool must not leave the slot cold for every other one.
        let mut parsed: Vec<crate::protocol::Tool> = tools
            .iter()
            .filter_map(|tool| serde_json::from_value(tool.clone()).ok())
            .collect();
        // The same normalisation a discovery fill applies; the resend set it
        // returns stays with discovery, so this fill grants no retries.
        let _ = super::prepare_tool_metadata(&self.name, &mut parsed);
        let lease = self.begin_internal_activity_for(&key);
        let entry = Arc::clone(lease.entry());
        let _ = entry
            .tools_cache
            .get_or_fetch_shared_then(
                self.cache_ttl,
                || {
                    let tools = parsed.clone();
                    async move { Ok((tools, ())) }
                },
                |()| {},
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};

    /// One malformed entry in a drained `tools/list` must not leave the slot
    /// cold: the valid tool beside it is still judged, so its invented key is
    /// refused rather than forwarded unchecked.
    #[tokio::test]
    async fn a_malformed_listed_tool_does_not_leave_the_slot_cold() {
        let backend = Backend::new(
            "edits",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        let listed = [
            json!({"name": 5, "inputSchema": "not a schema"}),
            json!({"name": "edit", "inputSchema": {"type": "object",
                "properties": {"a": {"type": "string"}}}}),
        ];
        backend.remember_listed_tools(None, false, &listed).await;
        let refusal = backend.undeclared_key_refusal(None, "edit", &json!({"b": 1}));
        assert!(refusal.is_some(), "the valid tool was not remembered");
    }
}
