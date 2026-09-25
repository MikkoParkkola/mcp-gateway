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
    /// Replaces the slot even when a discovery fill is still fresh: this list
    /// is the one the caller was shown last, and it was drained in full, so it
    /// also clears the slot's truncated mark. A page fetched under a caller's
    /// own credential never lands in the shared slot, which every caller reads.
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
        // A store, not a fill: it must not depend on the slot reading as
        // stale, nor queue behind a discovery fill already on the wire.
        let _ = entry
            .tools_cache
            .get_or_fetch_shared_then(
                std::time::Duration::ZERO,
                || {
                    let tools = parsed.clone();
                    async move { Ok((tools, ())) }
                },
                |()| {
                    entry
                        .tools_truncated
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                },
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
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

    fn edit_declaring(key: &str) -> serde_json::Value {
        json!({"name": "edit", "inputSchema": {"type": "object",
            "properties": {key: {"type": "string"}}}})
    }

    /// F14a: a fully drained direct list replaces a still-fresh discovery fill
    /// in the caller's slot, so calls are judged against what the caller was
    /// last shown. A credentialed page still never reaches the shared slot.
    #[tokio::test]
    async fn a_drained_direct_list_overwrites_a_fresh_discovery_fill() {
        let backend = Backend::new(
            "edits",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        let lease = backend.begin_internal_activity_for(&crate::backend::PoolKey::Shared);
        let discovered: crate::protocol::Tool =
            serde_json::from_value(edit_declaring("a")).expect("a tool");
        lease
            .entry()
            .tools_cache
            .get_or_fetch_shared(Duration::from_secs(600), || {
                let tools = vec![discovered.clone()];
                async move { Ok(tools) }
            })
            .await
            .expect("the discovery fill");
        lease.entry().tools_truncated.store(true, Ordering::SeqCst);

        backend
            .remember_listed_tools(None, true, &[edit_declaring("b")])
            .await;
        let judged = |key: &str| backend.undeclared_key_refusal(None, "edit", &json!({key: 1}));
        assert!(
            judged("a").is_none(),
            "a credentialed page reached the shared slot"
        );
        assert!(judged("b").is_some(), "the discovery fill still stands");

        backend
            .remember_listed_tools(None, false, &[edit_declaring("b")])
            .await;
        assert!(
            judged("b").is_none(),
            "the drained list must replace the fresh discovery fill"
        );
        assert!(judged("a").is_some());
        assert!(
            !backend.cached_tools_snapshot_and_truncated().1,
            "a drained list is complete; the truncated mark must not survive it"
        );
    }

    /// F14a, item 4: the replacement is a store, not a fill that reads the
    /// slot as stale. It neither queues behind a discovery fill already on
    /// the wire nor loses to it when that fill lands afterwards.
    #[tokio::test]
    async fn a_drained_direct_list_beats_an_in_flight_discovery_fill() {
        let backend = Backend::new(
            "edits",
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        );
        let lease = backend.begin_internal_activity_for(&crate::backend::PoolKey::Shared);
        let entry = std::sync::Arc::clone(lease.entry());
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let discovered: crate::protocol::Tool =
            serde_json::from_value(edit_declaring("a")).expect("a tool");
        let fill = tokio::spawn({
            let (started, release) = (started.clone(), release.clone());
            async move {
                entry
                    .tools_cache
                    .get_or_fetch_shared(Duration::from_secs(600), || {
                        let (started, release) = (started.clone(), release.clone());
                        let tools = vec![discovered.clone()];
                        async move {
                            started.notify_one();
                            release.notified().await;
                            Ok(tools)
                        }
                    })
                    .await
            }
        });
        started.notified().await;

        tokio::time::timeout(
            Duration::from_secs(5),
            backend.remember_listed_tools(None, false, &[edit_declaring("b")]),
        )
        .await
        .expect("the direct list must not wait for an in-flight fill");
        release.notify_one();
        fill.await.expect("join").expect("the discovery fill");

        let judged = |key: &str| backend.undeclared_key_refusal(None, "edit", &json!({key: 1}));
        assert!(judged("b").is_none(), "the later-landing fill overwrote it");
        assert!(judged("a").is_some());
    }
}
