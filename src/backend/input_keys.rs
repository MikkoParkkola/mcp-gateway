// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Undeclared tool-call argument keys, judged against the caller's own
//! catalogue slot (MIK-7570.SCHEMA.1, R2).

use std::sync::Arc;

use serde_json::Value;

use super::fill_check::{
    Completeness, TEXT_UNAVAILABLE, is_transport_failure, text_absent, text_partial,
};
use super::{Backend, PoolKey};
use crate::config::InputSchemaEnforcement;
use crate::trust::closed_keys::count;

/// A miss the check cannot judge: `closed` refuses with `text`, counted by
/// `labels[0]`; `standard` forwards, counted by `labels[1]`.
fn miss(
    mode: InputSchemaEnforcement,
    labels: [&'static str; 2],
    text: impl FnOnce() -> String,
) -> Option<String> {
    if mode == InputSchemaEnforcement::Closed {
        count(labels[0]);
        Some(text())
    } else {
        count(labels[1]);
        None
    }
}

/// The schema could not be read (design §2 step 4, first column).
fn unavailable(mode: InputSchemaEnforcement) -> Option<String> {
    miss(
        mode,
        ["input_schema_refused_unavailable", "input_schema_unknown"],
        || TEXT_UNAVAILABLE.to_owned(),
    )
}

impl Backend {
    /// Refusal text for a `tools/call` whose arguments carry keys the tool's
    /// `inputSchema` does not declare, or `None` when the call may proceed.
    ///
    /// The schema comes from THIS caller's slot only: a "valid parameters"
    /// list built from another caller's catalogue would disclose it. When the
    /// slot does not hold the tool, F13 fetches the caller's own catalogue
    /// once, as the caller, through the slot's single-flight fill
    /// ([`Self::tools_for_check`]), then applies the mode table: `closed`
    /// refuses what it cannot vouch for (texts U, P, A), `standard` forwards
    /// and counts, `off` returns before any fetch. A3: a `Shared` slot is
    /// fetched only for a caller that sent no credential, since the shared
    /// fill runs under the gateway's own login.
    ///
    /// # Errors
    ///
    /// The slot's own `CircuitOpen` or `RateLimited` when its failsafe
    /// refused the fill, and under `closed` the fill's transport error when
    /// the backend could not be reached (A3): the call gets the error a
    /// refused or failed dispatch gets.
    pub(crate) async fn undeclared_key_refusal(
        &self,
        identity_key: Option<&str>,
        headers: &[(String, String)],
        tool: &str,
        arguments: &Value,
    ) -> crate::Result<Option<String>> {
        let mode = self.config.input_schema_enforcement;
        if mode == InputSchemaEnforcement::Off {
            return Ok(None);
        }
        if let Some(cached) = self.get_cached_tool_for(identity_key, tool) {
            return Ok(self.judge_keys(&cached.input_schema, tool, arguments, mode));
        }
        if !self.fetch_carries_caller_identity(identity_key) && !headers.is_empty() {
            count("input_schema_fetch_skipped_a3");
            return Ok(unavailable(mode));
        }
        let (tools, completeness) = match self.tools_for_check(identity_key, headers).await {
            Ok(fetched) => fetched,
            // Raised only by the fill's own failsafe gate: no transport
            // constructs either variant.
            Err(e @ (crate::Error::CircuitOpen { .. } | crate::Error::RateLimited(_))) => {
                return Err(e);
            }
            // A3: under `closed`, a backend that could not be reached answers
            // as a failed dispatch would (and is accounted as one). A cooldown
            // fast-fail answers as the failure it stands in for. `standard`
            // forwards, and the dispatch then fails on its own.
            Err(e)
                if mode == InputSchemaEnforcement::Closed
                    && is_transport_failure(&e)
                    && !self.cooling_after_unreadable_list(identity_key) =>
            {
                return Err(e);
            }
            Err(_) => return Ok(unavailable(mode)),
        };
        if let Some(found) = tools.iter().find(|t| t.name == tool) {
            return Ok(self.judge_keys(&found.input_schema, tool, arguments, mode));
        }
        Ok(match completeness {
            Completeness::Complete => miss(
                mode,
                ["input_schema_refused_absent", "input_schema_absent_forward"],
                || text_absent(tool),
            ),
            Completeness::Truncated => miss(
                mode,
                [
                    "input_schema_refused_truncated",
                    "input_schema_truncated_forward",
                ],
                text_partial,
            ),
            Completeness::Unknown => unavailable(mode),
        })
    }

    fn judge_keys(
        &self,
        schema: &Value,
        tool: &str,
        arguments: &Value,
        mode: InputSchemaEnforcement,
    ) -> Option<String> {
        let empty = Value::Object(serde_json::Map::new());
        let arguments = if arguments.is_null() {
            &empty
        } else {
            arguments
        };
        let refusal = crate::capability::undeclared_key_refusal(arguments, schema, mode)?;
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
        entry.tools_cache.replace(parsed, || {
            entry
                .tools_truncated
                .store(false, std::sync::atomic::Ordering::SeqCst);
        });
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
        let refusal = backend
            .undeclared_key_refusal(None, &[], "edit", &json!({"b": 1}))
            .await;
        assert!(
            refusal.expect("no failsafe refusal").is_some(),
            "the valid tool was not remembered"
        );
    }

    /// The check on `edit` with one argument `key`, on a warm shared slot.
    async fn judged(backend: &Backend, key: &str) -> Option<String> {
        backend
            .undeclared_key_refusal(None, &[], "edit", &json!({key: 1}))
            .await
            .expect("no failsafe refusal")
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
        assert!(
            judged(&backend, "a").await.is_none(),
            "a credentialed page reached the shared slot"
        );
        assert!(
            judged(&backend, "b").await.is_some(),
            "the discovery fill still stands"
        );

        backend
            .remember_listed_tools(None, false, &[edit_declaring("b")])
            .await;
        assert!(
            judged(&backend, "b").await.is_none(),
            "the drained list must replace the fresh discovery fill"
        );
        assert!(judged(&backend, "a").await.is_some());
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

        assert!(
            judged(&backend, "b").await.is_none(),
            "the later-landing fill overwrote it"
        );
        assert!(judged(&backend, "a").await.is_some());
    }
}
