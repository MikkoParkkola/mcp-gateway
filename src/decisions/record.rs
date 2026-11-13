// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The note a deny writes into the transparency log, and its reading back.
//!
//! It goes in the log that holds the refusals it closes, so both leave at the
//! same retention edge: a deny never outlives, or is outlived by, the
//! refusals it covers. One note carries every open capability of the request
//! with the exact refusal positions the admin was shown.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::items::OpenRequest;
use super::{LogPos, Source, UiDecision};

/// The record kind of a UI decision in the transparency log.
pub(crate) const UI_DECISION_KIND: &str = "ui_decision";

/// The decision a deny records.
const DECLINE: &str = "decline";

/// The same deny of the same refusals is the same id, from any process: a
/// SHA-256 over a domain separator, the subject and agent, and every
/// (capability, position), sorted, each field length-prefixed.
pub(crate) fn event_id(request: &OpenRequest) -> String {
    let mut parts: Vec<(&str, &str, u64)> = request
        .entries
        .iter()
        .flat_map(|(capability, positions)| {
            positions
                .iter()
                .map(move |pos| (capability.as_str(), pos.entry.as_str(), pos.counter))
        })
        .collect();
    parts.sort_unstable();
    parts.dedup();
    let mut bytes = b"mcpg/ui-decision/decline/v1\0".to_vec();
    let mut field = |text: &str| {
        bytes.extend((text.len() as u64).to_be_bytes());
        bytes.extend(text.as_bytes());
    };
    field(&request.authority);
    field(&request.subject);
    field(&request.agent);
    for (capability, entry, counter) in &parts {
        field(capability);
        field(entry);
        field(&counter.to_string());
    }
    crate::hashing::sha256_hex(&bytes)
}

/// The note's fields for a deny of `request` with `reason`, at the scope
/// `digest` the admin saw. The logger adds the principal and the chain.
pub(crate) fn record_fields(
    request: &OpenRequest,
    reason: &str,
    digest: &str,
    id: &str,
    at: DateTime<Utc>,
) -> Map<String, Value> {
    let entries: Vec<Value> = request
        .entries
        .iter()
        .map(|(capability, positions)| {
            json!({
                "capability": capability,
                "positions": positions
                    .iter()
                    .map(|pos| json!({"entry": pos.entry, "counter": pos.counter}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut fields = Map::new();
    for (key, value) in [
        ("kind", json!(UI_DECISION_KIND)),
        ("event_id", json!(id)),
        ("timestamp", json!(at.to_rfc3339())),
        ("decision", json!(DECLINE)),
        ("authority", json!(request.authority)),
        ("subject", json!(request.subject)),
        ("agent", json!(request.agent)),
        ("reason", json!(reason)),
        ("request_digest", json!(digest)),
        ("entries", Value::Array(entries)),
    ] {
        fields.insert(key.to_owned(), value);
    }
    fields
}

/// What a deny of `request` folds into the set: one decision per open
/// capability, each closing exactly its positions.
pub(crate) fn decisions_of(request: &OpenRequest) -> Vec<UiDecision> {
    request
        .entries
        .iter()
        .map(|(capability, positions)| UiDecision {
            authority: request.authority.clone(),
            subject: request.subject.clone(),
            agent: request.agent.clone(),
            capability: capability.clone(),
            closes: positions.iter().cloned().collect(),
        })
        .collect()
}

/// A written deny read back into its decisions, live or replayed alike;
/// `None` for a record that is not a well-formed decline.
pub(crate) fn decisions_from_record(record: &Map<String, Value>) -> Option<Vec<UiDecision>> {
    let text = |key: &str| record.get(key).and_then(Value::as_str);
    if text("decision")? != DECLINE {
        return None;
    }
    let (authority, subject, agent) = (text("authority")?, text("subject")?, text("agent")?);
    let entries = record.get("entries")?.as_array()?;
    if entries.is_empty() {
        return None;
    }
    entries
        .iter()
        .map(|entry| {
            let positions: Option<BTreeSet<LogPos>> = entry
                .get("positions")?
                .as_array()?
                .iter()
                .map(|pos| {
                    Some(LogPos {
                        log: Source::Access,
                        entry: pos.get("entry")?.as_str()?.to_owned(),
                        counter: pos.get("counter")?.as_u64()?,
                    })
                })
                .collect();
            let positions = positions?;
            if positions.is_empty() {
                return None;
            }
            Some(UiDecision {
                authority: authority.to_owned(),
                subject: subject.to_owned(),
                agent: agent.to_owned(),
                capability: entry.get("capability")?.as_str()?.to_owned(),
                closes: positions,
            })
        })
        .collect()
}
