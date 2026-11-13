// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decline a deny records in the governance audit log, and its reading
//! back.
//!
//! One record carries every open capability of the request with the exact
//! refusal positions the admin was shown, so a later refusal of the same
//! capability has another position and opens the request again.

use crate::control_plane::{UiDecisionEntry, UiDecisionRecord};

use super::items::OpenRequest;
use super::{LogPos, Source, UiDecision};

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
    mutant!(
        "randomid",
        field(&format!("{:?}", std::time::SystemTime::now())),
        ()
    );
    field(&request.subject);
    field(&request.agent);
    for (capability, entry, counter) in &parts {
        field(capability);
        field(entry);
        field(&counter.to_string());
    }
    crate::hashing::sha256_hex(&bytes)
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
            closes: mutant!(
                "nopositions",
                Default::default(),
                positions.iter().cloned().collect()
            ),
        })
        .collect()
}

/// The record of a deny of `request`, at the scope `digest` the admin saw.
pub(crate) fn decision_record(request: &OpenRequest, digest: &str) -> UiDecisionRecord {
    UiDecisionRecord {
        authority: request.authority.clone(),
        subject: request.subject.clone(),
        agent: request.agent.clone(),
        scope_digest: digest.to_owned(),
        entries: request
            .entries
            .iter()
            .map(|(capability, positions)| UiDecisionEntry {
                capability: capability.clone(),
                positions: positions
                    .iter()
                    .map(|pos| (pos.entry.clone(), pos.counter))
                    .collect(),
            })
            .take(mutant!("oneentry", 1, usize::MAX))
            .collect(),
    }
}

/// A recorded deny read back into its decisions; `None` for a record that
/// names no capability, or a capability with no refusal.
pub(crate) fn decisions_from_record(record: &UiDecisionRecord) -> Option<Vec<UiDecision>> {
    if record.entries.is_empty() {
        return None;
    }
    record
        .entries
        .iter()
        .map(|entry| {
            (!entry.positions.is_empty()).then(|| UiDecision {
                authority: record.authority.clone(),
                subject: record.subject.clone(),
                agent: record.agent.clone(),
                capability: entry.capability.clone(),
                closes: entry
                    .positions
                    .iter()
                    .map(|(hash, counter)| LogPos {
                        log: Source::Access,
                        entry: hash.clone(),
                        counter: *counter,
                    })
                    .collect(),
            })
        })
        .collect()
}
