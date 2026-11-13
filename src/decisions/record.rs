// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decline a deny records in the governance audit log, and its reading
//! back.
//!
//! One record carries every open capability of the request with the exact
//! refusal positions the admin was shown, so a later refusal of the same
//! capability has another position and opens the request again.

use crate::control_plane::{UiDecisionEntry, UiDecisionKind, UiDecisionRecord};

use super::items::OpenRequest;
use super::{LogPos, Source, UiDecision};

/// The same deny of the same refusals is the same id, from any process: a
/// SHA-256 over a domain separator, the subject and agent, and every
/// (capability, position), sorted, each field length-prefixed.
pub(crate) fn event_id(request: &OpenRequest) -> String {
    let mut bytes = b"mcpg/ui-decision/decline/v1\0".to_vec();
    for text in [
        request.authority.as_str(),
        request.subject.as_str(),
        request.agent.as_str(),
    ] {
        push_field(&mut bytes, text);
    }
    for (capability, entry, counter) in &sorted_positions(request) {
        push_field(&mut bytes, capability);
        push_field(&mut bytes, entry);
        push_field(&mut bytes, &counter.to_string());
    }
    crate::hashing::sha256_hex(&bytes)
}

/// Every (capability, entry, counter) `request` names, sorted and without
/// repeats, so the order they are listed in changes no id.
fn sorted_positions(request: &OpenRequest) -> Vec<(&str, &str, u64)> {
    let mut parts: Vec<(&str, &str, u64)> = request
        .entries
        .iter()
        .flat_map(|(capability, positions)| {
            positions
                .iter()
                .map(move |pos| (capability.as_str(), pos.entry.as_str(), pos.counter))
        })
        .collect();
    mutant!("unsorted", (), parts.sort_unstable());
    parts.dedup();
    parts
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

/// The record of a deny of `request`, at the scope `digest` the admin saw.
pub(crate) fn decision_record(request: &OpenRequest, digest: &str) -> UiDecisionRecord {
    UiDecisionRecord {
        authority: request.authority.clone(),
        subject: request.subject.clone(),
        agent: request.agent.clone(),
        scope_digest: digest.to_owned(),
        decision: Some(UiDecisionKind::Decline),
        rows: Vec::new(),
        expires_at: None,
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
            .collect(),
    }
}

/// A recorded deny read back into its decisions; `None` for a record that
/// names no capability, or a capability with no refusal.
pub(crate) fn decisions_from_record(record: &UiDecisionRecord) -> Option<Vec<UiDecision>> {
    // Only a decline closes refusals: an accept closes its request once its
    // rows are published, so a revoke of them can open it again.
    if mutant!("foldsaccepts", false, !record.is_decline()) || record.entries.is_empty() {
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

/// How long an accepted grant lasts: the ttl the administrator asked for,
/// or for good.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "staged: the accept route, a later part, calls this"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptTtl {
    /// For this many seconds from the first attempt.
    Seconds(u64),
    /// Until revoked.
    Permanent,
}

/// One length-prefixed field, so no two field lists share an encoding.
fn push_field(bytes: &mut Vec<u8>, text: &str) {
    mutant!(
        "nolenprefix",
        (),
        bytes.extend((text.len() as u64).to_be_bytes())
    );
    bytes.extend(text.as_bytes());
}

/// What an accept of `request` is, at the scope digest the administrator
/// was shown and with `ttl`: a SHA-256 over a domain separator and the
/// length-prefixed subject, agent, digest, every refusal position (sorted)
/// and the ttl. It leaves out the generation and the expiry, so a retry and
/// a partial revoke keep the ids of the rows still live.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "staged: the accept route, a later part, calls this"
    )
)]
pub(crate) fn accept_key(request: &OpenRequest, scope_digest: &str, ttl: AcceptTtl) -> String {
    let parts = sorted_positions(request);
    let mut bytes = b"mcpg/ui-decision/accept-key/v1\0".to_vec();
    for text in [
        mutant!("noauthority", "", request.authority.as_str()),
        mutant!("nosubject", "", request.subject.as_str()),
        mutant!("noagent", "", request.agent.as_str()),
        mutant!("nodigest", "", scope_digest),
    ] {
        push_field(&mut bytes, text);
    }
    push_field(&mut bytes, &parts.len().to_string());
    for (capability, entry, counter) in mutant!("nopositions", &parts[..0], &parts[..]) {
        push_field(&mut bytes, capability);
        push_field(&mut bytes, entry);
        push_field(&mut bytes, &counter.to_string());
    }
    let ttl = match ttl {
        AcceptTtl::Seconds(seconds) => format!("ttl:{seconds}"),
        AcceptTtl::Permanent => "permanent".to_owned(),
    };
    mutant!("nottl", (), push_field(&mut bytes, &ttl));
    crate::hashing::sha256_hex(&bytes)
}

/// The audit event id of an accept: its key and `generation`, the count of
/// the request's rows revoked or expired when it ran. A retry has the same
/// id; a new accept after a revoke has another.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "staged: the accept route, a later part, calls this"
    )
)]
pub(crate) fn accept_event_id(key: &str, generation: u64) -> String {
    let mut bytes = b"mcpg/ui-decision/accept/v1\0".to_vec();
    push_field(&mut bytes, key);
    mutant!(
        "eventnon",
        (),
        push_field(&mut bytes, &generation.to_string())
    );
    crate::hashing::sha256_hex(&bytes)
}

/// The grant row id an accept writes for `capability`: its key, the
/// capability and `generation`, that capability's rows revoked or expired
/// when it ran. Only a revoked capability gets a new id.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "staged: the accept route, a later part, calls this"
    )
)]
pub(crate) fn accept_row_id(key: &str, capability: &str, generation: u64) -> String {
    let mut bytes = b"mcpg/ui-decision/row/v1\0".to_vec();
    push_field(
        &mut bytes,
        &mutant!(
            "rowfromevent",
            accept_event_id(key, generation),
            key.to_owned()
        ),
    );
    mutant!("rownocap", (), push_field(&mut bytes, capability));
    mutant!(
        "rownog",
        (),
        push_field(&mut bytes, &generation.to_string())
    );
    crate::hashing::sha256_hex(&bytes)
}
