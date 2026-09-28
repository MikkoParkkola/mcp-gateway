// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The auditor's durable state and the plan computation (design 5.1, 5.2
//! steps 2-5). Kept apart from the append/commit half so each stays readable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::grant_audit::{JournalRead, PlannedRecord, UNKNOWN_ACTOR};
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan, GrantChangeRecord,
    GrantChangeVerb,
};
use crate::identity_grants::IdentityGrant;
use crate::identity_grants::journal::{JournalEntry, JournalVerb, grant_digest, parse_journal};

/// The state file (design 5.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct State {
    pub(super) v: u32,
    pub(super) grants_path: String,
    pub(super) generation: u64,
    pub(super) consumed: BTreeSet<String>,
    pub(super) missing_reported: BTreeSet<String>,
    /// Grant id to digest at the last committed reconciliation; `None` until
    /// one commits (no baseline).
    pub(super) grants: Option<BTreeMap<String, String>>,
    pub(super) gap: bool,
    pub(super) pending: Option<Pending>,
}

/// A durable plan: the records to append and the state to commit after them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Pending {
    pub(super) records: Vec<PlannedRecord>,
    pub(super) next: Box<State>,
}

impl State {
    /// A state with no baseline for `grants`.
    pub(super) fn fresh(grants: &Path) -> Self {
        Self {
            v: 1,
            grants_path: grants.display().to_string(),
            ..Self::default()
        }
    }

    /// The state file, or a fresh state when there is none.
    ///
    /// Any other read or parse failure is an error, never a fresh state: a
    /// lost pending plan would append its records a second time.
    pub(super) fn load(path: &Path, grants: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::fresh(grants)),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Write atomically.
    pub(super) fn save(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string(self).map_err(|e| e.to_string())?;
        crate::config_persistence::write_text_atomic(path, &text)
    }

    /// State kept for another grant file carries no baseline or consumed ids
    /// for this one. The generation stays monotonic so event ids stay unique
    /// in the one log, and an unrecorded gap stays owed.
    pub(super) fn for_path(self, grants: &Path) -> Self {
        let path = grants.display().to_string();
        if self.grants_path == path {
            return self;
        }
        Self {
            generation: self.generation,
            gap: self.gap,
            ..Self::fresh(grants)
        }
    }
}

/// Build one grant record.
pub(super) fn record(
    event_id: String,
    target_id: &str,
    change: GrantChangeRecord,
    reason: &str,
) -> PlannedRecord {
    PlannedRecord {
        event_id: event_id.clone(),
        event: ControlPlaneAuditEvent {
            event_id,
            actor_id: UNKNOWN_ACTOR.to_string(),
            action: ControlPlaneAction::MutateGrant,
            target_id: target_id.to_string(),
            reason: reason.to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "edit the grant file".to_string(),
                step: "identity grants CLI or the grant file; the gateway applies it on reload"
                    .to_string(),
            },
            grant_change: Some(change),
        },
    }
}

/// The first row per grant id: the row the CLI edits and digests.
fn first_rows(rows: &[IdentityGrant]) -> BTreeMap<String, &IdentityGrant> {
    let mut first = BTreeMap::new();
    for row in rows {
        first.entry(row.grant_id.clone()).or_insert(row);
    }
    first
}

/// A record before its event id is assigned.
struct Draft {
    /// `Some(entry id)` for a journal record.
    entry: Option<String>,
    target: String,
    change: GrantChangeRecord,
    reason: &'static str,
}

fn journal_verb(verb: JournalVerb) -> GrantChangeVerb {
    match verb {
        JournalVerb::Add => GrantChangeVerb::Add,
        JournalVerb::Replace => GrantChangeVerb::Replace,
        JournalVerb::Revoke => GrantChangeVerb::Revoke,
    }
}

fn indeterminate(cause: &str) -> Draft {
    Draft {
        entry: None,
        target: cause.to_string(),
        change: GrantChangeRecord::new(GrantChangeVerb::Indeterminate),
        reason: "grant history here cannot be stated exactly",
    }
}

/// A grant whose file row differs from what the journal accounts for.
fn mismatch(
    verb: GrantChangeVerb,
    grant_id: &str,
    digest: Option<String>,
    row: Option<&IdentityGrant>,
) -> Draft {
    let mut change = GrantChangeRecord::new(verb);
    change.digest = digest;
    change.expires_at = row.and_then(|r| r.expires_at);
    Draft {
        entry: None,
        target: grant_id.to_string(),
        change,
        reason: "grant file changed with no journal entry",
    }
}

fn journal_record(entry: &JournalEntry) -> Draft {
    let mut change = GrantChangeRecord::new(journal_verb(entry.verb));
    change.digest = Some(entry.digest.clone());
    change.expires_at = entry.expires_at;
    change.occurred_at = Some(entry.at);
    change.os_account_hint.clone_from(&entry.os_account);
    Draft {
        entry: Some(entry.entry_id.clone()),
        target: entry.grant_id.clone(),
        change,
        reason: "identity grants CLI change",
    }
}

/// Steps 2-5: the records this reconciliation owes, and the state to commit
/// after them. `reported` holds the unreadable-journal causes this process
/// already recorded (once per cause per process).
pub(super) fn plan(
    state: &State,
    rows: &[IdentityGrant],
    journal: &JournalRead,
    reported: &mut BTreeSet<String>,
) -> (Vec<PlannedRecord>, State) {
    let generation = state.generation + 1;
    // Every plan holds the gap record when the gap is set (step 5), so every
    // committed plan may clear it.
    let mut next = State {
        generation,
        gap: false,
        pending: None,
        ..state.clone()
    };
    let mut out = Vec::new();
    if state.gap {
        out.push(indeterminate("gap"));
    }
    let bytes = match journal {
        JournalRead::Missing => {
            reported.clear();
            Vec::new()
        }
        JournalRead::Bytes(bytes) => {
            reported.clear();
            bytes.clone()
        }
        JournalRead::Unreadable(cause) => {
            // Steps 3-4 skipped and the baseline kept: CLI changes are
            // recorded once the journal is readable again.
            if reported.insert(cause.clone()) {
                out.push(indeterminate("journal-unreadable"));
            }
            return (finish(out, generation), next);
        }
    };
    let parsed = parse_journal(&bytes);
    let present: BTreeSet<&str> = parsed.entries.iter().map(|e| e.entry_id.as_str()).collect();
    let missing: Vec<String> = state
        .consumed
        .iter()
        .filter(|id| !id.starts_with("torn:") && !present.contains(id.as_str()))
        .filter(|id| !state.missing_reported.contains(*id))
        .cloned()
        .collect();
    if !missing.is_empty() {
        out.push(indeterminate("journal-discontinuity"));
        next.missing_reported.extend(missing);
    }
    for torn in &parsed.torn {
        if next.consumed.insert(format!("torn:{torn}")) {
            out.push(indeterminate("journal-torn-line"));
        }
    }

    let oob = if state.gap {
        GrantChangeVerb::Indeterminate
    } else {
        GrantChangeVerb::OutOfBand
    };
    let has_baseline = state.grants.is_some();
    let mut expected: BTreeMap<String, Option<String>> = state
        .grants
        .iter()
        .flatten()
        .map(|(id, digest)| (id.clone(), Some(digest.clone())))
        .collect();
    for entry in parsed
        .entries
        .iter()
        .filter(|e| !state.consumed.contains(&e.entry_id))
    {
        // Step 3: an intervening direct edit shows as a `prev_digest` that is
        // not the expected digest. With no baseline, the first entry for a
        // grant seeds it instead.
        let known = expected.get(&entry.grant_id).cloned();
        let edited = match known {
            Some(want) => want != entry.prev_digest,
            None => has_baseline && entry.prev_digest.is_some(),
        };
        if edited {
            out.push(mismatch(
                oob,
                &entry.grant_id,
                entry.prev_digest.clone(),
                None,
            ));
        }
        out.push(journal_record(entry));
        expected.insert(entry.grant_id.clone(), Some(entry.digest.clone()));
        next.consumed.insert(entry.entry_id.clone());
    }

    // Step 4. Grants the journal never mentions are compared only against a
    // baseline; without one they predate the journal.
    let actual = first_rows(rows);
    let mut ids: BTreeSet<&String> = expected.keys().collect();
    if has_baseline {
        ids.extend(actual.keys());
    }
    for id in ids {
        let want = expected.get(id).cloned().flatten();
        let row = actual.get(id).copied();
        let have = row.map(grant_digest);
        if want != have {
            out.push(mismatch(oob, id, have, row));
        }
    }
    next.grants = Some(
        actual
            .iter()
            .map(|(id, row)| (id.clone(), grant_digest(row)))
            .collect(),
    );
    (finish(out, generation), next)
}

/// Event ids (step 6): a journal record keeps its entry id; every other record
/// is numbered by generation and its ordinal in the plan.
fn finish(drafts: Vec<Draft>, generation: u64) -> Vec<PlannedRecord> {
    drafts
        .into_iter()
        .enumerate()
        .map(|(ordinal, draft)| {
            let event_id = match &draft.entry {
                Some(entry) => format!("grant-journal:{entry}"),
                None => format!(
                    "grant-{}:{generation}:{ordinal}",
                    verb_name(draft.change.verb)
                ),
            };
            record(event_id, &draft.target, draft.change, draft.reason)
        })
        .collect()
}

/// The verb's wire name (`out_of_band`, `indeterminate`, ...).
fn verb_name(verb: GrantChangeVerb) -> String {
    serde_json::to_value(verb)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}
