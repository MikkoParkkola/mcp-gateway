// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision and freeze step: settle each token's decision and freeze the terminals the
//! journal still owes, before any of them is delivered.

use serde_json::{Map, Value};

use super::super::{
    Fact, FrozenRecord, IntentId, JournalDecision, JournalSession, JournalV2, Phase, ResultClass,
    TerminalRole, TokenState,
};
use super::DrainError;
use crate::config_persistence::commit::Refusal;
use crate::security::transparency_log::settle::{Attribution, Reason, Role};

pub(super) fn refuse_attempt(
    journal: &mut JournalSession,
    refusal: &Refusal,
) -> Result<(), DrainError> {
    let token = journal
        .state
        .attempts
        .iter()
        .rev()
        .find(|owner| owner.decision.is_none())
        .map(|owner| owner.intent_id.clone());
    if let Some(token) = token {
        #[cfg(test)]
        super::super::observe::decision_computing(&journal.target);
        let reason = match refusal {
            Refusal::Moved => Reason::Moved,
            Refusal::Other(_) => Reason::Refused,
        };
        journal
            .decide(&token, decision(ResultClass::NotWritten, reason, None))
            .map_err(|_| DrainError::Journal)?;
    }
    Ok(())
}

pub(super) fn decide_missing(journal: &mut JournalSession) -> Result<(), DrainError> {
    let missing: Vec<_> = journal
        .state
        .attempts
        .iter()
        .chain(journal.state.writer.iter())
        .filter(|owner| owner.decision.is_none())
        .map(|owner| owner.intent_id.clone())
        .collect();
    for token in missing {
        let choice = compute_decision(journal, &token)?;
        journal
            .decide(&token, choice)
            .map_err(|_| DrainError::Journal)?;
    }
    Ok(())
}

fn compute_decision(
    journal: &JournalSession,
    token: &IntentId,
) -> Result<JournalDecision, DrainError> {
    #[cfg(test)]
    super::super::observe::decision_computing(&journal.target);
    let writer = journal
        .state
        .writer
        .as_ref()
        .is_some_and(|owner| &owner.intent_id == token);
    match &journal.state.fact {
        Some(Fact::RolledBack(_)) => {
            let by = journal.state.attempts.iter().rev().find(|owner| {
                writer
                    && owner.decision.as_ref().is_some_and(|choice| {
                        choice.result == ResultClass::Written && choice.reason == Reason::RolledBack
                    })
            });
            Ok(decision(
                if writer {
                    ResultClass::NotWritten
                } else {
                    ResultClass::Written
                },
                Reason::RolledBack,
                by.map(|owner| owner.intent_id.clone()),
            ))
        }
        Some(Fact::Committed(_)) if journal.state.phase == Phase::Accepted => {
            Ok(decision(ResultClass::Written, Reason::Committed, None))
        }
        Some(Fact::Untouched) if !writer => Ok(decision(
            ResultClass::NotWritten,
            Reason::NothingPending,
            None,
        )),
        Some(Fact::Untouched) => Ok(JournalDecision {
            terminal: TerminalRole::Abandoned,
            ..decision(ResultClass::NotWritten, Reason::Abandoned, None)
        }),
        _ => Err(DrainError::RepairPending),
    }
}

fn decision(result: ResultClass, reason: Reason, settled_by: Option<IntentId>) -> JournalDecision {
    JournalDecision {
        result,
        reason,
        settled_by,
        terminal: TerminalRole::Outcome,
        delivery_stopped: false,
    }
}

pub(super) fn owner_mut<'a>(
    journal: &'a mut JournalSession,
    token: &IntentId,
) -> Result<&'a mut TokenState, DrainError> {
    journal
        .state
        .writer
        .iter_mut()
        .chain(&mut journal.state.attempts)
        .find(|owner| &owner.intent_id == token)
        .ok_or(DrainError::Journal)
}

pub(super) fn frozen(
    token: &IntentId,
    role: Role,
    payload: Map<String, Value>,
    attribution: Option<Attribution>,
) -> Result<FrozenRecord, DrainError> {
    let payload_json = serde_json::to_vec(&payload).map_err(|_| DrainError::Journal)?;
    let mut caller = payload;
    caller.insert("event".into(), role.event().into());
    caller.insert("token".into(), token.0.clone().into());
    let bytes = serde_json::to_vec(&caller).map_err(|_| DrainError::Journal)?;
    Ok(FrozenRecord {
        role,
        payload_json,
        attribution,
        caller_digest: crate::hashing::sha256_hex(&bytes),
        delivered: false,
        parked: None,
    })
}

/// The terminal (or deferred) record `owner` still owes, built from its decision and counter;
/// `None` when it owes none. The one builder: the drains freeze with it and the handover's size
/// bound projects with it.
pub(super) fn terminal_record(
    state: &JournalV2,
    owner: &TokenState,
) -> Result<Option<FrozenRecord>, DrainError> {
    let Some(counter) = owner.intent_counter else {
        return Err(DrainError::Journal);
    };
    let intent: Map<String, Value> =
        serde_json::from_slice(&owner.intent.payload_json).map_err(|_| DrainError::Journal)?;
    let kind = intent.get("kind").cloned().ok_or(DrainError::Journal)?;
    let mut payload = Map::new();
    payload.insert("kind".into(), kind);
    payload.insert("intent_counter".into(), counter.into());
    let role = if let Some(choice) = &owner.decision {
        let role = match choice.terminal {
            TerminalRole::Outcome => Role::Outcome,
            TerminalRole::Abandoned => Role::Abandoned,
        };
        if owner.records.iter().any(|record| record.role == role) {
            return Ok(None);
        }
        payload.insert(
            "result".into(),
            serde_json::to_value(choice.result).map_err(|_| DrainError::Journal)?,
        );
        payload.insert(
            "reason".into(),
            serde_json::to_value(choice.reason).map_err(|_| DrainError::Journal)?,
        );
        if let Some(token) = &choice.settled_by {
            let attempt = state
                .attempts
                .iter()
                .find(|attempt| &attempt.intent_id == token)
                .ok_or(DrainError::Journal)?;
            let counter = attempt.intent_counter.ok_or(DrainError::Journal)?;
            payload.insert(
                "settled_by".into(),
                serde_json::json!({"token": token.0, "intent_counter": counter}),
            );
        }
        role
    } else if state.pending.is_some()
        && state
            .writer
            .as_ref()
            .is_some_and(|writer| writer.intent_id == owner.intent_id)
    {
        if owner
            .records
            .iter()
            .any(|record| record.role == Role::Deferred)
        {
            return Ok(None);
        }
        payload.insert("reason".into(), "left_to_recovery".into());
        Role::Deferred
    } else {
        return Ok(None);
    };
    frozen(
        &owner.intent_id,
        role,
        payload,
        owner.intent.attribution.clone(),
    )
    .map(Some)
}

pub(super) fn freeze_records(journal: &mut JournalSession) -> Result<(), DrainError> {
    let owners: Vec<_> = journal
        .state
        .attempts
        .iter()
        .chain(journal.state.writer.iter())
        .cloned()
        .collect();
    for owner in owners {
        if let Some(record) = terminal_record(&journal.state, &owner)? {
            owner_mut(journal, &owner.intent_id)?.records.push(record);
            journal.persist().map_err(|_| DrainError::Journal)?;
        }
    }
    Ok(())
}
