// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Repair and immutable delivery while one session owns the config lock.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Map, Value};

use super::{
    Decision, Fact, FrozenRecord, IntentId, JournalError, JournalSession, ParkReason, Phase,
    ResultClass, TerminalRole, TokenState,
};
use crate::config_persistence::commit::{self, Action, FileRevision, Found, NotDurable, Refusal};
use crate::config_persistence::journal::Recovered;
use crate::config_persistence::lock::Locked;
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::identity::LogId;
use crate::security::transparency_log::settle::{Appended, Attribution, Reason, Role, Unsettled};

pub(crate) struct DrainSession {
    locked: Locked,
    configured: PathBuf,
    journal: Option<JournalSession>,
}

pub(crate) struct JournalDrain;

pub(crate) struct RepairReport {
    recovered: Recovered,
    reload_owed: bool,
}

pub(crate) struct DrainFailure {
    session: Box<DrainSession>,
    error: DrainError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DrainError {
    Journal,
    RepairPending,
    NoLogger,
    OtherLog,
    Refused,
    Unconfirmed,
    Parked,
    Finish,
}

pub(crate) struct Delivery {
    binding: LogId,
    token: IntentId,
    role: Role,
    payload: Map<String, Value>,
    attribution: Option<Attribution>,
}

pub(crate) trait SettleSink: Send + Sync {
    fn log_id(&self) -> LogId;
    fn settle<'a>(
        &'a self,
        record: &'a Delivery,
    ) -> Pin<Box<dyn Future<Output = Result<Appended, Unsettled>> + Send + 'a>>;
}

impl SettleSink for Arc<TransparencyLogger> {
    fn log_id(&self) -> LogId {
        self.as_ref().log_id()
    }

    fn settle<'a>(
        &'a self,
        record: &'a Delivery,
    ) -> Pin<Box<dyn Future<Output = Result<Appended, Unsettled>> + Send + 'a>> {
        Box::pin(async move {
            match &record.attribution {
                Some(attribution) => {
                    self.settle_attributed(
                        &record.binding,
                        &record.token.0,
                        record.role,
                        record.payload.clone(),
                        attribution.actor.clone(),
                    )
                    .await
                }
                None => {
                    TransparencyLogger::settle(
                        self,
                        &record.binding,
                        &record.token.0,
                        record.role,
                        record.payload.clone(),
                    )
                    .await
                }
            }
        })
    }
}

impl JournalDrain {
    pub(crate) fn repair(
        session: &mut DrainSession,
        at_start: bool,
    ) -> Result<RepairReport, DrainError> {
        let Some(journal) = &session.journal else {
            return Ok(report(Recovered::Nothing, at_start));
        };
        if journal
            .state
            .writer
            .iter()
            .chain(&journal.state.attempts)
            .any(|owner| owner.handed_over)
        {
            return Err(DrainError::Journal);
        }
        let owed = journal.state.phase == Phase::Staged
            && (journal.state.pending.is_some()
                || matches!(journal.state.fact, Some(Fact::Committed(_))));
        Self::recovery_intent(session, owed, at_start).map_err(|_| DrainError::Journal)?;
        #[cfg(test)]
        fault::hit(&session.locked.target, fault::At::RepairPaused)
            .map_err(|_| DrainError::Journal)?;
        let journal = session.journal.as_mut().ok_or(DrainError::Journal)?;
        let recovered = match journal.state.phase {
            Phase::Accepted => {
                let expected = journal
                    .state
                    .new_revision
                    .as_ref()
                    .ok_or(DrainError::Journal)?;
                commit::verify(&session.locked, &session.configured, expected)
                    .map_err(|_| DrainError::RepairPending)?;
                #[cfg(test)]
                super::observe::note(&journal.target, super::observe::Event::ForwardVerified);
                Recovered::KeptNew
            }
            Phase::Staged if owed => restore(journal, &session.locked, &session.configured)?,
            _ => Recovered::Nothing,
        };
        decide_missing(journal)?;
        Ok(report(recovered, at_start))
    }

    pub(crate) async fn run(
        session: DrainSession,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Result<DrainSession, DrainFailure> {
        // The detached worker owns the session through repair, delivery and cleanup.
        // A cancelled waiter drops only its join handle, never the worker's lock.
        let runtime = tokio::runtime::Handle::current();
        let task = tokio::task::spawn_blocking(move || {
            runtime.block_on(async move {
                let mut session = session;
                let result = Self::run_owned(&mut session, log).await;
                match result {
                    Ok(()) => Ok(session),
                    Err(error) => Err(DrainFailure {
                        session: Box::new(session),
                        error,
                    }),
                }
            })
        });
        match task.await {
            Ok(result) => result,
            Err(error) => std::panic::resume_unwind(error.into_panic()),
        }
    }

    async fn run_owned(
        session: &mut DrainSession,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Result<(), DrainError> {
        let Some(journal) = &session.journal else {
            return Ok(());
        };
        if journal.state.pending.is_none()
            && journal.state.fact.is_some()
            && (journal.state.phase == Phase::Accepted
                || !matches!(journal.state.fact, Some(Fact::Committed(_))))
            && journal
                .state
                .writer
                .iter()
                .chain(&journal.state.attempts)
                .all(|owner| owner.finished(&journal.state.attempts))
        {
            return finish(session);
        }
        if let Some(binding) = &journal.state.binding {
            let logger = log.as_ref().ok_or(DrainError::NoLogger)?;
            if logger.as_ref().log_id() != *binding {
                return Err(DrainError::OtherLog);
            }
        }
        // This whole future runs in the blocking worker that owns the session.
        let repair = Self::repair(session, false);
        if repair
            .as_ref()
            .is_err_and(|error| *error != DrainError::RepairPending)
        {
            return repair.map(|_| ());
        }
        if repair.is_err()
            && session
                .journal
                .as_ref()
                .is_some_and(|journal| journal.state.phase == Phase::Accepted)
        {
            return Err(DrainError::RepairPending);
        }
        if let Some(log) = log {
            Self::deliver(session, &log).await?;
        }
        repair?;
        finish(session)
    }

    pub(crate) async fn deliver(
        session: &mut DrainSession,
        log: &Arc<TransparencyLogger>,
    ) -> Result<(), DrainError> {
        let Some(journal) = session.journal.as_mut() else {
            return Ok(());
        };
        let Some(binding) = journal.state.binding.clone() else {
            return Ok(());
        };
        let sink: &dyn SettleSink = log;
        if sink.log_id() != binding {
            return Err(DrainError::OtherLog);
        }
        if journal
            .state
            .writer
            .iter()
            .chain(&journal.state.attempts)
            .any(|owner| owner.handed_over)
        {
            return Err(DrainError::Journal);
        }
        // Re-sync a retained candidate before trusting any in-memory delivery flag.
        journal.persist().map_err(|_| DrainError::Journal)?;
        let owners: Vec<_> = journal
            .state
            .writer
            .iter()
            .chain(&journal.state.attempts)
            .map(|owner| owner.intent_id.clone())
            .collect();
        for token in &owners {
            send_record(journal, sink, &binding, token, None).await?;
        }
        // Counters are now acknowledged; freeze only missing caller payloads.
        freeze_records(journal)?;
        let terminal_order: Vec<_> = journal
            .state
            .attempts
            .iter()
            .chain(journal.state.writer.iter())
            .map(|owner| owner.intent_id.clone())
            .collect();
        for token in terminal_order {
            let count = owner_mut(journal, &token)?.records.len();
            for index in 0..count {
                send_record(journal, sink, &binding, &token, Some(index)).await?;
            }
        }
        Ok(())
    }

    pub(crate) fn recovery_intent(
        session: &mut DrainSession,
        owed: bool,
        at_start: bool,
    ) -> Result<Option<IntentId>, JournalError> {
        let Some(journal) = session.journal.as_mut() else {
            return Ok(None);
        };
        if !owed || journal.state.binding.is_none() {
            return Ok(None);
        }
        if let Some(attempt) = journal
            .state
            .attempts
            .iter()
            .find(|owner| owner.decision.is_none())
        {
            return Ok(Some(attempt.intent_id.clone()));
        }
        let token = IntentId(uuid::Uuid::new_v4().simple().to_string());
        let mut payload = Map::new();
        payload.insert("at_start".into(), at_start.into());
        payload.insert("kind".into(), "settle.recovery".into());
        if let Some(writer) = &journal.state.writer {
            payload.insert("settles".into(), writer.intent_id.0.clone().into());
        } else {
            payload.insert("root".into(), true.into());
        }
        let intent = frozen(&token, Role::RecoveryIntent, payload, None)
            .map_err(|_| JournalError::InvalidState)?;
        journal.state.attempts.push(TokenState {
            intent_id: token.clone(),
            intent,
            intent_counter: None,
            decision: None,
            records: Vec::new(),
            handed_over: false,
        });
        journal.persist()?;
        #[cfg(test)]
        fault::hit(&journal.target, fault::At::AttemptPersisted)?;
        Ok(Some(token))
    }
}

fn report(recovered: Recovered, at_start: bool) -> RepairReport {
    RepairReport {
        recovered,
        reload_owed: !at_start && recovered == Recovered::RolledBack,
    }
}

fn finish(session: &mut DrainSession) -> Result<(), DrainError> {
    if let Some(journal) = session.journal.as_mut() {
        journal.finish().map_err(|_| DrainError::Finish)?;
    }
    session.journal = None;
    Ok(())
}

fn restore(
    journal: &mut JournalSession,
    locked: &Locked,
    configured: &Path,
) -> Result<Recovered, DrainError> {
    let original = crate::config::read_recovery_text(&super::super::original_path(&locked.target))
        .map_err(|_| DrainError::RepairPending)?
        .ok_or(DrainError::RepairPending)?;
    let expected = journal
        .state
        .original_revision
        .clone()
        .ok_or(DrainError::Journal)?;
    if FileRevision::of(original.as_bytes()) != expected {
        return Err(DrainError::RepairPending);
    }
    if journal
        .state
        .pending
        .as_ref()
        .is_none_or(|pending| pending.action != Action::Restore)
    {
        // Replacing a pending Forward must first durably remove its committed claim.
        journal.state.pending = None;
        journal
            .begin_action(Action::Restore, expected.clone())
            .map_err(|_| DrainError::Journal)?;
    }
    let proof = match commit::verify(locked, configured, &expected) {
        Ok(proof) => Ok(proof),
        Err(NotDurable::NotOnDisk {
            found: Found::Bytes(found),
        }) if journal
            .state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.pre_action == found) =>
        {
            commit::commit(locked, configured, Action::Restore, original.as_bytes())
        }
        Err(error) => Err(error),
    };
    match proof {
        Ok(proof) => {
            journal
                .record_fact(Action::Restore, &proof)
                .map_err(|_| DrainError::Journal)?;
            #[cfg(test)]
            super::observe::note(&journal.target, super::observe::Event::RestoreVerified);
            Ok(Recovered::RolledBack)
        }
        Err(error) => {
            if matches!(error, NotDurable::Sync(_) | NotDurable::Repointed(_)) {
                if let Some(pending) = &mut journal.state.pending {
                    pending.tried = true;
                }
                journal.persist().map_err(|_| DrainError::Journal)?;
            }
            if let NotDurable::Refused(refusal) = error {
                refuse_attempt(journal, &refusal)?;
            }
            Err(DrainError::RepairPending)
        }
    }
}

fn refuse_attempt(journal: &mut JournalSession, refusal: &Refusal) -> Result<(), DrainError> {
    let token = journal
        .state
        .attempts
        .iter()
        .rev()
        .find(|owner| owner.decision.is_none())
        .map(|owner| owner.intent_id.clone());
    if let Some(token) = token {
        #[cfg(test)]
        super::observe::decision_computing(&journal.target);
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

fn decide_missing(journal: &mut JournalSession) -> Result<(), DrainError> {
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

fn compute_decision(journal: &JournalSession, token: &IntentId) -> Result<Decision, DrainError> {
    #[cfg(test)]
    super::observe::decision_computing(&journal.target);
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
        Some(Fact::Untouched) => Ok(Decision {
            terminal: TerminalRole::Abandoned,
            ..decision(ResultClass::NotWritten, Reason::Abandoned, None)
        }),
        _ => Err(DrainError::RepairPending),
    }
}

fn decision(result: ResultClass, reason: Reason, settled_by: Option<IntentId>) -> Decision {
    Decision {
        result,
        reason,
        settled_by,
        terminal: TerminalRole::Outcome,
        delivery_stopped: false,
    }
}

fn owner_mut<'a>(
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

fn frozen(
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

fn freeze_records(journal: &mut JournalSession) -> Result<(), DrainError> {
    let owners: Vec<_> = journal
        .state
        .attempts
        .iter()
        .chain(journal.state.writer.iter())
        .cloned()
        .collect();
    for owner in owners {
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
                continue;
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
                let attempt = journal
                    .state
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
        } else if journal.state.pending.is_some()
            && journal
                .state
                .writer
                .as_ref()
                .is_some_and(|writer| writer.intent_id == owner.intent_id)
        {
            if owner
                .records
                .iter()
                .any(|record| record.role == Role::Deferred)
            {
                continue;
            }
            payload.insert("reason".into(), "left_to_recovery".into());
            Role::Deferred
        } else {
            continue;
        };
        let record = frozen(
            &owner.intent_id,
            role,
            payload,
            owner.intent.attribution.clone(),
        )?;
        owner_mut(journal, &owner.intent_id)?.records.push(record);
        journal.persist().map_err(|_| DrainError::Journal)?;
    }
    Ok(())
}

async fn send_record(
    journal: &mut JournalSession,
    sink: &dyn SettleSink,
    binding: &LogId,
    token: &IntentId,
    index: Option<usize>,
) -> Result<(), DrainError> {
    let owner = owner_mut(journal, token)?;
    let record = match index {
        Some(index) => &owner.records[index],
        None => &owner.intent,
    };
    if record.parked.is_some() {
        return Err(DrainError::Parked);
    }
    if record.delivered {
        return Ok(());
    }
    let Ok(payload) = serde_json::from_slice(&record.payload_json) else {
        return park_record(journal, token, index, ParkReason::ArtifactCorrupt);
    };
    let delivery = Delivery {
        binding: binding.clone(),
        token: token.clone(),
        role: record.role,
        payload,
        attribution: record.attribution.clone(),
    };
    #[cfg(test)]
    super::observe::note(&journal.target, super::observe::Event::BStarted);
    let appended = sink.settle(&delivery).await;
    let receipt = match appended {
        Ok(receipt) if receipt.id == *binding => receipt,
        Ok(_) | Err(Unsettled::OtherLog) => return Err(DrainError::OtherLog),
        Err(Unsettled::Refused(_)) => return Err(DrainError::Refused),
        Err(Unsettled::Unconfirmed(_)) => return Err(DrainError::Unconfirmed),
        Err(Unsettled::Invalid(_)) => {
            #[cfg(test)]
            super::observe::note(&journal.target, super::observe::Event::BInvalid);
            return park_record(journal, token, index, ParkReason::InvalidPayload);
        }
    };
    #[cfg(test)]
    appended_boundary(&journal.target, delivery.role)?;
    let owner = owner_mut(journal, token)?;
    if let Some(index) = index {
        owner.records[index].delivered = true;
    } else {
        owner.intent_counter.get_or_insert(receipt.counter);
        owner.intent.delivered = true;
    }
    journal.persist().map_err(|_| DrainError::Journal)?;
    #[cfg(test)]
    super::observe::note(&journal.target, super::observe::Event::FlagSynced);
    #[cfg(test)]
    if delivery.role == Role::Deferred {
        fault::hit(&journal.target, fault::At::DeferredFlagged).map_err(|_| DrainError::Journal)?;
    }
    Ok(())
}

fn park_record(
    journal: &mut JournalSession,
    token: &IntentId,
    index: Option<usize>,
    reason: ParkReason,
) -> Result<(), DrainError> {
    let owner = owner_mut(journal, token)?;
    let record = match index {
        Some(index) => &mut owner.records[index],
        None => &mut owner.intent,
    };
    record.parked = Some(reason);
    journal.persist().map_err(|_| DrainError::Journal)?;
    Err(DrainError::Parked)
}

#[cfg(test)]
fn appended_boundary(target: &Path, role: Role) -> Result<(), DrainError> {
    let at = match role {
        Role::Intent(_) | Role::RecoveryIntent => fault::At::IntentAppended,
        Role::Outcome | Role::Abandoned => fault::At::OutcomeAppended,
        _ => return Ok(()),
    };
    // The fault registry observes armed hits; ordinary runs still observe the boundary.
    let before = fault::fired(target);
    fault::hit(target, at).map_err(|_| DrainError::Journal)?;
    if fault::fired(target) == before {
        super::observe::note(target, fault::event(at));
    }
    Ok(())
}

#[path = "config_persistence_journal_v2_crash_tests.rs"]
mod crash_tests;
#[path = "config_persistence_journal_v2_drain_fault_tests.rs"]
pub(crate) mod fault;
#[path = "config_persistence_journal_v2_drain_fixtures_tests.rs"]
mod fixtures;
#[path = "config_persistence_journal_v2_repair_tests.rs"]
mod repair_tests;
#[path = "config_persistence_journal_v2_root_tests.rs"]
mod root_tests;
#[path = "config_persistence_journal_v2_drain_tests.rs"]
mod tests;

#[path = "config_persistence_journal_v2_crash_fixtures_tests.rs"]
mod crash_fixtures;

#[path = "config_persistence_journal_v2_torn_tests.rs"]
mod torn_cases;

#[path = "config_persistence_journal_v2_crash_assertions_tests.rs"]
mod crash_assertions;

#[path = "config_persistence_journal_v2_delivery_cases_tests.rs"]
mod delivery_cases;

#[path = "config_persistence_journal_v2_crash_cases_tests.rs"]
mod crash_cases;
