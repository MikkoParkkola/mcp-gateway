// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Repair and immutable delivery while one session owns the config lock.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Map, Value};

use super::{Fact, IntentId, JournalError, JournalSession, JournalV2, Phase, TokenState};
use crate::config_persistence::commit::{self, Action, FileRevision, Found, NotDurable};
use crate::config_persistence::journal::Recovered;
use crate::config_persistence::lock::Locked;
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::identity::LogId;
use crate::security::transparency_log::settle::{Appended, Attribution, Role, Unsettled};
// `terminal_record` is used by the file drain and the handover, through this import.
use decide::{decide_missing, frozen, refuse_attempt, terminal_record};
use deliver::deliver_all;

pub(crate) struct DrainSession {
    locked: Locked,
    configured: PathBuf,
    journal: Option<JournalSession>,
}

impl DrainSession {
    /// A session over the held lock and the journal opened under it (`None`: no v2 journal).
    pub(crate) fn new(locked: Locked, configured: PathBuf, state: Option<JournalV2>) -> Self {
        let journal = state.map(|state| JournalSession {
            target: locked.target.clone(),
            state,
            backing: super::Backing::Journal,
        });
        Self {
            locked,
            configured,
            journal,
        }
    }

    /// The config the lock was taken for, resolved once at acquisition.
    pub(crate) fn target(&self) -> &Path {
        &self.locked.target
    }

    /// The v2 journal this session holds, if any.
    pub(crate) fn journal(&self) -> Option<&JournalV2> {
        self.journal.as_ref().map(|journal| &journal.state)
    }
}

pub(crate) struct JournalDrain;

// The report's contents are read only by the repair rows: the one product caller (startup)
// needs the repair's effect on disk, not this summary. A runtime repair's caller would read it.
pub(crate) struct RepairReport {
    #[cfg(test)]
    recovered: Recovered,
    #[cfg(test)]
    reload_owed: bool,
}

pub(crate) struct DrainFailure {
    session: Box<DrainSession>,
    error: DrainError,
}

impl DrainFailure {
    /// Why the drain stopped.
    pub(crate) fn error(&self) -> DrainError {
        self.error
    }

    /// The config whose journal the failed drain held, still locked until this is dropped.
    pub(crate) fn target(&self) -> &std::path::Path {
        self.session.target()
    }
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
    /// The abandoned file was refused as found; it is kept byte-identical.
    FileRefused,
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
            return Ok(report(&session.locked.target, Recovered::Nothing, at_start));
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
        Ok(report(&session.locked.target, recovered, at_start))
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
        // A handed-over token counts as finished, so the shortcut below would unlink a donor
        // whose file was never written. Only the handover's own resume, which proves the file
        // first, may finish a handed-over journal.
        if journal
            .state
            .writer
            .iter()
            .chain(&journal.state.attempts)
            .any(|owner| owner.handed_over)
        {
            return Err(DrainError::Journal);
        }
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
            // Refreshed from the file on disk: a log replaced behind this
            // handle is refused here, before any repair acts.
            let current = logger.refreshed_log_id().map_err(|_| DrainError::Refused)?;
            if current != *binding {
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
        deliver_all(journal, sink, &binding).await
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
        let reused = journal
            .state
            .attempts
            .iter()
            .find(|owner| owner.decision.is_none())
            .map(|owner| owner.intent_id.clone());
        if let Some(token) = reused {
            // An earlier persist of this attempt may have failed after it was
            // added in memory: no repair acts before the attempt is durable.
            journal.persist()?;
            return Ok(Some(token));
        }
        let token = IntentId(crate::ids::new_v4().simple().to_string());
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
        #[cfg(test)]
        fault::hit(&journal.target, fault::At::BeforeAttemptPersist)?;
        journal.persist()?;
        #[cfg(test)]
        fault::hit(&journal.target, fault::At::AttemptPersisted)?;
        Ok(Some(token))
    }
}

// A recovery is the one moment the config on disk changes without a writer: say so.
fn report(target: &std::path::Path, recovered: Recovered, at_start: bool) -> RepairReport {
    if recovered != Recovered::Nothing {
        tracing::info!(
            journal = %crate::config_persistence::journal::journal_path(target).display(),
            ?recovered,
            at_start,
            "recovered a config write a crashed writer left"
        );
    }
    RepairReport {
        #[cfg(test)]
        recovered,
        #[cfg(test)]
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

#[cfg(tp3)]
#[cfg(test)]
#[path = "config_persistence_journal_v2_crash_tests.rs"]
mod crash_tests;
#[path = "config_persistence_journal_v2_drain_decide.rs"]
mod decide;
#[path = "config_persistence_journal_v2_drain_deliver.rs"]
mod deliver;
#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_fault_tests.rs"]
pub(crate) mod fault;
#[path = "config_persistence_journal_v2_drain_file.rs"]
pub(crate) mod file;
#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_fixtures_tests.rs"]
mod fixtures;
#[path = "config_persistence_journal_v2_drain_handover.rs"]
pub(crate) mod handover;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_persistence_journal_v2_repair_tests.rs"]
mod repair_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_persistence_journal_v2_root_tests.rs"]
mod root_tests;
// Unix only: the abandoned-file fixtures come from a handover, and off Unix `hand_over` refuses
// the donor as foreign before the startup gate is reached.
#[cfg(tp3)]
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_startup_tests.rs"]
mod startup_tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_tests.rs"]
mod tests;
#[cfg(tp3)]
#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_sessionless_tests.rs"]
mod unsessioned_build_tests;
// Unix only: crash_s1 kills a child process at the repair step.
#[cfg(tp3)]
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_serve_crash_tests.rs"]
mod serve_crash_tests;

#[cfg(test)]
#[path = "config_persistence_journal_v2_crash_fixtures_tests.rs"]
mod crash_fixtures;

#[cfg(test)]
#[path = "config_persistence_journal_v2_torn_tests.rs"]
mod torn_cases;

#[cfg(test)]
#[path = "config_persistence_journal_v2_crash_assertions_tests.rs"]
mod crash_assertions;

#[cfg(test)]
#[path = "config_persistence_journal_v2_delivery_cases_tests.rs"]
mod delivery_cases;

#[cfg(test)]
#[path = "config_persistence_journal_v2_crash_cases_tests.rs"]
mod crash_cases;
