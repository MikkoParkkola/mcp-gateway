// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-compiled S6a2 surface, pending the repair and delivery implementation.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::{Map, Value};

use super::{IntentId, JournalError, JournalSession};
use crate::config_persistence::journal::Recovered;
use crate::config_persistence::lock::Locked;
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::identity::LogId;
use crate::security::transparency_log::settle::{Appended, Attribution, Role, Unsettled};

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
    session: DrainSession,
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
        // stub: S6a2
        self.as_ref().log_id()
    }

    fn settle<'a>(
        &'a self,
        record: &'a Delivery,
    ) -> Pin<Box<dyn Future<Output = Result<Appended, Unsettled>> + Send + 'a>> {
        // stub: S6a2
        let _ = record;
        Box::pin(async { Err(Unsettled::OtherLog) })
    }
}

impl JournalDrain {
    pub(crate) fn repair(
        session: &mut DrainSession,
        at_start: bool,
    ) -> Result<RepairReport, DrainError> {
        // stub: S6a2
        let _ = (session, at_start);
        Ok(RepairReport {
            recovered: Recovered::Nothing,
            reload_owed: false,
        })
    }

    pub(crate) async fn run(
        session: DrainSession,
        log: Option<Arc<TransparencyLogger>>,
    ) -> Result<DrainSession, DrainFailure> {
        // stub: S6a2
        let _ = log;
        Err(DrainFailure {
            session,
            error: DrainError::Journal,
        })
    }

    pub(crate) async fn deliver(
        session: &mut DrainSession,
        log: &Arc<TransparencyLogger>,
    ) -> Result<(), DrainError> {
        // stub: S6a2
        let _ = (session, log);
        Err(DrainError::Journal)
    }

    pub(crate) fn recovery_intent(
        session: &mut DrainSession,
        owed: bool,
        at_start: bool,
    ) -> Result<Option<IntentId>, JournalError> {
        // stub: S6a2
        let _ = (session, owed, at_start);
        Ok(None)
    }
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
