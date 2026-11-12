// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 refusal controls inspect the actual unacknowledged intent.

use super::super::observe::{self, Event};
use super::fixtures::{
    Live, OUTCOME, WRITER, acquire, decided, reopen, reread, retry, runtime, state, state_of,
    terminal_count,
};
use super::{DrainError, JournalDrain};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::security::transparency_log::settle::FailSettle;

pub(super) fn before_append(row: &str) {
    let live = Live::new();
    let mut initial = state(&live.resolved);
    decided(&mut initial);
    let mut owner = live.seed(initial, row);
    let before = std::fs::read(&live.log_path).expect(row);
    let refused_intent = state_of(&owner).writer.as_ref().expect(row).intent.clone();
    let token = state_of(&owner)
        .writer
        .as_ref()
        .expect(row)
        .intent_id
        .clone();
    assert!(
        !refused_intent.delivered,
        "{row}: fixture intent starts unflagged"
    );
    let intent_count = live
        .records()
        .iter()
        .filter(|record| {
            record["token"] == token.0 && record["event"] == refused_intent.role.event()
        })
        .count();
    let watching = observe::watch(&live.path);
    let overlay = crash_fs::arm_config(&live.path);
    live.log.arm_settle_fault(FailSettle::BeforeAppend);
    let result = runtime(JournalDrain::deliver(&mut owner, &live.log));
    assert_eq!(
        result,
        Err(DrainError::Refused),
        "{row}: B BeforeAppend is Refused"
    );
    assert_eq!(
        observe::events(&live.path)
            .iter()
            .filter(|e| **e == Event::BStarted)
            .count(),
        1,
        "{row}: exactly one real B call reached the refusal seam"
    );
    assert_eq!(
        std::fs::read(&live.log_path).expect(row),
        before,
        "{row}: no first-call bytes"
    );
    assert_eq!(
        state_of(&owner).writer.as_ref().expect(row).intent,
        refused_intent,
        "{row}: refused intent remains byte-identical and unflagged"
    );
    crash_fs::cut(&live.resolved, Mode::DropAll);
    drop(overlay);
    drop(owner);
    let mut owner = reopen(acquire(&live.path));
    let writer = state_of(&owner).writer.as_ref().expect(row);
    assert_eq!(writer.intent_id, token, "{row}: same token after reopen");
    assert_eq!(
        writer.intent, refused_intent,
        "{row}: refused intent still unflagged after reopen"
    );
    retry(&mut owner, &live, row);
    assert_eq!(
        state_of(&owner).writer.as_ref().expect(row).records[0].payload_json,
        OUTCOME,
        "{row}: retry uses exact same payload"
    );
    assert_eq!(
        terminal_count(&live.records(), WRITER),
        1,
        "{row}: one logical terminal"
    );
    let records = live.records();
    let intents: Vec<_> = records
        .iter()
        .filter(|record| {
            record["token"] == token.0 && record["event"] == refused_intent.role.event()
        })
        .collect();
    assert_eq!(
        intents.len(),
        intent_count + 1,
        "{row}: retry actually resubmits refused intent"
    );
    super::crash_assertions::assert_payload(
        intents.last().expect(row),
        &token.0,
        refused_intent.role,
        &refused_intent.payload_json,
        row,
    );
    super::crash_assertions::accounted(&live.records(), row, &[WRITER.to_owned()]);
    live.verify(row);
    drop(watching);
}

pub(super) fn after_append(row: &str) {
    let live = Live::new();
    let mut initial = state(&live.resolved);
    decided(&mut initial);
    let mut owner = live.seed(initial, row);
    let before = std::fs::read(&live.log_path).expect(row);
    live.log.arm_settle_fault(FailSettle::AfterAppend);
    let result = runtime(JournalDrain::deliver(&mut owner, &live.log));
    assert_eq!(
        result,
        Err(DrainError::Unconfirmed),
        "{row}: AfterAppend is not Refused"
    );
    assert_ne!(
        std::fs::read(&live.log_path).expect(row),
        before,
        "{row}: append may already have landed"
    );
    assert!(
        !state_of(&owner)
            .writer
            .as_ref()
            .expect(row)
            .intent
            .delivered,
        "{row}: unconfirmed intent has no acknowledged flag"
    );
    reread(&mut owner);
    retry(&mut owner, &live, row);
    super::crash_assertions::accounted(&live.records(), row, &[WRITER.to_owned()]);
    live.verify(row);
}
