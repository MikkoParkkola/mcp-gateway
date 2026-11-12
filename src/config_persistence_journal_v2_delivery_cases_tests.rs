// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Isolated delivery subcases preserve the named row collectors.

use std::sync::Arc;

use super::super::{IntentId, JournalDecision};
use super::fixtures::{
    Live, OUTCOME, SAVE, WRITER, actor, decided, payload, retry, runtime, state, state_of,
    terminal_count,
};
use super::{Delivery, DrainError, DrainSession, JournalDrain, SettleSink};
use crate::config_persistence::journal;
use crate::security::transparency_log::settle::{Attribution, IntentKind, Role};

pub(super) fn sink_contract(row: &str) {
    let live = Live::new();
    let delivery = Delivery {
        binding: live.log.log_id(),
        token: IntentId(WRITER.to_owned()),
        role: Role::Intent(IntentKind::Save),
        payload: payload(SAVE),
        attribution: Some(Attribution { actor: actor() }),
    };
    assert_eq!(delivery.token.0, WRITER, "{row}: delivery retains token");
    assert_eq!(
        delivery.attribution.as_ref().map(|a| &a.actor),
        Some(&actor()),
        "{row}: delivery retains actor"
    );
    let sink: &dyn SettleSink = &live.log;
    assert_eq!(sink.log_id(), delivery.binding, "{row}: sink binding");
    let result = runtime(sink.settle(&delivery));
    assert!(
        result.is_ok(),
        "{row}: shared sink delivers attributed record"
    );
    let appended = result.expect(row);
    assert_eq!(appended.counter, 3, "{row}: sink appended expected counter");
    let records = live.records();
    let writers: Vec<_> = records.iter().filter(|r| r["token"] == WRITER).collect();
    assert_eq!(
        writers.len(),
        1,
        "{row}: exactly one sink-produced writer record"
    );
    assert_eq!(
        writers[0]["counter"].as_u64(),
        Some(appended.counter),
        "{row}: sink receipt matches actual record"
    );
    assert_eq!(
        writers[0]["who"],
        serde_json::to_value(actor()).expect(row),
        "{row}: sink preserves full actor"
    );
    direct_actor_control(&live, &delivery, appended.counter, row);
    live.verify(row);
}

pub(super) fn finish_only(row: &str) {
    let live = Live::new();
    let mut initial = state(&live.resolved);
    decided(&mut initial);
    let writer = initial.writer.as_mut().expect(row);
    writer.intent.delivered = true;
    writer.records[0].delivered = true;
    let owner = live.seed(initial, row);
    runtime(
        live.log
            .settle(&live.log.log_id(), WRITER, Role::Outcome, payload(OUTCOME)),
    )
    .expect("seed already delivered terminal");
    let before = std::fs::read(&live.log_path).expect(row);
    let armed = journal::fault::set(&live.path, journal::fault::Fault::FailJournalRemove);
    let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
    assert!(
        matches!(&result, Err(failure) if failure.error == DrainError::Finish),
        "{row}: fully flagged owner takes finish-only path"
    );
    assert_eq!(
        std::fs::read(&live.log_path).expect(row),
        before,
        "{row}: no append on finish retry"
    );
    assert_eq!(
        journal::fault::fired(&live.path),
        1,
        "{row}: cleanup fault reached exactly once"
    );
    assert!(
        journal::journal_path(&live.path).exists(),
        "{row}: cleanup failure retains owner"
    );
    drop(armed);
}

fn direct_actor_control(live: &Live, delivery: &Delivery, previous: u64, row: &str) {
    let direct = runtime(live.log.settle_attributed(
        &delivery.binding,
        "actor-control",
        delivery.role,
        delivery.payload.clone(),
        actor(),
    ));
    assert!(direct.is_ok(), "{row}: actor-only primitive appends");
    let direct = direct.expect(row);
    assert_eq!(
        direct.counter,
        previous + 1,
        "{row}: independent actor control counter"
    );
    let records = live.records();
    let controls: Vec<_> = records
        .iter()
        .filter(|r| r["token"] == "actor-control")
        .collect();
    assert_eq!(controls.len(), 1, "{row}: direct primitive appended once");
    assert_eq!(
        controls[0]["counter"].as_u64(),
        Some(direct.counter),
        "{row}: direct receipt matches append"
    );
    assert_eq!(
        controls[0]["who"],
        serde_json::to_value(actor()).expect(row),
        "{row}: direct primitive preserves complete actor"
    );
    live.verify(row);
}

pub(super) fn retained_retry(
    owner: &mut DrainSession,
    live: &Live,
    choice: &JournalDecision,
    row: &str,
) {
    retry(owner, live, row);
    assert_eq!(
        state_of(owner)
            .writer
            .as_ref()
            .expect(row)
            .decision
            .as_ref(),
        Some(choice),
        "{row}: persisted decision unchanged after each retry"
    );
    let records = live.records();
    assert_eq!(
        terminal_count(&records, WRITER),
        1,
        "{row}: retained terminal exists"
    );
    for terminal in records
        .iter()
        .filter(|r| r["token"] == WRITER && r["event"] == Role::Outcome.event())
    {
        super::crash_assertions::assert_payload(terminal, WRITER, Role::Outcome, OUTCOME, row);
    }
    assert_eq!(
        state_of(owner).writer.as_ref().expect(row).records[0].payload_json,
        OUTCOME,
        "{row}: persisted terminal retains complete caller payload"
    );
}
