// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Independent pre-cut inventories and read-only crash artifact assertions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::super::fixtures::decision;
use super::super::observe::{self, Event};
use super::super::{IntentId, JournalV2, ResultClass};
use super::crash_fixtures::{ATTEMPT_OUTCOME, WRITER_OUTCOME};
use super::fault::Captured;
use super::fixtures::{
    ATTEMPT, RECOVERY, SAVE, WRITER, acquire, payload, records_at, terminal_count,
};
use crate::config_persistence::commit::Action;
use crate::config_persistence::journal;
use crate::config_persistence::lock;
use crate::security::transparency_log::settle::{Reason, Role, caller_view};
use crate::security::transparency_log::{TransparencyLogConfig, VerifyMode, verify_audit_log};

pub(super) fn expected_tokens(row: &str, captured: &Captured) -> Vec<String> {
    let expected = match row {
        "crash_d1" => {
            assert_eq!(
                captured.tokens.len(),
                2,
                "{row}: writer plus one planned attempt"
            );
            let attempt = captured
                .tokens
                .iter()
                .find(|token| *token != WRITER)
                .expect(row);
            assert!(
                !attempt.is_empty(),
                "{row}: independently captured attempt token"
            );
            vec![WRITER.to_owned(), attempt.clone()]
        }
        "crash_d2" | "crash_d3" | "crash_d4" | "crash_d5" | "crash_d8" => {
            vec![WRITER.to_owned(), ATTEMPT.to_owned()]
        }
        "crash_d6" | "crash_d7" => vec![WRITER.to_owned()],
        _ => panic!("{row}: missing explicit live-token inventory"),
    };
    assert_eq!(
        captured.tokens.iter().collect::<BTreeSet<_>>(),
        expected.iter().collect::<BTreeSet<_>>(),
        "{row}: exact pre-cut live-token set"
    );
    if row == "crash_d3" {
        assert!(
            captured.computations > 0,
            "{row}: real decision computation observed before cut"
        );
    }
    if row == "crash_d7" {
        assert!(
            captured.write_faults.is_some_and(|fired| fired > 0),
            "{row}: child witnessed the logger partial-write fault before kill"
        );
    }
    expected
}

pub(super) fn no_recompute(path: &Path, row: &str) {
    if row == "crash_d3" {
        let events = observe::events(path);
        assert!(
            !events.contains(&Event::DecisionComputed),
            "{row}: recovery never enters decision computation"
        );
        assert!(
            !events.contains(&Event::DecisionProposed),
            "{row}: recovery never proposes even an equal replacement decision"
        );
    }
}

pub(super) fn inspect_crash(
    path: &Path,
    log_path: &Path,
    config: &TransparencyLogConfig,
    row: &str,
    expected: &[String],
) {
    // Decode bytes directly: no session, logger refresh or recovery may run first.
    let bytes = std::fs::read(journal::journal_path(path)).expect("projected journal");
    let state = JournalV2::decode(&bytes).expect("projected journal decodes");
    let tokens: BTreeSet<_> = state
        .writer
        .iter()
        .chain(&state.attempts)
        .map(|owner| owner.intent_id.0.as_str())
        .collect();
    assert_eq!(
        tokens,
        expected.iter().map(String::as_str).collect(),
        "{row}: durable token set"
    );
    let verdict = verify_audit_log(log_path, config, VerifyMode::Live, None);
    if row == "crash_d7" {
        torn_tail(path, log_path, row);
        assert!(!verdict.is_ok_and(|v| v.ok), "{row}: reader sees torn tail");
        return;
    }
    assert!(
        verdict.is_ok_and(|v| v.ok),
        "{row}: reader verdict before recovery"
    );
    let records = records_at(log_path);
    match row {
        "crash_d2" => appended_intent(&state, &records, row),
        "crash_d3" | "crash_d4" => retained_decisions(&state, row),
        "crash_d5" => {
            deferred_restore(&state, &records, row);
            let locked = acquire(path);
            assert!(
                lock::refuse_pending_v2(&locked).is_err(),
                "{row}: unresolved Restore refuses next writer"
            );
        }
        _ => {}
    }
    if row == "crash_d4" {
        assert_eq!(
            terminal_count(&records, ATTEMPT),
            1,
            "{row}: attempt outcome exists at cut"
        );
        assert_eq!(
            terminal_count(&records, WRITER),
            0,
            "{row}: no writer outcome at cut"
        );
    }
}

fn torn_tail(path: &Path, log_path: &Path, row: &str) {
    let raw = std::fs::read(log_path).expect(row);
    assert!(
        !raw.ends_with(b"\n"),
        "{row}: torn tail has no final newline"
    );
    let start = raw.iter().rposition(|byte| *byte == b'\n').expect(row) + 1;
    let tail = &raw[start..];
    let previous: Value = serde_json::from_slice(
        raw[..start - 1]
            .rsplit(|byte| *byte == b'\n')
            .next()
            .expect("surviving complete record"),
    )
    .expect("complete record before torn tail");
    let captured: Captured = serde_json::from_slice(
        &std::fs::read(path.with_extension("s6a2-seam")).expect("pre-kill witness"),
    )
    .expect("partial-write evidence");
    // Only the random envelope trace comes from the failed write's witness.
    // The unflagged intent must replay `SAVE`, even though its first copy survived.
    let mut expected = payload(SAVE);
    expected.extend(payload(
        br#"{"event":"config_save_intent","outcome":"ok","schema_version":2,"who":{"account":"gateway","principal":""}}"#,
    ));
    expected.insert("token".into(), WRITER.into());
    expected.insert(
        "trace_id".into(),
        captured
            .partial_write_trace
            .expect("witnessed trace")
            .into(),
    );
    expected.insert(
        "counter".into(),
        (previous["counter"].as_u64().expect(row) + 1).into(),
    );
    expected.insert("prev_entry_hash".into(), previous["entry_hash"].clone());
    let core = serde_json::to_vec(&expected).expect("independent expected core");
    let hash = format!("sha256:{}", hex::encode(Sha256::digest(&core)));
    expected.insert("entry_hash".into(), hash.into());
    let mut line = serde_json::to_vec(&expected).expect("independent expected line");
    line.push(b'\n');
    assert!(
        !tail.is_empty() && tail.len() < line.len() - 1 && line.starts_with(tail),
        "{row}: non-empty strict prefix of the expected serialized record"
    );
    assert!(
        serde_json::from_slice::<Value>(tail).is_err(),
        "{row}: incomplete JSON, not a complete record missing its newline"
    );
}

fn appended_intent(state: &JournalV2, records: &[Value], row: &str) {
    let attempt = &state.attempts[0];
    assert_eq!(
        attempt.intent.payload_json, RECOVERY,
        "{row}: frozen attempt bytes"
    );
    assert!(
        !attempt.intent.delivered,
        "{row}: appended intent acknowledgement is not persisted"
    );
    assert_eq!(
        attempt.intent_counter, None,
        "{row}: appended counter is not persisted"
    );
    let intents: Vec<_> = records
        .iter()
        .filter(|r| r["token"] == ATTEMPT && r["event"] == "config_recovery_intent")
        .collect();
    assert_eq!(
        intents.len(),
        1,
        "{row}: attempt intent appended before cut"
    );
    assert_payload(intents[0], ATTEMPT, Role::RecoveryIntent, RECOVERY, row);
}

fn retained_decisions(state: &JournalV2, row: &str) {
    let mut expected = decision(ResultClass::NotWritten, Reason::RolledBack);
    expected.settled_by = Some(IntentId(ATTEMPT.into()));
    assert_eq!(
        state.writer.as_ref().expect(row).decision,
        Some(expected),
        "{row}: retained writer decision"
    );
    assert_eq!(
        state.attempts[0].decision,
        Some(decision(ResultClass::Written, Reason::RolledBack)),
        "{row}: retained attempt decision"
    );
}

fn deferred_restore(state: &JournalV2, records: &[Value], row: &str) {
    // D5 seeds `WRITER` with `SAVE`, counter 3 and no attribution. The unresolved
    // writer's `left_to_recovery` fields follow `terminal_blocks_finish`.
    const DEFERRED: &[u8] =
        br#"{"intent_counter":3,"kind":"settle.save","reason":"left_to_recovery"}"#;
    // Independently hashed sorted caller JSON, including `event` and `token`.
    const CALLER_DIGEST: &str = "f8abe00b275ed19a921bc3df65c48b0e99de7dcca53aa4b22d7276bd028348ea";
    let pending = state.pending.as_ref().expect("unresolved Restore at D5");
    assert_eq!(pending.action, Action::Restore, "{row}: pending Restore");
    assert!(
        pending.tried && state.fact.is_none(),
        "{row}: failed Sync proves no fact"
    );
    assert!(
        state.writer.as_ref().expect(row).decision.is_none(),
        "{row}: no guessed writer decision"
    );
    let deferred: Vec<_> = state
        .writer
        .iter()
        .chain(&state.attempts)
        .flat_map(|owner| owner.records.iter().map(move |record| (owner, record)))
        .filter(|(_, record)| record.role == Role::Deferred)
        .collect();
    assert_eq!(deferred.len(), 1, "{row}: one persisted deferred record");
    let (owner, record) = deferred[0];
    assert_eq!(owner.intent_id.0, WRITER, "{row}: deferred writer token");
    assert_eq!(
        owner.intent_counter,
        Some(3),
        "{row}: writer intent counter"
    );
    assert_eq!(
        record.payload_json, DEFERRED,
        "{row}: independent deferred journal payload"
    );
    assert_eq!(record.attribution, None, "{row}: deferred attribution");
    assert_eq!(
        record.caller_digest, CALLER_DIGEST,
        "{row}: independent deferred journal caller digest"
    );
    assert!(
        record.delivered,
        "{row}: deferred acknowledgement durably flagged"
    );
    let landed = records
        .iter()
        .find(|r| r["token"] == owner.intent_id.0 && r["event"] == Role::Deferred.event())
        .expect("deferred record appended before flag");
    assert_payload(landed, WRITER, Role::Deferred, DEFERRED, row);
    let caller = caller_view(landed.as_object().expect(row));
    let caller_bytes = serde_json::to_vec(&caller).expect(row);
    assert_eq!(
        hex::encode(Sha256::digest(&caller_bytes)),
        CALLER_DIGEST,
        "{row}: independent deferred log caller digest"
    );
}

pub(super) fn assert_payload(record: &Value, token: &str, role: Role, literal: &[u8], row: &str) {
    let mut expected = payload(literal);
    expected.insert("event".into(), role.event().into());
    expected.insert("token".into(), token.into());
    assert_eq!(
        caller_view(record.as_object().expect(row)),
        expected,
        "{row}: complete retained caller payload"
    );
}

pub(super) fn accounted(records: &[Value], row: &str, expected: &[String]) {
    let actual: BTreeSet<_> = records.iter().filter_map(|r| r["token"].as_str()).collect();
    assert_eq!(
        actual,
        expected.iter().map(String::as_str).collect(),
        "{row}: exact recovered live-token set"
    );
    for token in expected {
        assert!(
            records
                .iter()
                .all(|r| { r["token"] != *token || r["event"] != Role::Abandoned.event() }),
            "{row}: no additional abandonment terminal for {token}"
        );
        let event = if token == WRITER {
            "config_save_intent"
        } else {
            "config_recovery_intent"
        };
        assert!(
            records
                .iter()
                .any(|r| r["token"] == *token && r["event"] == event),
            "{row}: expected token {token} has its intent"
        );
        assert_eq!(
            terminal_count(records, token),
            1,
            "{row}: expected token {token} has exactly one logical terminal"
        );
    }
    let mut seen = BTreeMap::new();
    for record in records.iter().filter(|r| r["token"].is_string()) {
        let token = record["token"].as_str().expect(row);
        let event = record["event"].as_str().expect(row);
        let content = (
            caller_view(record.as_object().expect(row)),
            record["who"].clone(),
        );
        if let Some(previous) = seen.insert((token, event), content.clone()) {
            assert_eq!(
                previous, content,
                "{row}: physical retries have identical caller and actor"
            );
        }
    }
    if matches!(row, "crash_d3" | "crash_d4") {
        for (token, literal) in [(WRITER, WRITER_OUTCOME), (ATTEMPT, ATTEMPT_OUTCOME)] {
            for terminal in records
                .iter()
                .filter(|r| r["token"] == token && r["event"] == Role::Outcome.event())
            {
                assert_payload(terminal, token, Role::Outcome, literal, row);
            }
        }
    }
    if row == "crash_d4" {
        let first = |token: &str| {
            records
                .iter()
                .position(|r| r["token"] == token && r["event"] == Role::Outcome.event())
                .expect(row)
        };
        assert!(
            first(ATTEMPT) < first(WRITER),
            "{row}: attempt outcome precedes first writer outcome"
        );
    }
}
