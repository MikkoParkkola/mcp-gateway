// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Round-2 cases share the existing row collectors, including panic isolation.

use std::path::Path;

use serde_json::{Value, json};

use super::super::observe::{self, Event};
use super::super::{
    Fact, IntentId, JournalError, JournalV2, Pending, Phase, ResultClass, TerminalRole,
};
use super::r2_fixtures::{
    ABANDONED_PAIRS, DECISION_SETTLED_BY_CASES, DEFERRED_CONFLICT, DEFERRED_CONFLICT_ATTRIBUTION,
    DEFERRED_CONFLICT_CALLER_DIGEST, DEFERRED_EQUAL, FACT_COMMITTED_MATCH, FACT_COMMITTED_WRONG,
    FACT_ROLLED_BACK_MATCH, FACT_ROLLED_BACK_WRONG, OUTCOME_PAIRS, PENDING_FORWARD_MATCH,
    PENDING_FORWARD_WRONG, PENDING_RESTORE_MATCH, PENDING_RESTORE_WRONG,
};
use super::{
    AUDIT_WHO_PRINCIPAL, INTENT, NEW, OLD, bytes, collect_case, config, decision, frozen, intended,
    session, wire,
};
use crate::config_persistence::commit::{Action, FileRevision};
use crate::config_persistence::journal;
use crate::config_persistence::lock::Locked;
use crate::security::transparency_log::settle::{Attribution, Reason, Role};

pub(crate) fn journal_cases(failures: &mut Vec<String>) {
    const ROW: &str = "journal_versions";
    for action in [Action::Forward, Action::Restore] {
        for valid in [false, true] {
            let id = if valid {
                "Q1_begin_action_right_destination"
            } else {
                "Q1_begin_action_wrong_destination"
            };
            collect_case(
                failures,
                ROW,
                &format!("{id}_{action:?}"),
                if valid {
                    "Ok(()), correct pending destination/source persisted"
                } else {
                    "Err(InvalidState), state and durable bytes untouched"
                },
                || begin_destination(action, valid),
            );
        }
    }
    journal_decode_cases(failures);
    for (terminal, pairs) in [("Outcome", OUTCOME_PAIRS), ("Abandoned", ABANDONED_PAIRS)] {
        for &(result, reason, valid, fixture) in pairs {
            let id = format!("Q4_invalid_result_reason_pairs_{terminal}_{result}_{reason}");
            collect_case(failures, ROW, &id, decode_expectation(valid), || {
                decode_case(fixture, valid)
            });
        }
    }
    for &(id, valid, fixture) in DECISION_SETTLED_BY_CASES {
        collect_case(failures, ROW, id, decode_expectation(valid), || {
            decode_case(fixture, valid)
        });
    }
    for size in [1_048_576, 1_048_577] {
        for operation in ["encode", "persist"] {
            let id = if size == 1_048_576 {
                "Q3_encode_at_cap"
            } else {
                "Q3_encode_over_cap"
            };
            collect_case(
                failures,
                ROW,
                &format!("{id}_{operation}"),
                if size == 1_048_576 {
                    "exact-cap encoding/persist succeeds with exact bytes"
                } else {
                    "Err(Persist), previously persisted journal untouched"
                },
                || encoding_cap(size, operation),
            );
        }
    }
    for equal in [false, true] {
        let id = if equal {
            "Q5_equal_deferred_records_validate"
        } else {
            "Q5_conflicting_deferred_records_validate"
        };
        collect_case(failures, ROW, id, decode_expectation(equal), || {
            let (dir, _path, _locked) = config();
            let state = deferred_state(dir.path(), equal);
            let result = state.validate();
            let expected = if equal {
                Ok(())
            } else {
                Err(JournalError::InvalidState)
            };
            if result == expected {
                Ok(())
            } else {
                Err(format!("validate={result:?}"))
            }
        });
    }
    deferred_extra_cases(failures, false);
}

fn journal_decode_cases(failures: &mut Vec<String>) {
    const ROW: &str = "journal_versions";
    for (id, fixture, valid) in [
        (
            "Q1_decode_pending_wrong_destination_Forward",
            PENDING_FORWARD_WRONG,
            false,
        ),
        (
            "Q1_decode_pending_wrong_destination_Restore",
            PENDING_RESTORE_WRONG,
            false,
        ),
        (
            "Q1_decode_pending_right_destination_Forward",
            PENDING_FORWARD_MATCH,
            true,
        ),
        (
            "Q1_decode_pending_right_destination_Restore",
            PENDING_RESTORE_MATCH,
            true,
        ),
        (
            "Q1_decode_committed_fact_wrong_revision",
            FACT_COMMITTED_WRONG,
            false,
        ),
        (
            "Q1_decode_rolledback_fact_wrong_revision",
            FACT_ROLLED_BACK_WRONG,
            false,
        ),
        (
            "Q1_decode_committed_fact_right_revision",
            FACT_COMMITTED_MATCH,
            true,
        ),
        (
            "Q1_decode_rolledback_fact_right_revision",
            FACT_ROLLED_BACK_MATCH,
            true,
        ),
        (
            "Q5_conflicting_deferred_records_decode",
            DEFERRED_CONFLICT,
            false,
        ),
        (
            "Q5_conflicting_deferred_attribution_decode",
            DEFERRED_CONFLICT_ATTRIBUTION,
            false,
        ),
        (
            "Q5_conflicting_deferred_caller_digest_decode",
            DEFERRED_CONFLICT_CALLER_DIGEST,
            false,
        ),
        ("Q5_equal_deferred_records_decode", DEFERRED_EQUAL, true),
    ] {
        collect_case(failures, ROW, id, decode_expectation(valid), || {
            decode_case(fixture, valid)
        });
    }
}

fn decode_expectation(valid: bool) -> &'static str {
    if valid {
        "Ok(valid state)"
    } else {
        "Err(InvalidState)"
    }
}

fn decode_case(fixture: &[u8], valid: bool) -> Result<(), String> {
    let result = JournalV2::decode(fixture);
    if (valid && result.is_ok()) || (!valid && result == Err(JournalError::InvalidState)) {
        Ok(())
    } else {
        Err(format!("decode={result:?}"))
    }
}

fn begin_destination(action: Action, valid: bool) -> Result<(), String> {
    let (dir, path, locked) = config();
    let mut state = intended(dir.path());
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    let (destination, source) = match action {
        Action::Forward => (FileRevision::of(NEW), FileRevision::of(OLD)),
        Action::Restore => (FileRevision::of(OLD), FileRevision::of(NEW)),
    };
    if action == Action::Restore {
        state.fact = Some(Fact::Committed(FileRevision::of(NEW)));
    }
    journal::stage_original(&path, OLD).map_err(|e| format!("stage={e:?}"))?;
    let mut owner = session(&locked, state.clone());
    let before = bytes(&path);
    let _watching = observe::watch(&path);
    let result = owner.begin_action(
        action,
        if valid {
            destination.clone()
        } else {
            FileRevision::of(b"wrong destination")
        },
    );
    let disk = bytes(&path);
    let passed = if valid {
        let expected_pending = Some(Pending {
            action,
            expected: destination,
            pre_action: source,
            tried: false,
        });
        result == Ok(())
            && owner.state.pending == expected_pending
            && owner.state.fact.is_none()
            && disk == serde_json::to_vec(&wire(&owner.state)).map_err(|e| e.to_string())?
    } else {
        result == Err(JournalError::InvalidState) && owner.state == state && disk == before
    };
    let original_retained =
        std::fs::read(journal::original_path(&path)).is_ok_and(|contents| contents == OLD);
    if passed && original_retained && observe::events(&path).is_empty() {
        Ok(())
    } else {
        Err(format!(
            "begin_action={result:?}, state_retained={}, bytes_retained={}, \
             original_retained={original_retained}, pending={:?}",
            owner.state == state,
            disk == before,
            owner.state.pending,
        ))
    }
}

fn encoding_cap(size: usize, operation: &str) -> Result<(), String> {
    let (dir, path, locked) = config();
    let mut owner = session(&locked, intended(dir.path()));
    let before = bytes(&path);
    let token = owner
        .state
        .writer
        .as_ref()
        .ok_or("writer")?
        .intent_id
        .0
        .clone();
    let payload = |padding: String| json!({"kind": "settle.save", "padding": padding});
    owner.state.writer.as_mut().ok_or("writer")?.intent =
        frozen(&token, INTENT, &payload(String::new()));
    // Independent wire sizing: a '3' byte becomes `51,` (3 bytes), a 'd'
    // becomes `100,` (4 bytes). Fixed-width digest changes cannot change size.
    let base = serde_json::to_vec(&wire(&owner.state))
        .map_err(|e| e.to_string())?
        .len();
    let delta = size
        .checked_sub(base)
        .ok_or("fixture overhead exceeds cap")?;
    let fours = delta % 3;
    let threes = (delta - 4 * fours) / 3;
    let padding = "3".repeat(threes) + &"d".repeat(fours);
    owner.state.writer.as_mut().ok_or("writer")?.intent = frozen(&token, INTENT, &payload(padding));
    let expected = serde_json::to_vec(&wire(&owner.state)).map_err(|e| e.to_string())?;
    if expected.len() != size {
        return Err(format!("fixture size={}, wanted={size}", expected.len()));
    }
    let (accepted, detail) = if operation == "encode" {
        let result = owner.state.encode();
        let accepted = if size == 1_048_576 {
            result.as_ref().is_ok_and(|encoded| encoded == &expected)
        } else {
            result == Err(JournalError::Persist)
        };
        (
            accepted,
            format!("encode={:?}", result.as_ref().map(Vec::len)),
        )
    } else {
        let result = owner.persist();
        let expected_result = if size == 1_048_576 {
            Ok(())
        } else {
            Err(JournalError::Persist)
        };
        (result == expected_result, format!("persist={result:?}"))
    };
    let after = bytes(&path);
    let retained = if operation == "persist" && size == 1_048_576 {
        after == expected
    } else {
        after == before
    };
    if accepted && retained {
        Ok(())
    } else {
        Err(format!(
            "{detail}, target_size={size}, expected_disk_bytes={retained}",
        ))
    }
}

pub(crate) fn terminal_cases(failures: &mut Vec<String>) {
    const ROW: &str = "terminal_blocks_finish";
    for role in [TerminalRole::Outcome, TerminalRole::Abandoned] {
        for case in [
            "Q2_terminal_settled_by_mismatch",
            "Q2_terminal_settled_by_presence_payload_only",
            "Q2_terminal_settled_by_presence_decision_only",
            "Q2_terminal_counter_mismatch",
            "Q2_terminal_counter_mismatch_settled_by",
            "Q2_terminal_matching_control",
        ] {
            // Abandoned decision-only linkage is refused on decode in Q6.
            // Nested settled_by counters belong to Outcome only.
            if role == TerminalRole::Abandoned
                && matches!(
                    case,
                    "Q2_terminal_settled_by_presence_decision_only"
                        | "Q2_terminal_counter_mismatch_settled_by"
                )
            {
                continue;
            }
            let success = case == "Q2_terminal_matching_control";
            collect_case(
                failures,
                ROW,
                &format!("{case}_{role:?}"),
                if success {
                    "Ok(()), original then journal unlinked, one directory sync"
                } else {
                    "Err(Finish), journal/state/original untouched, no cleanup events"
                },
                || {
                    let (dir, path, locked) = config();
                    let state = linkage_state(dir.path(), role, case)?;
                    check_finish(&locked, &path, &state, success, false)
                },
            );
        }
    }
    for equal in [false, true] {
        let id = if equal {
            "Q5_equal_deferred_records_finish"
        } else {
            "Q5_conflicting_deferred_records_finish"
        };
        collect_case(
            failures,
            ROW,
            id,
            if equal {
                "equal retries collapse, finish=Ok(()), ordered/synced cleanup"
            } else {
                "Err(InvalidState) or Err(Finish), all evidence untouched, no cleanup"
            },
            || {
                let (dir, path, locked) = config();
                let state = deferred_state(dir.path(), equal);
                check_finish(&locked, &path, &state, equal, !equal)
            },
        );
    }
    deferred_extra_cases(failures, true);
}

fn terminal_state(dir: &Path, role: TerminalRole) -> JournalV2 {
    let mut state = intended(dir);
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    let writer = state.writer.as_mut().expect("fixture writer");
    writer.intent.delivered = true;
    writer.intent_counter = Some(7);
    let (record_role, reason) = match role {
        TerminalRole::Outcome => (Role::Outcome, Reason::Refused),
        TerminalRole::Abandoned => (Role::Abandoned, Reason::Abandoned),
    };
    let mut choice = decision(ResultClass::NotWritten, reason);
    choice.terminal = role;
    writer.decision = Some(choice);
    let mut terminal = frozen(
        &writer.intent_id.0,
        record_role,
        &json!({
            "kind": "settle.save", "result": "not_written", "reason": reason,
            "intent_counter": 7,
        }),
    );
    terminal.delivered = true;
    writer.records.push(terminal);
    state
}

fn linkage_state(dir: &Path, role: TerminalRole, case: &str) -> Result<JournalV2, String> {
    let mut state = terminal_state(dir, role);
    // The referenced recovery token is acknowledged and finished independently,
    // so the target mismatch is the only reason cleanup should be blocked.
    for (token, counter) in [("recovery-1", 17), ("recovery-2", 27)] {
        let mut recovery = state.writer.as_ref().ok_or("writer")?.clone();
        recovery.intent_id = IntentId(token.into());
        recovery.intent = frozen(
            token,
            Role::RecoveryIntent,
            &json!({
                "kind": "settle.recovery",
                "settles": state.writer.as_ref().ok_or("writer")?.intent_id.0,
            }),
        );
        recovery.intent.delivered = true;
        recovery.intent_counter = Some(counter);
        recovery.decision = Some(decision(ResultClass::NotWritten, Reason::NothingPending));
        let mut terminal = frozen(
            token,
            Role::Outcome,
            &json!({
                "kind": "settle.recovery", "result": "not_written", "reason": "nothing_pending",
                "intent_counter": counter,
            }),
        );
        terminal.delivered = true;
        recovery.records = vec![terminal];
        state.attempts.push(recovery);
    }
    let writer = state.writer.as_mut().ok_or("writer")?;
    let choice = writer.decision.as_mut().ok_or("decision")?;
    let mut payload: Value =
        serde_json::from_slice(&writer.records[0].payload_json).map_err(|e| e.to_string())?;
    let linked = role == TerminalRole::Outcome || case != "Q2_terminal_matching_control";
    if role == TerminalRole::Outcome {
        choice.settled_by = Some(IntentId("recovery-1".into()));
    }
    if linked {
        payload["settled_by"] = json!({"token": "recovery-1", "intent_counter": 17});
    }
    match case {
        "Q2_terminal_settled_by_mismatch" => {
            payload["settled_by"] = json!({"token": "recovery-2", "intent_counter": 27});
        }
        "Q2_terminal_settled_by_presence_payload_only" => choice.settled_by = None,
        "Q2_terminal_settled_by_presence_decision_only" => {
            payload
                .as_object_mut()
                .ok_or("object")?
                .remove("settled_by");
        }
        "Q2_terminal_counter_mismatch" => {
            // Isolate the own-counter check from Abandoned's forbidden settled_by.
            if role == TerminalRole::Abandoned {
                choice.settled_by = None;
                payload
                    .as_object_mut()
                    .ok_or("object")?
                    .remove("settled_by");
            }
            payload["intent_counter"] = json!(8);
        }
        "Q2_terminal_counter_mismatch_settled_by" => {
            payload["settled_by"]["intent_counter"] = json!(18);
        }
        _ => {}
    }
    let mut changed = frozen(&writer.intent_id.0, writer.records[0].role, &payload);
    changed.delivered = true;
    writer.records = vec![changed];
    Ok(state)
}

fn deferred_state(dir: &Path, equal: bool) -> JournalV2 {
    let mut state = terminal_state(dir, TerminalRole::Outcome);
    let writer = state.writer.as_mut().expect("fixture writer");
    let mut first = frozen(
        &writer.intent_id.0,
        Role::Deferred,
        &json!({"kind": "settle.save", "reason": "left_to_recovery", "intent_counter": 7}),
    );
    first.delivered = true;
    let mut retry = if equal {
        first.clone()
    } else {
        frozen(
            &writer.intent_id.0,
            Role::Deferred,
            &json!({"kind": "settle.save", "reason": "renamed_not_durable", "intent_counter": 7}),
        )
    };
    retry.delivered = true;
    writer.records.insert(0, retry);
    writer.records.insert(0, first);
    state
}

// Keep the equal-retry setup intact; change exactly one frozen-content field.
fn deferred_conflict_state(dir: &Path, attribution: bool) -> Result<JournalV2, String> {
    let mut state = deferred_state(dir, true);
    let retry = &mut state.writer.as_mut().ok_or("writer")?.records[1];
    if attribution {
        retry.attribution = Some(Attribution {
            actor: crate::security::audit::AuditWho::from_persisted(AUDIT_WHO_PRINCIPAL)
                .map_err(|error| format!("attribution error: {error:?}"))?,
        });
    } else {
        retry.caller_digest = "0".repeat(64);
    }
    Ok(state)
}

fn deferred_extra_cases(failures: &mut Vec<String>, finish: bool) {
    let (row, operation, expected) = if finish {
        (
            "terminal_blocks_finish",
            "finish",
            "Err(InvalidState) or Err(Finish), all evidence untouched, no cleanup",
        )
    } else {
        ("journal_versions", "validate", "Err(InvalidState)")
    };
    for (id, attribution) in [
        ("Q5_conflicting_deferred_attribution", true),
        ("Q5_conflicting_deferred_caller_digest", false),
    ] {
        collect_case(
            failures,
            row,
            &format!("{id}_{operation}"),
            expected,
            || {
                let (dir, path, locked) = config();
                let state = deferred_conflict_state(dir.path(), attribution)?;
                if finish {
                    check_finish(&locked, &path, &state, false, true)
                } else {
                    let result = state.validate();
                    if result == Err(JournalError::InvalidState) {
                        Ok(())
                    } else {
                        Err(format!("validate={result:?}"))
                    }
                }
            },
        );
    }
}

fn check_finish(
    locked: &Locked,
    path: &Path,
    state: &JournalV2,
    success: bool,
    invalid_state_allowed: bool,
) -> Result<(), String> {
    journal::stage_original(path, OLD).map_err(|e| format!("stage={e:?}"))?;
    let mut owner = session(locked, state.clone());
    let before = bytes(path);
    let _watching = observe::watch(path);
    let result = owner.finish();
    let events = observe::events(path);
    let journal_after = std::fs::read(journal::journal_path(path));
    let original_after = std::fs::read(journal::original_path(path));
    let journal_retained = journal_after.as_ref().is_ok_and(|b| b == &before);
    let original_retained = original_after.as_ref().is_ok_and(|b| b == OLD);
    let state_retained = owner.state == *state;
    let removed = matches!(&journal_after, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        && matches!(&original_after, Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    let passed = if success {
        result == Ok(())
            && removed
            && events
                == vec![
                    Event::OriginalUnlinked,
                    Event::JournalUnlinked,
                    Event::DirectorySynced,
                ]
    } else {
        (result == Err(JournalError::Finish)
            || (invalid_state_allowed && result == Err(JournalError::InvalidState)))
            && journal_retained
            && original_retained
            && state_retained
            && events.is_empty()
    };
    if passed {
        Ok(())
    } else {
        Err(format!(
            "finish={result:?}, journal_retained={journal_retained}, \
             original_retained={original_retained}, state_retained={state_retained}, \
             artifacts_removed={removed}, events={events:?}",
        ))
    }
}
