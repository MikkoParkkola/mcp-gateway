// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S6a1 state rows seed claims independently; no synthetic `CommitToken` exists.

use std::path::Path;

use serde_json::{Value, json};

use super::fixtures::*;
use super::observe::{self, Event};
use super::*;
use crate::config_persistence::crash_fs::{self, Mode};
use crate::config_persistence::journal::{self, fault};

#[test]
fn terminal_blocks_finish() {
    const ROW: &str = "terminal_blocks_finish";
    let (dir, path, locked) = config();
    let mut state = intended(dir.path());
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    let writer = state.writer.as_mut().expect(ROW);
    writer.intent.delivered = true;
    writer.intent_counter = Some(7);
    let mut deferred = frozen(
        &writer.intent_id.0,
        Role::Deferred,
        &json!({"kind": "settle.save", "reason": "left_to_recovery", "intent_counter": 7}),
    );
    deferred.delivered = true;
    writer.records.push(deferred);
    journal::stage_original(&path, OLD).expect(ROW);
    let mut owner = session(&locked, state);
    let before = bytes(&path);
    assert!(
        owner.finish().is_err(),
        "{ROW}: intent plus deferred is not terminal"
    );
    assert_eq!(bytes(&path), before, "{ROW}: journal retained unchanged");
    assert_eq!(
        std::fs::read(journal::original_path(&path)).expect(ROW),
        OLD,
        "{ROW}: original retained"
    );
    let writer = owner.state.writer.as_mut().expect(ROW);
    writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
    let mut invalid = frozen(
        &writer.intent_id.0,
        Role::Outcome,
        &json!({
            "kind": "settle.save", "result": "not_written", "reason": "refused",
            "intent_counter": 7,
        }),
    );
    invalid.parked = Some(ParkReason::InvalidPayload);
    writer.records.push(invalid);
    seed(&path, &owner.state);
    let before = bytes(&path);
    assert!(
        owner.finish().is_err(),
        "{ROW}: unresolved Invalid evidence blocks cleanup"
    );
    assert_eq!(bytes(&path), before, "{ROW}: rejected evidence retained");

    terminal_requires_all_deliveries();

    let mut failures = Vec::new();
    terminal_consistency_cases(&mut failures);
    assert!(
        failures.is_empty(),
        "{ROW}: {} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

fn terminal_requires_all_deliveries() {
    const ROW: &str = "terminal_blocks_finish";
    for missing in ["intent", "deferred"] {
        let (dir, path, locked) = config();
        let mut state = intended(dir.path());
        state.phase = Phase::Staged;
        state.new_revision = Some(FileRevision::of(NEW));
        let writer = state.writer.as_mut().expect(ROW);
        writer.intent.delivered = missing != "intent";
        writer.intent_counter = Some(7);
        writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
        let mut deferred = frozen(
            &writer.intent_id.0,
            Role::Deferred,
            &json!({"kind": "settle.save", "reason": "left_to_recovery", "intent_counter": 7}),
        );
        deferred.delivered = missing != "deferred";
        let mut terminal = frozen(
            &writer.intent_id.0,
            Role::Outcome,
            &json!({
                "kind": "settle.save", "result": "not_written", "reason": "refused",
                "intent_counter": 7,
            }),
        );
        terminal.delivered = true;
        writer.records = vec![deferred, terminal];
        journal::stage_original(&path, OLD).expect(ROW);
        let mut owner = session(&locked, state.clone());
        let before = bytes(&path);
        let watching = observe::watch(&path);
        assert_eq!(
            owner.finish(),
            Err(JournalError::Finish),
            "{ROW}: delivered terminal cannot bypass undelivered {missing}"
        );
        assert_eq!(
            bytes(&path),
            before,
            "{ROW}: {missing} retains journal bytes"
        );
        assert_eq!(
            owner.state, state,
            "{ROW}: {missing} retains in-memory state"
        );
        assert_eq!(
            std::fs::read(journal::original_path(&path)).expect(ROW),
            OLD,
            "{ROW}: {missing} retains original bytes"
        );
        assert!(
            observe::events(&path).is_empty(),
            "{ROW}: {missing} prevents cleanup"
        );
        let writer = owner.state.writer.as_mut().expect(ROW);
        writer.intent.delivered = true;
        writer.records[0].delivered = true;
        assert_eq!(
            owner.persist(),
            Ok(()),
            "{ROW}: acknowledge missing {missing}"
        );
        assert_eq!(
            owner.finish(),
            Ok(()),
            "{ROW}: all delivered permits cleanup"
        );
        assert!(
            !journal::exists(&path) && !journal::original_path(&path).exists(),
            "{ROW}: completing {missing} removes both artifacts"
        );
        drop(watching);
    }
}

fn terminal_consistency_cases(failures: &mut Vec<String>) {
    const ROW: &str = "terminal_blocks_finish";
    for terminal_role in [TerminalRole::Outcome, TerminalRole::Abandoned] {
        for (case, case_id) in [
            ("result mismatch", "G2_result_mismatch"),
            ("reason mismatch", "G2_reason_mismatch"),
            ("equal terminal collapse", "K1_equal_terminal_collapse"),
            (
                "conflicting terminal payload",
                "K1_conflicting_terminal_payload",
            ),
            (
                "conflicting terminal attribution",
                "K1_conflicting_terminal_attribution",
            ),
            (
                "conflicting terminal caller digest",
                "K1_conflicting_terminal_caller_digest",
            ),
        ] {
            let case_id = format!("{terminal_role:?}_{case_id}");
            let expected = if case == "equal terminal collapse" {
                "finish=Ok(()), both artifacts removed, ordered and synced cleanup"
            } else {
                "finish=Err(Finish), unchanged journal/state/original, no cleanup events"
            };
            collect_case(failures, ROW, &case_id, expected, || {
                terminal_consistency_case(terminal_role, case)
            });
        }
    }
}

fn terminal_consistency_case(terminal_role: TerminalRole, case: &str) -> Result<(), String> {
    let (dir, path, locked) = config();
    let state = terminal_consistency_state(dir.path(), terminal_role, case)?;
    journal::stage_original(&path, OLD)
        .map_err(|error| format!("stage original error: {error:?}"))?;
    let mut owner = session(&locked, state.clone());
    let before = std::fs::read(journal::journal_path(&path))
        .map_err(|error| format!("read journal error: {error:?}"))?;
    let watching = observe::watch(&path);
    let finished = owner.finish();
    let events = observe::events(&path);
    let journal_after = std::fs::read(journal::journal_path(&path));
    let original_after = std::fs::read(journal::original_path(&path));
    let state_retained = owner.state == state;
    let journal_retained = journal_after.as_ref().is_ok_and(|after| after == &before);
    let original_retained = original_after.as_ref().is_ok_and(|after| after == OLD);
    let removed = matches!(&journal_after, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        && matches!(&original_after, Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    let passed = if case == "equal terminal collapse" {
        finished == Ok(())
            && removed
            && events
                == vec![
                    Event::OriginalUnlinked,
                    Event::JournalUnlinked,
                    Event::DirectorySynced,
                ]
    } else {
        finished == Err(JournalError::Finish)
            && journal_retained
            && state_retained
            && original_retained
            && events.is_empty()
    };
    drop(watching);
    if passed {
        Ok(())
    } else {
        Err(format!(
            "finish={finished:?}, artifacts_removed={removed}, \
             journal_retained={journal_retained}, state_retained={state_retained}, \
             original_retained={original_retained}, events={events:?}",
        ))
    }
}

fn terminal_consistency_state(
    dir: &Path,
    terminal_role: TerminalRole,
    case: &str,
) -> Result<JournalV2, String> {
    let mut state = intended(dir);
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    let writer = state.writer.as_mut().ok_or("missing fixture writer")?;
    writer.intent.delivered = true;
    writer.intent_counter = Some(7);
    let (role, mut choice, payload) = match terminal_role {
        TerminalRole::Outcome => (
            Role::Outcome,
            decision(ResultClass::NotWritten, Reason::Refused),
            json!({
                "kind": "settle.save", "result": "not_written", "reason": "refused",
                "intent_counter": 7,
            }),
        ),
        TerminalRole::Abandoned => (
            Role::Abandoned,
            decision(ResultClass::Unproven, Reason::Abandoned),
            json!({
                "kind": "settle.save", "result": "unproven", "reason": "abandoned",
                "intent_counter": 7,
            }),
        ),
    };
    choice.terminal = terminal_role;
    writer.decision = Some(choice);
    let mut terminal = frozen(&writer.intent_id.0, role, &payload);
    terminal.delivered = true;
    if matches!(case, "result mismatch" | "reason mismatch") {
        let mut changed = payload;
        if case == "result mismatch" {
            changed["result"] = match terminal_role {
                TerminalRole::Outcome => json!("written"),
                TerminalRole::Abandoned => json!("not_written"),
            };
        } else {
            changed["reason"] = json!("writer_died");
        }
        terminal = frozen(&writer.intent_id.0, role, &changed);
        terminal.delivered = true;
        writer.records = vec![terminal];
    } else {
        let mut retry = terminal.clone();
        match case {
            "conflicting terminal payload" => {
                let mut changed = payload;
                changed["reason"] = json!("writer_died");
                // Equal digests alone must not hide different frozen payload bytes.
                retry.payload_json = serde_json::to_vec(&changed)
                    .map_err(|error| format!("payload encoding error: {error:?}"))?;
            }
            "conflicting terminal attribution" => {
                retry.attribution = Some(Attribution {
                    actor: crate::security::audit::AuditWho::from_persisted(AUDIT_WHO_PRINCIPAL)
                        .map_err(|error| format!("attribution error: {error:?}"))?,
                });
            }
            "conflicting terminal caller digest" => {
                retry.caller_digest = "0".repeat(64);
            }
            _ => {}
        }
        writer.records = vec![terminal, retry];
    }
    Ok(state)
}

#[test]
fn overwrite_decision() {
    const ROW: &str = "overwrite_decision";
    let (dir, path, locked) = config();
    let mut state = intended(dir.path());
    let original = decision(ResultClass::NotWritten, Reason::Refused);
    let writer = state.writer.as_mut().expect(ROW);
    writer.intent.delivered = true;
    writer.intent_counter = Some(7);
    writer.decision = Some(original.clone());
    let token = writer.intent_id.clone();
    let mut owner = session(&locked, state);
    let before = bytes(&path);
    reject_decision_overwrites(&mut owner, &token, &original, &path, &before);
    let mut stopped = original.clone();
    stopped.delivery_stopped = true;
    let armed = crash_fs::arm_config(&path);
    assert_eq!(
        owner.decide(&token, stopped.clone()),
        Ok(()),
        "{ROW}: delivery_stopped false to true is allowed"
    );
    crash_fs::cut(dir.path(), Mode::DropAll);
    drop(armed);
    assert_eq!(
        reopened(&locked, ROW).writer.expect(ROW).decision,
        Some(stopped.clone()),
        "{ROW}: only delivery_stopped changes and is durable"
    );
    let stopped_bytes = bytes(&path);
    let stopped_digest = crate::hashing::sha256_hex(&stopped_bytes);
    assert_ne!(
        stopped_bytes, before,
        "{ROW}: allowed flag transition persists"
    );
    assert_eq!(
        owner.decide(&token, stopped.clone()),
        Ok(()),
        "{ROW}: identical stopped decision accepted"
    );
    assert_eq!(
        bytes(&path),
        stopped_bytes,
        "{ROW}: stopped retry preserves bytes"
    );
    assert_eq!(
        owner.decide(&token, original),
        Err(JournalError::ChangedDecision),
        "{ROW}: delivery_stopped true to false is forbidden"
    );
    let after = bytes(&path);
    assert_eq!(
        after, stopped_bytes,
        "{ROW}: reverse transition preserves bytes"
    );
    assert_eq!(
        crate::hashing::sha256_hex(&after),
        stopped_digest,
        "{ROW}: reverse transition preserves hash"
    );
    assert_eq!(
        owner.state.writer.as_ref().expect(ROW).decision,
        Some(stopped),
        "{ROW}: reverse transition preserves in-memory decision"
    );
}

fn reject_decision_overwrites(
    owner: &mut JournalSession,
    token: &IntentId,
    original: &Decision,
    path: &Path,
    before: &[u8],
) {
    const ROW: &str = "overwrite_decision";
    let digest = crate::hashing::sha256_hex(before);
    let mut result = original.clone();
    result.result = ResultClass::Written;
    let mut reason = original.clone();
    reason.reason = Reason::Moved;
    let mut settled_by = original.clone();
    settled_by.settled_by = Some(IntentId("another-attempt".into()));
    let mut terminal = original.clone();
    terminal.terminal = TerminalRole::Abandoned;
    for (field, changed) in [
        ("result", result),
        ("reason", reason),
        ("settled_by", settled_by),
        ("terminal", terminal),
    ] {
        assert_eq!(
            owner.decide(token, changed),
            Err(JournalError::ChangedDecision),
            "{ROW}: a different {field} cannot overwrite"
        );
        let after = bytes(path);
        assert_eq!(after, before, "{ROW}: persisted bytes unchanged");
        assert_eq!(
            crate::hashing::sha256_hex(&after),
            digest,
            "{ROW}: persisted hash unchanged"
        );
        assert_eq!(
            owner.state.writer.as_ref().expect(ROW).decision,
            Some(original.clone()),
            "{ROW}: in-memory decision unchanged"
        );
    }
    assert_eq!(
        owner.decide(token, original.clone()),
        Ok(()),
        "{ROW}: identical decision accepted"
    );
    assert_eq!(
        bytes(path),
        before,
        "{ROW}: identical decision preserves bytes"
    );
}

#[test]
fn finish_original_before_journal() {
    const ROW: &str = "finish_original_before_journal";
    let (dir, path, locked) = config();
    // Test-only setup; create/stage durability assertions belong to S6c.
    let mut owner = create_intended(&locked, intended(dir.path())).expect(ROW);
    owner.stage(OLD, FileRevision::of(NEW)).expect(ROW);
    let writer = owner.state.writer.as_mut().expect(ROW);
    writer.intent_counter = Some(7);
    writer.intent.delivered = true;
    writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
    let mut terminal = frozen(
        &writer.intent_id.0,
        Role::Outcome,
        &json!({
            "kind": "settle.save", "result": "not_written", "reason": "refused",
            "intent_counter": 7,
        }),
    );
    terminal.delivered = true;
    writer.records.push(terminal);
    seed(&path, &owner.state);
    let journal_path = journal::journal_path(&path);
    let original_path = journal::original_path(&path);
    let audit_path = dir.path().join("audit/log.jsonl");
    let audit_before = std::fs::read(&audit_path).expect(ROW);
    let before_syncs =
        fault::synced(&journal_path) + fault::synced(&original_path) + fault::synced(&path);
    let watching = observe::watch(&path);
    let armed = crash_fs::arm_config(&path);
    assert_eq!(owner.finish(), Ok(()), "{ROW}: completed owner finishes");
    assert_eq!(
        observe::events(&path),
        vec![
            Event::OriginalUnlinked,
            Event::JournalUnlinked,
            Event::DirectorySynced
        ],
        "{ROW}: unlink original, unlink journal, then exactly one directory sync"
    );
    assert_eq!(
        fault::synced(&journal_path) + fault::synced(&original_path) + fault::synced(&path),
        before_syncs + 1,
        "{ROW}: exactly one independently counted real directory sync"
    );
    // Finish may sync their shared directory through any sibling path.
    let target_syncs = fault::synced(&path);
    assert!(
        !original_path.exists() && !journal_path.exists(),
        "{ROW}: both artifacts absent on return"
    );
    crash_fs::cut(dir.path(), Mode::DropAll);
    drop(armed);
    assert!(
        !original_path.exists() && !journal_path.exists(),
        "{ROW}: DropAll cannot resurrect either artifact"
    );
    assert!(
        matches!(open(&locked), Ok(None)),
        "{ROW}: reopen sees no owner"
    );
    assert_eq!(
        std::fs::read(&path).expect(ROW),
        OLD,
        "{ROW}: no A write retry"
    );
    assert_eq!(
        fault::synced(&path),
        target_syncs,
        "{ROW}: no A commit or verify retry"
    );
    assert_eq!(
        std::fs::read(audit_path).expect(ROW),
        audit_before,
        "{ROW}: no B append retry"
    );
    drop(watching);
}

#[test]
fn begin_action_derives_pre_action() {
    const ROW: &str = "begin_action_derives_pre_action";
    for action in [Action::Forward, Action::Restore] {
        let (dir, path, locked) = config();
        let original = FileRevision::of(OLD);
        let new = FileRevision::of(NEW);
        assert_ne!(original, new, "{ROW}: distinct stored revisions");
        let mut state = intended(dir.path());
        state.phase = Phase::Staged;
        state.new_revision = Some(new.clone());
        if action == Action::Restore {
            state.fact = Some(Fact::Committed(new.clone()));
        }
        let mut owner = session(&locked, state);
        let (expected, pre_action) = match action {
            Action::Forward => (new, original),
            Action::Restore => (original, new),
        };
        let armed = crash_fs::arm_config(&path);
        assert_eq!(
            owner.begin_action(action, expected.clone()),
            Ok(()),
            "{ROW}: begin accepts the action without a pre_action argument"
        );
        let pending = owner.state.pending.as_ref().expect(ROW);
        assert_eq!(
            pending.pre_action, pre_action,
            "{ROW}: {action:?} derives pre_action before decode can rebuild it"
        );
        assert_eq!(pending.expected, expected, "{ROW}: live expected revision");
        assert_eq!(pending.action, action, "{ROW}: live action");
        assert_eq!(
            owner.state.fact, None,
            "{ROW}: begin clears fact immediately"
        );
        crash_fs::cut(dir.path(), Mode::DropAll);
        drop(armed);
        let loaded = reopened(&locked, ROW);
        assert_eq!(
            loaded.fact, None,
            "{ROW}: pending clears fact, including Restore committed"
        );
        let pending = loaded.pending.expect(ROW);
        assert_eq!(
            pending.pre_action, pre_action,
            "{ROW}: action selects stored source revision"
        );
        assert_eq!(
            pending.expected, expected,
            "{ROW}: expected is independent of pre_action"
        );
        assert_eq!(pending.action, action, "{ROW}: action retained");
        let wire: Value = serde_json::from_slice(&bytes(&path)).expect(ROW);
        assert!(
            wire["pending"].get("pre_action").is_none(),
            "{ROW}: pre_action is derived, never an independent wire field"
        );
    }
    for action in [Action::Forward, Action::Restore] {
        let (dir, path, locked) = config();
        let mut state = intended(dir.path());
        state.phase = Phase::Staged;
        state.fact = None;
        state.new_revision = Some(FileRevision::of(NEW));
        match action {
            Action::Forward => state.original_revision = None,
            Action::Restore => state.new_revision = None,
        }
        let mut owner = session(&locked, state.clone());
        let before = bytes(&path);
        let expected = match action {
            Action::Forward => FileRevision::of(NEW),
            Action::Restore => FileRevision::of(OLD),
        };
        assert_eq!(
            owner.begin_action(action, expected),
            Err(JournalError::InvalidState),
            "{ROW}: missing source revision rejected"
        );
        assert_eq!(
            bytes(&path),
            before,
            "{ROW}: missing source leaves bytes unchanged"
        );
        assert_eq!(
            owner.state, state,
            "{ROW}: missing source leaves state unchanged"
        );
    }
}
