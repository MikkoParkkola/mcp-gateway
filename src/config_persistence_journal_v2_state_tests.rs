// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S6a1 state rows seed claims independently; no synthetic CommitToken exists.

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
        &writer.token.0,
        Role::Deferred,
        json!({"kind": "settle.save", "reason": "left_to_recovery", "intent_counter": 7}),
    );
    deferred.delivered = true;
    writer.records.push(deferred);
    journal::stage_original(&path, OLD).expect(ROW);
    let mut owner = session(&locked, state);
    let before = bytes(&path);
    assert!(owner.finish().is_err(), "{ROW}: intent plus deferred is not terminal");
    assert_eq!(bytes(&path), before, "{ROW}: journal retained unchanged");
    assert_eq!(
        std::fs::read(journal::original_path(&path)).expect(ROW),
        OLD,
        "{ROW}: original retained"
    );
    let writer = owner.state.writer.as_mut().expect(ROW);
    writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
    let mut invalid = frozen(
        &writer.token.0,
        Role::Outcome,
        json!({
            "kind": "settle.save", "result": "not_written", "reason": "refused",
            "intent_counter": 7,
        }),
    );
    invalid.parked = Some(ParkReason::InvalidPayload);
    writer.records.push(invalid);
    seed(&path, &owner.state);
    let before = bytes(&path);
    assert!(owner.finish().is_err(), "{ROW}: unresolved Invalid evidence blocks cleanup");
    assert_eq!(bytes(&path), before, "{ROW}: rejected evidence retained");

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
            &writer.token.0,
            Role::Deferred,
            json!({"kind": "settle.save", "reason": "left_to_recovery", "intent_counter": 7}),
        );
        deferred.delivered = missing != "deferred";
        let mut terminal = frozen(
            &writer.token.0,
            Role::Outcome,
            json!({
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
        assert_eq!(bytes(&path), before, "{ROW}: {missing} retains journal bytes");
        assert_eq!(owner.state, state, "{ROW}: {missing} retains in-memory state");
        assert_eq!(
            std::fs::read(journal::original_path(&path)).expect(ROW),
            OLD,
            "{ROW}: {missing} retains original bytes"
        );
        assert!(observe::events(&path).is_empty(), "{ROW}: {missing} prevents cleanup");
        let writer = owner.state.writer.as_mut().expect(ROW);
        writer.intent.delivered = true;
        writer.records[0].delivered = true;
        assert_eq!(owner.persist(), Ok(()), "{ROW}: acknowledge missing {missing}");
        assert_eq!(owner.finish(), Ok(()), "{ROW}: all delivered permits cleanup");
        assert!(
            !journal::exists(&path) && !journal::original_path(&path).exists(),
            "{ROW}: completing {missing} removes both artifacts"
        );
        drop(watching);
    }
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
    let token = writer.token.clone();
    let mut owner = session(&locked, state);
    let before = bytes(&path);
    let digest = crate::hashing::sha256_hex(&before);
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
            owner.decide(&token, changed),
            Err(JournalError::ChangedDecision),
            "{ROW}: a different {field} cannot overwrite"
        );
        let after = bytes(&path);
        assert_eq!(after, before, "{ROW}: persisted bytes unchanged");
        assert_eq!(crate::hashing::sha256_hex(&after), digest, "{ROW}: persisted hash unchanged");
        assert_eq!(
            owner.state.writer.as_ref().expect(ROW).decision,
            Some(original.clone()),
            "{ROW}: in-memory decision unchanged"
        );
    }
    assert_eq!(
        owner.decide(&token, original.clone()),
        Ok(()),
        "{ROW}: identical decision accepted"
    );
    assert_eq!(bytes(&path), before, "{ROW}: identical decision preserves bytes");
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
    assert_ne!(stopped_bytes, before, "{ROW}: allowed flag transition persists");
    assert_eq!(
        owner.decide(&token, stopped.clone()),
        Ok(()),
        "{ROW}: identical stopped decision accepted"
    );
    assert_eq!(bytes(&path), stopped_bytes, "{ROW}: stopped retry preserves bytes");
    assert_eq!(
        owner.decide(&token, original),
        Err(JournalError::ChangedDecision),
        "{ROW}: delivery_stopped true to false is forbidden"
    );
    let after = bytes(&path);
    assert_eq!(after, stopped_bytes, "{ROW}: reverse transition preserves bytes");
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

#[test]
fn finish_original_before_journal() {
    const ROW: &str = "finish_original_before_journal";
    let (dir, path, locked) = config();
    let mut state = intended(dir.path());
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    let writer = state.writer.as_mut().expect(ROW);
    writer.intent_counter = Some(7);
    writer.intent.delivered = true;
    writer.decision = Some(decision(ResultClass::NotWritten, Reason::Refused));
    let mut terminal = frozen(
        &writer.token.0,
        Role::Outcome,
        json!({
            "kind": "settle.save", "result": "not_written", "reason": "refused",
            "intent_counter": 7,
        }),
    );
    terminal.delivered = true;
    writer.records.push(terminal);
    journal::stage_original(&path, OLD).expect(ROW);
    let mut owner = session(&locked, state);
    let journal_path = journal::journal_path(&path);
    let original_path = journal::original_path(&path);
    let audit_path = dir.path().join("audit/log.jsonl");
    let audit_before = std::fs::read(&audit_path).expect(ROW);
    let before_syncs = fault::synced(&journal_path)
        + fault::synced(&original_path)
        + fault::synced(&path);
    let watching = observe::watch(&path);
    let armed = crash_fs::arm_config(&path);
    assert_eq!(owner.finish(), Ok(()), "{ROW}: completed owner finishes");
    assert_eq!(
        observe::events(&path),
        vec![Event::OriginalUnlinked, Event::JournalUnlinked, Event::DirectorySynced],
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
    assert!(matches!(open(&locked), Ok(None)), "{ROW}: reopen sees no owner");
    assert_eq!(std::fs::read(&path).expect(ROW), OLD, "{ROW}: no A write retry");
    assert_eq!(fault::synced(&path), target_syncs, "{ROW}: no A commit or verify retry");
    assert_eq!(std::fs::read(audit_path).expect(ROW), audit_before, "{ROW}: no B append retry");
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
            pending.pre_action,
            pre_action,
            "{ROW}: {action:?} derives pre_action before decode can rebuild it"
        );
        assert_eq!(pending.expected, expected, "{ROW}: live expected revision");
        assert_eq!(pending.action, action, "{ROW}: live action");
        assert_eq!(owner.state.fact, None, "{ROW}: begin clears fact immediately");
        crash_fs::cut(dir.path(), Mode::DropAll);
        drop(armed);
        let loaded = reopened(&locked, ROW);
        assert_eq!(loaded.fact, None, "{ROW}: pending clears fact, including Restore committed");
        let pending = loaded.pending.expect(ROW);
        assert_eq!(pending.pre_action, pre_action, "{ROW}: action selects stored source revision");
        assert_eq!(pending.expected, expected, "{ROW}: expected is independent of pre_action");
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
        assert_eq!(bytes(&path), before, "{ROW}: missing source leaves bytes unchanged");
        assert_eq!(owner.state, state, "{ROW}: missing source leaves state unchanged");
    }
}
