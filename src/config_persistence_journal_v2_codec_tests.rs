// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S6a1 schema rows; the expected bytes never come from the codec under test.

use std::path::Path;

use serde_json::{Value, json};

use super::fixtures::*;
use super::*;
use crate::config_persistence::commit;
use crate::config_persistence::journal::{self, Recovered};
use crate::config_persistence::{FileMode, Symlink, write_atomic};
use crate::gateway::record_principal::RecordPrincipal;
use crate::security::audit::AuditWho;
use crate::security::transparency_log::settle::IntentKind;

fn round_trip(bytes: &[u8], row: &str) -> JournalV2 {
    let decoded = checked(JournalV2::decode(bytes), row);
    assert_eq!(decoded.version, 2, "{row}: exact version");
    assert_eq!(checked(decoded.encode(), row), bytes, "{row}: stable bytes");
    decoded
}

#[test]
fn journal_versions() {
    const ROW: &str = "journal_versions";
    legacy_versions();
    let (_dir, path, locked) = config();
    let journal_path = journal::journal_path(&path);
    write_atomic(
        &journal_path,
        JOURNAL_V2_ATTRIBUTION,
        FileMode::Private,
        Symlink::Replace,
    )
    .expect(ROW);
    let current = reopened(&locked, ROW);
    assert_eq!(current.version, 2, "{ROW}: v2 parsed");
    assert_eq!(
        bytes(&path),
        JOURNAL_V2_ATTRIBUTION,
        "{ROW}: v2 bytes preserved"
    );
    assert!(
        journal::recover(&path).is_err(),
        "{ROW}: legacy recovery refuses v2"
    );
    assert_eq!(
        bytes(&path),
        JOURNAL_V2_ATTRIBUTION,
        "{ROW}: unhandled v2 retained"
    );
    let mut unknown: Value = serde_json::from_slice(JOURNAL_V2_ATTRIBUTION).expect(ROW);
    unknown["version"] = json!(99);
    let unknown = serde_json::to_vec(&unknown).expect(ROW);
    write_atomic(&journal_path, &unknown, FileMode::Private, Symlink::Replace).expect(ROW);
    assert!(
        matches!(open(&locked), Err(JournalError::UnsupportedVersion)),
        "{ROW}: unknown version refused"
    );
    assert_eq!(bytes(&path), unknown, "{ROW}: unknown evidence retained");
    journal_revision_and_role_codecs();
    journal_state_controls(&path, &journal_path, &locked);
    durable_record_fact(ROW);

    let mut failures = Vec::new();
    journal_boundary_cases(&current, &mut failures);
    assert!(
        failures.is_empty(),
        "{ROW}: {} case(s) failed:\n{}",
        failures.len(),
        failures.join("\n"),
    );
}

fn legacy_versions() {
    const ROW: &str = "journal_versions";
    for all_renamed in [false, true] {
        let (_dir, path, locked) = config();
        journal::stage_original(&locked.target, OLD).expect(ROW);
        journal::begin(&locked.target, FileRevision::of(OLD).as_str().into()).expect(ROW);
        write_atomic(&path, NEW, FileMode::Private, Symlink::Replace).expect(ROW);
        if all_renamed {
            journal::mark_all_renamed(&locked.target).expect(ROW);
        }
        let before = bytes(&path);
        let legacy: Value = serde_json::from_slice(&before).expect(ROW);
        assert_eq!(
            legacy,
            json!({
                "version": 1,
                "state": if all_renamed { "all_renamed" } else { "staged" },
                "target": locked.target,
                "original": journal::original_path(&path),
                "original_revision": FileRevision::of(OLD).as_str(),
            }),
            "{ROW}: unchanged legacy wire contract"
        );
        assert!(
            matches!(open(&locked), Ok(Some(OpenJournal::Legacy(_)))),
            "{ROW}: v1 dispatches to legacy"
        );
        assert_eq!(bytes(&path), before, "{ROW}: open preserves legacy bytes");
        let expected = if all_renamed {
            Recovered::KeptNew
        } else {
            Recovered::RolledBack
        };
        assert_eq!(
            journal::recover(&path).expect(ROW),
            expected,
            "{ROW}: v1 recovery"
        );
        assert_eq!(
            std::fs::read(&path).expect(ROW),
            if all_renamed { NEW } else { OLD },
            "{ROW}: recovered config bytes"
        );
        assert!(
            !journal::exists(&path) && !journal::original_path(&path).exists(),
            "{ROW}: legacy cleanup"
        );
    }
}

fn journal_revision_and_role_codecs() {
    const ROW: &str = "journal_versions";
    let revision = FileRevision::of(OLD);
    assert_eq!(
        FileRevision::parse_journal(revision.as_str()),
        Ok(revision.clone()),
        "{ROW}: lowercase revision decoded"
    );
    for bad in [
        "a".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
        "a".repeat(65),
    ] {
        assert!(
            FileRevision::parse_journal(&bad).is_err(),
            "{ROW}: invalid revision"
        );
    }
    let id = checked(LogId::from_journal("opaque-log:not-a-uuid".into()), ROW);
    assert_eq!(
        id.as_str(),
        "opaque-log:not-a-uuid",
        "{ROW}: opaque identity retained"
    );
    for bad in [String::new(), "x".repeat(1_048_576)] {
        assert!(LogId::from_journal(bad).is_err(), "{ROW}: invalid identity");
    }
    for role in Role::ALL {
        assert_eq!(
            Role::from_event(role.event()),
            Some(role),
            "{ROW}: every role decodes"
        );
    }
    for (fixture, role) in [
        (JOURNAL_V2_HANDED_OVER, Role::Intent(IntentKind::Save)),
        (JOURNAL_V2_ADOPT, Role::Intent(IntentKind::Adopt)),
        (JOURNAL_V2_RESTORE, Role::Intent(IntentKind::Restore)),
        (JOURNAL_V2_BACKEND, Role::Intent(IntentKind::Backend)),
        (JOURNAL_V2_ATTRIBUTION, Role::Intent(IntentKind::KeyCreate)),
        (JOURNAL_V2_ROOT, Role::RecoveryIntent),
    ] {
        let state = round_trip(fixture, ROW);
        let owner = state
            .writer
            .as_ref()
            .or_else(|| state.attempts.first())
            .expect(ROW);
        assert_eq!(
            owner.intent.role, role,
            "{ROW}: exact journal intent role {role:?}"
        );
    }
    assert_eq!(
        Role::Intent(IntentKind::KeyCreate).event(),
        "config_key_create_intent",
        "{ROW}: sixth intent has a typed event"
    );
}

fn journal_state_controls(path: &Path, journal_path: &Path, locked: &Locked) {
    const ROW: &str = "journal_versions";
    let accepted = round_trip(JOURNAL_V2_ACCEPTED, ROW);
    assert_eq!(
        accepted.phase,
        Phase::Accepted,
        "{ROW}: valid accepted control"
    );
    assert_eq!(
        accepted.fact,
        accepted.new_revision.map(Fact::Committed),
        "{ROW}: accepted control has a matching committed fact"
    );
    let pending = round_trip(JOURNAL_V2_PENDING, ROW);
    assert_eq!(
        pending.fact, None,
        "{ROW}: valid pending control has no fact"
    );
    let action = pending.pending.expect(ROW);
    assert_eq!(
        Some(action.pre_action),
        pending.original_revision,
        "{ROW}: pending control derives the stored source revision"
    );
    for (case, fixture) in [
        (
            "accepted without new revision",
            JOURNAL_V2_INVALID_ACCEPTED_NO_REVISION,
        ),
        ("accepted without fact", JOURNAL_V2_INVALID_ACCEPTED_NO_FACT),
        (
            "accepted with untouched fact",
            JOURNAL_V2_INVALID_ACCEPTED_UNTOUCHED,
        ),
        (
            "accepted with mismatched fact",
            JOURNAL_V2_INVALID_ACCEPTED_WRONG_REVISION,
        ),
        ("pending and fact together", JOURNAL_V2_INVALID_PENDING_FACT),
    ] {
        assert_eq!(
            JournalV2::decode(fixture),
            Err(JournalError::InvalidState),
            "{ROW}: {case} rejected by decode"
        );
        write_atomic(journal_path, fixture, FileMode::Private, Symlink::Replace).expect(ROW);
        assert!(
            matches!(open(locked), Err(JournalError::InvalidState)),
            "{ROW}: {case} rejected on open"
        );
        assert_eq!(
            bytes(path),
            fixture,
            "{ROW}: {case} preserves invalid evidence"
        );
    }
}

fn journal_boundary_cases(current: &JournalV2, failures: &mut Vec<String>) {
    const ROW: &str = "journal_versions";
    // Each boundary has its own target and panic boundary: neither masks G1.
    for (case, size) in [
        ("G3_exact_limit", 1_048_576),
        ("G3_oversized_journal", 1_048_577),
    ] {
        let expected = if size == 1_048_576 {
            "exactly 1048576 bytes, original v2 state, unchanged journal bytes"
        } else {
            "exactly 1048577 bytes, Err(Unreadable), unchanged journal bytes"
        };
        collect_case(failures, ROW, case, expected, || {
            let (_dir, path, locked) = config();
            let journal_path = journal::journal_path(&path);
            let mut bounded = JOURNAL_V2_ATTRIBUTION.to_vec();
            bounded.resize(size, b' ');
            write_atomic(&journal_path, &bounded, FileMode::Private, Symlink::Replace)
                .map_err(|error| format!("write error: {error:?}"))?;
            let before =
                std::fs::read(&journal_path).map_err(|error| format!("read error: {error:?}"))?;
            let opened = open(&locked);
            let retained = std::fs::read(&journal_path).is_ok_and(|after| after == bounded);
            let accepted = if size == 1_048_576 {
                matches!(
                    &opened,
                    Ok(Some(OpenJournal::Current(state))) if state.as_ref() == current
                )
            } else {
                matches!(&opened, Err(JournalError::Unreadable))
            };
            if before.len() == size && accepted && retained {
                Ok(())
            } else {
                Err(format!(
                    "{} bytes, open={opened:?}, bytes_retained={retained}",
                    before.len(),
                ))
            }
        });
    }
    for (case, fixture) in [
        (
            "G1_duplicate_writer_attempt",
            JOURNAL_V2_DUPLICATE_WRITER_ATTEMPT,
        ),
        ("G1_duplicate_attempts", JOURNAL_V2_DUPLICATE_ATTEMPTS),
    ] {
        collect_case(
            failures,
            ROW,
            case,
            "decode=Err(InvalidState), open=Err(InvalidState), unchanged journal bytes",
            || {
                let (_dir, path, locked) = config();
                let journal_path = journal::journal_path(&path);
                let decoded = JournalV2::decode(fixture);
                write_atomic(&journal_path, fixture, FileMode::Private, Symlink::Replace)
                    .map_err(|error| format!("write error: {error:?}"))?;
                let opened = open(&locked);
                let retained = std::fs::read(&journal_path).is_ok_and(|after| after == fixture);
                if matches!(&decoded, Err(JournalError::InvalidState))
                    && matches!(&opened, Err(JournalError::InvalidState))
                    && retained
                {
                    Ok(())
                } else {
                    Err(format!(
                        "decode={decoded:?}, open={opened:?}, bytes_retained={retained}",
                    ))
                }
            },
        );
    }
}

fn durable_record_fact(row: &str) {
    use crate::config_persistence::crash_fs::{self, Mode};

    let (dir, path, locked) = config();
    let mut state = intended(dir.path());
    state.phase = Phase::Staged;
    state.new_revision = Some(FileRevision::of(NEW));
    state.pending = Some(Pending {
        action: Action::Forward,
        expected: FileRevision::of(NEW),
        pre_action: FileRevision::of(OLD),
        tried: false,
    });
    state.fact = None;
    // Seed pending state independently of create/stage and begin_action.
    let mut owner = session(&locked, state);
    let proof = commit::commit(&locked, &path, Action::Forward, NEW).expect(row);
    let armed = crash_fs::arm_config(&path);
    assert_eq!(
        owner.record_fact(Action::Forward, &proof),
        Ok(()),
        "{row}: real A proof"
    );
    crash_fs::cut(dir.path(), Mode::DropAll);
    drop(armed);
    let recorded = reopened(&locked, row);
    assert_eq!(
        recorded.phase,
        Phase::Staged,
        "{row}: fact checked before accepted persist"
    );
    assert_eq!(
        recorded.fact,
        Some(Fact::Committed(FileRevision::of(NEW))),
        "{row}: record_fact is durable before any later persist"
    );
    assert_eq!(
        recorded.pending, None,
        "{row}: record_fact durably clears pending"
    );
}

#[test]
fn golden_journal_v2_attribution_decode() {
    const ROW: &str = "golden_journal_v2_attribution_decode";
    for (fixture, actor_bytes) in [
        (JOURNAL_V2_ATTRIBUTION, AUDIT_WHO_PRINCIPAL),
        (JOURNAL_V2_NONE, AUDIT_WHO_NONE),
    ] {
        let state = round_trip(fixture, ROW);
        let writer = state.writer.expect(ROW);
        assert_eq!(
            writer.intent.role,
            Role::Intent(IntentKind::KeyCreate),
            "{ROW}: role"
        );
        let actor = writer.intent.attribution.expect(ROW).actor;
        let expected: Value = serde_json::from_slice(actor_bytes).expect(ROW);
        assert_eq!(
            serde_json::to_value(&actor).expect(ROW),
            expected,
            "{ROW}: exact actor"
        );
        assert_eq!(
            actor.principal.as_str(),
            expected["principal"].as_str().expect(ROW),
            "{ROW}: principal is restored without rekeying"
        );
        let payload: Value = serde_json::from_slice(&writer.intent.payload_json).expect(ROW);
        assert_eq!(
            payload,
            json!({"subject": "deploy-bot", "kind": "settle.key_create"}),
            "{ROW}: caller payload keeps key name only"
        );
        let envelope = crate::security::audit::AuditEnvelope::ok(actor);
        let mut fields = serde_json::Map::new();
        envelope.write_into(&mut fields);
        assert!(
            !fields.contains_key("subject") && !fields.contains_key("value"),
            "{ROW}: no top-level envelope subject or value"
        );
    }
}

#[test]
fn golden_journal_v2_root_decode() {
    const ROW: &str = "golden_journal_v2_root_decode";
    let state = round_trip(JOURNAL_V2_ROOT, ROW);
    assert_eq!(state.writer, None, "{ROW}: no predecessor writer");
    assert_eq!(state.attempts.len(), 1, "{ROW}: exactly one root token");
    let intent = &state.attempts[0].intent;
    assert_eq!(intent.role, Role::RecoveryIntent, "{ROW}: root role");
    let payload: Value = serde_json::from_slice(&intent.payload_json).expect(ROW);
    assert_eq!(
        payload.get("root"),
        Some(&Value::Bool(true)),
        "{ROW}: explicit root marker"
    );
    assert!(
        payload.get("settles").is_none(),
        "{ROW}: no invented predecessor"
    );
}

#[test]
fn golden_journal_v2_parked_decode() {
    const ROW: &str = "golden_journal_v2_parked_decode";
    let state = round_trip(JOURNAL_V2_PARKED, ROW);
    let intent = state.writer.expect(ROW).intent;
    assert_eq!(
        intent.parked,
        Some(ParkReason::InvalidPayload),
        "{ROW}: parked reason"
    );
    assert_eq!(
        intent.payload_json, b"{invalid",
        "{ROW}: rejected bytes unchanged"
    );
    assert!(!intent.delivered, "{ROW}: rejection is not delivery");
}

#[test]
fn golden_journal_v2_handed_over_decode() {
    const ROW: &str = "golden_journal_v2_handed_over_decode";
    let state = round_trip(JOURNAL_V2_HANDED_OVER, ROW);
    let writer = state.writer.as_ref().expect(ROW);
    assert!(writer.handed_over, "{ROW}: ownership flag retained");
    assert!(
        !writer.intent.delivered,
        "{ROW}: decode does not invent delivery"
    );
    assert!(
        writer.records.is_empty(),
        "{ROW}: decode does not freeze records"
    );
    let (_dir, path, locked) = config();
    write_atomic(
        &journal::journal_path(&path),
        JOURNAL_V2_HANDED_OVER,
        FileMode::Private,
        Symlink::Replace,
    )
    .expect(ROW);
    assert_eq!(
        reopened(&locked, ROW),
        state,
        "{ROW}: open does not freeze or deliver"
    );
    assert_eq!(
        bytes(&path),
        JOURNAL_V2_HANDED_OVER,
        "{ROW}: open leaves owner unchanged"
    );
}

#[test]
fn reason_codec_s6a() {
    const ROW: &str = "reason_codec_s6a";
    const ABANDONED: &[u8] = br#""abandoned""#;
    const MOVED: &[u8] = br#""moved""#;
    const REFUSED: &[u8] = br#""refused""#;
    const WRITER_DIED: &[u8] = br#""writer_died""#;
    const UNKNOWN: &[u8] = br#""future_reason""#;
    for (bytes, reason) in [
        (ABANDONED, Reason::Abandoned),
        (MOVED, Reason::Moved),
        (REFUSED, Reason::Refused),
        (WRITER_DIED, Reason::WriterDied),
    ] {
        assert_eq!(
            Reason::from_journal(bytes),
            Ok(reason),
            "{ROW}: fixed reason decodes"
        );
        assert_eq!(
            serde_json::to_vec(&reason).expect(ROW),
            bytes,
            "{ROW}: exact spelling"
        );
    }
    assert!(
        Reason::from_journal(UNKNOWN).is_err(),
        "{ROW}: unknown rejected by codec"
    );
    reason_decision_cases();
}

fn reason_decision_cases() {
    const ROW: &str = "reason_codec_s6a";
    for (fixture, result, reason, terminal, settled_by, delivery_stopped) in [
        (
            JOURNAL_V2_DECISION_WRITTEN,
            ResultClass::Written,
            Reason::Committed,
            TerminalRole::Outcome,
            None,
            false,
        ),
        (
            JOURNAL_V2_DECISION_NOT_WRITTEN,
            ResultClass::NotWritten,
            Reason::Refused,
            TerminalRole::Outcome,
            None,
            false,
        ),
        (
            JOURNAL_V2_DECISION_UNPROVEN,
            ResultClass::Unproven,
            Reason::Abandoned,
            TerminalRole::Abandoned,
            Some(IntentId("recovery-1".into())),
            false,
        ),
        (
            JOURNAL_V2_DECISION_ABANDONED_NOT_WRITTEN,
            ResultClass::NotWritten,
            Reason::Abandoned,
            TerminalRole::Abandoned,
            None,
            true,
        ),
    ] {
        let state = round_trip(fixture, ROW);
        assert_eq!(
            state.writer.expect(ROW).decision,
            Some(Decision {
                result,
                reason,
                settled_by,
                terminal,
                delivery_stopped,
            }),
            "{ROW}: exact non-null decision for {result:?}/{terminal:?}"
        );
    }
    for (case, fixture) in [
        ("Outcome/Unproven", JOURNAL_V2_INVALID_OUTCOME_UNPROVEN),
        (
            "Outcome/Abandoned reason",
            JOURNAL_V2_INVALID_OUTCOME_ABANDONED,
        ),
        (
            "Outcome/RenamedNotDurable",
            JOURNAL_V2_INVALID_OUTCOME_RENAMED,
        ),
        (
            "Outcome/LeftToRecovery",
            JOURNAL_V2_INVALID_OUTCOME_DEFERRED,
        ),
        ("Abandoned/Written", JOURNAL_V2_INVALID_ABANDONED_WRITTEN),
        (
            "Abandoned/NotWritten/Refused",
            JOURNAL_V2_INVALID_ABANDONED_REFUSED,
        ),
        (
            "Abandoned/Unproven/Refused",
            JOURNAL_V2_INVALID_ABANDONED_UNPROVEN_REFUSED,
        ),
    ] {
        assert_eq!(
            JournalV2::decode(fixture),
            Err(JournalError::InvalidState),
            "{ROW}: illegal {case} decision rejected on load"
        );
    }
}

#[test]
fn record_principal_persisted_decode() {
    const ROW: &str = "record_principal_persisted_decode";
    for principal in ["0123ab45cd67", "ABCDEF012345", ""] {
        let decoded = checked(RecordPrincipal::from_persisted(principal), ROW);
        assert_eq!(
            decoded.as_str(),
            principal,
            "{ROW}: exact principal, no rekeying"
        );
    }
    for fixture in [AUDIT_WHO_PRINCIPAL, AUDIT_WHO_NONE] {
        let actor = checked(AuditWho::from_persisted(fixture), ROW);
        let expected: Value = serde_json::from_slice(fixture).expect(ROW);
        assert_eq!(
            serde_json::to_value(&actor).expect(ROW),
            expected,
            "{ROW}: all fields"
        );
        let encoded = serde_json::to_vec(&actor).expect(ROW);
        assert_eq!(
            encoded, fixture,
            "{ROW}: stable actor bytes and exact empty sentinel"
        );
    }
    for bad in [
        "0",
        "0123ab45cd6",
        "0123ab45cd678",
        "0123ab45cd6g",
        "none",
        "é123ab45cd6",
    ] {
        assert!(
            RecordPrincipal::from_persisted(bad).is_err(),
            "{ROW}: malformed principal"
        );
        let mut actor: Value = serde_json::from_slice(AUDIT_WHO_PRINCIPAL).expect(ROW);
        actor["principal"] = json!(bad);
        assert!(
            AuditWho::from_persisted(&serde_json::to_vec(&actor).expect(ROW)).is_err(),
            "{ROW}: malformed actor principal is rejected, never erased"
        );
    }
}
