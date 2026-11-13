// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! File-drain rows: the abandoned file drains into its own log, refuses what it cannot prove,
//! and keeps a refused file exactly as found.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use super::super::super::abandoned::{
    AbandonedFrame, MAX_ABANDONED_BYTES, Slot, decode_frames, encode_frame, frames_of, marked,
};
use super::super::super::fixtures::{collect_case, config, seed};
use super::super::super::{FrozenRecord, IntentId, JournalSession, JournalV2, ParkReason, Phase};
use super::super::fixtures::{Live, attempt, decided, reread, runtime, staged, state};
use super::super::handover::{abandoned_path, hand_over};
use super::super::{DrainError, DrainSession};
use super::{complete, drain_abandoned, state_from_frames};
use crate::config_persistence::journal;
use crate::security::transparency_log::settle::Role;

/// A donor bound to a live log, handed over: the abandoned file exists and the journal is gone.
pub(super) struct DrainRig {
    pub(super) live: Live,
    pub(super) session: DrainSession,
    /// The donor as seeded, before the handover flagged it.
    pub(super) donor: JournalV2,
}

/// One decided writer whose outcome is not yet delivered, bound to `live`'s log, then handed over.
pub(super) fn drain_rig(row: &str, edit: impl FnOnce(&mut JournalV2)) -> DrainRig {
    let live = Live::new();
    let mut donor = state(&live.resolved);
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    donor.binding = Some(live.log.log_id());
    edit(&mut donor);
    let mut session = live.seed(donor.clone(), row);
    assert_eq!(hand_over(&mut session), Ok(()), "{row}: fixture handover");
    DrainRig {
        live,
        session,
        donor,
    }
}

/// The rig's donor with the writer's intent undelivered and no counter: the drain must deliver
/// the intent, then freeze and deliver the terminal itself.
pub(super) fn unfrozen(donor: &mut JournalV2) {
    let writer = donor.writer.as_mut().expect("fixture writer");
    writer.intent_counter = None;
    writer.records.clear();
}

impl DrainRig {
    pub(super) fn drain(&mut self) -> Result<(), super::super::DrainError> {
        runtime(drain_abandoned(
            &mut self.session,
            Some(Arc::clone(&self.live.log)),
        ))
    }

    pub(super) fn file(&self) -> Option<Vec<u8>> {
        file_at(&self.live.path)
    }

    pub(super) fn journal(&self) -> Option<Vec<u8>> {
        std::fs::read(journal::journal_path(&self.live.path)).ok()
    }
}

pub(super) fn file_at(config: &Path) -> Option<Vec<u8>> {
    std::fs::read(abandoned_path(config)).ok()
}

/// The frames a handover of `donor` writes, encoded and joined: an independent reference file.
pub(super) fn reference_file(donor: &JournalV2) -> Vec<u8> {
    frames_of(&marked(donor))
        .expect("the donor is bound")
        .iter()
        .map(|frame| encode_frame(frame).expect("a frame fits"))
        .collect::<Vec<_>>()
        .concat()
}

/// The distinct terminal contents the log holds for `token`: result, reason, settled_by and the
/// intent counter. Equal repeats collapse; a second entry is a terminal frozen twice.
pub(super) fn terminal_contents(live: &Live, token: &str) -> std::collections::BTreeSet<String> {
    live.records()
        .iter()
        .filter(|r| {
            r["token"] == token
                && (r["event"] == "config_write_outcome" || r["event"] == "config_write_abandoned")
        })
        .map(|r| {
            format!(
                "{} {} {} {} {}",
                r["event"], r["result"], r["reason"], r["settled_by"], r["intent_counter"]
            )
        })
        .collect()
}

/// Write `bytes` over the rig's abandoned path at mode 0600. A symlink is removed first, so
/// the bytes land on a new file at the path rather than on whatever the link names.
fn plant(rig: &DrainRig, bytes: &[u8]) {
    let path = abandoned_path(&rig.live.path);
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, bytes).expect("plant");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}

fn encoded(frames: &[AbandonedFrame]) -> Vec<u8> {
    frames
        .iter()
        .map(|frame| encode_frame(frame).expect("a frame fits"))
        .collect::<Vec<_>>()
        .concat()
}

/// The rig donor without a live log: the binding `state` already carries is enough.
fn rig_donor() -> JournalV2 {
    let mut donor = state(Path::new("."));
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    donor
}

/// The rig donor with the intent and its one terminal marked delivered.
fn delivered_donor() -> JournalV2 {
    let mut donor = rig_donor();
    let writer = donor.writer.as_mut().expect("fixture writer");
    writer.intent.delivered = true;
    for record in &mut writer.records {
        record.delivered = true;
    }
    donor
}

fn set_result(record: &mut FrozenRecord, result: &str) {
    let mut value: serde_json::Value =
        serde_json::from_slice(&record.payload_json).expect("payload");
    value["result"] = serde_json::Value::String(result.to_owned());
    record.payload_json = serde_json::to_vec(&value).expect("payload");
}

/// The rig file's frames, each altered into a shape a drain must refuse, plus a file past the cap.
fn bad_files(frames: &[AbandonedFrame]) -> Vec<(&'static str, Vec<u8>)> {
    let mut record_first = frames.to_vec();
    record_first.swap(0, 1);
    let mut gap = frames.to_vec();
    gap[1].slot = Slot::Record(1);
    let intent = frames[0].clone();
    let duplicate = vec![intent.clone(), intent];
    let mut unflagged = frames.to_vec();
    unflagged[0].owner.as_mut().expect("owner").handed_over = false;
    let mut other = frames[0].clone();
    other.intent_id = IntentId(format!("{}-b", other.intent_id.0));
    let root = other.owner.as_ref().expect("owner").root;
    other.owner.as_mut().expect("owner").root = !root;
    let mut roots = frames.to_vec();
    roots.push(other);
    let mut owned_record = frames.to_vec();
    owned_record[1].owner = frames[0].owner.clone();
    let mut no_decision = frames.to_vec();
    no_decision[0].owner.as_mut().expect("owner").decision = None;
    let mut wrong_result = frames.to_vec();
    set_result(&mut wrong_result[1].record, "written");
    vec![
        ("a record before its intent", encoded(&record_first)),
        ("a record index gap", encoded(&gap)),
        ("a duplicate token", encoded(&duplicate)),
        ("handed_over false", encoded(&unflagged)),
        ("roots that differ", encoded(&roots)),
        ("owner facts on a record", encoded(&owned_record)),
        ("a decision missing", encoded(&no_decision)),
        (
            "a pre-frozen terminal result differs",
            encoded(&wrong_result),
        ),
        ("over the byte cap", vec![b'0'; MAX_ABANDONED_BYTES + 1]),
    ]
}

fn refuse_planted(rig: &mut DrainRig, row: &str, name: &str, bytes: &[u8]) -> Result<(), String> {
    plant(rig, bytes);
    let before = rig.file();
    assert_eq!(rig.drain(), Err(DrainError::FileRefused), "{row}: {name}");
    assert_eq!(rig.file(), before, "{row}: {name} unchanged");
    Ok(())
}

fn refuse_symlink(rig: &mut DrainRig, row: &str, good: &[u8]) -> Result<(), String> {
    let path = abandoned_path(&rig.live.path);
    let target = rig.live.path.with_file_name("good-file");
    std::fs::write(&target, good).expect("symlink target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("mode");
    std::fs::remove_file(&path).expect("clear the abandoned path");
    std::os::unix::fs::symlink(&target, &path).expect("symlink");
    let link = std::fs::read_link(&path).expect("link");
    assert_eq!(rig.drain(), Err(DrainError::FileRefused), "{row}: symlink");
    assert_eq!(
        std::fs::read_link(&path).ok().as_ref(),
        Some(&link),
        "{row}: symlink unchanged"
    );
    assert_eq!(
        std::fs::read(&target).ok().as_deref(),
        Some(good),
        "{row}: target unchanged"
    );
    Ok(())
}

fn refuse_group(rig: &mut DrainRig, row: &str, good: &[u8]) -> Result<(), String> {
    let path = abandoned_path(&rig.live.path);
    plant(rig, good);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("mode");
    let before = rig.file();
    assert_eq!(
        rig.drain(),
        Err(DrainError::FileRefused),
        "{row}: group readable"
    );
    assert_eq!(rig.file(), before, "{row}: group readable unchanged");
    assert_eq!(
        std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777,
        0o640,
        "{row}: group readable mode"
    );
    Ok(())
}

/// One decided writer, plus an attempt whose terminal is frozen and not delivered.
fn with_undelivered_attempt(donor: &mut JournalV2) {
    let mut terminal = donor.writer.as_ref().expect("writer").records[0].clone();
    terminal.delivered = false;
    let decision = donor.writer.as_ref().expect("writer").decision.clone();
    let counter = donor.writer.as_ref().expect("writer").intent_counter;
    let mut extra = attempt();
    extra.decision = decision;
    extra.intent_counter = counter;
    extra.intent.delivered = true;
    extra.records.push(terminal);
    donor.attempts.push(extra);
}

#[test]
fn drain_delivers_and_removes_the_file() {
    const ROW: &str = "drain_delivers_and_removes_the_file";
    let mut rig = drain_rig(ROW, unfrozen);
    assert!(rig.file().is_some(), "{ROW}: the handover left the file");
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(rig.file(), None, "{ROW}: the drained file is gone");
    assert_eq!(rig.journal(), None, "{ROW}: no journal was recreated");
    let writer = &rig
        .donor
        .writer
        .as_ref()
        .expect("fixture writer")
        .intent_id
        .0;
    assert_eq!(
        terminal_contents(&rig.live, writer).len(),
        1,
        "{ROW}: exactly one terminal for the writer"
    );
    rig.live.verify(ROW);
}

#[test]
fn state_from_frames_round_trips() {
    const ROW: &str = "state_from_frames_round_trips";
    let standard = rig_donor();
    let mut with_attempt = standard.clone();
    let mut extra = attempt();
    extra.decision = with_attempt
        .writer
        .as_ref()
        .expect("writer")
        .decision
        .clone();
    with_attempt.attempts.push(extra);
    let mut root = standard.clone();
    root.attempts = vec![root.writer.take().expect("writer")];
    let mut failures = Vec::new();
    for (name, donor) in [
        ("the standard donor", standard),
        ("an extra attempt", with_attempt),
        ("a root donor", root),
    ] {
        collect_case(
            &mut failures,
            ROW,
            name,
            "Some, and the same frames and bytes",
            || {
                let frames = frames_of(&marked(&donor)).expect("the donor is bound");
                let rebuilt = state_from_frames(frames.clone());
                assert!(rebuilt.is_some(), "{ROW}: {name}");
                let again = rebuilt.as_ref().and_then(|donor| frames_of(donor));
                assert_eq!(again.as_ref(), Some(&frames), "{ROW}: {name} frames");
                assert_eq!(
                    again.as_ref().map(|frames| encoded(frames)),
                    Some(encoded(&frames)),
                    "{ROW}: {name} bytes"
                );
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn complete_requires_every_token() {
    const ROW: &str = "complete_requires_every_token";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "every token delivered",
        "complete",
        || {
            assert!(complete(&delivered_donor()), "{ROW}: every token");
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "an undelivered terminal",
        "not complete",
        || {
            let mut donor = delivered_donor();
            with_undelivered_attempt(&mut donor);
            assert!(!complete(&donor), "{ROW}: undelivered terminal");
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "a terminal role that differs",
        "not complete",
        || {
            let mut donor = delivered_donor();
            donor.writer.as_mut().expect("writer").records[0].role = Role::Abandoned;
            assert!(!complete(&donor), "{ROW}: terminal role");
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "two terminal payloads",
        "not complete",
        || {
            let mut donor = delivered_donor();
            let writer = donor.writer.as_mut().expect("writer");
            let mut other = writer.records[0].clone();
            set_result(&mut other, "written");
            writer.records.push(other);
            assert!(!complete(&donor), "{ROW}: two payloads");
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "a parked record",
        "not complete",
        || {
            let mut donor = delivered_donor();
            donor.writer.as_mut().expect("writer").records[0].parked =
                Some(ParkReason::InvalidPayload);
            assert!(!complete(&donor), "{ROW}: parked");
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn drain_refuses_bad_shape() {
    const ROW: &str = "drain_refuses_bad_shape";
    let mut rig = drain_rig(ROW, |_| {});
    let good = rig.file().expect(ROW);
    let frames = decode_frames(&good).expect(ROW).frames;
    assert!(
        matches!(
            frames.first(),
            Some(frame) if frame.slot == Slot::Intent
                && frame.owner.as_ref().is_some_and(|owner| {
                    owner.handed_over && owner.decision.is_some()
                })
        ) && matches!(
            frames.get(1),
            Some(frame) if frame.slot == Slot::Record(0) && frame.owner.is_none()
        ),
        "{ROW}: the rig file is an intent frame then its record"
    );
    let mut failures = Vec::new();
    for (name, bytes) in bad_files(&frames) {
        collect_case(
            &mut failures,
            ROW,
            name,
            "FileRefused and the same bytes",
            || refuse_planted(&mut rig, ROW, name, &bytes),
        );
    }
    collect_case(
        &mut failures,
        ROW,
        "a symlink",
        "FileRefused, link and target unchanged",
        || refuse_symlink(&mut rig, ROW, &good),
    );
    collect_case(
        &mut failures,
        ROW,
        "group readable",
        "FileRefused and the same bytes",
        || refuse_group(&mut rig, ROW, &good),
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn drain_refuses_live_journal() {
    const ROW: &str = "drain_refuses_live_journal";
    let mut rig = drain_rig(ROW, |_| {});
    seed(&rig.live.path, &rig.donor);
    reread(&mut rig.session);
    assert!(
        rig.session.journal.is_some(),
        "{ROW}: the session holds the journal"
    );
    let journal_before = rig.journal();
    let file_before = rig.file();
    let records_before = rig.live.records().len();
    assert!(
        journal_before.is_some(),
        "{ROW}: the journal is beside the file"
    );
    assert_eq!(rig.drain(), Err(DrainError::Journal), "{ROW}");
    assert_eq!(rig.journal(), journal_before, "{ROW}: journal unchanged");
    assert_eq!(rig.file(), file_before, "{ROW}: file unchanged");
    assert_eq!(
        rig.live.records().len(),
        records_before,
        "{ROW}: no new log record"
    );
}

#[test]
fn drain_without_logger() {
    const ROW: &str = "drain_without_logger";
    let mut rig = drain_rig(ROW, |_| {});
    let before = rig.file();
    assert_eq!(
        runtime(drain_abandoned(&mut rig.session, None)),
        Err(DrainError::NoLogger),
        "{ROW}"
    );
    assert_eq!(rig.file(), before, "{ROW}: file unchanged");
}

#[test]
fn abandoned_backing_contained() {
    const ROW: &str = "abandoned_backing_contained";
    let (_dir, target, _locked) = config();
    let state = marked(&rig_donor());
    let mut session = JournalSession::over_abandoned(target.clone(), state.clone());
    assert_eq!(session.persist(), Ok(()), "{ROW}");
    assert!(
        !journal::journal_path(&target).exists(),
        "{ROW}: no journal was written"
    );
    assert_eq!(
        std::fs::read(abandoned_path(&target)).ok().as_deref(),
        Some(reference_file(&state).as_slice()),
        "{ROW}: the abandoned file is that state's frames"
    );
    let original = journal::original_path(&target);
    std::fs::write(&original, b"staged-original").expect("staged original");
    assert!(
        session.finish().is_err(),
        "{ROW}: finish refuses an abandoned file"
    );
    assert!(original.exists(), "{ROW}: the staged original remains");
    assert!(
        abandoned_path(&target).exists(),
        "{ROW}: the abandoned file remains"
    );
}

#[test]
fn drain_empty_file_removed() {
    const ROW: &str = "drain_empty_file_removed";
    let mut rig = drain_rig(ROW, |_| {});
    plant(&rig, b"");
    let before = rig.live.records().len();
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(rig.file(), None, "{ROW}: an empty file is removed");
    assert_eq!(
        rig.live.records().len(),
        before,
        "{ROW}: no log record was added"
    );
}
