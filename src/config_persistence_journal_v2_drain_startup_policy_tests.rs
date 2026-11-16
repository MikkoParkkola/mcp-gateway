// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The startup gate's finish stage over real drains: each policy P1-P7, the journal then the
//! file, the parked and refused cases, and a failed delivery (crash_s4).

use super::*;

/// GATE.4: each policy P1-P7 maps to its start result, artifact bytes, and owed records.
#[test]
fn finish_maps_each_policy() {
    const ROW: &str = "finish_maps_each_policy";
    let mut failures = Vec::new();
    for (case, expected, run) in [
        (
            "P1",
            "Ok, journal gone, writer-1 owed",
            policy_p1 as fn() -> Result<(), String>,
        ),
        ("P2", "JournalPending, journal identical", policy_p2),
        ("P3", "JournalPending, journal identical", policy_p3),
        ("P4", "Ok, file gone, writer-1 owed", policy_p4),
        ("P5", "AbandonedPending", policy_p5),
        ("P6", "Ok, abandoned bytes identical", policy_p6),
        ("P7", "Ok, journal gone", policy_p7),
    ] {
        journal_fixtures::collect_case(&mut failures, ROW, case, expected, run);
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
fn policy_p1() -> Result<(), String> {
    const ROW: &str = "finish_maps_each_policy P1";
    let live = Live::new();
    plant_accepted(&live, ROW);
    let session = prepared(&live.path, ROW);
    if artifact(&live.resolved, JOURNAL, ROW).is_empty() {
        return Err(format!("{ROW}: journal missing after prepare"));
    }
    finished(session, Some(Arc::clone(&live.log)), ROW);
    gone(&live.resolved, JOURNAL, ROW);
    let records = live.records();
    owe(&records, "writer-1", "config_save_intent", None, 1, ROW);
    owe(
        &records,
        "writer-1",
        "config_write_outcome",
        Some(("written", "committed")),
        1,
        ROW,
    );
    let recoveries = records
        .iter()
        .filter(|r| r["event"] == "config_recovery_intent")
        .count();
    assert_eq!(
        recoveries,
        0,
        "{ROW}: no config_recovery_intent; arrived {}",
        arrived(&records)
    );
    free(&live.path, ROW);
    Ok(())
}
fn policy_p2() -> Result<(), String> {
    refuse_bound("finish_maps_each_policy P2", true)
}
fn policy_p3() -> Result<(), String> {
    refuse_bound("finish_maps_each_policy P3", false)
}
fn refuse_bound(row: &str, foreign: bool) -> Result<(), String> {
    let live = Live::new();
    let other = Live::new();
    drop(live.seed(state(&live.resolved), row));
    let session = prepared(&live.path, row);
    let baseline = artifact(&live.resolved, JOURNAL, row);
    let log = foreign.then(|| Arc::clone(&other.log));
    let error = super::super::fixtures::runtime(finish_start(session, log));
    if error != Err(StartError::JournalPending) {
        return Err(format!("{row}: want JournalPending, got {error:?}"));
    }
    same(&live.resolved, JOURNAL, &baseline, row);
    free(&live.path, row);
    Ok(())
}
fn policy_p4() -> Result<(), String> {
    const ROW: &str = "finish_maps_each_policy P4";
    let live = Live::new();
    let session = abandon(&live, ROW, |_| {});
    finished(session, Some(Arc::clone(&live.log)), ROW);
    gone(&live.resolved, ABANDONED, ROW);
    let records = live.records();
    owe(&records, "writer-1", "config_save_intent", None, 1, ROW);
    owe(
        &records,
        "writer-1",
        "config_write_outcome",
        Some(("written", "committed")),
        1,
        ROW,
    );
    free(&live.path, ROW);
    Ok(())
}
fn policy_p5() -> Result<(), String> {
    const ROW: &str = "finish_maps_each_policy P5";
    let live = Live::new();
    let other = Live::new();
    let session = abandon(&live, ROW, |_| {});
    let baseline = artifact(&live.resolved, ABANDONED, ROW);
    let error = super::super::fixtures::runtime(finish_start(session, Some(other.log)));
    if error != Err(StartError::AbandonedPending) {
        return Err(format!("{ROW}: want AbandonedPending, got {error:?}"));
    }
    // Section 5 names the error. Byte-identity is the OtherLog keep (the file is not deleted).
    same(&live.resolved, ABANDONED, &baseline, ROW);
    free(&live.path, ROW);
    Ok(())
}
fn policy_p6() -> Result<(), String> {
    const ROW: &str = "finish_maps_each_policy P6";
    let live = Live::new();
    let session = abandon(&live, ROW, |_| {});
    let baseline = artifact(&live.resolved, ABANDONED, ROW);
    finished(session, None, ROW);
    same(&live.resolved, ABANDONED, &baseline, ROW);
    free(&live.path, ROW);
    Ok(())
}
fn policy_p7() -> Result<(), String> {
    const ROW: &str = "finish_maps_each_policy P7";
    let live = Live::new();
    plant_unbound(&live);
    let session = prepared(&live.path, ROW);
    if artifact(&live.resolved, JOURNAL, ROW).is_empty() {
        return Err(format!("{ROW}: journal missing after prepare"));
    }
    finished(session, None, ROW);
    gone(&live.resolved, JOURNAL, ROW);
    free(&live.path, ROW);
    Ok(())
}

/// GATE.4: a bound journal and a matching abandoned file drain in that order, then both are gone.
#[test]
fn finish_drains_journal_then_file() {
    const ROW: &str = "finish_drains_journal_then_file";
    let live = Live::new();
    let mut session = live.seed(file_donor(&live), ROW);
    handed(&mut session, ROW);
    drop(session);
    plant_staged(&live, ROW);
    finished(prepared(&live.path, ROW), Some(Arc::clone(&live.log)), ROW);
    let records = live.records();
    expect_staged_owed(&records, ROW);
    owe(&records, "file-1", "config_save_intent", None, 1, ROW);
    owe(
        &records,
        "file-1",
        "config_write_outcome",
        Some(("not_written", "refused")),
        1,
        ROW,
    );
    let file_at: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record["token"] == "file-1")
        .map(|(index, _)| index)
        .collect();
    let journal_ix: Vec<_> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record["token"].is_string() && record["token"] != "file-1")
        .map(|(index, _)| index)
        .collect();
    assert!(
        !file_at.is_empty() && !journal_ix.is_empty(),
        "{ROW}: both; {}",
        arrived(&records)
    );
    assert!(
        journal_ix.iter().copied().max().unwrap_or(0) < file_at.iter().copied().min().unwrap_or(0),
        "{ROW}: journal records then file-1; arrived {}",
        arrived(&records)
    );
    gone(&live.resolved, JOURNAL, ROW);
    gone(&live.resolved, ABANDONED, ROW);
    free(&live.path, ROW);
}

/// GATE.4: an abandoned frame the log rejects is parked, and the file stays.
#[test]
fn finish_parks_invalid_payload() {
    const ROW: &str = "finish_parks_invalid_payload";
    let live = Live::new();
    let session = abandon(&live, ROW, |donor| {
        unfrozen(donor);
        donor.writer.as_mut().expect(ROW).intent.payload_json = br#"{"kind":17}"#.to_vec();
    });
    let error = super::super::fixtures::runtime(finish_start(session, Some(Arc::clone(&live.log))));
    assert_eq!(
        error,
        Err(StartError::InvalidAuditPayload),
        "{ROW}: InvalidAuditPayload"
    );
    let frames = decode_frames(&artifact(&live.resolved, ABANDONED, ROW))
        .unwrap_or_else(|_| panic!("{ROW}: frames decode"));
    let parked: Vec<_> = frames
        .frames
        .iter()
        .filter(|frame| frame.record.parked == Some(ParkReason::InvalidPayload))
        .map(|frame| frame.intent_id.0.as_str())
        .collect();
    assert_eq!(
        parked,
        ["writer-1"],
        "{ROW}: park persisted on writer-1; parked {parked:?}"
    );
}

/// GATE.4: a journal record the log rejects is parked in the journal, which stays.
#[test]
fn finish_parks_invalid_journal_payload() {
    const ROW: &str = "finish_parks_invalid_journal_payload";
    let live = Live::new();
    let mut journal = state(&live.resolved);
    journal.writer.as_mut().expect(ROW).intent.payload_json = br#"{"kind":17}"#.to_vec();
    drop(live.seed(journal, ROW));
    let error = super::super::fixtures::runtime(finish_start(
        prepared(&live.path, ROW),
        Some(Arc::clone(&live.log)),
    ));
    assert_eq!(
        error,
        Err(StartError::InvalidAuditPayload),
        "{ROW}: InvalidAuditPayload"
    );
    let writer = journal_at(&live, ROW).writer.expect(ROW);
    assert_eq!(writer.intent_id.0, "writer-1", "{ROW}: parked token");
    assert_eq!(
        writer.intent.parked,
        Some(ParkReason::InvalidPayload),
        "{ROW}: park persisted"
    );
}

/// GATE.4: a torn abandoned file with logging off is AbandonedPending, not P6's accept.
#[test]
fn finish_refuses_unreadable_file_without_log() {
    const ROW: &str = "finish_refuses_unreadable_file_without_log";
    let live = Live::new();
    drop(abandon(&live, ROW, |_| {}));
    let good = artifact(&live.resolved, ABANDONED, ROW);
    let torn = good[..good.len() - 3].to_vec();
    plant_abandoned(&live.resolved, &torn);
    let session = prepared(&live.path, ROW);
    assert_eq!(
        artifact(&live.resolved, ABANDONED, ROW),
        torn,
        "{ROW}: torn tail kept"
    );
    let error = super::super::fixtures::runtime(finish_start(session, None));
    assert_eq!(
        error,
        Err(StartError::AbandonedPending),
        "{ROW}: AbandonedPending, not P6 accept"
    );
    same(&live.resolved, ABANDONED, &torn, ROW);
    free(&live.path, ROW);
}

/// GATE.4: a fault after the intent append is JournalPending and leaves the intent unflagged.
#[test]
fn crash_s4() {
    const ROW: &str = "crash_s4";
    let live = Live::new();
    plant_accepted(&live, ROW);
    let session = prepared(&live.path, ROW);
    let _armed = fault::arm(&live.path, Fault::Fail(At::IntentAppended));
    let error = super::super::fixtures::runtime(finish_start(session, Some(Arc::clone(&live.log))))
        .expect_err(ROW);
    assert_eq!(error, StartError::JournalPending, "{ROW}: JournalPending");
    assert_eq!(
        error.to_string(),
        SENTENCE,
        "{ROW}: Display is the fixed sentence"
    );
    let writer = journal_at(&live, ROW).writer.expect(ROW);
    assert_eq!(writer.intent_id.0, "writer-1", "{ROW}: undelivered token");
    assert!(
        !writer.intent.delivered,
        "{ROW}: writer-1 intent not flagged delivered"
    );
    free(&live.path, ROW);
}
