// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An all-records reader is told of every record the logger writes, as it was
//! persisted, with the logger's rewrite generation, and of no failed write.

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::super::TransparencyLogger;
use super::super::rotation::{EV_EXPIRED, EV_SEALED, WriteFault};
use super::super::rotation_tests::{append, cfg, lines, log_path, rotate_n};
use crate::security::audit::AuditEnvelope;

/// What one reader was told: the record, its counter and the generation.
type Told = Arc<Mutex<Vec<(Map<String, Value>, u64, u64)>>>;

fn listen(log: &TransparencyLogger) -> Told {
    let told: Told = Arc::default();
    let sink = Arc::clone(&told);
    log.subscribe_all(Arc::new(
        move |record: &Map<String, Value>, counter: u64, generation: u64| {
            sink.lock()
                .unwrap()
                .push((record.clone(), counter, generation));
        },
    ));
    told
}

fn event(fields: Value) -> Map<String, Value> {
    let Value::Object(map) = fields else {
        panic!("an event is an object");
    };
    map
}

fn records(path: &Path) -> Vec<Map<String, Value>> {
    lines(path)
        .into_iter()
        .map(|v| v.as_object().cloned().unwrap())
        .collect()
}

#[test]
fn h1_every_kind_of_record_is_announced_as_it_was_persisted() {
    for signed in [false, true] {
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let log = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        let before = records(&path).len();
        let told = listen(&log);
        // A call (no kind), an admin action (an event) and a config record.
        log.log_invocation("s", "c", "srv", "tool", "sha256:aa", "sha256:bb")
            .unwrap();
        log.append_event(
            event(json!({"event": "admin_action", "action": "reload"})),
            &AuditEnvelope::gateway(),
        )
        .unwrap();
        log.append_event(
            event(json!({"kind": "config", "change": 1})),
            &AuditEnvelope::gateway(),
        )
        .unwrap();
        let written = records(&path)[before..].to_vec();
        let told = told.lock().unwrap().clone();
        assert_eq!(written.len(), 3, "signed={signed}");
        assert_eq!(
            told.iter().map(|(r, _, _)| r.clone()).collect::<Vec<_>>(),
            written,
            "signed={signed}: each record as persisted, in order"
        );
        for (record, counter, _) in &told {
            assert_eq!(
                record.get("counter").and_then(Value::as_u64),
                Some(*counter)
            );
            assert!(record.contains_key("prev_entry_hash") && record.contains_key("entry_hash"));
            assert_eq!(
                record.contains_key("sig") && record.contains_key("key_id"),
                signed,
                "signed={signed}: the signature rides along"
            );
        }
    }
}

#[test]
fn h1_a_failed_write_is_never_announced() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    append(&log, 1);
    log.arm_write_fault(Some(WriteFault::WriteError));
    assert!(
        log.log_invocation("s", "c", "srv", "t", "a", "b").is_err(),
        "the write fault fires"
    );
    append(&log, 2);
    let counters: Vec<u64> = told.lock().unwrap().iter().map(|t| t.1).collect();
    let on_disk: Vec<u64> = records(&path)
        .iter()
        .filter_map(|r| r.get("counter").and_then(Value::as_u64))
        .collect();
    assert_eq!(counters.len(), 2, "two writes succeeded, one failed");
    assert!(
        told.lock().unwrap().iter().all(|t| t.2 == 0),
        "a failed write is not a rewrite"
    );
    assert!(
        counters.iter().all(|c| on_disk.contains(c)),
        "only persisted records are announced: {counters:?} vs {on_disk:?}"
    );
}

#[test]
fn h1_the_seal_and_the_expiry_record_are_announced() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    let told = listen(&log);
    let event_of =
        |r: &Map<String, Value>| r.get("event").and_then(Value::as_str).map(str::to_owned);
    // With one segment retained, each rotation expires the one before it, so
    // the segment count never grows: append until an expiry is announced.
    let mut i = 0;
    while !told
        .lock()
        .unwrap()
        .iter()
        .any(|(r, _, _)| event_of(r).as_deref() == Some(EV_EXPIRED))
    {
        append(&log, i);
        i += 1;
        assert!(i < 2_000, "no expiry was announced");
    }
    append(&log, i);
    let told = told.lock().unwrap();
    assert!(
        told.iter()
            .any(|(r, _, _)| event_of(r).as_deref() == Some(EV_SEALED))
    );
    assert!(
        told.iter()
            .any(|(r, _, _)| event_of(r).as_deref() == Some(EV_EXPIRED))
    );
    assert!(
        told.windows(2).all(|w| w[0].1 < w[1].1),
        "announced in chain order"
    );
    assert!(
        told.iter().all(|(_, _, g)| *g == 0),
        "rotation and retention never raise the generation"
    );
}

#[test]
fn h2_a_file_shrunk_in_place_raises_the_generation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    for i in 0..3 {
        append(&log, i);
    }
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
    append(&log, 3);
    let told = told.lock().unwrap();
    let (first, last) = (told.first().unwrap().2, told.last().unwrap().2);
    assert_eq!(first, 0);
    assert!(last > first, "the shrink raised the generation");
}

#[test]
fn h2_a_counter_moved_back_raises_the_generation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    append(&log, 0);
    append(&log, 1);
    let older = dir.path().join("older.jsonl");
    std::fs::copy(&path, &older).unwrap();
    append(&log, 2);
    append(&log, 3);
    // The active file replaced by an older copy: a new file, a lower tail.
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&older, &path).unwrap();
    append(&log, 4);
    let told = told.lock().unwrap();
    let before: Vec<u64> = told[..4].iter().map(|t| t.2).collect();
    assert_eq!(before, vec![0; 4]);
    assert!(
        told[4..].iter().all(|t| t.2 > 0),
        "every write after the replacement carries a raised generation: {told:?}"
    );
}

#[test]
fn h2_rotation_and_a_rebuild_that_finds_the_counter_in_place_do_not_raise_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    rotate_n(&log, &path, 2);
    // A governance append re-reads the tail every time: the counter is where
    // this writer left it.
    for n in 0..3 {
        log.append_event_synced(
            event(json!({"kind": "config", "change": n})),
            &AuditEnvelope::gateway(),
        )
        .unwrap();
    }
    let told = told.lock().unwrap();
    assert!(!told.is_empty());
    assert!(told.iter().all(|t| t.2 == 0), "no raise: {told:?}");
}

/// Every announced record is on disk exactly as announced, once, and no
/// counter is announced twice.
fn assert_announced_as_persisted(path: &Path, told: &Told) {
    let on_disk: Vec<Map<String, Value>> = super::super::segments::list_segments(path)
        .unwrap()
        .iter()
        .flat_map(|s| records(&s.path))
        .chain(records(path))
        .collect();
    let told = told.lock().unwrap();
    for (record, counter, _) in told.iter() {
        assert!(
            on_disk.contains(record),
            "announced record {counter} is not on disk as announced"
        );
    }
    let counters: Vec<u64> = told.iter().map(|t| t.1).collect();
    assert!(
        counters.windows(2).all(|w| w[0] < w[1]),
        "announced out of order or twice: {counters:?}"
    );
}

#[test]
fn h1_a_failed_sync_is_never_announced_and_the_next_write_is() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    log.arm_write_fault(Some(WriteFault::SyncError));
    assert!(
        log.append_event_synced(
            event(json!({"kind": "config", "change": 1})),
            &AuditEnvelope::gateway()
        )
        .is_err(),
        "the sync fault fires"
    );
    log.append_event_synced(
        event(json!({"kind": "config", "change": 2})),
        &AuditEnvelope::gateway(),
    )
    .unwrap();
    let changes: Vec<u64> = told
        .lock()
        .unwrap()
        .iter()
        .filter_map(|t| t.0.get("change").and_then(Value::as_u64))
        .collect();
    assert_eq!(changes, vec![2], "only the write whose sync succeeded");
    assert!(
        told.lock().unwrap().iter().all(|t| t.2 == 0),
        "a failed sync is not a rewrite"
    );
    assert_announced_as_persisted(&path, &told);
}

#[test]
fn h1_a_disk_full_retry_is_announced_once_behind_its_expiry_record() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&log, &path, 1);
    let told = listen(&log);
    log.arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
    append(&log, 1);
    log.arm_write_fault(None);
    let told_now = told.lock().unwrap().clone();
    let events: Vec<Option<String>> = told_now
        .iter()
        .map(|t| t.0.get("event").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let expiry = events
        .iter()
        .position(|e| e.as_deref() == Some(EV_EXPIRED))
        .expect("the expiry record is announced");
    assert_eq!(
        told_now.len(),
        expiry + 2,
        "the retried call follows it, once"
    );
    assert_announced_as_persisted(&path, &told);
}

#[test]
fn h2_a_same_counter_fork_raises_the_generation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    for i in 0..3 {
        append(&log, i);
    }
    // Another log of the same length and a different history.
    let other_dir = crate::test_dir_keep::kept_tempdir();
    let other_path = log_path(&other_dir);
    let other = TransparencyLogger::open(cfg(&other_path, 12, false)).unwrap();
    for i in 10..13 {
        append(&other, i);
    }
    drop(other);
    std::fs::remove_file(&path).unwrap();
    std::fs::copy(&other_path, &path).unwrap();
    append(&log, 3);
    let told = told.lock().unwrap();
    assert!(
        told.last().unwrap().2 > 0,
        "the fork raised the generation: {told:?}"
    );
}

#[test]
fn h2_a_new_segment_cut_after_its_first_record_raises_the_generation() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    rotate_n(&log, &path, 1);
    append(&log, 100);
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
    append(&log, 101);
    assert!(told.lock().unwrap().last().unwrap().2 > 0);
}

#[test]
fn h2_a_file_cut_after_subscribing_and_before_any_append_raises_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    {
        let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        for i in 0..3 {
            append(&first, i);
        }
    }
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
    append(&log, 3);
    assert!(told.lock().unwrap().last().unwrap().2 > 0);
}

fn cut_in_half(path: &Path) {
    let len = std::fs::metadata(path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(len / 2)
        .unwrap();
}

#[test]
fn h2_a_second_reader_subscribing_after_a_cut_does_not_hide_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let first = listen(&log);
    for i in 0..3 {
        append(&log, i);
    }
    cut_in_half(&path);
    let second = listen(&log);
    append(&log, 3);
    // The second subscribe found the cut and raised the generation once; both
    // readers see that record with it.
    assert_eq!(first.lock().unwrap().last().unwrap().2, 1);
    assert_eq!(second.lock().unwrap().last().unwrap().2, 1);
}

#[test]
fn h2_a_cut_after_a_rebuild_whose_write_failed_raises_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    for i in 0..3 {
        append(&log, i);
    }
    // The active file goes away: the next append rebuilds onto a new file,
    // and its own record write fails, so no write records the new end.
    std::fs::remove_file(&path).unwrap();
    log.arm_write_fault(Some(WriteFault::WriteError));
    assert!(log.log_invocation("s", "c", "srv", "t", "a", "b").is_err());
    // No write after the failed one: the cut comes before any write could
    // record the rebuilt file's end, so only the rebuild's own baseline sees it.
    cut_in_half(&path);
    append(&log, 3);
    let told = told.lock().unwrap();
    assert_eq!(
        told.last().unwrap().2,
        2,
        "one rise for the replaced tail, one for the cut: {told:?}"
    );
}

#[test]
fn h2_a_cut_after_a_rotation_whose_write_failed_raises_it() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let log = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let told = listen(&log);
    // Inside the rotation, after the rename: the record that triggered it
    // fails to write, so no write records the new segment's end.
    log.on_rotation_window(Box::new(|l: &TransparencyLogger| {
        l.arm_write_fault(Some(WriteFault::WriteError));
    }));
    let mut i = 0;
    while log.log_invocation("s", "c", "srv", "t", "a", "b").is_ok() {
        i += 1;
        assert!(i < 1_000, "no rotation happened");
    }
    log.on_rotation_window(Box::new(|_: &TransparencyLogger| {}));
    assert_eq!(
        log.write_faults_fired(),
        1,
        "the armed fault, and nothing else, failed it"
    );
    assert!(
        !super::super::segments::list_segments(&path)
            .unwrap()
            .is_empty(),
        "a rotation happened"
    );
    assert!(
        told.lock().unwrap().iter().all(|t| t.2 == 0),
        "the rotation and its failed write raised nothing"
    );
    cut_in_half(&path);
    append(&log, 1);
    assert_eq!(
        told.lock().unwrap().last().unwrap().2,
        1,
        "the cut of the new segment raised the generation once"
    );
}
