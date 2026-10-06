// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7944 finding 5: a counter or segment number a record supplies at
//! `u64::MAX` is a failed verdict, never an overflow panic or a wrap to 0.
//! Each log is built so every earlier check passes and the named `+ 1` is
//! reached.

use std::path::Path;

use serde_json::{Map, Value, json};

use super::rotation::{EV_EXPIRED, EV_OPENED, EV_SEALED};
use super::rotation_tests::{cfg, log_path};
use super::segments::sealed_path;
use super::*;

const MAX: u64 = u64::MAX;
const MODES: [VerifyMode; 2] = [VerifyMode::Live, VerifyMode::Archive];

fn fields(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(map) => map,
        other => panic!("fields takes an object: {other}"),
    }
}

/// Write `records` (counter, fields) to `file` as one chain from `prev`;
/// returns the last entry hash.
fn write_chain(path: &Path, file: &Path, prev: &str, records: Vec<(u64, Value)>) -> String {
    let config = cfg(path, 12, false);
    let mut prev = prev.to_string();
    let mut body = String::new();
    for (counter, v) in records {
        let (line, hash) = chain_line(&config, fields(v), counter, &prev).unwrap();
        body += &(line + "\n");
        prev = hash;
    }
    std::fs::write(file, body).unwrap();
    prev
}

fn plain() -> Value {
    json!({"kind": "probe"})
}

fn seal(next: Option<u64>) -> Value {
    match next {
        Some(n) => json!({"event": EV_SEALED, "next_segment_seq": n}),
        None => json!({"event": EV_SEALED}),
    }
}

fn opened(seq: u64, prev_seq: Option<u64>, link: Option<&str>) -> Value {
    let mut v = json!({"event": EV_OPENED, "segment_seq": seq});
    if let Some(p) = prev_seq {
        v["prev_segment_seq"] = p.into();
    }
    if let Some(h) = link {
        v["prev_segment_final_hash"] = h.into();
    }
    v
}

/// Fails with an overflow verdict in both modes, no panic.
fn assert_overflow(path: &Path) {
    for mode in MODES {
        let r = verify_segments(path, &cfg(path, 12, false), mode).unwrap();
        assert!(!r.ok, "{mode:?}: {r:?}");
        let msg = r.error_message.unwrap_or_default();
        assert!(msg.contains("overflow"), "{mode:?}: {msg}");
    }
}

/// `finish`: the last record at `u64::MAX`, no `.hwm`, a sealed sibling.
#[test]
fn a_final_counter_at_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let s0 = sealed_path(&path, 0);
    let sealed = write_chain(
        &path,
        &s0,
        "genesis",
        vec![(MAX - 3, plain()), (MAX - 2, seal(Some(1)))],
    );
    write_chain(
        &path,
        &path,
        &sealed,
        vec![(MAX - 1, opened(1, Some(0), Some(&sealed))), (MAX, plain())],
    );
    assert_overflow(&path);
}

/// `check_entry`: a record at `u64::MAX` followed by another.
#[test]
fn a_record_after_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    write_chain(&path, &path, "genesis", vec![(MAX, plain()), (0, plain())]);
    assert_overflow(&path);
}

/// `first_record`: a seal at `u64::MAX` followed by an open record.
#[test]
fn an_open_record_after_a_seal_at_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let s0 = sealed_path(&path, 0);
    let sealed = write_chain(
        &path,
        &s0,
        "genesis",
        vec![(MAX - 1, plain()), (MAX, seal(Some(1)))],
    );
    write_chain(
        &path,
        &path,
        &sealed,
        vec![(5, opened(1, Some(0), Some(&sealed)))],
    );
    assert_overflow(&path);
}

/// `finish`: an expiry record whose `last_counter` is `u64::MAX`.
#[test]
fn an_expiry_last_counter_at_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let link = format!("sha256:{}", "a".repeat(64));
    write_chain(
        &path,
        &path,
        &link,
        vec![
            (10, opened(5, Some(4), Some(&link))),
            (
                11,
                json!({"event": EV_EXPIRED, "segment_seq": 4, "last_counter": MAX, "final_hash": link}),
            ),
        ],
    );
    assert_overflow(&path);
}

/// The newest sealed segment numbered `u64::MAX`, with an active file.
#[test]
fn an_active_file_after_segment_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    write_chain(
        &path,
        &sealed_path(&path, MAX),
        "genesis",
        vec![(1, opened(MAX, None, None)), (2, seal(Some(0)))],
    );
    std::fs::write(&path, "").unwrap();
    assert_overflow(&path);
}

/// A seal naming no next segment in segment `u64::MAX`.
#[test]
fn a_seal_without_next_in_segment_max_is_a_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    write_chain(
        &path,
        &sealed_path(&path, MAX),
        "genesis",
        vec![(1, opened(MAX, None, None)), (2, seal(None))],
    );
    assert_overflow(&path);
}
