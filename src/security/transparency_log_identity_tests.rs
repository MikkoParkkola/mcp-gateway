// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The log's `log_id`: minted once, reused by every reopen and rotation, kept
//! out of `.hwm`, and absent from no 4.0 segment's open record.

use std::path::Path;

use serde_json::Value;

use super::identity::EV_IDENTIFIED;
use super::rotation_tests::{append, cfg, event, lines, log_path, rotate_n, verify};
use super::segments::{HighWater, encode_hwm, list_segments, read_hwm, sibling, write_hwm};
use super::*;

/// Every record of the log, oldest segment first.
fn all_records(path: &Path) -> Vec<Value> {
    let mut all = Vec::new();
    for seg in list_segments(path).unwrap() {
        all.extend(lines(&seg.path));
    }
    all.extend(lines(path));
    all
}

fn identified(path: &Path) -> Vec<Value> {
    let all = all_records(path);
    all.into_iter()
        .filter(|v| event(v) == Some(EV_IDENTIFIED))
        .collect()
}

/// Rewrite a one-segment 4.0 log as a beta one: no `log_id` on the open
/// record, no identified record, re-chained, and `.hwm` re-minted at the new
/// tail with the same fixed layout.
fn beta_shape(path: &Path) {
    let c = cfg(path, 12, false);
    let (mut prev, mut counter, mut body) = ("genesis".to_string(), 0_u64, String::new());
    for v in lines(path)
        .iter()
        .filter(|v| event(v) != Some(EV_IDENTIFIED))
    {
        let mut fields = v.as_object().unwrap().clone();
        fields.remove("entry_hash");
        fields.remove("log_id");
        counter += 1;
        let (line, hash) = chain_line(&c, fields, counter, &prev).unwrap();
        body += &(line + "\n");
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
    let mark = HighWater {
        counter,
        entry_hash: prev,
        segment_seq: 0,
    };
    // Remove first: an in-place rewrite would keep any longer tail.
    std::fs::remove_file(sibling(path, "hwm")).unwrap();
    write_hwm(path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
}

#[test]
fn log_id_upgrade() {
    // GIVEN: a beta-shaped log that verifies
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    beta_shape(&path);
    let hwm_before = std::fs::read(sibling(&path, "hwm")).unwrap();
    assert!(identified(&path).is_empty(), "the fixture has no identity");
    assert!(verify(&path, false).ok, "a beta log verifies");

    // WHEN: 4.0 opens it, it is reopened, and it rotates
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id().clone();
    let upgraded = std::fs::read(sibling(&path, "hwm")).unwrap();
    // `.hwm` first, before any record or verify check: same fixed length as
    // the beta layout, and the id nowhere in it.
    assert_eq!(upgraded.len(), hwm_before.len(), "`.hwm` layout unchanged");
    assert!(!String::from_utf8_lossy(&upgraded).contains(id.as_str()));
    drop(l);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);

    // THEN: one identified record, one id everywhere, `.hwm` keeps its layout
    let found = identified(&path);
    assert_eq!(found.len(), 1, "minted once: {found:?}");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
    assert_eq!(l.log_id(), &id, "the id survives a reopen");
    let opened = lines(&path);
    assert_eq!(event(&opened[0]), Some(rotation::EV_OPENED));
    assert_eq!(opened[0]["log_id"].as_str(), Some(id.as_str()), "rotation");
    let hwm = std::fs::read(sibling(&path, "hwm")).unwrap();
    assert!(!String::from_utf8_lossy(&hwm).contains(id.as_str()));
    assert!(read_hwm(&path, b"", "test").is_some());
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}

#[test]
#[allow(non_snake_case)]
fn crash_S2() {
    // GIVEN: a logger just built (an in-process drop stands in for the kill)
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let built = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = built.log_id().clone();
    drop(built);

    // WHEN: the log is reopened twice
    for _ in 0..2 {
        let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        // THEN: the same id, and still one identified record
        assert_eq!(again.log_id(), &id);
        drop(again);
    }
    let found = identified(&path);
    assert_eq!(found.len(), 1, "never a second identified record");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
    assert_eq!(lines(&path)[0]["log_id"].as_str(), Some(id.as_str()));
}

#[test]
fn a_caller_cannot_append_an_audit_log_identified_record() {
    // GIVEN: a log with its minted id
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id().clone();
    let before = all_records(&path).len();

    // WHEN: a caller tries to name another id
    let mut forged = serde_json::Map::new();
    forged.insert("event".into(), EV_IDENTIFIED.into());
    forged.insert("log_id".into(), "forged".into());
    let refused = l.append_event(forged, &AuditEnvelope::gateway());

    // THEN: it is refused, nothing is appended, and a reopen keeps the id
    assert!(refused.is_err(), "the event is the logger's alone");
    assert_eq!(all_records(&path).len(), before);
    drop(l);
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    assert_eq!(again.log_id(), &id);
}

/// Replace `dst` with a copy of `src` through a rename, so `dst` is a new
/// file (a new inode) as another writer's swap would leave it.
fn swap_in(src: &Path, dst: &Path) {
    let tmp = dst.with_extension("swap");
    std::fs::copy(src, &tmp).unwrap();
    std::fs::rename(&tmp, dst).unwrap();
}

#[test]
fn a_log_replaced_under_a_live_logger_is_adopted_with_its_id() {
    // GIVEN: a live logger on one log, and a second log with its own id
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);
    let other = tempfile::tempdir().unwrap();
    let theirs = log_path(&other);
    let replacement = TransparencyLogger::open(cfg(&theirs, 12, false)).unwrap();
    append(&replacement, 0);
    let their_id = replacement.log_id().as_str().to_string();
    drop(replacement);
    assert_ne!(l.log_id().as_str(), their_id, "two logs, two ids");

    // WHEN: the second log replaces the first underneath it, whole (active
    // file and mark), and the live logger writes and then rotates
    swap_in(&theirs, &path);
    swap_in(&sibling(&theirs, "hwm"), &sibling(&path, "hwm"));
    append(&l, 1);
    rotate_n(&l, &path, 1);

    // THEN: the new segment carries the replacement's id, the logger holds
    // it, and the change was raised as an identity change
    let opened = lines(&path);
    assert_eq!(event(&opened[0]), Some(rotation::EV_OPENED));
    assert_eq!(opened[0]["log_id"].as_str(), Some(their_id.as_str()));
    assert_eq!(l.log_id().as_str(), their_id, "the logger adopted the id");
    let raised = l.subscribers.raised();
    assert!(raised.contains(&"log_id"), "raised: {raised:?}");
}
