// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A log whose active file vanished starts again with a new id, and that
//! identity change leaves a trace: a reserved marker after the new genesis's
//! identified record, a warning naming both ids, and a verify warning.

use serde_json::Value;

use super::rotation_tests::{append, cfg, event, lines, log_path, verify};
use super::segments::{read_hwm, sibling};
use super::*;
use crate::test_log_capture::capture_warnings;

const PREDECESSOR: &str = "audit_log_predecessor_missing";

/// The events of `records` in order, a caller record (no event) as "".
fn events(records: &[Value]) -> Vec<&str> {
    records.iter().map(|v| event(v).unwrap_or("")).collect()
}

#[test]
fn a_log_deleted_under_a_live_logger_names_its_predecessor() {
    for keep_hwm in [false, true] {
        // GIVEN: a live logger on an unrotated log with records
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        append(&l, 0);
        let old = l.log_id();
        let mark = read_hwm(&path, b"", "test").unwrap();

        // WHEN: the active file is deleted (the mark kept or not), and it writes
        std::fs::remove_file(&path).unwrap();
        if !keep_hwm {
            std::fs::remove_file(sibling(&path, "hwm")).unwrap();
        }
        let ((), warned) = capture_warnings(|| append(&l, 1));

        // THEN: the new genesis, as the mark-missing path leaves it, then the
        // marker naming the old id and the identified record
        let head = lines(&path);
        let at = if keep_hwm {
            assert_eq!(
                events(&head),
                [
                    rotation::EV_OPENED,
                    rotation::EV_HWM_MISSING,
                    PREDECESSOR,
                    identity::EV_IDENTIFIED,
                    ""
                ],
                "{head:?}"
            );
            assert_eq!(head[0]["counter"].as_u64(), Some(mark.counter + 1));
            assert_eq!(head[0][rotation::HWM_MISSING_AT].as_u64(), Some(1));
            2
        } else {
            let want = [
                rotation::EV_OPENED,
                PREDECESSOR,
                identity::EV_IDENTIFIED,
                "",
            ];
            assert_eq!(events(&head), want, "{head:?}");
            assert_eq!(head[0]["counter"].as_u64(), Some(1));
            1
        };
        let marker = &head[at];
        assert_eq!(marker["previous_log_id"].as_str(), Some(old.as_str()));
        if keep_hwm {
            let hw = &marker["previous_high_water"];
            assert_eq!(hw["counter"].as_u64(), Some(mark.counter));
            assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));
        } else {
            assert!(marker.get("previous_high_water").is_none(), "{marker}");
        }

        // THEN: the logger holds the new id, raised as an identity change
        let new = l.log_id();
        assert_ne!(new, old, "keep_hwm: {keep_hwm}");
        assert_eq!(head[at + 1]["log_id"].as_str(), Some(new.as_str()));
        let raised = l.subscribers.raised();
        assert!(raised.contains(&"log_id"), "{raised:?}");
        assert!(!raised.contains(&"tail"), "{raised:?}");
        assert!(warned.contains(old.as_str()), "{warned}");
        assert!(warned.contains(new.as_str()), "{warned}");

        // THEN: verify reports the marker by the old id; with the mark kept it
        // also fails, naming the deletion, as before
        let r = verify(&path, false);
        assert!(
            r.warnings.iter().any(|w| w.contains(old.as_str())),
            "{:?}",
            r.warnings
        );
        if keep_hwm {
            let msg = r.error_message.unwrap_or_default();
            assert!(msg.contains("the active segment was deleted"), "{msg}");
        } else {
            assert!(r.ok, "{:?}", r.error_message);
        }
    }
}

#[test]
fn a_cold_fresh_log_and_its_reopen_record_no_predecessor() {
    // GIVEN: a fresh log, written and reopened
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&again, 1);

    // THEN: no marker, and verify warns of none
    assert!(!events(&lines(&path)).contains(&PREDECESSOR));
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_caller_cannot_append_an_audit_log_predecessor_missing_record() {
    // GIVEN: a log
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let before = lines(&path).len();

    // WHEN: a caller names the reserved event
    let mut forged = serde_json::Map::new();
    forged.insert("event".into(), PREDECESSOR.into());
    forged.insert("previous_log_id".into(), "forged".into());
    let refused = l.append_event(forged, &AuditEnvelope::gateway());

    // THEN: refused, nothing appended
    assert!(refused.is_err(), "the event is the logger's alone");
    assert_eq!(lines(&path).len(), before);
}
