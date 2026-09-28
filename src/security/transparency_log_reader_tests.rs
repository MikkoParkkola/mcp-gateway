// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R5: `audit show` reads a live, leased log. It rescans once when a file it
//! listed vanished or the segment list changed under it, reports a busy log
//! when that happens twice, and never rescans for mere growth.

use std::sync::Arc;

use super::rotation_tests::{cfg, log_path, rotate_n};
use super::segments::sibling;
use super::verify::{AFTER_STREAM, BEFORE_STREAM, LISTED, PASSES};
use super::*;

fn session_entry(l: &TransparencyLogger, i: usize) {
    l.log_invocation("reader-s", "c", "srv", &format!("t{i}"), "a", "b")
        .expect("append");
}

fn passes() -> usize {
    PASSES.with(std::cell::Cell::get)
}

type HookSlot = std::cell::RefCell<Option<Box<dyn FnOnce()>>>;

fn set(hook: &'static std::thread::LocalKey<HookSlot>, f: impl FnOnce() + 'static) {
    hook.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

/// A live writer holds the lease; the readers never need it.
#[test]
fn readers_work_beside_a_live_leased_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    session_entry(&l, 0);
    rotate_n(&l, &path, 1);
    session_entry(&l, 1);
    assert_eq!(show_session_entries(&path, "reader-s").unwrap().len(), 2);
    assert!(verify_log(&path).unwrap().ok);
}

/// One disruption (the listed active file renamed away mid-read): exactly one
/// rescan, then the whole result.
#[test]
fn show_rescans_once_when_a_listed_file_vanishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    session_entry(&l, 0);
    let (p, gone) = (path.clone(), sibling(&path, "moved"));
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f = Arc::clone(&fired);
    set(&LISTED, move || {
        std::fs::rename(&p, &gone).unwrap();
        f.store(true, std::sync::atomic::Ordering::SeqCst);
        set(&BEFORE_STREAM, move || std::fs::rename(&gone, &p).unwrap());
    });
    PASSES.with(|c| c.set(0));
    let got = show_session_entries(&path, "reader-s").unwrap();
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "hook never fired"
    );
    assert_eq!(got.len(), 1);
    assert_eq!(passes(), 2, "exactly one rescan");
}

/// A rotation under the reader on both passes: a busy log, not a result.
#[test]
fn show_reports_busy_when_the_log_changes_twice() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    session_entry(&l, 0);
    let (l1, p1) = (Arc::clone(&l), path.clone());
    set(&AFTER_STREAM, move || {
        rotate_n(&l1, &p1, 1);
        let (l2, p2) = (Arc::clone(&l1), p1.clone());
        set(&AFTER_STREAM, move || rotate_n(&l2, &p2, 1));
    });
    PASSES.with(|c| c.set(0));
    let err = show_session_entries(&path, "reader-s").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "{err}");
    assert!(err.to_string().contains("changed during"), "{err}");
    assert_eq!(passes(), 2, "one rescan, then busy");
}

/// Growth alone (an append during the read): no rescan.
#[test]
fn show_does_not_rescan_for_growth() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    session_entry(&l, 0);
    let l1 = Arc::clone(&l);
    set(&AFTER_STREAM, move || session_entry(&l1, 1));
    PASSES.with(|c| c.set(0));
    let got = show_session_entries(&path, "reader-s").unwrap();
    assert!(!got.is_empty());
    assert_eq!(passes(), 1, "growth is not a rotation");
}
