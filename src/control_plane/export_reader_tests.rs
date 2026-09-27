// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R5 for the exporter: it scans a live, leased log without the lease,
//! rescans once when a listed file vanishes under it, reports a busy log when
//! the log changes on both passes, and never rescans for growth.

use std::path::Path;
use std::sync::Arc;

use super::segments::{EXPORT_AFTER_SCAN, EXPORT_LISTED, EXPORT_PASSES};
use super::{CollectingSink, ExportError, ExportSource, LogExporter};
use crate::security::transparency_log::segments::sibling;
use crate::security::transparency_log::{
    RotationConfig, TransparencyLogConfig, TransparencyLogger,
};

type Hook = &'static std::thread::LocalKey<super::segments::HookSlot>;

fn set(hook: Hook, f: impl FnOnce() + 'static) {
    hook.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

fn passes() -> usize {
    EXPORT_PASSES.with(std::cell::Cell::get)
}

fn logger(path: &Path) -> Arc<TransparencyLogger> {
    Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "test".to_string(),
            rotation: RotationConfig {
                max_segment_bytes: 4096,
                ..RotationConfig::default()
            },
            lease_wait_secs: 0,
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    )
}

fn event(l: &TransparencyLogger, id: &str) {
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), "control_plane_audit".into());
    m.insert("event_id".into(), id.into());
    l.append_event(m, &crate::security::audit::AuditEnvelope::gateway())
        .expect("append");
}

fn exporter(dir: &Path, log: &Path) -> LogExporter {
    LogExporter::open(
        ExportSource::Governance,
        log.to_path_buf(),
        dir.join("cursor.json"),
    )
    .unwrap()
}

/// One vanish mid-scan: one rescan, nothing lost.
#[test]
fn export_rescans_once_when_a_listed_file_vanishes() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = logger(&log);
    (0..3).for_each(|i| event(&l, &format!("a{i}")));
    let mut exp = exporter(dir.path(), &log);
    let (p, gone) = (log.clone(), sibling(&log, "moved"));
    set(&EXPORT_LISTED, move || {
        std::fs::rename(&p, &gone).unwrap();
        set(&EXPORT_LISTED, move || std::fs::rename(&gone, &p).unwrap());
    });
    EXPORT_PASSES.with(|c| c.set(0));
    let sink = CollectingSink::new();
    let out = exp.poll(&sink).unwrap();
    assert_eq!(out.forwarded, 3, "entries lost to the vanish");
    assert_eq!(passes(), 2, "exactly one rescan");
}

/// The log changes on both passes: a busy poll that forwards nothing, and
/// the next poll carries on.
#[test]
fn export_reports_busy_when_the_log_changes_twice() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = logger(&log);
    (0..3).for_each(|i| event(&l, &format!("a{i}")));
    let mut exp = exporter(dir.path(), &log);
    let (p, gone) = (log.clone(), sibling(&log, "moved"));
    set(&EXPORT_LISTED, move || {
        std::fs::rename(&p, &gone).unwrap();
        set(&EXPORT_LISTED, move || {
            std::fs::rename(&gone, &p).unwrap();
            let (p2, g2) = (p.clone(), gone.clone());
            std::fs::rename(&p2, &g2).unwrap();
            set(&EXPORT_AFTER_SCAN, move || {
                std::fs::rename(&g2, &p2).unwrap();
            });
        });
    });
    EXPORT_PASSES.with(|c| c.set(0));
    let sink = CollectingSink::new();
    match exp.poll(&sink) {
        Err(ExportError::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::Interrupted, "{e}");
        }
        other => panic!("expected a busy poll, got {other:?}"),
    }
    assert_eq!(passes(), 2, "one rescan, then busy");
    assert!(sink.delivered().is_empty());
    assert_eq!(
        exp.poll(&sink).unwrap().forwarded,
        3,
        "the next poll recovers"
    );
}

/// Growth during the scan: no rescan.
#[test]
fn export_does_not_rescan_for_growth() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = logger(&log);
    (0..3).for_each(|i| event(&l, &format!("a{i}")));
    let mut exp = exporter(dir.path(), &log);
    let l1 = Arc::clone(&l);
    set(&EXPORT_AFTER_SCAN, move || event(&l1, "grown"));
    EXPORT_PASSES.with(|c| c.set(0));
    let out = exp.poll(&CollectingSink::new()).unwrap();
    assert!(out.forwarded >= 3);
    assert_eq!(passes(), 1, "growth is not a rotation");
}
