// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reader is told of each written record of its kind once, with the entry
//! hash the append returned, and of nothing else.

use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::super::TransparencyLogger;
use super::super::rotation_tests::{cfg, log_path};
use crate::security::audit::AuditEnvelope;

fn record(kind: &str, n: u64) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("kind".into(), kind.into());
    fields.insert("n".into(), json!(n));
    fields
}

#[test]
fn a_reader_sees_each_written_record_of_its_kind_once() {
    let dir = tempfile::tempdir().unwrap();
    let log = TransparencyLogger::open(cfg(&log_path(&dir), 12, false)).unwrap();
    let seen: Arc<Mutex<Vec<(u64, String)>>> = Arc::default();
    let sink = Arc::clone(&seen);
    log.subscribe(
        "wanted",
        Arc::new(
            move |fields: &Map<String, Value>, hash: &str, _counter: u64| {
                let n = fields.get("n").and_then(Value::as_u64).unwrap_or_default();
                sink.lock().unwrap().push((n, hash.to_string()));
            },
        ),
    );

    let first = log
        .append_event(record("wanted", 1), &AuditEnvelope::gateway())
        .unwrap();
    log.append_event(record("other", 2), &AuditEnvelope::gateway())
        .unwrap();
    log.fail_next_append_for_test();
    assert!(
        log.append_event(record("wanted", 3), &AuditEnvelope::gateway())
            .is_err()
    );
    let fourth = log
        .append_event(record("wanted", 4), &AuditEnvelope::gateway())
        .unwrap();

    assert_eq!(*seen.lock().unwrap(), vec![(1, first), (4, fourth)]);
}
