// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read log records back from a real tracing subscriber, as JSON.
//!
//! The pattern of `security::agent_identity_audit_tests`, shared so a test
//! can assert what an operator's log would show.

use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every record `run` emits on this thread, one parsed JSON object each.
///
/// The subscriber is thread-local and `run` is synchronous (an async body
/// runs on a current-thread runtime inside it), so a parallel test cannot
/// write into this capture. The process-wide TRACE registry keeps every
/// callsite's cached interest open, so no record is filtered out before the
/// scoped subscriber sees it.
pub(crate) fn records(run: impl FnOnce()) -> Vec<serde_json::Value> {
    keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = sink.0.lock().unwrap().clone();
    String::from_utf8(bytes)
        .expect("utf-8 log output")
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON object per line"))
        .collect()
}

/// `operation`'s value and the WARN-and-above lines it logged on this thread,
/// as plain text. Feature-free, so a row that only reads a warning runs in
/// every feature combination (MIK-8219).
pub(crate) fn capture_warnings<T>(operation: impl FnOnce() -> T) -> (T, String) {
    keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let result = tracing::subscriber::with_default(subscriber, operation);
    let output = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    (result, output)
}

/// The process-wide TRACE registry, installed once: a scoped subscriber
/// only sees an event whose callsite interest is not already cached as off.
fn keep_interest_open() {
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
}

/// A live count, on this thread, of log records containing `text`, for a
/// test that must wait for a record rather than read the log afterwards.
/// Counting stops when the guard drops.
pub(crate) fn live_count(
    text: &'static str,
) -> (
    tracing::subscriber::DefaultGuard,
    tokio::sync::watch::Receiver<usize>,
) {
    keep_interest_open();
    let (count, seen) = tokio::sync::watch::channel(0);
    let count = Arc::new(count);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || Counter(Arc::clone(&count), text))
        .finish();
    (tracing::subscriber::set_default(subscriber), seen)
}

struct Counter(Arc<tokio::sync::watch::Sender<usize>>, &'static str);

impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if String::from_utf8_lossy(bytes).contains(self.1) {
            self.0.send_modify(|n| *n += 1);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// How many of `records` are at `level` with a message containing `text`.
pub(crate) fn count(records: &[serde_json::Value], level: &str, text: &str) -> usize {
    records
        .iter()
        .filter(|r| {
            r["level"] == level
                && r["fields"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(text))
        })
        .count()
}
