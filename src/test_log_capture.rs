// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read log records back from a real tracing subscriber, as JSON.
//!
//! The pattern of `security::agent_identity_audit_tests`, shared so a test
//! can assert what an operator's log would show.

use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;

// The one keeper, shared with the binary's capture (MIK-8254).
#[path = "test_support/interest.rs"]
mod interest;
// Re-exported at its old path: callers outside this file (#3696) use
// `crate::test_log_capture::keep_interest_open`.
pub(crate) use interest::keep_interest_open;

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

/// A live count, on this thread, of log records at exactly `level` whose
/// message contains `text`, for a test that must wait for a record rather
/// than read the log afterwards. Counting stops when the guard drops.
pub(crate) fn live_count_at(
    level: tracing::Level,
    text: &'static str,
) -> (
    tracing::subscriber::DefaultGuard,
    tokio::sync::watch::Receiver<usize>,
) {
    keep_interest_open();
    let (tx, rx) = tokio::sync::watch::channel(0);
    let layer = SingleLevelCounter {
        level,
        text,
        sender: Arc::new(tx),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    (tracing::subscriber::set_default(subscriber), rx)
}

struct SingleLevelCounter {
    level: tracing::Level,
    text: &'static str,
    sender: Arc<tokio::sync::watch::Sender<usize>>,
}

/// The concatenated `str` and `debug` fields of one event, so a `contains`
/// check sees the message however the macros recorded it.
struct FieldText(String);

impl tracing::field::Visit for FieldText {
    fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
        self.0.push_str(value);
        self.0.push(' ');
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!("{value:?}"));
        self.0.push(' ');
    }
}

impl<S> tracing_subscriber::Layer<S> for SingleLevelCounter
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().level() != &self.level {
            return;
        }
        let mut seen = FieldText(String::new());
        event.record(&mut seen);
        if seen.0.contains(self.text) {
            self.sender.send_modify(|n| *n += 1);
        }
    }
}

/// A live count, on this thread, for several `(level, text)` pairs in ONE
/// subscriber, for a test that needs e.g. an INFO baseline and a WARN heal at
/// once. Two `set_default` guards cannot both count (the inner shadows the
/// outer on this thread), so one capture counts all of them. Counting stops
/// when the guard drops; `filters[i]` is counted in the returned `Vec[i]`.
pub(crate) fn live_counts_at(
    filters: &[(tracing::Level, &'static str)],
) -> (
    tracing::subscriber::DefaultGuard,
    tokio::sync::watch::Receiver<Vec<usize>>,
) {
    keep_interest_open();
    let (tx, rx) = tokio::sync::watch::channel(vec![0; filters.len()]);
    let layer = MultiLevelCounter {
        filters: filters.to_vec(),
        sender: Arc::new(tx),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    (tracing::subscriber::set_default(subscriber), rx)
}

struct MultiLevelCounter {
    filters: Vec<(tracing::Level, &'static str)>,
    sender: Arc<tokio::sync::watch::Sender<Vec<usize>>>,
}

impl<S> tracing_subscriber::Layer<S> for MultiLevelCounter
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut seen = FieldText(String::new());
        event.record(&mut seen);
        let level = event.metadata().level();
        if !self
            .filters
            .iter()
            .any(|(wanted, text)| level == wanted && seen.0.contains(text))
        {
            return;
        }
        self.sender.send_modify(|counts| {
            for (slot, (wanted, text)) in self.filters.iter().enumerate() {
                if level == wanted && seen.0.contains(text) {
                    counts[slot] += 1;
                }
            }
        });
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

/// MIK-8254 guard: every test file that installs its own scoped subscriber
/// also keeps callsite interest open, so the next capture cannot bring the
/// flake back. Lexical by design: a file that names `subscriber::with_default`
/// or `subscriber::set_default` must also reach the keeper (directly, or
/// through `test_log_capture` or the shared `error_capture`).
#[test]
fn every_scoped_log_capture_keeps_interest_open() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a source dir") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    walk(&root.join("tests"), &mut files);
    let installs = ["subscriber::with_default(", "subscriber::set_default("];
    let keeps = ["keep_interest_open", "test_log_capture", "error_capture"];
    let mut missing: Vec<String> = files
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            let installs_one = installs.iter().any(|needle| text.contains(needle));
            let keeps_one = keeps.iter().any(|needle| text.contains(needle));
            (installs_one && !keeps_one).then(|| {
                path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            })
        })
        .collect();
    missing.sort();
    // A second keeper, pasted inline, is the duplication this family removed:
    // a static Once that installs a global Registry, outside the one keeper.
    let mut copies: Vec<String> = files
        .iter()
        .filter(|path| !path.ends_with("test_support/interest.rs"))
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).ok()?;
            // Split so this guard's own source never matches itself.
            let inline_keeper = text.contains(concat!("call", "_once"))
                && text.contains(concat!("set_global", "_default("))
                && text.contains(concat!("Registry", "::default()"));
            inline_keeper.then(|| {
                path.strip_prefix(root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            })
        })
        .collect();
    copies.sort();
    assert!(
        copies.is_empty(),
        "these files define their own callsite-interest keeper instead of calling \
         crate::test_log_capture::keep_interest_open (one definition; MIK-8254): {copies:#?}"
    );
    assert!(
        missing.is_empty(),
        "these test files install a scoped log subscriber without keeping \
         callsite interest open (call crate::test_log_capture::keep_interest_open \
         first; MIK-8254): {missing:#?}"
    );
}
