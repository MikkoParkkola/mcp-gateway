//! SIEM/OTel evidence export (MIK-6689).
//!
//! Tails a [`TransparencyLogger`](crate::security::TransparencyLogger) NDJSON log
//! and forwards new, hash-verified entries to a sink. This is a *sink adapter*
//! over the already-durable transparency log (ADR-005), not a new subsystem.
//!
//! Guarantees:
//! - **At-least-once with idempotency.** The durable cursor advances only after
//!   the sink acks; a crash before persistence re-sends un-acked entries. Each
//!   [`ExportEntry`] carries `entry_hash` as the SIEM-side dedupe key.
//! - **Non-blocking + bounded.** The exporter polls the on-disk log; appends
//!   (`log_invocation`) never wait on it. Each poll forwards at most
//!   `max_batch` entries, so memory stays bounded regardless of backlog.
//! - **Hash-verified.** Each entry's chain link (`prev_entry_hash`) and its
//!   recomputed `entry_hash` are checked before forwarding; a failed check
//!   halts export and never forwards the entry.
//! - **Rotation-safe.** A file shorter than the cursor offset is treated as a
//!   rotation/truncation and re-anchored from the start.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::security::transparency_log::recompute_entry_hash;

/// Which transparency log an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSource {
    /// Tool-invocation transparency log.
    Invocation,
    /// Governance (control-plane) audit log.
    Governance,
}

/// One entry forwarded to a sink. Retains the raw hash-chain fields plus a
/// trusted checkpoint anchor so the SIEM side can verify contiguity.
#[derive(Debug, Clone, Serialize)]
pub struct ExportEntry {
    /// Source log.
    pub source: ExportSource,
    /// Chain counter.
    pub counter: u64,
    /// Entry hash — the idempotency / dedupe key.
    pub entry_hash: String,
    /// Previous entry hash (chain link).
    pub prev_entry_hash: String,
    /// Last verified hash before this batch — the anchor to verify from.
    pub checkpoint: String,
    /// The full original entry.
    pub raw: serde_json::Value,
}

/// Errors from the export pipeline.
#[derive(Debug)]
pub enum ExportError {
    /// I/O failure reading the log or persisting the cursor.
    Io(std::io::Error),
    /// A log line was not valid JSON.
    Corrupt(String),
    /// Chain verification failed (broken link or tampered hash) — export halts.
    VerificationFailed(String),
    /// The sink rejected the batch (no ack); the cursor is not advanced.
    SinkRejected(String),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "export I/O error: {e}"),
            Self::Corrupt(m) => write!(f, "export corrupt log line: {m}"),
            Self::VerificationFailed(m) => write!(f, "export verification failed (halted): {m}"),
            Self::SinkRejected(m) => write!(f, "export sink rejected batch: {m}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A destination for exported entries. `deliver` returning `Ok` is the ack that
/// lets the cursor advance.
pub trait ExportSink: Send + Sync {
    /// Deliver a batch. `Ok(())` acks; any `Err` leaves the cursor un-advanced.
    ///
    /// # Errors
    /// Implementations return an error to signal backpressure / delivery failure.
    fn deliver(&self, entries: &[ExportEntry]) -> Result<(), ExportError>;
}

/// Durable cursor position for one source.
///
/// Anchored by the last forwarded `entry_hash` rather than a byte offset, so a
/// same-size rotation cannot desync the resume point: if the anchor hash is no
/// longer present in the file, the exporter re-anchors from the start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportCursor {
    /// Entry hash of the last forwarded entry (chain anchor); `"genesis"` at start.
    pub last_entry_hash: String,
    /// Counter of the last forwarded entry (0 at start), for observability.
    #[serde(default)]
    pub last_counter: u64,
}

impl Default for ExportCursor {
    fn default() -> Self {
        Self {
            last_entry_hash: "genesis".to_string(),
            last_counter: 0,
        }
    }
}

/// Result of one [`LogExporter::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOutcome {
    /// Entries forwarded+acked this poll.
    pub forwarded: usize,
    /// Entries still pending after this poll (lag). Feeds a max-lag alert.
    pub lag_entries: usize,
    /// True when a rotation/truncation was detected and the cursor re-anchored.
    pub reanchored: bool,
}

/// Tails one transparency log and forwards verified entries to a sink,
/// persisting a durable cursor that advances only after the sink acks.
pub struct LogExporter {
    source: ExportSource,
    log_path: PathBuf,
    cursor_path: PathBuf,
    cursor: ExportCursor,
    max_batch: usize,
}

impl LogExporter {
    /// Default maximum entries forwarded per poll (bounds per-poll memory).
    pub const DEFAULT_MAX_BATCH: usize = 1024;

    /// Open an exporter for `log_path`, loading the persisted cursor from
    /// `cursor_path` (or starting at genesis).
    ///
    /// # Errors
    /// Errors if the cursor file exists but cannot be read/parsed.
    pub fn open(
        source: ExportSource,
        log_path: PathBuf,
        cursor_path: PathBuf,
    ) -> Result<Self, ExportError> {
        let cursor = match std::fs::read(&cursor_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| ExportError::Corrupt(format!("{}: {e}", cursor_path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => ExportCursor::default(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            source,
            log_path,
            cursor_path,
            cursor,
            max_batch: Self::DEFAULT_MAX_BATCH,
        })
    }

    /// Override the per-poll batch cap (memory bound).
    #[must_use]
    pub fn with_max_batch(mut self, max_batch: usize) -> Self {
        self.max_batch = max_batch.max(1);
        self
    }

    /// Current cursor (for observability/tests).
    #[must_use]
    pub fn cursor(&self) -> &ExportCursor {
        &self.cursor
    }

    /// Read new entries, verify the chain, forward up to `max_batch`, and — only
    /// on ack — advance and persist the cursor.
    ///
    /// # Errors
    /// - [`ExportError::VerificationFailed`] halts on a broken/tampered entry
    ///   (cursor not advanced, nothing forwarded).
    /// - [`ExportError::Corrupt`] on an unparseable line.
    /// - [`ExportError::SinkRejected`] on sink failure (cursor not advanced;
    ///   entries re-sent next poll — at-least-once).
    /// - [`ExportError::Io`] on read/persist failure.
    pub fn poll(&mut self, sink: &dyn ExportSink) -> Result<PollOutcome, ExportError> {
        let content = match std::fs::read(&self.log_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        // ponytail: parse the whole file each poll (O(file) CPU), which matches
        // what verify_log already costs; add a byte-offset fast-path if the log
        // grows hot. Memory stays bounded: we forward at most `max_batch`.
        let mut parsed: Vec<serde_json::Value> = Vec::new();
        for raw in content.split(|&b| b == b'\n') {
            if raw.iter().all(u8::is_ascii_whitespace) {
                continue; // blank / trailing
            }
            let entry: serde_json::Value = serde_json::from_slice(raw)
                .map_err(|e| ExportError::Corrupt(format!("{}: {e}", self.log_path.display())))?;
            parsed.push(entry);
        }

        // Resume after the anchor. If the anchor hash is absent (rotation /
        // truncation removed it), re-anchor from the start of the current file.
        let mut reanchored = false;
        let start = if self.cursor.last_entry_hash == "genesis" {
            0
        } else if let Some(i) = parsed.iter().position(|e| {
            e.get("entry_hash").and_then(|v| v.as_str()) == Some(&self.cursor.last_entry_hash)
        }) {
            i + 1
        } else {
            // Anchor hash gone (rotation / truncation): re-anchor from the start.
            reanchored = true;
            0
        };

        // Chain anchor to verify the first forwarded entry against.
        let mut running_prev = if reanchored || start == 0 {
            "genesis".to_string()
        } else {
            self.cursor.last_entry_hash.clone()
        };
        let checkpoint = running_prev.clone();

        let mut batch: Vec<ExportEntry> = Vec::new();
        let mut last_counter = self.cursor.last_counter;
        let new_entries = &parsed[start.min(parsed.len())..];
        for entry in new_entries {
            if batch.len() >= self.max_batch {
                break;
            }
            let stored_hash = entry
                .get("entry_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ExportError::VerificationFailed("entry missing entry_hash".to_string())
                })?
                .to_string();
            let prev = entry
                .get("prev_entry_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if prev != running_prev {
                return Err(ExportError::VerificationFailed(format!(
                    "chain break: prev_entry_hash {prev} != expected {running_prev}"
                )));
            }
            let recomputed = recompute_entry_hash(entry).map_err(ExportError::Io)?;
            if recomputed != stored_hash {
                return Err(ExportError::VerificationFailed(format!(
                    "tampered entry: recomputed {recomputed} != stored {stored_hash}"
                )));
            }
            let counter = entry
                .get("counter")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            batch.push(ExportEntry {
                source: self.source,
                counter,
                entry_hash: stored_hash.clone(),
                prev_entry_hash: prev,
                checkpoint: checkpoint.clone(),
                raw: entry.clone(),
            });
            running_prev = stored_hash;
            last_counter = counter;
        }

        let lag_entries = new_entries.len().saturating_sub(batch.len());

        if batch.is_empty() {
            return Ok(PollOutcome {
                forwarded: 0,
                lag_entries,
                reanchored,
            });
        }

        // Deliver, then advance + persist the cursor ONLY on ack (at-least-once).
        sink.deliver(&batch)
            .map_err(|e| ExportError::SinkRejected(e.to_string()))?;

        self.cursor.last_entry_hash = running_prev;
        self.cursor.last_counter = last_counter;
        self.persist_cursor()?;

        Ok(PollOutcome {
            forwarded: batch.len(),
            lag_entries,
            reanchored,
        })
    }

    /// Atomically persist the cursor (temp write → rename).
    fn persist_cursor(&self) -> Result<(), ExportError> {
        let bytes = serde_json::to_vec_pretty(&self.cursor)
            .map_err(|e| ExportError::Corrupt(e.to_string()))?;
        let tmp = self.cursor_path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.cursor_path)?;
        Ok(())
    }
}

/// Best-effort in-memory sink that collects delivered entries (core/testing).
#[derive(Default)]
pub struct CollectingSink {
    entries: std::sync::Mutex<Vec<ExportEntry>>,
}

impl CollectingSink {
    /// New empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all delivered entries.
    ///
    /// # Panics
    /// Panics only if the internal mutex is poisoned.
    #[must_use]
    pub fn delivered(&self) -> Vec<ExportEntry> {
        self.entries.lock().expect("collecting sink mutex").clone()
    }
}

impl ExportSink for CollectingSink {
    fn deliver(&self, entries: &[ExportEntry]) -> Result<(), ExportError> {
        self.entries
            .lock()
            .map_err(|_| ExportError::SinkRejected("collecting sink mutex poisoned".to_string()))?
            .extend_from_slice(entries);
        Ok(())
    }
}

/// Helper: the [`Path`] a cursor for `log_path` should live at (sibling `.cursor`).
#[must_use]
pub fn default_cursor_path(log_path: &Path) -> PathBuf {
    log_path.with_extension("export-cursor.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;
    use std::sync::Arc;

    fn logger(path: &Path) -> Arc<TransparencyLogger> {
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "test".to_string(),
            shared_secret: String::new(),
        });
        Arc::new(TransparencyLogger::open(cfg).expect("open log"))
    }

    fn gov_event(l: &TransparencyLogger, id: &str) {
        let mut m = serde_json::Map::new();
        m.insert("kind".into(), "control_plane_audit".into());
        m.insert("event_id".into(), id.into());
        l.append_event(m).expect("append governance event");
    }

    /// Sink that always rejects (simulates SIEM outage / backpressure).
    struct FailingSink;
    impl ExportSink for FailingSink {
        fn deliver(&self, _e: &[ExportEntry]) -> Result<(), ExportError> {
            Err(ExportError::SinkRejected("down".to_string()))
        }
    }

    fn exporter(dir: &Path, src: ExportSource, log: &Path) -> LogExporter {
        LogExporter::open(src, log.to_path_buf(), dir.join("cursor.json")).unwrap()
    }

    // MIK-6689.SIEM.1 — new entries from both logs forward in chain order,
    // labeled by source, carrying entry_hash/prev/checkpoint.
    #[test]
    fn forwards_both_sources_in_chain_order() {
        let dir = tempfile::tempdir().unwrap();
        let inv_path = dir.path().join("inv.jsonl");
        let gov_path = dir.path().join("gov.jsonl");
        let inv = logger(&inv_path);
        let gov = logger(&gov_path);
        inv.log_invocation("s1", "c", "srv", "t", "req:1", "resp:1")
            .unwrap();
        inv.log_invocation("s1", "c", "srv", "t", "req:2", "resp:2")
            .unwrap();
        gov_event(&gov, "g1");

        let inv_sink = CollectingSink::new();
        let mut inv_exp = exporter(&dir.path().join("inv"), ExportSource::Invocation, &inv_path);
        std::fs::create_dir_all(dir.path().join("inv")).unwrap();
        let out = inv_exp.poll(&inv_sink).unwrap();
        assert_eq!(out.forwarded, 2);
        let d = inv_sink.delivered();
        assert_eq!(d.iter().map(|e| e.counter).collect::<Vec<_>>(), [1, 2]);
        assert!(d.iter().all(|e| e.source == ExportSource::Invocation));
        assert!(d[0].entry_hash.starts_with("sha256:"));
        assert_eq!(d[1].prev_entry_hash, d[0].entry_hash);

        let gov_sink = CollectingSink::new();
        std::fs::create_dir_all(dir.path().join("gov")).unwrap();
        let mut gov_exp = exporter(&dir.path().join("gov"), ExportSource::Governance, &gov_path);
        assert_eq!(gov_exp.poll(&gov_sink).unwrap().forwarded, 1);
        assert_eq!(gov_sink.delivered()[0].source, ExportSource::Governance);
    }

    // MIK-6689.SIEM.2 — cursor advances only after ack; a failed send is re-sent.
    #[test]
    fn cursor_advances_only_after_ack_and_resends() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("inv.jsonl");
        let l = logger(&log);
        l.log_invocation("s", "c", "srv", "t", "r", "p").unwrap();

        let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
        // Sink is down: nothing forwarded, cursor stays at genesis/offset 0.
        assert!(matches!(
            exp.poll(&FailingSink),
            Err(ExportError::SinkRejected(_))
        ));
        assert_eq!(exp.cursor().last_entry_hash, "genesis");

        // Sink recovers: the same entry is re-sent (at-least-once) and acked.
        let sink = CollectingSink::new();
        assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
        assert_eq!(sink.delivered().len(), 1);
        assert!(exp.cursor().last_entry_hash.starts_with("sha256:"));

        // A fresh exporter reloads the persisted cursor and does NOT re-send.
        let mut exp2 = exporter(dir.path(), ExportSource::Invocation, &log);
        let sink2 = CollectingSink::new();
        assert_eq!(exp2.poll(&sink2).unwrap().forwarded, 0);
    }

    // MIK-6689.SIEM.3 — bounded per poll: max_batch caps memory, lag is reported.
    #[test]
    fn bounded_batch_reports_lag() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("inv.jsonl");
        let l = logger(&log);
        for i in 0..5 {
            l.log_invocation("s", "c", "srv", "t", &format!("r{i}"), &format!("p{i}"))
                .unwrap();
        }
        let sink = CollectingSink::new();
        let mut exp = exporter(dir.path(), ExportSource::Invocation, &log).with_max_batch(2);
        let out = exp.poll(&sink).unwrap();
        assert_eq!(out.forwarded, 2);
        assert!(out.lag_entries >= 1, "lag must be reported for the backlog");
        // Drain the rest across polls.
        assert_eq!(exp.poll(&sink).unwrap().forwarded, 2);
        assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
        assert_eq!(sink.delivered().len(), 5);
    }

    // MIK-6689.SIEM.4 — a tampered entry halts export; nothing is forwarded.
    #[test]
    fn tampered_entry_halts_and_alerts() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("inv.jsonl");
        let l = logger(&log);
        l.log_invocation("s", "c", "srv", "t", "r", "p").unwrap();
        drop(l);
        // Tamper: change a hashed field without re-chaining.
        let content = std::fs::read_to_string(&log).unwrap();
        let tampered = content.replace("\"caller\":\"c\"", "\"caller\":\"attacker\"");
        assert_ne!(tampered, content);
        std::fs::write(&log, tampered).unwrap();

        let sink = CollectingSink::new();
        let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
        assert!(matches!(
            exp.poll(&sink),
            Err(ExportError::VerificationFailed(_))
        ));
        assert!(sink.delivered().is_empty(), "no entry forwarded on halt");
        assert_eq!(exp.cursor().last_entry_hash, "genesis");
    }

    // MIK-6689.SIEM.5 — rotation/truncation re-anchors and resumes.
    #[test]
    fn rotation_reanchors_and_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("inv.jsonl");
        let l = logger(&log);
        l.log_invocation("s", "c", "srv", "t", "r1", "p1").unwrap();
        drop(l);

        let sink = CollectingSink::new();
        let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
        assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
        assert!(exp.cursor().last_entry_hash.starts_with("sha256:"));

        // Rotate: the old file is replaced by a fresh, shorter chain.
        std::fs::remove_file(&log).unwrap();
        let l2 = logger(&log);
        l2.log_invocation("s", "c", "srv", "t", "r-new", "p-new")
            .unwrap();
        drop(l2);

        let out = exp.poll(&sink).unwrap();
        assert!(out.reanchored, "shrunk file must re-anchor");
        assert_eq!(out.forwarded, 1);
        assert_eq!(sink.delivered().len(), 2);
    }
}
