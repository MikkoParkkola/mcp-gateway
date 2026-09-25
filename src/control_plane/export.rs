// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
//! - **Hash-verified (+ optional HMAC).** Each entry's chain link
//!   (`prev_entry_hash`) and its recomputed `entry_hash` are checked before
//!   forwarding; a failed check halts export and never forwards the entry. When
//!   a signing secret is configured (`with_signing_secret`, wired at runtime by
//!   MIK-6703), each entry's per-entry HMAC is also authenticated, so a
//!   self-consistent re-chained forgery is rejected too (MIK-6700). Without a
//!   secret it degrades to hash-only. A re-anchor is surfaced
//!   (`PollOutcome::reanchored`) so it can be alerted on.
//! - **Rotation-safe (in-place).** The cursor anchors on the last forwarded
//!   `entry_hash`; a truncated/rewritten-in-place file whose anchor is gone is
//!   re-anchored from the start. Rename-style external logrotate that strands an
//!   unexported tail in an archive file is NOT drained (the gateway owns this
//!   append-only log and should not be externally rotated); archive draining is
//!   a follow-up.

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
    /// HMAC secret for per-entry `sig` verification. `None` (or empty) verifies
    /// the hash chain only; `Some(non-empty)` also authenticates each entry's
    /// HMAC so a re-chain forgery is caught on the export path too (MIK-6700
    /// HMAC.3). Runtime wiring of the secret is MIK-6703.
    signing_secret: Option<String>,
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
            signing_secret: None,
        })
    }

    /// Override the per-poll batch cap (memory bound).
    #[must_use]
    pub fn with_max_batch(mut self, max_batch: usize) -> Self {
        self.max_batch = max_batch.max(1);
        self
    }

    /// Configure the HMAC secret used to authenticate each entry's `sig` during
    /// the scan. An empty secret is treated as unset (hash-chain-only), matching
    /// [`verify_log`](crate::security::transparency_log::verify_log).
    #[must_use]
    pub fn with_signing_secret(mut self, secret: impl Into<String>) -> Self {
        let secret = secret.into();
        self.signing_secret = if secret.is_empty() {
            None
        } else {
            Some(secret)
        };
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
        // Scan anchored at the current cursor. If the anchor hash is absent
        // (rotation/truncation removed it), re-anchor and scan from the start.
        let mut reanchored = false;
        let mut scan = self.scan(&self.cursor.last_entry_hash)?;
        if !scan.anchor_found && self.cursor.last_entry_hash != "genesis" {
            reanchored = true;
            scan = self.scan("genesis")?;
        }

        if scan.batch.is_empty() {
            return Ok(PollOutcome {
                forwarded: 0,
                lag_entries: scan.lag,
                reanchored,
            });
        }

        // Deliver, then persist the NEW cursor, then adopt it in memory. Only an
        // ack advances the cursor (at-least-once); and durable state is written
        // before in-memory state so a persist failure re-sends rather than skips.
        sink.deliver(&scan.batch)
            .map_err(|e| ExportError::SinkRejected(e.to_string()))?;
        let next = ExportCursor {
            last_entry_hash: scan.last_hash,
            last_counter: scan.last_counter,
        };
        self.persist_cursor(&next)?;
        let forwarded = scan.batch.len();
        self.cursor = next;

        Ok(PollOutcome {
            forwarded,
            lag_entries: scan.lag,
            reanchored,
        })
    }

    /// Stream the log from the start, skip to `anchor` (or forward from the
    /// first entry when `anchor == "genesis"`), verify + collect up to
    /// `max_batch` entries, and count the remaining backlog as `lag`.
    ///
    /// Memory is bounded to one line plus the batch: entries beyond `max_batch`
    /// are counted, not buffered, and a partial trailing line (no newline yet)
    /// is left for a later poll rather than parsed.
    fn scan(&self, anchor: &str) -> Result<Scan, ExportError> {
        use std::io::{BufRead, BufReader};

        let mut scan = Scan {
            batch: Vec::new(),
            last_hash: anchor.to_string(),
            last_counter: self.cursor.last_counter,
            lag: 0,
            anchor_found: anchor == "genesis",
        };
        let file = match std::fs::File::open(&self.log_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(scan),
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file);
        let mut passed = anchor == "genesis";
        let mut running_prev = "genesis".to_string();
        let checkpoint = anchor.to_string();
        let mut buf: Vec<u8> = Vec::new();

        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break; // EOF
            }
            if buf.last() != Some(&b'\n') {
                break; // partial trailing line (racing a writer) — leave for next poll
            }
            let raw = &buf[..buf.len() - 1];
            if raw.iter().all(u8::is_ascii_whitespace) {
                continue; // blank line
            }

            // Backlog past the batch cap: count it, don't parse/buffer (bounded).
            if passed && scan.batch.len() >= self.max_batch {
                scan.lag += 1;
                continue;
            }

            let entry: serde_json::Value = serde_json::from_slice(raw)
                .map_err(|e| ExportError::Corrupt(format!("{}: {e}", self.log_path.display())))?;
            let stored_hash = entry
                .get("entry_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ExportError::VerificationFailed("entry missing entry_hash".to_string())
                })?
                .to_string();

            if !passed {
                // Skipping to the anchor entry; forward everything after it.
                if stored_hash == anchor {
                    passed = true;
                    scan.anchor_found = true;
                    running_prev = anchor.to_string();
                }
                continue;
            }

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
            let recomputed = recompute_entry_hash(&entry).map_err(ExportError::Io)?;
            if recomputed != stored_hash {
                return Err(ExportError::VerificationFailed(format!(
                    "tampered entry: recomputed {recomputed} != stored {stored_hash}"
                )));
            }
            // Per-entry HMAC check when a secret is configured (MIK-6700 HMAC.3):
            // catches a re-chained forgery that leaves a stale `sig`.
            if let Some(secret) = self.signing_secret.as_deref()
                && let Err(msg) = crate::security::transparency_log::verify_entry_sig(
                    &entry,
                    &stored_hash,
                    secret.as_bytes(),
                )
            {
                return Err(ExportError::VerificationFailed(format!(
                    "entry {stored_hash}: {msg}"
                )));
            }
            let counter = entry
                .get("counter")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            scan.batch.push(ExportEntry {
                source: self.source,
                counter,
                entry_hash: stored_hash.clone(),
                prev_entry_hash: prev,
                checkpoint: checkpoint.clone(),
                raw: entry,
            });
            running_prev = stored_hash;
            scan.last_counter = counter;
        }

        scan.last_hash = running_prev;
        Ok(scan)
    }

    /// Atomically persist a cursor (temp write → rename). Persisting the NEW
    /// cursor before adopting it in memory keeps durable state at-or-behind
    /// runtime state, so a persist failure re-sends rather than skips.
    fn persist_cursor(&self, cursor: &ExportCursor) -> Result<(), ExportError> {
        let bytes =
            serde_json::to_vec_pretty(cursor).map_err(|e| ExportError::Corrupt(e.to_string()))?;
        let tmp = self.cursor_path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.cursor_path)?;
        Ok(())
    }
}

/// Internal per-poll scan result.
struct Scan {
    batch: Vec<ExportEntry>,
    last_hash: String,
    last_counter: u64,
    lag: usize,
    anchor_found: bool,
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

/// Runtime SIEM-export configuration (MIK-6703). Opt-in; disabled by default so
/// the export background task is only spawned when an operator configures it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ExportConfig {
    /// Enable the background export task.
    pub enabled: bool,
    /// Destination NDJSON file the sink appends forwarded entries to (the SIEM
    /// agent tails this). One JSON object per line. This is the core sink; an
    /// OTel/HTTP sink is a separate enterprise follow-up.
    pub sink_path: String,
    /// Poll cadence in seconds (how often the task tails the logs).
    pub poll_interval_secs: u64,
    /// Max entries forwarded per poll per source (memory bound).
    pub max_batch: usize,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sink_path: "~/.mcp-gateway/export/siem.ndjson".to_string(),
            poll_interval_secs: 15,
            max_batch: LogExporter::DEFAULT_MAX_BATCH,
        }
    }
}

/// Core NDJSON [`ExportSink`]: appends each forwarded entry as one JSON line to
/// a local file the SIEM agent tails. Fully synchronous (no async bridging), so
/// it composes with the sync [`LogExporter::poll`] contract. Delivery is the
/// ack: the file write must succeed (and be fsynced) before the cursor advances.
pub struct FileExportSink {
    path: PathBuf,
    /// Fail-closed latch (MIK-6703 review). Set `false` if a partial write can
    /// NOT be rolled back, so the torn-prefix stream integrity can no longer be
    /// guaranteed; all subsequent deliveries then refuse (export halts, cursor
    /// never advances) rather than risk appending after a torn prefix.
    healthy: std::sync::atomic::AtomicBool,
}

impl FileExportSink {
    /// Open (create-append) the sink at `path`, creating parent dirs.
    ///
    /// # Errors
    /// Errors if the parent directory cannot be created.
    pub fn open(path: PathBuf) -> Result<Self, ExportError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            healthy: std::sync::atomic::AtomicBool::new(true),
        })
    }
}

impl ExportSink for FileExportSink {
    fn deliver(&self, entries: &[ExportEntry]) -> Result<(), ExportError> {
        use std::io::Write;
        use std::sync::atomic::Ordering::{Acquire, Release};

        // Fail closed: once integrity can no longer be guaranteed (a partial
        // write that could not be rolled back), refuse all further deliveries so
        // the cursor never advances over a torn stream (MIK-6703 review #1).
        if !self.healthy.load(Acquire) {
            return Err(ExportError::SinkRejected(
                "export sink halted after an unrecoverable partial write".to_string(),
            ));
        }

        let mut buf = String::new();
        for e in entries {
            let line = serde_json::to_string(e)
                .map_err(|err| ExportError::SinkRejected(format!("serialize: {err}")))?;
            buf.push_str(&line);
            buf.push('\n');
        }

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        // All-or-nothing append: record the pre-write length so a PARTIAL
        // write_all (prefix written, then error) can be rolled back. Otherwise
        // the torn prefix stays and a later retry appends the full batch after
        // it, corrupting the stream while the retry's success advances the
        // cursor — silently "delivering" an unparseable line.
        let start_len = f.metadata()?.len();
        if let Err(e) = f.write_all(buf.as_bytes()) {
            // Roll back to pre-batch length. If the rollback itself fails we can
            // NOT guarantee the stream is clean, so latch unhealthy (fail-closed)
            // — subsequent deliveries refuse rather than append after a torn
            // prefix (MIK-6703 review #1).
            if f.set_len(start_len).and_then(|()| f.sync_all()).is_err() {
                self.healthy.store(false, Release);
            }
            return Err(e.into());
        }
        // fsync before the ack: the cursor advances only after deliver returns
        // Ok, so the sink write must be durable first to hold at-least-once
        // across a power loss (flush alone leaves an OS-buffer window).
        f.sync_all()?;
        // Also fsync the parent directory so a first-create's directory entry is
        // durable before the cursor advances (a crash could otherwise lose the
        // newly-created sink file). Done unconditionally — no `existed` sample —
        // to avoid a TOCTOU miss, and an empty parent (a bare relative path) is
        // resolved to "." so the case is not skipped (MIK-6703 review #2). A dir
        // fsync when nothing changed is a cheap no-op at the 15s poll cadence.
        // Unix-only (portable directory fsync).
        #[cfg(unix)]
        {
            let parent = self
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

/// Observable status of the export task for one source, updated after each poll
/// and read by the control-plane export-status route (MIK-6703 SIEM.RUN.2).
/// Uses atomics so the async route can read it without locking the task.
#[derive(Debug, Default)]
pub struct SourceExportStatus {
    /// Total entries forwarded+acked since startup.
    pub forwarded_total: std::sync::atomic::AtomicU64,
    /// Entries still pending after the last poll (current lag).
    pub last_lag: std::sync::atomic::AtomicU64,
    /// Max lag observed since startup (feeds the max-lag alert).
    pub max_lag: std::sync::atomic::AtomicU64,
    /// Number of re-anchor events (rotation/truncation detected).
    pub reanchor_total: std::sync::atomic::AtomicU64,
    /// Number of poll errors (verification failures / sink rejections).
    pub error_total: std::sync::atomic::AtomicU64,
}

impl SourceExportStatus {
    /// Fold one poll outcome into the running counters.
    pub fn record(&self, outcome: &PollOutcome) {
        use std::sync::atomic::Ordering::Relaxed;
        self.forwarded_total
            .fetch_add(outcome.forwarded as u64, Relaxed);
        let lag = outcome.lag_entries as u64;
        self.last_lag.store(lag, Relaxed);
        self.max_lag.fetch_max(lag, Relaxed);
        if outcome.reanchored {
            self.reanchor_total.fetch_add(1, Relaxed);
        }
    }

    /// Record a poll error.
    pub fn record_error(&self) {
        self.error_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Snapshot as a serialisable map for the status route.
    #[must_use]
    pub fn snapshot(&self) -> serde_json::Value {
        use std::sync::atomic::Ordering::Relaxed;
        serde_json::json!({
            "forwarded_total": self.forwarded_total.load(Relaxed),
            "last_lag": self.last_lag.load(Relaxed),
            "max_lag": self.max_lag.load(Relaxed),
            "reanchor_total": self.reanchor_total.load(Relaxed),
            "error_total": self.error_total.load(Relaxed),
        })
    }
}

/// Shared export status for both log sources (invocation + governance).
#[derive(Debug, Default)]
pub struct ExportStatus {
    /// Invocation-log export counters.
    pub invocation: SourceExportStatus,
    /// Governance-log export counters.
    pub governance: SourceExportStatus,
}

impl ExportStatus {
    /// Snapshot both sources for the status route.
    #[must_use]
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "invocation": self.invocation.snapshot(),
            "governance": self.governance.snapshot(),
        })
    }
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
