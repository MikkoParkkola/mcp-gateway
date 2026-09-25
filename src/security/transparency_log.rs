// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Tamper-evident append-only transparency log for tool invocations (issue #133, D3).
//!
//! Every completed tool invocation is committed to a hash-chain NDJSON log so
//! that any post-hoc modification (tampering, deletion, reordering) is
//! detectable by `mcp-gateway audit verify`.
//!
//! # Entry schema (one line per invocation)
//!
//! ```json
//! {
//!   "counter": 42,
//!   "timestamp": "2026-04-27T00:00:00Z",
//!   "session_id": "sess-123",
//!   "caller": "api-key-prod",
//!   "server": "github",
//!   "tool": "create_issue",
//!   "request_hash": "sha256:...",
//!   "response_hash": "sha256:...",
//!   "prev_entry_hash": "sha256:...",
//!   "entry_hash": "sha256:...",
//!   "sig": "hmac-sha256:...",   // omitted when shared_secret is empty
//!   "key_id": "v1"              // omitted when shared_secret is empty
//! }
//! ```
//!
//! # Hash chain rule
//!
//! 1. Build the entry **without** `entry_hash`, `sig`, and `key_id`.
//! 2. `entry_hash = sha256(serde_json::to_string(&entry_without_those_fields))`
//! 3. `sig = hmac_sha256(shared_secret, raw_entry_hash_bytes || key_id_bytes)`
//!    — `key_id` is bound into the signed message so it cannot be altered.
//!
//! Because `serde_json::Map` is a `BTreeMap` (keys sorted alphabetically, no
//! `preserve_order` feature), serialisation is deterministic and the hash
//! computed on write is exactly reproducible on read.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tracing::warn;

// ── Type aliases ──────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

// ── Read bounds (MIK-6710 memory-DoS mitigation) ───────────────────────────────

/// Maximum bytes a full-log reader (`verify_log`, `verify_log_signed`,
/// `log_contains_signed_entry`, `show_session_entries`) will load into memory.
///
/// An attacker (or a runaway caller) who grows the audit log without bound
/// must not be able to force the gateway to materialise an arbitrarily large
/// `String` on every `audit verify` / `audit show` call. 256 MiB comfortably
/// covers any transparency log an operator hasn't already rotated; beyond
/// that we fail closed rather than allocate unbounded memory (MIK-6710).
const MAX_AUDIT_READ_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum bytes scanned backward from EOF when recovering the last
/// (possibly still-being-written) line for chain-state recovery.
///
/// Crash recovery on [`TransparencyLogger::open`] and the resync path in
/// [`TransparencyLogger::append_core`] must find the tail entry without ever
/// reading the whole audit log — only the last few KB matter. 4 MiB is far
/// larger than any legitimate single NDJSON entry, so the true last line is
/// always fully contained in the scanned window (MIK-6710).
const MAX_TAIL_SCAN_BYTES: u64 = 4 * 1024 * 1024;

// D1-f failure policy and degraded state, split out for the file-size ceiling.
#[path = "transparency_log_degraded.rs"]
mod degraded;

use crate::security::audit::{AuditEnvelope, AuditWho};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Runtime configuration for the transparency log.
///
/// Serialisation lives in `src/config/features/security.rs` alongside the
/// other security configs; this struct is the "resolved" in-memory copy.
#[derive(Clone)]
pub struct TransparencyLogConfig {
    /// Enable the transparency log.  Default: `false` (opt-in).
    pub enabled: bool,
    /// Path to the NDJSON log file.  `~` is expanded at open time.
    pub path: String,
    /// Key identifier written into `key_id` when signing is active.
    pub key_id: String,
    /// HMAC shared secret.  When empty, the `sig` / `key_id` fields are
    /// omitted from each entry (hash chain still provides tamper evidence).
    pub shared_secret: String,
}

// Manual `Debug` that redacts the HMAC shared secret (CWE-532, mirrors PR
// #323). A derived `Debug` would print the resolved signing secret verbatim
// into any trace or error context; only its presence is surfaced.
impl std::fmt::Debug for TransparencyLogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransparencyLogConfig")
            .field("enabled", &self.enabled)
            .field("path", &self.path)
            .field("key_id", &self.key_id)
            .field(
                "shared_secret",
                &if self.shared_secret.is_empty() {
                    "<empty>"
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
}

impl Default for TransparencyLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "~/.mcp-gateway/transparency/transparency.jsonl".to_string(),
            key_id: "default".to_string(),
            shared_secret: String::new(),
        }
    }
}

// ── Internal mutable state ────────────────────────────────────────────────────

/// All mutable state guarded by a single `Mutex` for atomic chain updates.
struct Inner {
    writer: BufWriter<File>,
    counter: u64,
    last_entry_hash: String,
}

// ── TransparencyLogger ────────────────────────────────────────────────────────

/// Append-only, tamper-evident hash-chain logger for tool invocations.
///
/// Thread-safe: wrap in `Arc` for shared ownership across async tasks.
///
/// # Crash recovery
///
/// On [`TransparencyLogger::open`] the last non-empty line of the existing log
/// file is read to recover `counter` and `last_entry_hash`.  New entries
/// continue the chain seamlessly after a gateway restart.
pub struct TransparencyLogger {
    inner: Mutex<Inner>,
    config: Arc<TransparencyLogConfig>,
    #[cfg(test)]
    fail_next_append: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    append_attempts: std::sync::atomic::AtomicUsize,
    /// Persistent I/O fault: every append fails while set (D1-T17).
    #[cfg(test)]
    fail_appends: std::sync::atomic::AtomicBool,
    failure_policy: crate::security::audit::AuditFailurePolicy,
    /// Set by a failed append under `FailClosed`, cleared by a successful one.
    degraded: std::sync::atomic::AtomicBool,
    /// Every failed append, whatever the policy.
    append_failures: std::sync::atomic::AtomicU64,
    /// Index of the last failure's cause (`usize::MAX` before any failure).
    last_failure_cause: std::sync::atomic::AtomicUsize,
}

/// Which rung of the correlation chain supplied an invocation entry's
/// `session_id` field.
///
/// Recorded alongside the key because the key alone is opaque: an operator
/// reading two entries with different keys cannot otherwise tell whether the
/// caller changed or the gateway merely fell to a different rung. A key with
/// no source names an invocation nobody can place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationSource {
    /// A W3C trace id the caller carried in `_meta`; spans the whole call.
    OtelTraceId,
    /// The connection's session id — a legacy caller that sent no trace.
    SessionId,
    /// The trace id the gateway minted for this invocation. Always available,
    /// which is what makes the chain total.
    TraceId,
}

/// A correlation key together with the rung that supplied it. They travel as
/// one value because a key without its provenance is what CONTROL.3a set out
/// to remove.
#[derive(Debug, Clone, Copy)]
pub struct CorrelationKey<'a> {
    /// The key written to the entry's `session_id` field.
    pub id: &'a str,
    /// Which rung of the chain produced `id`.
    pub source: CorrelationSource,
}

impl CorrelationSource {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::OtelTraceId => "otel_trace_id",
            Self::SessionId => "session_id",
            Self::TraceId => "trace_id",
        }
    }
}

impl TransparencyLogger {
    /// Open (or create) the transparency log file and recover chain state.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the parent directory cannot be created, if
    /// the file cannot be opened, or if the last existing line is malformed.
    pub fn open(config: Arc<TransparencyLogConfig>) -> io::Result<Self> {
        let path = expand_tilde(&config.path);

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        // Recover state from the last line (if the file already exists).
        let (counter, last_entry_hash) = if path.exists() {
            recover_chain_state(&path)?
        } else {
            (0u64, "genesis".to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        // Make the log file's directory entry durable, so a governance audit
        // file created on the first append cannot be lost by a crash while a
        // control-plane commit that depends on it is already durable. Unix only
        // (opening a directory as a file is not portable); best-effort.
        #[cfg(unix)]
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
            && let Ok(dir) = File::open(parent)
        {
            let _ = dir.sync_all();
        }

        Ok(Self {
            inner: Mutex::new(Inner {
                writer: BufWriter::new(file),
                counter,
                last_entry_hash,
            }),
            config,
            #[cfg(test)]
            fail_next_append: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            append_attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            fail_appends: std::sync::atomic::AtomicBool::new(false),
            failure_policy: crate::security::audit::AuditFailurePolicy::BestEffort,
            degraded: std::sync::atomic::AtomicBool::new(false),
            append_failures: std::sync::atomic::AtomicU64::new(0),
            last_failure_cause: std::sync::atomic::AtomicUsize::new(usize::MAX),
        })
    }

    /// Instance-local one-shot I/O fault, consumed by the real append path.
    #[cfg(test)]
    pub(crate) fn fail_next_append_for_test(&self) {
        self.fail_next_append
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn append_attempts_for_test(&self) -> usize {
        self.append_attempts
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Path the log writes to, with any leading `~/` expanded. Lets callers
    /// (e.g. the control-plane audit view) read the governance log back.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        expand_tilde(&self.config.path)
    }

    /// Append one entry covering the completed `request → response` pair.
    ///
    /// Hash-chain guarantees:
    /// - `prev_entry_hash` of this entry equals the `entry_hash` of the
    ///   previous entry (or `"genesis"` for the very first entry).
    /// - `entry_hash` is the SHA-256 of the canonical JSON of the entry
    ///   **without** `entry_hash`, `sig`, and `key_id`.
    /// - `sig` (when a non-empty `shared_secret` is configured) is
    ///   `hmac_sha256(shared_secret, raw_entry_hash_bytes)`.
    ///
    /// Failures are non-fatal: the caller should `warn!` but must not abort
    /// the tool invocation.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if serialisation or the file write fails.
    pub fn log_invocation(
        &self,
        session_id: &str,
        caller: &str,
        server: &str,
        tool: &str,
        request_hash: &str,
        response_hash: &str,
    ) -> io::Result<()> {
        self.log_invocation_correlated(
            CorrelationKey {
                id: session_id,
                source: CorrelationSource::SessionId,
            },
            &AuditEnvelope::ok(AuditWho::from_actor_id(caller)),
            server,
            tool,
            request_hash,
            Some(response_hash),
        )
    }

    /// As [`Self::log_invocation`], but records which rung of the correlation
    /// chain supplied `session_id`.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if serialisation or the file write fails.
    pub fn log_invocation_correlated(
        &self,
        key: CorrelationKey<'_>,
        envelope: &AuditEnvelope,
        server: &str,
        tool: &str,
        request_hash: &str,
        response_hash: Option<&str>,
    ) -> io::Result<()> {
        let timestamp = Utc::now().to_rfc3339();

        // Domain fields for an invocation entry. `counter`, `prev_entry_hash`,
        // `entry_hash`, and `sig`/`key_id` are added by `append_core`.
        let mut fields = serde_json::Map::new();
        // `caller` is kept for one major version as a copy of `who.account`.
        fields.insert("caller".into(), envelope.who.account().into());
        fields.insert("correlation_source".into(), key.source.as_str().into());
        fields.insert("request_hash".into(), request_hash.into());
        // A failed call has no response to hash.
        if let Some(response_hash) = response_hash {
            fields.insert("response_hash".into(), response_hash.into());
        }
        fields.insert("server".into(), server.into());
        fields.insert("session_id".into(), key.id.into());
        fields.insert("timestamp".into(), timestamp.into());
        fields.insert("tool".into(), tool.into());

        self.append_core(fields, envelope, false).map(|_| ())
    }

    /// Append an arbitrary governance/audit entry into the same tamper-evident
    /// hash chain. Callers supply their own domain fields (e.g. `actor_id`,
    /// `action`, `target_id`); the chain fields (`counter`, `prev_entry_hash`,
    /// `entry_hash`, and `sig`/`key_id` when signing is active) are added here.
    ///
    /// The reserved chain-field keys are rejected so a caller cannot forge them.
    /// Returns the entry's `entry_hash` so the caller can use it as a dedupe key.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if a reserved key is supplied, or if serialisation or
    /// the file write fails.
    pub fn append_event(
        &self,
        fields: serde_json::Map<String, serde_json::Value>,
        envelope: &AuditEnvelope,
    ) -> io::Result<String> {
        Self::reject_reserved_keys(&fields)?;
        self.append_core(fields, envelope, false)
    }

    /// Like [`Self::append_event`], but re-syncs chain state (`counter`,
    /// `last_entry_hash`) from the on-disk tail before appending. This is the
    /// cross-process-safe path: when an external OS lock serialises separate
    /// processes (e.g. a CLI and the server) writing the same log, each opened
    /// its own logger and cached a stale counter. Re-syncing under the lock
    /// picks up entries the other process appended, so the chain never forks.
    ///
    /// The underlying file is opened in append mode (`O_APPEND`), so the write
    /// still lands at the true end of file.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if a reserved key is supplied, or if the tail read,
    /// serialisation, or the file write fails.
    pub fn append_event_synced(
        &self,
        fields: serde_json::Map<String, serde_json::Value>,
        envelope: &AuditEnvelope,
    ) -> io::Result<String> {
        Self::reject_reserved_keys(&fields)?;
        self.append_core(fields, envelope, true)
    }

    fn reject_reserved_keys(fields: &serde_json::Map<String, serde_json::Value>) -> io::Result<()> {
        let chain = ["counter", "prev_entry_hash", "entry_hash", "sig", "key_id"];
        for reserved in chain.into_iter().chain(AuditEnvelope::RESERVED) {
            if fields.contains_key(reserved) {
                return Err(io::Error::other(format!(
                    "transparency log: reserved chain field '{reserved}' cannot be supplied by caller"
                )));
            }
        }
        Ok(())
    }

    /// Chain one entry from caller-supplied domain `fields`, returning its
    /// `entry_hash`. Shared by [`Self::log_invocation`], [`Self::append_event`],
    /// and [`Self::append_event_synced`] so the chain logic exists exactly once.
    ///
    /// When `resync` is set, the in-memory `counter`/`last_entry_hash` are first
    /// refreshed from the on-disk tail (for cross-process appends). In-memory
    /// state is advanced only **after** a successful write+flush, so a failed
    /// write leaves no counter gap.
    fn append_core(
        &self,
        fields: serde_json::Map<String, serde_json::Value>,
        envelope: &AuditEnvelope,
        resync: bool,
    ) -> io::Result<String> {
        let result = self.append_chained(fields, envelope, resync);
        self.record_append(result.as_ref().err());
        result
    }

    fn append_chained(
        &self,
        mut fields: serde_json::Map<String, serde_json::Value>,
        envelope: &AuditEnvelope,
        resync: bool,
    ) -> io::Result<String> {
        envelope.write_into(&mut fields);
        #[cfg(test)]
        {
            self.append_attempts
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            if self
                .fail_next_append
                .swap(false, std::sync::atomic::Ordering::AcqRel)
                || self.fail_appends.load(std::sync::atomic::Ordering::Acquire)
            {
                return Err(io::Error::other("injected transparency append failure"));
            }
        }
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("transparency log mutex poisoned"))?;

        if resync {
            let path = expand_tilde(&self.config.path);
            if path.exists() {
                let (counter, last_entry_hash) = recover_chain_state(&path)?;
                inner.counter = counter;
                inner.last_entry_hash = last_entry_hash;
            }
        }

        // Compute the next counter locally; commit to `inner` only on success.
        let counter = inner.counter + 1;
        let prev_entry_hash = inner.last_entry_hash.clone();

        // ── Step 1: complete the entry core (without entry_hash / sig / key_id) ─
        //
        // serde_json Map serialises with sorted keys (BTreeMap), so the hash is
        // deterministic and reproducible regardless of insertion order.
        fields.insert("counter".into(), counter.into());
        fields.insert("prev_entry_hash".into(), prev_entry_hash.into());

        // ── Step 2: entry_hash = sha256(canonical JSON of core) ───────────────
        let core_json = serde_json::to_string(&serde_json::Value::Object(fields.clone()))
            .map_err(io::Error::other)?;
        let entry_hash_bytes: [u8; 32] = sha256_raw(core_json.as_bytes());
        let entry_hash = format!("sha256:{}", hex::encode(entry_hash_bytes));

        // ── Step 3: sig = hmac_sha256(secret, entry_hash_bytes || key_id) ─────
        // key_id is bound INTO the signed message (not just written alongside)
        // so a stripped or altered key_id fails verification (MIK-6700 review).
        if !self.config.shared_secret.is_empty() {
            let msg = sig_message(&entry_hash_bytes, &self.config.key_id);
            let sig_hex = hmac_sha256_hex(self.config.shared_secret.as_bytes(), &msg);
            fields.insert("sig".into(), format!("hmac-sha256:{sig_hex}").into());
            fields.insert("key_id".into(), self.config.key_id.clone().into());
        }

        // ── Assemble + write the full entry ───────────────────────────────────
        fields.insert("entry_hash".into(), entry_hash.clone().into());
        let line =
            serde_json::to_string(&serde_json::Value::Object(fields)).map_err(io::Error::other)?;

        writeln!(inner.writer, "{line}")?;
        inner.writer.flush()?;
        // The synced path (governance audit) fsyncs for durability parity with
        // the control-plane store's fsync'd collection writes, so a power loss
        // cannot preserve a committed mutation while losing its audit record.
        // The hot invocation path only flushes (fsync-per-entry there is too
        // costly and its durability bar is lower).
        if resync {
            inner.writer.get_ref().sync_all()?;
        }

        // ── Advance chain state only after the write succeeded ─────────────────
        inner.counter = counter;
        inner.last_entry_hash.clone_from(&entry_hash);

        Ok(entry_hash)
    }
}

// ── Chain verification ────────────────────────────────────────────────────────

/// Result of a chain-integrity verification pass.
pub struct VerifyResult {
    /// `true` when every entry in the log passed all checks.
    pub ok: bool,
    /// Number of entries checked.
    pub entries_checked: usize,
    /// Counter of the first invalid entry (`None` when `ok == true`).
    pub error_at_counter: Option<u64>,
    /// Human-readable description of the first failure.
    pub error_message: Option<String>,
}

/// Read `path` and verify the complete hash chain (no HMAC check).
///
/// Checks, for every entry:
/// 1. Counter is exactly `previous_counter + 1` (monotonic, no gaps).
/// 2. `prev_entry_hash` matches the prior entry's `entry_hash`.
/// 3. `entry_hash` equals the recomputed SHA-256 of the entry without the
///    `entry_hash`, `sig`, and `key_id` fields.
///
/// This entry point does **not** authenticate the per-entry HMAC `sig`, so a
/// secret-holding attacker who re-chains an edited entry (recomputing every
/// `entry_hash`) is not detected here. Use [`verify_log_signed`] when a shared
/// secret is configured (MIK-6700).
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn verify_log(path: &Path) -> io::Result<VerifyResult> {
    verify_log_inner(path, None)
}

/// Read `path` and verify the hash chain **and**, when `config` has a non-empty
/// `shared_secret`, the per-entry HMAC `sig` (MIK-6700 HMAC.1).
///
/// With an empty secret this is byte-for-byte equivalent to [`verify_log`]
/// (HMAC.2 backward compatibility). With a secret configured, every entry must
/// carry a `sig` that is a valid `HMAC-SHA256(secret, raw_entry_hash_bytes)`;
/// an entry with a valid hash but a missing, malformed, or stale `sig` fails
/// verification — defeating a re-chain forgery.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn verify_log_signed(path: &Path, config: &TransparencyLogConfig) -> io::Result<VerifyResult> {
    let secret = config.shared_secret.as_bytes();
    let secret = if secret.is_empty() {
        None
    } else {
        Some(secret)
    };
    verify_log_inner(path, secret)
}

/// Return `true` if the log contains at least one signed entry (an entry
/// carrying a `sig` field).
///
/// Used by `audit verify` to refuse a silent hash-only verification of a log
/// that was written with signing enabled but is being checked without a secret
/// — otherwise a stale-sig forgery would pass with exit 0 (MIK-6700 review).
/// Scans until the first signed entry is found (early return); an empty or
/// wholly-unsigned log returns `false`.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn log_contains_signed_entry(path: &Path) -> io::Result<bool> {
    let content = bounded_read_to_string(path, MAX_AUDIT_READ_BYTES)?;
    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(trimmed)
            && entry.get("sig").is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Shared chain-verification core. When `secret` is `Some`, each entry's HMAC
/// `sig` is additionally authenticated.
fn verify_log_inner(path: &Path, secret: Option<&[u8]>) -> io::Result<VerifyResult> {
    let content = bounded_read_to_string(path, MAX_AUDIT_READ_BYTES)?;
    let mut prev_hash = "genesis".to_string();
    let mut prev_counter: Option<u64> = None;
    let mut entries_checked = 0usize;

    for (line_no, raw) in content.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: serde_json::Value = serde_json::from_str(trimmed).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: invalid JSON: {e}", line_no + 1),
            )
        })?;

        let counter = entry
            .get("counter")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: missing 'counter'", line_no + 1),
                )
            })?;

        let stored_entry_hash = entry
            .get("entry_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: missing 'entry_hash'", line_no + 1),
                )
            })?;

        let stored_prev_hash = entry
            .get("prev_entry_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: missing 'prev_entry_hash'", line_no + 1),
                )
            })?;

        // ── Check 1: monotonic counter ────────────────────────────────────────
        let expected_counter = prev_counter.map_or(counter, |pc| pc + 1);
        if counter != expected_counter {
            return Ok(VerifyResult {
                ok: false,
                entries_checked,
                error_at_counter: Some(counter),
                error_message: Some(format!(
                    "counter gap at entry {counter}: expected {expected_counter}"
                )),
            });
        }

        // ── Check 2: prev_entry_hash chain link ───────────────────────────────
        if stored_prev_hash != prev_hash {
            return Ok(VerifyResult {
                ok: false,
                entries_checked,
                error_at_counter: Some(counter),
                error_message: Some(format!(
                    "entry {counter}: prev_entry_hash mismatch \
                     (expected '{prev_hash}', got '{stored_prev_hash}')"
                )),
            });
        }

        // ── Check 3: recompute entry_hash ─────────────────────────────────────
        let recomputed = recompute_entry_hash(&entry)?;
        if recomputed != stored_entry_hash {
            return Ok(VerifyResult {
                ok: false,
                entries_checked,
                error_at_counter: Some(counter),
                error_message: Some(format!(
                    "entry {counter}: entry_hash mismatch \
                     (computed '{recomputed}', stored '{stored_entry_hash}')"
                )),
            });
        }

        // ── Check 4: per-entry HMAC sig (only when a secret is configured) ────
        if let Some(secret) = secret
            && let Err(msg) = verify_entry_sig(&entry, stored_entry_hash, secret)
        {
            return Ok(VerifyResult {
                ok: false,
                entries_checked,
                error_at_counter: Some(counter),
                error_message: Some(format!("entry {counter}: {msg}")),
            });
        }

        prev_hash = stored_entry_hash.to_string();
        prev_counter = Some(counter);
        entries_checked += 1;
    }

    Ok(VerifyResult {
        ok: true,
        entries_checked,
        error_at_counter: None,
        error_message: None,
    })
}

/// Read `path` and return all entries whose `session_id` matches `session`.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn show_session_entries(path: &Path, session: &str) -> io::Result<Vec<serde_json::Value>> {
    let content = bounded_read_to_string(path, MAX_AUDIT_READ_BYTES)?;
    let mut results = Vec::new();

    for raw in content.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                warn!("transparency log: skipping malformed line: {e}");
                continue;
            }
        };
        if entry.get("session_id").and_then(|v| v.as_str()) == Some(session) {
            results.push(entry);
        }
    }

    Ok(results)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Expand a leading `~/` in `s` to the user's home directory.
fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(s)
}

/// Read the last non-empty line of `path` to recover `(counter, last_entry_hash)`.
///
/// Reads only the tail of the file (bounded by [`MAX_TAIL_SCAN_BYTES`]), not
/// the whole log — crash recovery on every gateway restart must not scale
/// with the total size of the audit trail (MIK-6710).
fn recover_chain_state(path: &Path) -> io::Result<(u64, String)> {
    let Some(line) = read_last_nonempty_line(path)? else {
        return Ok((0, "genesis".to_string()));
    };

    let entry: serde_json::Value =
        serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let counter = entry
        .get("counter")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let entry_hash = entry
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("genesis")
        .to_string();

    Ok((counter, entry_hash))
}

/// Read `path` into a `String`, failing closed rather than allocating an
/// unbounded buffer when the file exceeds `max_bytes`.
///
/// The size check is a single `metadata()` call — an oversized file is never
/// opened for a full read, so the memory-DoS surface is closed at the check
/// itself, not after a partial read (MIK-6710).
///
/// # Errors
///
/// Returns `io::ErrorKind::InvalidData` when `path` exceeds `max_bytes`, or
/// any `io::Error` the underlying `metadata`/`read_to_string` calls produce.
fn bounded_read_to_string(path: &Path, max_bytes: u64) -> io::Result<String> {
    let len = std::fs::metadata(path)?.len();
    if len > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "transparency log at {} is {len} bytes, exceeding the {max_bytes}-byte read \
                 bound (MIK-6710); rotate the log before retrying this operation",
                path.display()
            ),
        ));
    }
    std::fs::read_to_string(path)
}

/// Read the last non-empty line of `path` without loading the whole file.
///
/// Seeks to the last `MAX_TAIL_SCAN_BYTES` bytes of the file (or the whole
/// file when it is smaller) and scans backward from there for a complete
/// line. Any single NDJSON entry is expected to be a small fraction of that
/// window, so the true last line is always fully contained in it; a
/// pathologically oversized final line simply fails downstream JSON parsing
/// rather than being silently truncated (safe failure, not a memory blowout).
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be opened, seeked, or read.
fn read_last_nonempty_line(path: &Path) -> io::Result<Option<String>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok(None);
    }

    let scan_len = file_len.min(MAX_TAIL_SCAN_BYTES);
    let offset =
        i64::try_from(scan_len).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    file.seek(SeekFrom::End(-offset))?;

    let buf_len =
        usize::try_from(scan_len).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut buf = vec![0u8; buf_len];
    file.read_exact(&mut buf)?;

    let text = String::from_utf8_lossy(&buf);
    Ok(text
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .map(str::to_string))
}

/// Recompute the `entry_hash` for an existing entry read from the log file.
///
/// Strips `entry_hash`, `sig`, and `key_id`, serialises what remains (`BTreeMap`
/// so alphabetically sorted), and returns `"sha256:<hex>"`. Public so incremental
/// consumers (e.g. the SIEM exporter, MIK-6689) can tamper-verify one entry at a
/// time instead of re-reading the whole file.
///
/// # Errors
///
/// Returns `io::Error` if `entry` is not a JSON object or cannot be serialised.
pub fn recompute_entry_hash(entry: &serde_json::Value) -> io::Result<String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry is not a JSON object"))?;

    // Build a clean copy without the hash-and-sig fields.
    let core: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .filter(|(k, _)| {
            k.as_str() != "entry_hash" && k.as_str() != "sig" && k.as_str() != "key_id"
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let core_json = serde_json::to_string(&core).map_err(io::Error::other)?;

    let hash_bytes = sha256_raw(core_json.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash_bytes)))
}

/// Verify one entry's HMAC `sig` against `secret`, given the entry's
/// already-hash-verified `entry_hash` string (`"sha256:<hex>"`).
///
/// The signature is `HMAC-SHA256(secret, sig_message(entry_hash_bytes, key_id))`
/// where `key_id` is bound INTO the signed message (matching `append_core`), so a
/// stripped/altered `key_id` also fails verification, not only a
/// stripped/altered `sig` (MIK-6700). Comparison is constant-time via
/// `Mac::verify_slice`. Under a configured secret every entry must carry both a
/// `sig` and a `key_id`; a missing/malformed field is an error, so neither can
/// be dropped to bypass.
///
/// # Errors
///
/// Returns a human-readable reason string when the signature is absent,
/// malformed, unsigned, or fails to authenticate.
pub fn verify_entry_sig(
    entry: &serde_json::Value,
    entry_hash: &str,
    secret: &[u8],
) -> Result<(), String> {
    let sig = entry
        .get("sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'sig' while a shared secret is configured".to_string())?;
    let key_id = entry
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'key_id' while a shared secret is configured".to_string())?;
    let sig_hex = sig
        .strip_prefix("hmac-sha256:")
        .ok_or_else(|| format!("malformed sig (expected 'hmac-sha256:' prefix): {sig}"))?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("sig is not valid hex: {e}"))?;
    let hash_hex = entry_hash
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("malformed entry_hash (expected 'sha256:' prefix): {entry_hash}"))?;
    let hash_bytes =
        hex::decode(hash_hex).map_err(|e| format!("entry_hash is not valid hex: {e}"))?;
    let hash_arr: [u8; 32] = hash_bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("entry_hash is not 32 bytes: {entry_hash}"))?;

    let msg = sig_message(&hash_arr, key_id);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&msg);
    mac.verify_slice(&sig_bytes)
        .map_err(|_| "HMAC sig mismatch (possible re-chain forgery or altered key_id)".to_string())
}

/// Build the HMAC message for an entry's `sig`: the 32 raw `entry_hash` bytes
/// followed by the `key_id` bytes. Binding `key_id` into the signed material
/// (rather than leaving it as unauthenticated metadata) means it cannot be
/// stripped or altered without invalidating the signature (MIK-6700).
fn sig_message(entry_hash_bytes: &[u8; 32], key_id: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + key_id.len());
    msg.extend_from_slice(entry_hash_bytes);
    msg.extend_from_slice(key_id.as_bytes());
    msg
}

/// Raw (non-hex) SHA-256 digest.
fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Compute `HMAC-SHA256(key, message)` and return lowercase hex.
fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    // HMAC accepts any key length; the `expect` here cannot panic.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "transparency_log_tests.rs"]
mod tests;

#[cfg(test)]
mod cwe532_debug_redaction {
    use super::*;

    const SENTINEL: &str = "SENTINEL_SECRET_a1b2c3";

    // The resolved in-memory TransparencyLogConfig::Debug must never surface
    // the HMAC shared secret.
    #[test]
    fn transparency_log_config_debug_redacts_shared_secret() {
        let cfg = TransparencyLogConfig {
            shared_secret: SENTINEL.to_string(),
            ..TransparencyLogConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains(SENTINEL), "leaked shared_secret: {dbg}");
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {dbg}"
        );
    }
}
