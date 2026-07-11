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

// ── Configuration ─────────────────────────────────────────────────────────────

/// Runtime configuration for the transparency log.
///
/// Serialisation lives in `src/config/features/security.rs` alongside the
/// other security configs; this struct is the "resolved" in-memory copy.
#[derive(Debug, Clone)]
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
        })
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
        let timestamp = Utc::now().to_rfc3339();

        // Domain fields for an invocation entry. `counter`, `prev_entry_hash`,
        // `entry_hash`, and `sig`/`key_id` are added by `append_core`.
        let mut fields = serde_json::Map::new();
        fields.insert("caller".into(), caller.into());
        fields.insert("request_hash".into(), request_hash.into());
        fields.insert("response_hash".into(), response_hash.into());
        fields.insert("server".into(), server.into());
        fields.insert("session_id".into(), session_id.into());
        fields.insert("timestamp".into(), timestamp.into());
        fields.insert("tool".into(), tool.into());

        self.append_core(fields, false).map(|_| ())
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
    ) -> io::Result<String> {
        Self::reject_reserved_keys(&fields)?;
        self.append_core(fields, false)
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
    ) -> io::Result<String> {
        Self::reject_reserved_keys(&fields)?;
        self.append_core(fields, true)
    }

    fn reject_reserved_keys(fields: &serde_json::Map<String, serde_json::Value>) -> io::Result<()> {
        for reserved in ["counter", "prev_entry_hash", "entry_hash", "sig", "key_id"] {
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
        mut fields: serde_json::Map<String, serde_json::Value>,
        resync: bool,
    ) -> io::Result<String> {
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
mod tests {
    use std::sync::Arc;

    use tempfile::NamedTempFile;

    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn cfg_no_sig(path: &Path) -> Arc<TransparencyLogConfig> {
        Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().to_string(),
            key_id: "test".to_string(),
            shared_secret: String::new(),
        })
    }

    fn cfg_with_sig(path: &Path) -> Arc<TransparencyLogConfig> {
        Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().to_string(),
            key_id: "test-key".to_string(),
            shared_secret: "a-test-secret-that-is-at-least-32-bytes!!".to_string(),
        })
    }

    fn write_entry(logger: &TransparencyLogger, session: &str, counter_hint: &str) {
        logger
            .log_invocation(
                session,
                "caller",
                "srv",
                &format!("tool_{counter_hint}"),
                "sha256:aaaa",
                "sha256:bbbb",
            )
            .expect("log_invocation must succeed");
    }

    fn read_entries(path: &Path) -> Vec<serde_json::Value> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    // ── Test 1: basic write + verify passes ───────────────────────────────────

    #[test]
    fn basic_write_and_verify_passes() {
        // GIVEN: a fresh transparency log
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();

        // WHEN: several entries are written
        write_entry(&logger, "sess-1", "1");
        write_entry(&logger, "sess-1", "2");
        write_entry(&logger, "sess-1", "3");

        // THEN: verify passes with correct count
        let result = verify_log(tmp.path()).unwrap();
        assert!(result.ok, "verify must pass: {:?}", result.error_message);
        assert_eq!(result.entries_checked, 3);
    }

    // ── Test 2: modifying response_hash breaks verification ───────────────────

    #[test]
    fn tampered_response_hash_breaks_verification() {
        // GIVEN: a log with two entries
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        write_entry(&logger, "sess-2", "a");
        write_entry(&logger, "sess-2", "b");

        // WHEN: the first entry's response_hash is mutated on disk
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let tampered = content.replacen("sha256:bbbb", "sha256:TAMPERED", 1);
        std::fs::write(tmp.path(), &tampered).unwrap();

        // THEN: verify detects the tampering
        let result = verify_log(tmp.path()).unwrap();
        assert!(!result.ok, "tampered entry must fail verification");
        assert!(result.error_at_counter.is_some());
    }

    // ── Test 3: deleting a middle entry breaks verification ───────────────────

    #[test]
    fn deleted_middle_entry_breaks_verification() {
        // GIVEN: a log with three entries
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        write_entry(&logger, "sess-3", "x");
        write_entry(&logger, "sess-3", "y");
        write_entry(&logger, "sess-3", "z");

        // WHEN: the second (middle) line is deleted
        let content = std::fs::read_to_string(tmp.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3, "expected 3 lines");
        let kept = format!("{}\n{}\n", lines[0], lines[2]); // skip lines[1]
        std::fs::write(tmp.path(), &kept).unwrap();

        // THEN: verify detects the gap
        let result = verify_log(tmp.path()).unwrap();
        assert!(!result.ok, "missing entry must fail verification");
    }

    // ── Test 4: show --session filters correctly ──────────────────────────────

    #[test]
    fn show_session_filters_correctly() {
        // GIVEN: a log with entries for two different sessions
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        logger
            .log_invocation("alpha", "c", "s", "t", "sha256:rr", "sha256:pp")
            .unwrap();
        logger
            .log_invocation("beta", "c", "s", "t", "sha256:rr", "sha256:pp")
            .unwrap();
        logger
            .log_invocation("alpha", "c", "s", "t2", "sha256:rr", "sha256:pp")
            .unwrap();

        // WHEN: show is called for session "alpha"
        let entries = show_session_entries(tmp.path(), "alpha").unwrap();

        // THEN: only "alpha" entries are returned
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(e["session_id"], "alpha");
        }
    }

    // ── Test 5: crash recovery restores counter and chain ────────────────────

    #[test]
    fn recovery_continues_chain_correctly() {
        // GIVEN: a log with two entries written by a first logger instance
        let tmp = NamedTempFile::new().unwrap();
        {
            let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
            write_entry(&logger, "sess-r", "1");
            write_entry(&logger, "sess-r", "2");
        }
        // The first logger is dropped here (simulating a gateway restart).

        // WHEN: a second logger opens the same file
        let logger2 = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        write_entry(&logger2, "sess-r", "3");

        // THEN: the chain is intact and counters are sequential
        let entries = read_entries(tmp.path());
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["counter"], 1u64);
        assert_eq!(entries[1]["counter"], 2u64);
        assert_eq!(entries[2]["counter"], 3u64);

        let result = verify_log(tmp.path()).unwrap();
        assert!(result.ok, "recovered chain must pass verification");
        assert_eq!(result.entries_checked, 3);
    }

    // ── Test 6: HMAC signature is present when secret is configured ───────────

    #[test]
    fn hmac_signature_present_when_secret_configured() {
        // GIVEN: a logger with a shared_secret
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_with_sig(tmp.path())).unwrap();
        write_entry(&logger, "sess-sig", "1");

        // WHEN: reading the written entry
        let entries = read_entries(tmp.path());
        let entry = &entries[0];

        // THEN: sig and key_id are present and correctly formatted
        let sig = entry["sig"].as_str().expect("sig must be a string");
        assert!(
            sig.starts_with("hmac-sha256:"),
            "sig must have hmac-sha256 prefix"
        );
        assert_eq!(sig.len(), "hmac-sha256:".len() + 64); // 64 hex chars = 32 bytes
        assert_eq!(entry["key_id"], "test-key");
    }

    // ── Test 7: no sig or key_id when secret is empty ────────────────────────

    #[test]
    fn no_sig_when_secret_empty() {
        // GIVEN: a logger without a shared_secret
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        write_entry(&logger, "sess-nosig", "1");

        // WHEN: reading the entry
        let entries = read_entries(tmp.path());
        let entry = &entries[0];

        // THEN: sig and key_id are absent
        assert!(entry.get("sig").is_none(), "sig must be absent");
        assert!(entry.get("key_id").is_none(), "key_id must be absent");
    }

    // ── Test 8: first entry's prev_entry_hash is "genesis" ───────────────────

    #[test]
    fn first_entry_prev_hash_is_genesis() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp.path())).unwrap();
        write_entry(&logger, "sess-g", "1");

        let entries = read_entries(tmp.path());
        assert_eq!(entries[0]["prev_entry_hash"], "genesis");
    }

    // ── Test 9: verify on empty file succeeds ────────────────────────────────

    #[test]
    fn verify_empty_file_passes() {
        let tmp = NamedTempFile::new().unwrap();
        // File is empty; nothing to verify.
        let result = verify_log(tmp.path()).unwrap();
        assert!(result.ok);
        assert_eq!(result.entries_checked, 0);
    }

    // ── Test 10: verify + show integration ───────────────────────────────────

    #[test]
    fn verify_and_show_after_mixed_sessions() {
        let tmp = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_with_sig(tmp.path())).unwrap();

        for i in 0..5u64 {
            let session = if i % 2 == 0 { "even" } else { "odd" };
            logger
                .log_invocation(
                    session,
                    "api-key-1",
                    "github",
                    "list_issues",
                    "sha256:req",
                    "sha256:res",
                )
                .unwrap();
        }

        // Chain must verify
        let verify = verify_log(tmp.path()).unwrap();
        assert!(verify.ok);
        assert_eq!(verify.entries_checked, 5);

        // Show must filter correctly
        let even = show_session_entries(tmp.path(), "even").unwrap();
        assert_eq!(even.len(), 3);
        let odd = show_session_entries(tmp.path(), "odd").unwrap();
        assert_eq!(odd.len(), 2);
    }

    // ── MIK-6700: per-entry HMAC verification ─────────────────────────────────

    // HMAC.1 (fail-fast): a re-chained edit that recomputes entry_hash but
    // leaves a STALE sig passes the hash-only verify_log (the gap this ticket
    // closes) yet FAILS verify_log_signed.
    #[test]
    fn rechained_forgery_with_stale_sig_fails_signed_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_with_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        write_entry(&logger, "sess", "2");
        write_entry(&logger, "sess", "3");
        drop(logger);

        // Forge the LAST entry: change a payload field, recompute ITS entry_hash
        // (no downstream entries need re-chaining), but leave the sig stale.
        let mut entries = read_entries(tmp.path());
        let last = entries.last_mut().unwrap();
        let forged_counter = last
            .get("counter")
            .and_then(serde_json::Value::as_u64)
            .unwrap();
        last["tool_id"] = serde_json::Value::String("forged_tool".to_string());
        let new_hash = recompute_entry_hash(last).unwrap();
        // Sanity: the edit actually changed the hash.
        assert_ne!(last["entry_hash"].as_str().unwrap(), new_hash);
        last["entry_hash"] = serde_json::Value::String(new_hash);
        // sig is intentionally left as the pre-edit value (the attacker cannot
        // recompute it without... the secret — but here we prove the check).
        let rewritten = entries
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(tmp.path(), format!("{rewritten}\n")).unwrap();

        // Hash-only verify PASSES — the chain is internally consistent.
        let plain = verify_log(tmp.path()).unwrap();
        assert!(
            plain.ok,
            "hash-only verify should pass on a re-chained edit: {:?}",
            plain.error_message
        );

        // Signed verify FAILS at the forged entry — the stale sig is caught.
        let signed = verify_log_signed(tmp.path(), &cfg).unwrap();
        assert!(!signed.ok, "signed verify must reject a stale-sig forgery");
        assert_eq!(signed.error_at_counter, Some(forged_counter));
    }

    // HMAC.1: an intact signed log passes verify_log_signed.
    #[test]
    fn intact_signed_log_passes_signed_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_with_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        write_entry(&logger, "sess", "2");
        drop(logger);

        let result = verify_log_signed(tmp.path(), &cfg).unwrap();
        assert!(
            result.ok,
            "intact signed log must verify: {:?}",
            result.error_message
        );
        assert_eq!(result.entries_checked, 2);
    }

    // HMAC.1: stripping the sig cannot bypass the check under a configured secret.
    #[test]
    fn stripped_sig_fails_signed_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_with_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        drop(logger);

        let mut entries = read_entries(tmp.path());
        entries[0].as_object_mut().unwrap().remove("sig");
        std::fs::write(
            tmp.path(),
            format!("{}\n", serde_json::to_string(&entries[0]).unwrap()),
        )
        .unwrap();

        // Hash chain still fine (recompute strips sig anyway), but signed fails.
        assert!(verify_log(tmp.path()).unwrap().ok);
        assert!(!verify_log_signed(tmp.path(), &cfg).unwrap().ok);
    }

    // MIK-6700 review #1: key_id is bound into the sig, so altering it fails
    // signed verify even though the hash chain (which strips key_id) still holds.
    #[test]
    fn altered_key_id_fails_signed_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_with_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        drop(logger);

        let mut entries = read_entries(tmp.path());
        entries[0]["key_id"] = serde_json::Value::String("attacker-key".to_string());
        std::fs::write(
            tmp.path(),
            format!("{}\n", serde_json::to_string(&entries[0]).unwrap()),
        )
        .unwrap();

        // Hash-only verify passes (key_id is not in entry_hash); signed fails.
        assert!(verify_log(tmp.path()).unwrap().ok);
        assert!(
            !verify_log_signed(tmp.path(), &cfg).unwrap().ok,
            "altered key_id must fail signed verify"
        );
    }

    // MIK-6700 review #1: stripping key_id (leaving a valid-looking sig) fails
    // signed verify — a signed entry must carry a key_id.
    #[test]
    fn stripped_key_id_fails_signed_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_with_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        drop(logger);

        let mut entries = read_entries(tmp.path());
        entries[0].as_object_mut().unwrap().remove("key_id");
        std::fs::write(
            tmp.path(),
            format!("{}\n", serde_json::to_string(&entries[0]).unwrap()),
        )
        .unwrap();

        assert!(verify_log(tmp.path()).unwrap().ok);
        assert!(
            !verify_log_signed(tmp.path(), &cfg).unwrap().ok,
            "stripped key_id must fail signed verify"
        );
    }

    // MIK-6700 review #2 (residual): detect a signed log so `audit verify`
    // refuses to hash-only-verify it without a secret.
    #[test]
    fn log_contains_signed_entry_detects_signed_and_unsigned() {
        // Signed log.
        let tmp_s = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_with_sig(tmp_s.path())).unwrap();
        write_entry(&logger, "sess", "1");
        drop(logger);
        assert!(
            log_contains_signed_entry(tmp_s.path()).unwrap(),
            "a signed log must be detected as signed"
        );

        // Unsigned log.
        let tmp_u = NamedTempFile::new().unwrap();
        let logger = TransparencyLogger::open(cfg_no_sig(tmp_u.path())).unwrap();
        write_entry(&logger, "sess", "1");
        drop(logger);
        assert!(
            !log_contains_signed_entry(tmp_u.path()).unwrap(),
            "an unsigned log must not be detected as signed"
        );
    }

    // HMAC.2 (backward compat): an unsigned log verifies identically whether
    // checked via verify_log or verify_log_signed with an empty secret.
    #[test]
    fn unsigned_log_backward_compatible() {
        let tmp = NamedTempFile::new().unwrap();
        let cfg = cfg_no_sig(tmp.path());
        let logger = TransparencyLogger::open(cfg.clone()).unwrap();
        write_entry(&logger, "sess", "1");
        write_entry(&logger, "sess", "2");
        drop(logger);

        let plain = verify_log(tmp.path()).unwrap();
        let signed = verify_log_signed(tmp.path(), &cfg).unwrap();
        assert!(plain.ok && signed.ok);
        assert_eq!(plain.entries_checked, signed.entries_checked);
    }

    // ── MIK-6710: bounded reads against a memory-DoS audit log ────────────────

    #[test]
    fn recover_chain_state_finds_last_entry_without_reading_oversized_log() {
        // GIVEN: a log whose leading content alone exceeds the tail-scan
        // window (MAX_TAIL_SCAN_BYTES), followed by one well-formed entry as
        // the final line.
        let tmp = NamedTempFile::new().unwrap();
        let padding_line = "x".repeat(1024);
        let mut content = String::new();
        for _ in 0..(5 * 1024) {
            content.push_str(&padding_line);
            content.push('\n');
        }
        let last_entry = serde_json::json!({
            "counter": 42u64,
            "entry_hash": "sha256:deadbeef",
        });
        content.push_str(&last_entry.to_string());
        content.push('\n');
        assert!(
            content.len() as u64 > MAX_TAIL_SCAN_BYTES,
            "test setup must exceed the tail-scan window to exercise the bounded path"
        );
        std::fs::write(tmp.path(), &content).unwrap();

        // WHEN: chain state is recovered
        let (counter, entry_hash) = recover_chain_state(tmp.path()).unwrap();

        // THEN: the correct last entry is found via the bounded tail scan
        // alone — a whole-file read would also pass this assertion, but the
        // bounded scan (proven by MAX_TAIL_SCAN_BYTES-sized reads in
        // `read_last_nonempty_line`) never touches the multi-megabyte prefix.
        assert_eq!(counter, 42);
        assert_eq!(entry_hash, "sha256:deadbeef");
    }

    #[test]
    fn bounded_read_to_string_rejects_oversized_file_without_loading_it() {
        // GIVEN: a file larger than an artificially small read bound
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "x".repeat(100)).unwrap();

        // WHEN: the bound is smaller than the file
        let err = bounded_read_to_string(tmp.path(), 50).unwrap_err();

        // THEN: the read is refused (fail-closed) before any content is
        // loaded — the size check is a single `metadata()` call, and the
        // same file under a sufficient bound still reads correctly.
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let ok = bounded_read_to_string(tmp.path(), 200).unwrap();
        assert_eq!(ok.len(), 100);
    }
}
