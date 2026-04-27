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
//! 3. `sig = hmac_sha256(shared_secret, raw_entry_hash_bytes)`
//!
//! Because `serde_json::Map` is a `BTreeMap` (keys sorted alphabetically, no
//! `preserve_order` feature), serialisation is deterministic and the hash
//! computed on write is exactly reproducible on read.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use tracing::warn;

// ── Type aliases ──────────────────────────────────────────────────────────────

type HmacSha256 = Hmac<Sha256>;

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

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Recover state from the last line (if the file already exists).
        let (counter, last_entry_hash) = if path.exists() {
            recover_chain_state(&path)?
        } else {
            (0u64, "genesis".to_string())
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            inner: Mutex::new(Inner {
                writer: BufWriter::new(file),
                counter,
                last_entry_hash,
            }),
            config,
        })
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

        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "transparency log mutex poisoned"))?;

        inner.counter += 1;
        let counter = inner.counter;
        let prev_entry_hash = inner.last_entry_hash.clone();

        // ── Step 1: Build entry core (without entry_hash / sig / key_id) ──────
        //
        // serde_json::json! builds a BTreeMap, so keys are sorted alphabetically
        // on every serialisation — the hash is deterministic and reproducible.
        let entry_core = serde_json::json!({
            "caller":          caller,
            "counter":         counter,
            "prev_entry_hash": prev_entry_hash,
            "request_hash":    request_hash,
            "response_hash":   response_hash,
            "server":          server,
            "session_id":      session_id,
            "timestamp":       timestamp,
            "tool":            tool,
        });

        // ── Step 2: entry_hash = sha256(canonical JSON of core) ───────────────
        let core_json = serde_json::to_string(&entry_core)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let entry_hash_bytes: [u8; 32] = sha256_raw(core_json.as_bytes());
        let entry_hash = format!("sha256:{}", hex::encode(entry_hash_bytes));

        // ── Step 3: sig = hmac_sha256(secret, entry_hash_bytes) ──────────────
        let (sig_opt, key_id_opt) = if !self.config.shared_secret.is_empty() {
            let sig_hex = hmac_sha256_hex(self.config.shared_secret.as_bytes(), &entry_hash_bytes);
            (
                Some(format!("hmac-sha256:{sig_hex}")),
                Some(self.config.key_id.clone()),
            )
        } else {
            (None, None)
        };

        // ── Assemble the full entry ───────────────────────────────────────────
        let mut full_entry = entry_core;
        {
            let obj = full_entry
                .as_object_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "entry is not an object"))?;

            obj.insert(
                "entry_hash".to_string(),
                serde_json::Value::String(entry_hash.clone()),
            );
            if let (Some(sig), Some(kid)) = (sig_opt, key_id_opt) {
                obj.insert("sig".to_string(), serde_json::Value::String(sig));
                obj.insert("key_id".to_string(), serde_json::Value::String(kid));
            }
        }

        // ── Write to file ─────────────────────────────────────────────────────
        let line = serde_json::to_string(&full_entry)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        writeln!(inner.writer, "{line}")?;
        inner.writer.flush()?;

        // ── Advance chain state ───────────────────────────────────────────────
        inner.last_entry_hash = entry_hash;

        Ok(())
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

/// Read `path` and verify the complete hash chain.
///
/// Checks, for every entry:
/// 1. Counter is exactly `previous_counter + 1` (monotonic, no gaps).
/// 2. `prev_entry_hash` matches the prior entry's `entry_hash`.
/// 3. `entry_hash` equals the recomputed SHA-256 of the entry without the
///    `entry_hash`, `sig`, and `key_id` fields.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be read.
pub fn verify_log(path: &Path) -> io::Result<VerifyResult> {
    let content = std::fs::read_to_string(path)?;
    let mut prev_hash = "genesis".to_string();
    let mut prev_counter: Option<u64> = None;
    let mut entries_checked = 0usize;

    for (line_no, raw) in content.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        let entry: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: invalid JSON: {e}", line_no + 1),
                )
            })?;

        let counter = entry
            .get("counter")
            .and_then(|v| v.as_u64())
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
                     (expected '{}', got '{}')",
                    prev_hash, stored_prev_hash
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
pub fn show_session_entries(
    path: &Path,
    session: &str,
) -> io::Result<Vec<serde_json::Value>> {
    let content = std::fs::read_to_string(path)?;
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
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(s)
}

/// Read the last non-empty line of `path` to recover `(counter, last_entry_hash)`.
fn recover_chain_state(path: &Path) -> io::Result<(u64, String)> {
    let content = std::fs::read_to_string(path)?;
    let last_line = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .last();

    let Some(line) = last_line else {
        return Ok((0, "genesis".to_string()));
    };

    let entry: serde_json::Value = serde_json::from_str(line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let counter = entry
        .get("counter")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let entry_hash = entry
        .get("entry_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("genesis")
        .to_string();

    Ok((counter, entry_hash))
}

/// Recompute the `entry_hash` for an existing entry read from the log file.
///
/// Strips `entry_hash`, `sig`, and `key_id`, serialises what remains (BTreeMap
/// so alphabetically sorted), and returns `"sha256:<hex>"`.
fn recompute_entry_hash(entry: &serde_json::Value) -> io::Result<String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry is not a JSON object"))?;

    // Build a clean copy without the hash-and-sig fields.
    let core: serde_json::Map<String, serde_json::Value> = obj
        .iter()
        .filter(|(k, _)| k.as_str() != "entry_hash" && k.as_str() != "sig" && k.as_str() != "key_id")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let core_json = serde_json::to_string(&core)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let hash_bytes = sha256_raw(core_json.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hash_bytes)))
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
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
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

    fn write_entry(
        logger: &TransparencyLogger,
        session: &str,
        counter_hint: &str,
    ) {
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
        assert!(sig.starts_with("hmac-sha256:"), "sig must have hmac-sha256 prefix");
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
}
