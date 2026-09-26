// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the transparency log (moved out for the file-size ceiling).

use std::sync::Arc;

use tempfile::NamedTempFile;

use super::*;

// ── Helpers ───────────────────────────────────────────────────────────────

fn cfg_no_sig(path: &Path) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().to_string(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    })
}

fn cfg_with_sig(path: &Path) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().to_string(),
        key_id: "test-key".to_string(),
        shared_secret: "a-test-secret-that-is-at-least-32-bytes!!".to_string(),
        ..TransparencyLogConfig::default()
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

    // THEN: only "alpha" entries are returned, stored as its fingerprint
    assert_eq!(entries.len(), 2);
    let fp = crate::gateway::session_id::session_fp("alpha");
    assert!(entries.iter().all(|e| e["session_id"] == fp));
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
    // (D6 recovery reads the tail through the same bounded helper.)
    let tail: serde_json::Value =
        serde_json::from_str(&read_last_nonempty_line(tmp.path()).unwrap().unwrap()).unwrap();
    let (counter, entry_hash) = (
        tail["counter"].as_u64().unwrap(),
        tail["entry_hash"].as_str().unwrap(),
    );

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
