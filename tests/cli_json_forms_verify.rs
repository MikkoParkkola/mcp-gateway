// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! JSON forms of the verify commands and `audit show`, through the built binary. A verdict, pass or fail, is one
//! document under `--json` with today's exit; an error before a verdict prints nothing on stdout. Fixtures are
//! copied from `tests/d6_audit_verify_cli.rs` and `tests/audit_verify_pairing_cli.rs` (test plan r2, J13, S1).

#[path = "common/gateway_bin.rs"]
mod gateway_bin;
#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;
#[path = "common/provenance_fixture.rs"]
mod provenance_fixture;

use provenance_fixture::fixture;

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use mcp_gateway::security::TransparencyLogger;
use mcp_gateway::security::transparency_log::{
    RotationConfig, TransparencyLogConfig, recompute_entry_hash,
};
use serde_json::{Value, json};

/// What one run printed.
struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(home: &Path, args: &[&str]) -> Out {
    let out = gateway_bin::command(home, gateway_bin::Inherit::Nothing)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run mcp-gateway");
    Out {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The one document a `--json` run printed with exit `code`: exactly one line ending in one newline.
fn document(out: &Out, code: i32) -> Value {
    assert_eq!(out.code, Some(code), "stderr: {}", out.stderr);
    let line = out
        .stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("no single trailing newline: {:?}", out.stdout));
    assert!(!line.contains('\n'), "more than one line: {:?}", out.stdout);
    serde_json::from_str(line).unwrap_or_else(|e| panic!("not one JSON document ({e}): {line:?}"))
}

// ── fixtures ────────────────────────────────────────────────────────────────

/// The signing key of the signed fixtures; any long value works, it is never a real credential.
const LOG_KEY: &str = "audit-fixture-signing-value-0123456789abcdef";
const OTHER_KEY: &str = "audit-fixture-other-value-0123456789abcdef";

/// A gateway config with auth off and, when given, the log's signing key.
fn verify_config(dir: &Path, key: Option<&str>) -> String {
    let path = dir.join("gateway.yaml");
    let signing = key.map_or_else(String::new, |key| {
        format!("security:\n  transparency_log:\n    key_id: cli\n    shared_secret: \"{key}\"\n")
    });
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        format!("auth:\n  enabled: false\n{signing}"),
    )
    .expect("config");
    path.to_str().expect("utf-8 path").to_owned()
}

/// An unrotated log at `path` with two caller records, signed with `key` when given.
fn small_log(path: &Path, key: Option<&str>) {
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "cli".into(),
        shared_secret: key.unwrap_or_default().to_owned(),
        rotation: RotationConfig::default(),
    }))
    .expect("logger");
    for i in 0..2 {
        logger
            .log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .expect("append");
    }
}

/// Every record of the log file, read on its own (the oracle for counts and counters).
fn records(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("log")
        .lines()
        .map(|l| serde_json::from_str(l).expect("record"))
        .collect()
}

fn write_records(path: &Path, all: &[Value]) {
    let mut body = String::new();
    for v in all {
        writeln!(body, "{v}").expect("format");
    }
    std::fs::write(path, body).expect("log");
}

/// `records` chained onto the log at `path` (counter, previous hash and hash recomputed), the last one edited
/// after hashing when `tamper`.
fn chain_onto(path: &Path, extra: Vec<Value>, tamper: bool) {
    let mut all = records(path);
    for mut v in extra {
        let last = all.last().expect("a record");
        v["counter"] = (last["counter"].as_u64().expect("counter") + 1).into();
        v["prev_entry_hash"] = last["entry_hash"].clone();
        v["entry_hash"] = recompute_entry_hash(&v).expect("hash").into();
        all.push(v);
    }
    if tamper {
        all.last_mut().expect("a record")["note"] = "edited".into();
    }
    write_records(path, &all);
}

const PLANTED: &str = "PLANTED-VALUE-9318";
const BIDI_TOKEN: &str = "w\u{202e}1";

fn settle(event: &str, token: &str, extra: &Value) -> Value {
    let mut v = json!({"event": event, "token": token, "kind": "settle.save", "note": PLANTED});
    v.as_object_mut()
        .expect("object")
        .extend(extra.as_object().expect("object").clone());
    v
}

/// A fresh unsigned log holding the logger's own records, then `extra` chained on.
fn settle_log(path: &Path, extra: Vec<Value>, tamper: bool) {
    drop(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "cli".into(),
            ..TransparencyLogConfig::default()
        }))
        .expect("logger"),
    );
    chain_onto(path, extra, tamper);
}

/// A log rotated until its first segments expired (one segment kept), then `extra` chained onto the active file.
fn rotated_log(path: &Path, extra: Vec<Value>) {
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "cli".into(),
        rotation: RotationConfig {
            max_segment_bytes: 4096,
            retain_segments: 1,
            ..RotationConfig::default()
        },
        ..TransparencyLogConfig::default()
    }))
    .expect("logger");
    for i in 0..400 {
        logger
            .log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .expect("append");
    }
    drop(logger);
    chain_onto(path, extra, false);
}

/// The token escaped once, never raw, never escaped twice; the planted payload value absent.
fn assert_escaped_once(text: &str, what: &str) {
    assert!(text.contains("w\\u{202e}1"), "{what}: {text}");
    assert!(!text.contains(BIDI_TOKEN), "{what}: raw bidi: {text}");
    assert!(
        !text.contains("w\\\\u{202e}1"),
        "{what}: escaped twice: {text}"
    );
    assert!(
        !text.contains(PLANTED),
        "{what}: payload value printed: {text}"
    );
}

// ── audit verify (J13) ──────────────────────────────────────────────────────

fn verify_args<'a>(config: &'a str, log: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["--config", config, "audit", "verify", "--path", log];
    args.extend_from_slice(extra);
    args
}

#[test]
fn audit_verify_passing_logs_print_their_verdict() {
    require_private_home!();
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("transparency.jsonl");
    small_log(&log, None);
    // The fixture's records, listed before any count is pinned: the logger's own and the two appended.
    let n = records(&log).len();
    assert!(n >= 3, "the logger's records plus two: {n}");
    let config = verify_config(dir.path(), None);
    let log_s = log.to_str().expect("utf-8");

    let plain = run(dir.path(), &verify_args(&config, log_s, &[]));
    assert_eq!(
        (plain.code, plain.stdout.as_str(), plain.stderr.as_str()),
        (
            Some(0),
            &*format!(
                "✓ Chain verified (hash chain (no secret configured; HMAC not checked); live log) — {n} entries \
                 checked across 1 segments, 0 expired by retention, no tampering detected.\n"
            ),
            ""
        )
    );
    let json = run(dir.path(), &verify_args(&config, log_s, &["--json"]));
    assert!(
        json.stdout.starts_with("{\"schema_version\":1,"),
        "field order: {:?}",
        json.stdout
    );
    assert_eq!(
        document(&json, 0),
        json!({
            "schema_version": 1, "ok": true, "hmac_checked": false, "signed_entry_seen": false, "scope": "live",
            "entries_checked": n, "segments_checked": 1, "segments_expired": 0, "failed_check": null,
            "failed_at_counter": null, "error": null, "warnings": [], "notes": []
        })
    );
    let archive = run(
        dir.path(),
        &verify_args(&config, log_s, &["--archive", "--json"]),
    );
    assert_eq!(document(&archive, 0)["scope"], json!("archive"));

    // Signed, verified with its own key: the HMAC was checked and signed entries were seen.
    let signed_dir = tempfile::tempdir().expect("dir");
    let signed = signed_dir.path().join("transparency.jsonl");
    small_log(&signed, Some(LOG_KEY));
    let n = records(&signed).len();
    let config = verify_config(signed_dir.path(), Some(LOG_KEY));
    let out = run(
        signed_dir.path(),
        &verify_args(&config, signed.to_str().expect("utf-8"), &["--json"]),
    );
    assert_eq!(
        document(&out, 0),
        json!({
            "schema_version": 1, "ok": true, "hmac_checked": true, "signed_entry_seen": true, "scope": "live",
            "entries_checked": n, "segments_checked": 1, "segments_expired": 0, "failed_check": null,
            "failed_at_counter": null, "error": null, "warnings": [], "notes": []
        })
    );
}

#[test]
fn audit_verify_failed_verdicts_print_their_document_with_exit_1() {
    require_private_home!();
    // A chain failure: the last record edited after hashing.
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("transparency.jsonl");
    small_log(&log, None);
    chain_onto(&log, vec![json!({"event": "x", "note": "kept"})], true);
    let edited = records(&log).last().expect("a record")["counter"].clone();
    let config = verify_config(dir.path(), None);
    let log_s = log.to_str().expect("utf-8");
    let plain = run(dir.path(), &verify_args(&config, log_s, &[]));
    let json = run(dir.path(), &verify_args(&config, log_s, &["--json"]));
    let doc = document(&json, 1);
    assert_eq!(
        (&doc["ok"], &doc["failed_check"], &doc["failed_at_counter"]),
        (&json!(false), &json!("chain"), &edited)
    );
    let headline = format!("✗ Chain verification FAILED at counter {edited}: ");
    let message = plain
        .stderr
        .lines()
        .find_map(|l| l.strip_prefix(headline.as_str()))
        .unwrap_or_else(|| panic!("no failure line: {}", plain.stderr));
    assert_eq!(doc["error"], json!(message));
    assert_eq!((plain.code, plain.stdout.as_str()), (Some(1), ""));
    // A verdict prints no `error: ` line: a chain failure is not a local error.
    assert!(
        !plain.stderr.lines().any(|l| l.starts_with("error: ")),
        "{}",
        plain.stderr
    );
    assert_eq!(json.stderr, plain.stderr);

    // A signed log verified with another key: the HMAC check fails the verdict.
    let signed_dir = tempfile::tempdir().expect("dir");
    let signed = signed_dir.path().join("transparency.jsonl");
    small_log(&signed, Some(LOG_KEY));
    let config = verify_config(signed_dir.path(), Some(OTHER_KEY));
    let out = run(
        signed_dir.path(),
        &verify_args(&config, signed.to_str().expect("utf-8"), &["--json"]),
    );
    let doc = document(&out, 1);
    assert_eq!(
        (&doc["ok"], &doc["hmac_checked"]),
        (&json!(false), &json!(true))
    );

    // A pairing failure, its token escaped once and the planted payload nowhere.
    let pair_dir = tempfile::tempdir().expect("dir");
    let pair = pair_dir.path().join("transparency.jsonl");
    settle_log(
        &pair,
        vec![
            settle("config_save_intent", BIDI_TOKEN, &json!({})),
            settle(
                "config_write_delivery_stopped",
                BIDI_TOKEN,
                &json!({"intent_counter": 3}),
            ),
        ],
        false,
    );
    let config = verify_config(pair_dir.path(), None);
    let out = run(
        pair_dir.path(),
        &verify_args(
            &config,
            pair.to_str().expect("utf-8"),
            &["--archive", "--json"],
        ),
    );
    let doc = document(&out, 1);
    assert_eq!(doc["failed_check"], json!("pairing"));
    assert_escaped_once(doc["error"].as_str().expect("error text"), "error field");
    assert!(
        !out.stdout.contains(PLANTED) && !out.stderr.contains(PLANTED),
        "payload printed"
    );
}

#[test]
fn audit_verify_warnings_and_notes_are_in_the_document() {
    require_private_home!();
    // An interrupted intent: a warning on a passing chain.
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("transparency.jsonl");
    settle_log(
        &log,
        vec![
            settle("config_save_intent", BIDI_TOKEN, &json!({})),
            json!({"event": "config_write_note", "note": PLANTED}),
        ],
        false,
    );
    let config = verify_config(dir.path(), None);
    let log_s = log.to_str().expect("utf-8");
    let plain = run(dir.path(), &verify_args(&config, log_s, &["--archive"]));
    let json = run(
        dir.path(),
        &verify_args(&config, log_s, &["--archive", "--json"]),
    );
    let doc = document(&json, 0);
    // Written out (A8); the counter is the fixture's, read from the log it wrote.
    let at = records(&log)
        .iter()
        .find(|r| r["event"] == "config_save_intent")
        .and_then(|r| r["counter"].as_u64())
        .expect("the intent's counter");
    let warning = format!("intent interrupted at counter {at} (token w\\u{{202e}}1)");
    assert_eq!(
        plain.stderr,
        format!("warning: {warning}\n"),
        "plain stderr"
    );
    assert_eq!(doc["warnings"], json!([warning]));
    assert_escaped_once(&warning, "warning");
    assert_eq!(json.stderr, plain.stderr);

    // An outcome naming an expired intent: a note on a passing chain.
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("transparency.jsonl");
    rotated_log(
        &log,
        vec![settle(
            "config_write_outcome",
            "w\u{7}1",
            &json!({"intent_counter": 1}),
        )],
    );
    let config = verify_config(dir.path(), None);
    let log_s = log.to_str().expect("utf-8");
    let plain = run(dir.path(), &verify_args(&config, log_s, &[]));
    let json = run(dir.path(), &verify_args(&config, log_s, &["--json"]));
    let doc = document(&json, 0);
    // Written out (A8); the outcome's counter is the fixture's, read from the log it wrote.
    let at = records(&log)
        .last()
        .and_then(|r| r["counter"].as_u64())
        .expect("the outcome's counter");
    let note = format!(
        "intent expired: config_write_outcome at counter {at} names counter 1 (token w\\u{{7}}1)"
    );
    let notes: Vec<&str> = plain
        .stderr
        .lines()
        .filter_map(|l| l.strip_prefix("info: "))
        .collect();
    assert_eq!(notes, [note.as_str()], "{}", plain.stderr);
    assert_eq!(doc["notes"], json!([note]));
    assert!(
        !json.stdout.contains('\u{7}'),
        "raw control character: {:?}",
        json.stdout
    );
}

/// Not verdicts: a missing log, an unloadable config and signed entries with no key configured print nothing on
/// stdout under `--json`; stderr and exit are the text form's.
#[test]
fn audit_verify_errors_before_a_verdict_print_no_document() {
    require_private_home!();
    let dir = tempfile::tempdir().expect("dir");
    let config = verify_config(dir.path(), None);
    let missing = dir.path().join("missing.jsonl");
    let broken_dir = tempfile::tempdir().expect("dir");
    let broken = broken_dir.path().join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&broken, "server: [this is: not, valid\n")
        .expect("config");
    let small = dir.path().join("small.jsonl");
    small_log(&small, None);
    let signed = dir.path().join("signed.jsonl");
    small_log(&signed, Some(LOG_KEY));
    let missing_s = missing.to_str().expect("utf-8").to_owned();
    let signed_s = signed.to_str().expect("utf-8").to_owned();
    // Each case's error, written out (A8): an empty or wrong stderr fails here, not only a mismatch between forms.
    let cases = [
        (
            config.clone(),
            missing_s.clone(),
            format!("error: transparency log not found at {missing_s}\n"),
        ),
        (
            broken.to_str().expect("utf-8").to_owned(),
            small.to_str().expect("utf-8").to_owned(),
            "error: could not load gateway config for signed verification: ".to_owned(),
        ),
        (
            config,
            signed_s.clone(),
            format!(
                "error: log at {signed_s} has signed entries but no shared secret is configured"
            ),
        ),
    ];
    for (config, log, error) in &cases {
        let plain = run(dir.path(), &verify_args(config, log, &[]));
        let json = run(dir.path(), &verify_args(config, log, &["--json"]));
        assert_eq!(plain.code, Some(1), "{log}: {}", plain.stderr);
        assert!(
            plain.stderr.starts_with(error.as_str()),
            "{log}: {}",
            plain.stderr
        );
        assert_eq!(
            (json.code, json.stdout.as_str(), json.stderr.as_str()),
            (plain.code, "", plain.stderr.as_str()),
            "{log}"
        );
    }
}

// ── audit show (S1, JSONF.3) ────────────────────────────────────────────────

/// Hand-written entries, keys in alphabetical order so the pretty-printed literal holds whatever key order the
/// serializer keeps.
const SHOW_LOG: &str = "\
{\"counter\":1,\"note\":\"first\",\"session_id\":\"s-1\",\"tool\":\"alpha\"}
{\"counter\":2,\"note\":\"second\",\"session_id\":\"s-2\",\"tool\":\"beta\"}
{\"counter\":3,\"note\":\"third\",\"session_id\":\"s-1\",\"tool\":\"gamma\"}
";

#[test]
fn audit_show_prints_one_array() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("transparency.jsonl");
    std::fs::write(&log, SHOW_LOG).expect("log");
    let log = log.to_str().expect("utf-8");
    let show = |session: &str| {
        run(
            dir.path(),
            &["audit", "show", "--session", session, "--path", log],
        )
    };

    let two = show("s-1");
    assert_eq!(two.code, Some(0), "{}", two.stderr);
    let parsed: Value = serde_json::from_str(&two.stdout).expect("one JSON document");
    assert_eq!(
        parsed,
        json!([
            {"counter": 1, "note": "first", "session_id": "s-1", "tool": "alpha"},
            {"counter": 3, "note": "third", "session_id": "s-1", "tool": "gamma"}
        ])
    );
    let one = show("s-2");
    assert_eq!(
        (one.code, one.stdout.as_str()),
        (
            Some(0),
            "[\n  {\n    \"counter\": 2,\n    \"note\": \"second\",\n    \"session_id\": \"s-2\",\n    \
             \"tool\": \"beta\"\n  }\n]\n"
        )
    );
    let none = show("none");
    assert_eq!((none.code, none.stdout.as_str()), (Some(0), "[]\n"));
}

/// F (audit show has no flag): a missing log prints nothing on stdout and names the path.
#[test]
fn audit_show_missing_log_prints_nothing_on_stdout() {
    let dir = tempfile::tempdir().expect("dir");
    let log = dir.path().join("missing.jsonl");
    let log = log.to_str().expect("utf-8");
    let out = run(
        dir.path(),
        &["audit", "show", "--session", "s-1", "--path", log],
    );
    assert_eq!(
        (out.code, out.stdout.as_str(), out.stderr.as_str()),
        (
            Some(1),
            "",
            &*format!(
                "error: transparency log not found at {log}\nCheck that {log} exists, or pass --path naming the log.\n"
            )
        )
    );
}

// ── provenance verify (J14, V3) ─────────────────────────────────────────────

fn provenance(
    home: &Path,
    trust: &str,
    receipt: &str,
    result: Option<&str>,
    flags: &[&str],
) -> (Out, Out) {
    let mut args = vec!["provenance", "verify", "--trust", trust, receipt];
    if let Some(result) = result {
        args.extend(["--result", result]);
    }
    args.extend_from_slice(flags);
    let plain = run(home, &args);
    args.push("--json");
    (plain, run(home, &args))
}

/// One provenance verify case: receipt, result, extra flags, exit, text line, document.
type VerifyCase<'a> = (&'a str, Option<&'a str>, &'a [&'a str], i32, &'a str, Value);

fn verdict(status: &str, accepted: bool, kid: Option<&str>, reason: Option<&str>) -> Value {
    json!({"schema_version": 1, "status": status, "accepted": accepted, "kid": kid, "reason": reason})
}

#[test]
fn provenance_verify_prints_every_verdict() {
    let home = tempfile::tempdir().expect("home");
    let h = home.path();
    let trust = fixture(h, "jwk.json");
    let bound = fixture(h, "provenance.json");
    let unbound = fixture(h, "provenance_unbound.json");
    let result = fixture(h, "result.json");
    let unbound_result = h.join("unbound_result.json");
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &unbound_result,
        b"{\"n\":9007199254740992}",
    )
    .expect("result");
    let unbound_result = unbound_result.to_str().expect("utf-8");
    let kid = Some("prov-test-1");

    let cases: [VerifyCase<'_>; 5] = [
        (
            &bound,
            Some(&result),
            &[],
            0,
            "BOUND kid=prov-test-1\n",
            verdict("bound", true, kid, None),
        ),
        (
            &bound,
            None,
            &[],
            1,
            "SIGNATURE-ONLY kid=prov-test-1\n",
            verdict("signature_only", false, kid, None),
        ),
        (
            &bound,
            None,
            &["--signature-only"],
            0,
            "SIGNATURE-ONLY kid=prov-test-1 (accepted: --signature-only)\n",
            verdict("signature_only", true, kid, None),
        ),
        (
            &unbound,
            Some(unbound_result),
            &[],
            1,
            "UNBOUND kid=prov-test-1\n",
            verdict("unbound", false, kid, None),
        ),
        (
            &unbound,
            Some(unbound_result),
            &["--accept-unbound"],
            0,
            "UNBOUND kid=prov-test-1 (accepted: --accept-unbound)\n",
            verdict("unbound", true, kid, None),
        ),
    ];
    for (receipt, result, flags, code, text, doc) in cases {
        let (plain, json) = provenance(h, &trust, receipt, result, flags);
        assert_eq!(
            (plain.code, plain.stdout.as_str()),
            (Some(code), text),
            "{flags:?}"
        );
        assert_eq!(document(&json, code), doc, "{flags:?}");
        assert_eq!(json.stderr, plain.stderr, "{flags:?}");
    }
}

#[test]
fn provenance_verify_invalid_inputs_are_verdicts() {
    let home = tempfile::tempdir().expect("home");
    let h = home.path();
    let trust = fixture(h, "jwk.json");
    let receipt = fixture(h, "provenance.json");
    let result = fixture(h, "result.json");
    let unknown_kid = fixture(h, "jwk_unknown_kid.json");
    let missing = h.join("missing.json").to_str().expect("utf-8").to_owned();
    let garbled = h.join("garbled.json");
    mcp_gateway::gateway::test_helpers::write_owner_only(&garbled, b"not json").expect("file");
    let garbled = garbled.to_str().expect("utf-8").to_owned();
    let duplicated = h.join("duplicated.json");
    mcp_gateway::gateway::test_helpers::write_owner_only(&duplicated, b"{\"a\":1,\"a\":2}")
        .expect("file");
    let duplicated = duplicated.to_str().expect("utf-8").to_owned();

    // (trust, receipt, result, the reason, written out: A8)
    let cases: [(&str, &str, Option<&str>, &str); 6] = [
        (&missing, &receipt, None, "unreadable_input"),
        (&garbled, &receipt, None, "trust_malformed"),
        (&trust, &missing, None, "unreadable_input"),
        (&trust, &duplicated, None, "duplicate_member"),
        (&trust, &receipt, Some(&missing), "unreadable_input"),
        (&unknown_kid, &receipt, Some(&result), "unknown_kid"),
    ];
    for (trust, receipt, result, pinned) in cases {
        let (plain, json) = provenance(h, trust, receipt, result, &[]);
        let reason = plain
            .stdout
            .strip_prefix("INVALID ")
            .and_then(|r| r.strip_suffix('\n'))
            .unwrap_or_else(|| panic!("not an INVALID line: {:?}", plain.stdout));
        assert_eq!(reason, pinned, "{trust} {receipt} {result:?}");
        assert_eq!(plain.code, Some(1));
        assert_eq!(
            document(&json, 1),
            verdict("invalid", false, None, Some(reason)),
            "{trust} {receipt} {result:?}"
        );
    }
}

/// V2, binary half: `audit verify --export` on a missing file with a valid key file is a verdict document.
#[test]
fn audit_verify_export_missing_file_is_a_verdict() {
    let home = tempfile::tempdir().expect("home");
    let jwk = fixture(home.path(), "jwk.json");
    let missing = home.path().join("missing.ndjson");
    let missing = missing.to_str().expect("utf-8");
    let args = [
        "audit",
        "verify",
        "--export",
        missing,
        "--jwk",
        jwk.as_str(),
    ];
    let plain = run(home.path(), &args);
    let why = plain
        .stdout
        .strip_prefix("INVALID ")
        .and_then(|r| r.strip_suffix('\n'))
        .unwrap_or_else(|| panic!("not an INVALID line: {:?} / {}", plain.stdout, plain.stderr));
    assert_eq!(plain.code, Some(1));
    let mut flagged = args.to_vec();
    flagged.push("--json");
    let json = run(home.path(), &flagged);
    assert_eq!(
        document(&json, 1),
        json!({
            "schema_version": 1, "valid": false, "reason": why, "rows": null, "truncated": null,
            "integrity_failed": null, "kid": null
        })
    );
}
