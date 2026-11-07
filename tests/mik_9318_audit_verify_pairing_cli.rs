// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-9318 step 3, section 5 through the real CLI: a pairing failure has
//! its own headline, and no payload value, and no unescaped token, reaches
//! a warning, an "unverified:" warning or the failure line.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use mcp_gateway::security::TransparencyLogger;
use mcp_gateway::security::transparency_log::{TransparencyLogConfig, recompute_entry_hash};
use serde_json::{Value, json};

const PLANTED: &str = "PLANTED-VALUE-9318";
const BIDI_TOKEN: &str = "w\u{202e}1";

/// A settle record of `token` carrying the planted value.
fn settle(event: &str, token: &str, extra: &Value) -> Value {
    let mut v = json!({"event": event, "token": token, "kind": "settle.save", "note": PLANTED});
    v.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    v
}

/// A fresh unsigned log, then `records` chained after its own; `tamper`
/// edits the last record after chaining, so the chain check fails there.
fn write_log(path: &Path, records: Vec<Value>, tamper: bool) {
    drop(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "cli".into(),
            ..TransparencyLogConfig::default()
        }))
        .unwrap(),
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut all: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for mut v in records {
        let last = all.last().unwrap();
        v["counter"] = (last["counter"].as_u64().unwrap() + 1).into();
        v["prev_entry_hash"] = last["entry_hash"].clone();
        v["entry_hash"] = recompute_entry_hash(&v).unwrap().into();
        all.push(v);
    }
    if tamper {
        all.last_mut().unwrap()["note"] = "edited".into();
    }
    let mut body = String::new();
    for v in &all {
        writeln!(body, "{v}").unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// `audit verify --archive` (no `.hwm` needed): success, and all output.
fn verify(dir: &Path, log: &Path) -> (bool, String) {
    let config = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, "auth:\n  enabled: false\n")
        .unwrap();
    let mut cmd = gateway_bin::command(dir, gateway_bin::Inherit::Environment);
    cmd.arg("--config").arg(&config);
    cmd.args(["audit", "verify", "--archive", "--path"])
        .arg(log);
    let out = cmd.output().expect("audit verify runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// The token escaped once, never raw, never escaped twice.
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

#[test]
fn a_pairing_failure_prints_its_own_headline_with_the_token_escaped() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(
        &log,
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
    let (ok, text) = verify(dir.path(), &log);
    assert!(!ok, "{text}");
    let headline = "Pairing verification FAILED: delivery stopped with no outcome at counter 4 (token w\\u{202e}1)";
    assert!(text.contains(headline), "{text}");
    assert!(!text.contains("Chain verification FAILED"), "{text}");
    assert_escaped_once(&text, "failure line");
}

#[test]
fn warnings_and_unverified_warnings_print_no_payload_value_and_escape_the_token() {
    let intent = || settle("config_save_intent", BIDI_TOKEN, &json!({}));
    let note = json!({"event": "config_write_note", "note": PLANTED});
    // An interrupted intent: a warning on a passing chain.
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(&log, vec![intent(), note.clone()], false);
    let (ok, text) = verify(dir.path(), &log);
    assert!(ok, "{text}");
    assert!(text.contains("interrupted"), "{text}");
    assert_escaped_once(&text, "warning");
    // The same under a failed chain: an "unverified:" warning.
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(&log, vec![intent(), note], true);
    let (ok, text) = verify(dir.path(), &log);
    assert!(!ok, "{text}");
    assert!(text.contains("Chain verification FAILED"), "{text}");
    assert!(text.contains("unverified:"), "{text}");
    assert!(text.contains("interrupted"), "{text}");
    assert_escaped_once(&text, "unverified warning");
}
