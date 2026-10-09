// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7926.FIX.2: the invocation record of a call that ran a CLI child says
//! how it ended, how long it ran and how many bytes it wrote, never what.
//! Each row runs a real child inside the production notes scope and reads the
//! record fields the invocation writer would add.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::tests::{call, capability};
use crate::capability::CapabilityDefinition;
use crate::gateway::{MetaMcp, with_dispatch_scope};

/// Run `calls` in one call's scope; the record fields its notes produce.
async fn recorded(calls: &[(&CapabilityDefinition, Value)]) -> Map<String, Value> {
    let ((), notes) = with_dispatch_scope(async {
        for (cap, params) in calls {
            let _ = call(cap, params.clone()).await;
        }
    })
    .await;
    let meta = MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    notes.attribution(&meta, BTreeSet::new(), None)
}

fn only_process(fields: &Map<String, Value>) -> &Value {
    let process = fields
        .get("process")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no process field: {fields:?}"));
    assert_eq!(process.len(), 1, "{process:?}");
    &process[0]
}

#[tokio::test]
async fn a_clean_exit_records_its_code_duration_and_byte_counts() {
    let cap = capability("big", "x", "      output: text\n", 30);
    let fields = recorded(&[(&cap, json!({}))]).await;
    let process = only_process(&fields);
    assert_eq!(process["ended"], "exited", "{process}");
    assert_eq!(process["exit_code"], 0, "{process}");
    assert_eq!(process["stdout_bytes"], 6000, "{process}");
    assert_eq!(process["stderr_bytes"], 0, "{process}");
    assert!(process["duration_ms"].is_u64(), "{process}");
}

#[tokio::test]
async fn a_failing_exit_records_its_code_and_stderr_bytes() {
    let cap = capability("fail", "\"3\"", "", 30);
    let fields = recorded(&[(&cap, json!({}))]).await;
    let process = only_process(&fields);
    assert_eq!(process["ended"], "exited", "{process}");
    assert_eq!(process["exit_code"], 3, "{process}");
    assert!(process["stderr_bytes"].as_u64() > Some(0), "{process}");
}

#[tokio::test]
async fn a_timeout_is_recorded_as_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pidfile = dir.path().join("grandchild.pid");
    let cap = capability("grandchild", &format!("'{}'", pidfile.display()), "", 1);
    let fields = recorded(&[(&cap, json!({}))]).await;
    let process = only_process(&fields);
    assert_eq!(process["ended"], "timed_out", "{process}");
    assert!(process.get("exit_code").is_none(), "{process}");
    assert!(process["stdout_bytes"].is_null(), "{process}");
}

#[tokio::test]
async fn output_past_the_cap_is_recorded_as_an_overflow() {
    let cap = capability("flood", "x", "      max_output_bytes: 65536\n", 30);
    let fields = recorded(&[(&cap, json!({}))]).await;
    assert_eq!(only_process(&fields)["ended"], "output_overflow");
}

/// Counts only: what the child printed never reaches the record.
#[tokio::test]
async fn the_record_holds_no_output_text() {
    const CANARY: &str = "CANARY_7926_FIX2";
    let cap = capability("fail", "\"2\", \"--to={to}\"", "", 30);
    let fields = recorded(&[(&cap, json!({ "to": CANARY }))]).await;
    only_process(&fields);
    let text = Value::Object(fields).to_string();
    assert!(
        !text.contains(CANARY),
        "output text reached the record: {text}"
    );
}

/// Two calls at once each record only their own child.
#[tokio::test]
async fn concurrent_calls_record_only_their_own_child() {
    let ok = capability("big", "x", "      output: text\n", 30);
    let failing = capability("fail", "\"4\"", "", 30);
    let (first, second) = ([(&ok, json!({}))], [(&failing, json!({}))]);
    let (a, b) = tokio::join!(recorded(&first), recorded(&second));
    assert_eq!(only_process(&a)["exit_code"], 0);
    assert_eq!(only_process(&b)["exit_code"], 4);
}

/// A record is bounded: the first 16 children, and how many ran.
#[tokio::test]
async fn many_children_are_bounded_and_counted() {
    let cap = capability("big", "x", "      output: text\n", 30);
    let calls: Vec<_> = (0..17).map(|_| (&cap, json!({}))).collect();
    let fields = recorded(&calls).await;
    let process = fields.get("process").and_then(Value::as_array).cloned();
    assert_eq!(process.map(|p| p.len()), Some(16), "{fields:?}");
    assert_eq!(fields.get("process_total"), Some(&json!(17)), "{fields:?}");
}

/// A call that started no child keeps the record's schema.
#[tokio::test]
async fn a_call_without_a_child_adds_no_field() {
    let fields = recorded(&[]).await;
    assert!(fields.get("process").is_none(), "{fields:?}");
}

/// Byte counts are bytes: a non-ASCII argument echoed on stderr is counted
/// in UTF-8 bytes, not characters. Unix only: a Windows pipe takes the
/// child's locale encoding.
#[cfg(unix)]
#[tokio::test]
async fn byte_counts_are_utf8_bytes() {
    const WORD: &str = "naïve ✓";
    let cap = capability("fail", "\"3\", \"--\", \"{x}\"", "", 30);
    let fields = recorded(&[(&cap, json!({ "x": WORD }))]).await;
    // argv_echo.py `fail`: "argv=<args>\n" then "env=<test values>\n".
    let expected = format!("argv=3 -- {WORD}\nenv=\n").len();
    assert_eq!(only_process(&fields)["stderr_bytes"], expected);
}

/// A child ended by a signal has no exit code and says so.
#[cfg(unix)]
#[tokio::test]
async fn a_signalled_child_is_recorded_as_one() {
    let cap = capability("signal", "x", "", 30);
    let fields = recorded(&[(&cap, json!({}))]).await;
    let process = only_process(&fields);
    assert_eq!(process["ended"], "signalled", "{process}");
    assert!(process.get("exit_code").is_none(), "{process}");
}
