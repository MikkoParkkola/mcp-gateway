// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B FW1 (test plan v2 §5): the response of a call whose target
//! is absent for the caller is attributed to the gateway's own tool, never
//! to the absent target, for every reason it is absent. Observed through the
//! response firewall's own audit row, which records `policy_targets` for
//! every response it inspects (`audit.rs` `log_response_artifact`), matched
//! or not, so no rule and no new seam is needed.

use serde_json::{Value, json};

use super::direct_guards_fixture::{Answer, fixture_firewalled_audited, send};

/// The key: scoped to `alpha` and the never-registered `ghost`.
const KEY: &str = "k-alpha-ghost";

/// The three cells: registered but out of scope, in scope but unregistered,
/// neither.
const CELLS: [&str; 3] = ["alpha-pt", "ghost", "nosuch_8387"];

/// The gateway's own target, the one an absent name's response gets.
fn gateway_target() -> Value {
    json!([{"server": "gateway", "tool": "gateway_invoke"}])
}

/// One cell: the answer with the name blanked, and every response row's
/// `policy_targets` for the call.
async fn cell(server: &str) -> (String, Vec<Value>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("firewall.jsonl");
    let fx = fixture_firewalled_audited(Answer::Ok, audit.clone()).await;
    let call = json!({"name": "gateway_invoke",
        "arguments": {"server": server, "tool": "read", "arguments": {}}});
    let (status, mut body) = send(&fx, "/mcp", KEY, "tools/call", call, None).await;
    if let Some(obj) = body.as_object_mut() {
        obj.remove("id");
    }
    let rows: Vec<Value> = std::fs::read_to_string(&audit)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "response" && row["tool"] == "gateway_invoke")
        .map(|row| row["policy_targets"].clone())
        .collect();
    let answer = format!("{} {}", status.as_u16(), body).replace(server, "SERVER");
    (answer, rows)
}

/// FW1, a guard: the three cells answer alike, and each writes a non-empty
/// set of response rows whose `policy_targets` is exactly the gateway's own
/// target. Green on the tip: S1 records each absent name, and
/// `without_withheld` drops it from the response targets. Mutants: M10
/// (S1's `record_absent` removed: every cell keeps its own target, so the
/// pin fails while the cells still agree) and M23 (the record kept only for
/// `OutOfScope`: `ghost` keeps its target, so the cells differ).
#[tokio::test]
async fn fw1_an_absent_targets_response_is_attributed_to_the_gateway() {
    let mut answers = Vec::new();
    for server in CELLS {
        let (answer, rows) = cell(server).await;
        assert!(
            !rows.is_empty(),
            "FW1 {server}: premise: the response firewall wrote a row; answer {answer}"
        );
        for targets in &rows {
            assert_eq!(
                targets,
                &gateway_target(),
                "FW1 {server}: policy_targets contains the absent target; answer {answer}"
            );
        }
        answers.push((server, answer));
    }
    assert!(
        answers.iter().all(|(_, a)| *a == answers[0].1),
        "FW1: cells differ: {answers:?}"
    );
}
