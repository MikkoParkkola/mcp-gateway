// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7407.RESPONSE.5 on the direct route (MIK-7669): `POST /mcp/{name}` gets
//! the counted fixtures the meta route and stdio have. Each served `tools/call`
//! and `tools/list` answer, blocked or allowed, is inspected once by the
//! router's instance and never by the Meta-MCP's, and it writes one delivery
//! record whose hash is the body the client received. The policy-target rows
//! prove the rule is resolved against the call's own target: the same rule
//! keyed on another target does not apply.

use super::{CANARY, TOOL, Wired, inspections, listing_state, post};
use crate::security::TransparencyLogger;
use crate::security::firewall::{FirewallAction, FirewallRule};
use crate::security::transparency_log::TransparencyLogConfig;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;

/// A listing with credential material in it, which the default (High) blocks.
fn leaky() -> String {
    format!("echo; uses token {CANARY}")
}

fn rule(tool_match: &str, action: FirewallAction) -> FirewallRule {
    FirewallRule {
        tool_match: tool_match.to_string(),
        action,
        reason: Some("direct counted fixture".to_string()),
        scan: Vec::new(),
    }
}

/// The split wiring with a transparency log on the router's state, where the
/// direct route writes its delivery record.
struct Logged {
    wired: Wired,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

async fn logged(description: String, rules: Vec<FirewallRule>) -> Logged {
    let mut wired = listing_state(description, rules).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("audit.jsonl");
    let log = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "direct-counted".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    Arc::get_mut(&mut wired.0)
        .expect("state is unique")
        .transparency_log = Some(Arc::new(log));
    Logged {
        wired,
        path,
        _dir: dir,
    }
}

impl Logged {
    /// POST `body` to the direct route; the answer and the router and
    /// Meta-MCP inspections it cost.
    async fn send(&self, body: &Value) -> (Value, (usize, usize)) {
        let (state, handler, meta, _) = &self.wired;
        let before = (inspections(handler), inspections(meta));
        let (_status, answer) = post(state, "/mcp/demo", &[], body).await;
        let after = (inspections(handler), inspections(meta));
        (answer, (after.0 - before.0, after.1 - before.1))
    }

    fn deliveries(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
            .filter(|r| r["event"] == "response_delivery_attempt")
            .collect()
    }

    /// The answer's delivery record: exactly one, written after `seen`
    /// earlier ones, hashing the body served.
    fn assert_recorded(&self, seen: usize, answer: &Value) {
        let all = self.deliveries();
        assert_eq!(all.len(), seen + 1, "one record per answer: {all:#?}");
        let hash = format!("sha256:{}", crate::hashing::canonical_json_sha256(answer));
        assert_eq!(all[seen]["response_hash"], hash.as_str(), "{:#}", all[seen]);
    }
}

fn direct_call(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": TOOL, "arguments": {}}})
}

fn direct_list(id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/list"})
}

/// A refusal: an error, no result, and none of the content it withheld.
fn assert_withheld(what: &str, answer: &Value) {
    assert!(answer.get("error").is_some(), "{what}: refused: {answer}");
    assert!(
        answer.get("result").is_none_or(Value::is_null),
        "{what}: no result: {answer}"
    );
    assert!(
        !answer.to_string().contains(CANARY),
        "{what}: credential leaked: {answer}"
    );
}

/// Served, with the credential redacted out of it.
fn assert_served_clean(what: &str, answer: &Value) {
    assert!(answer.get("error").is_none(), "{what}: served: {answer}");
    assert!(answer.get("result").is_some(), "{what}: a result: {answer}");
    assert!(
        !answer.to_string().contains(CANARY),
        "{what}: not redacted: {answer}"
    );
}

/// Negative: with no rule, the default (High) refuses the call whose result
/// carries a credential and the listing that does, each inspected once by the
/// router and recorded once.
#[tokio::test]
async fn direct_refuses_blocked_responses_with_one_inspection() {
    // The call's tool is listed clean: only its result carries the credential.
    let rows = [
        ("call", "echo".to_string(), direct_call(1)),
        ("list", leaky(), direct_list(2)),
    ];
    for (what, description, body) in rows {
        let fx = logged(description, Vec::new()).await;
        let (answer, counts) = fx.send(&body).await;
        assert_withheld(what, &answer);
        assert_eq!(
            counts,
            (1, 0),
            "{what}: one router inspection, none on meta"
        );
        fx.assert_recorded(0, &answer);
    }
}

/// Positive: a rule allowing the called tool serves the call redacted, a clean
/// listing is served, and a Warn rule on the listing target serves the leaky
/// listing redacted; each inspected once by the router and recorded once.
#[tokio::test]
async fn direct_serves_allowed_responses_with_one_inspection() {
    let fx = logged("echo".to_string(), vec![rule(TOOL, FirewallAction::Allow)]).await;
    let (answer, counts) = fx.send(&direct_call(1)).await;
    assert_served_clean("allowed call", &answer);
    assert_eq!(counts, (1, 0), "allowed call: one router inspection");
    fx.assert_recorded(0, &answer);

    let fx = logged("echo".to_string(), Vec::new()).await;
    let (answer, counts) = fx.send(&direct_list(2)).await;
    assert_served_clean("clean list", &answer);
    assert_eq!(counts, (1, 0), "clean list: one router inspection");
    fx.assert_recorded(0, &answer);

    let fx = logged(leaky(), vec![rule("tools/list", FirewallAction::Warn)]).await;
    let (answer, counts) = fx.send(&direct_list(3)).await;
    assert_served_clean("warned list", &answer);
    assert_eq!(counts, (1, 0), "warned list: one router inspection");
    fx.assert_recorded(0, &answer);
}

/// Policy-target falsifiers: the rules that served the positive rows, keyed on
/// a target the answer does not have, do not apply, so the default refuses.
/// A route that resolved its policy on anything but the call's own target
/// (the method, the server, any rule) would serve these.
#[tokio::test]
async fn direct_policy_applies_only_to_the_answer_target() {
    let fx = logged(
        "echo".to_string(),
        vec![rule("zeta_echo", FirewallAction::Allow)],
    )
    .await;
    let (answer, counts) = fx.send(&direct_call(1)).await;
    assert_withheld("call under another tool's Allow", &answer);
    assert_eq!(counts, (1, 0));

    let fx = logged(leaky(), vec![rule(TOOL, FirewallAction::Warn)]).await;
    let (answer, counts) = fx.send(&direct_list(2)).await;
    assert_withheld("list under a tool's Warn", &answer);
    assert_eq!(counts, (1, 0));
}
