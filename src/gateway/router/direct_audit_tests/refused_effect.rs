// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A refusal the gateway decides records `response_effect: refused` even when
//! the frame it sends carries no refusal marker: an absent-name answer for a
//! denied tool, a gate's error on the meta route.

use super::*;

/// The one delivery record in the log.
fn only_attempt(fx: &Fixture) -> Value {
    let all: Vec<Value> = std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect();
    let [one] = all.as_slice() else {
        panic!("expected one delivery attempt: {all:?}");
    };
    one.clone()
}

/// A tool the key denies answers as an absent name: the gateway refused it.
#[tokio::test]
async fn a_denied_direct_delivery_records_refused() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Key).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "premise: an absent-name answer: {body}"
    );
    let event = only_attempt(&fx);
    assert_eq!(event["response_effect"], "refused", "{event}");
}

/// Response inspection in action mode refuses a planted key, on both routes,
/// and the refusal keeps the finding that blocked it.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn an_inspection_refusal_records_refused() {
    let key = ["AKIA", "IOSFODNN7", "EXAMPLE"].concat();
    let reply = json!({"content": [{"type": "text", "text": format!("AWS_ACCESS_KEY_ID={key}")}],
                       "isError": false});
    let invoke = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": "alpha", "tool": "t", "arguments": {}}}})
    .to_string();
    for (uri, call) in [("/mcp", invoke), ("/mcp/alpha", tools_call("t"))] {
        let fx = fixture(Setup {
            reply: Some(reply.clone()),
            meta_mode: MetaMode::InspectionBlocks,
            ..Setup::default()
        })
        .await;
        let (_, body) = post_to(&fx, uri, &call, &Caller::Anonymous).await;
        assert!(
            !body.to_string().contains(&key),
            "{uri}: premise: withheld: {body}"
        );
        let event = only_attempt(&fx);
        assert_eq!(event["response_effect"], "refused", "{uri}: {event}");
        let findings = event["response_findings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            findings.iter().any(|f| f["kind"] == "inspect:secret"
                && f["severity"] == "critical"
                && f["where"] == "result"),
            "{uri}: the blocking finding is kept: {event}"
        );
        assert!(
            !event.to_string().contains(&key),
            "{uri}: no content: {event}"
        );
    }
}

/// A fail-closed response contract refuses the answer on the meta route; the
/// error it renders carries no refusal marker.
#[tokio::test]
async fn a_contract_refusal_records_refused() {
    let fx = fixture(Setup {
        meta_mode: MetaMode::ContractRefuses,
        ..Setup::default()
    })
    .await;
    let invoke = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": "alpha", "tool": "t", "arguments": {}}}});
    let (_, body) = post_to(&fx, "/mcp", &invoke.to_string(), &Caller::Anonymous).await;
    assert!(body.get("error").is_some(), "premise: refused: {body}");
    let event = only_attempt(&fx);
    assert_eq!(event["response_effect"], "refused", "{event}");
}

/// A call refused with a 403 (here an agent identity the gateway requires
/// and the call lacks) is classed `denied` by its status: the gateway
/// refused it. A 429 is not: its outcome is an error, not a refusal.
#[tokio::test]
async fn a_forbidden_direct_call_records_refused() {
    let fx = fixture(Setup {
        agent_identity: Some(crate::config::AgentIdentityConfig {
            enabled: true,
            require_id: true,
            known_agents: vec![],
            ..Default::default()
        }),
        ..Setup::default()
    })
    .await;
    let (status, body) = post(&fx, "alpha", &tools_call("t"), &Caller::Anonymous).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "premise: {body}");
    let event = only_attempt(&fx);
    assert_eq!(event["response_effect"], "refused", "{event}");
}

/// A `gateway_invoke` of a tool the key denies is answered on `/mcp` as an
/// absent name: the gateway refused it, and the record says so.
#[tokio::test]
async fn a_withheld_meta_target_records_refused() {
    let fx = fixture(Setup {
        auth: Some(key_for_alpha(Some(vec!["t".to_string()]))),
        ..Setup::default()
    })
    .await;
    let invoke = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": "alpha", "tool": "t", "arguments": {}}}});
    let (status, body) = post_to(&fx, "/mcp", &invoke.to_string(), &Caller::Key).await;
    assert_eq!(status, StatusCode::OK, "premise: {body}");
    assert_eq!(body["result"]["isError"], true, "premise: absent: {body}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "premise: never dispatched"
    );
    let event = only_attempt(&fx);
    assert_eq!(event["response_effect"], "refused", "{event}");
}
