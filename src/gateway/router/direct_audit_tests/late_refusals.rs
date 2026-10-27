// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Gateway refusals met after the route stage: the relay block before a call
//! is sent, and the refusals of a backend's answer after it was (an unchained
//! answer under `require`, a question the caller never declared). Each
//! answers the caller with a refusal, so each records `refused`.

use super::*;

/// Ordinary prose, long enough for the relay detector's fingerprints.
const PROSE: &str = "The orchard ledger for the north slope records seven rows of late pears, \
    the grafting dates for each rootstock, the hours the drip lines ran during the dry weeks of \
    August, and which crew pruned the older trees after the second frost. It closes with the \
    count of crates sent to the cooperative press and a note about the broken ladder by the barn.";

/// The delivery records in the log.
fn attempts(fx: &Fixture) -> Vec<Value> {
    std::fs::read_to_string(&fx.path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["event"] == "response_delivery_attempt")
        .collect()
}

/// The last delivery record, which must state `refused`.
fn assert_last_refused(fx: &Fixture) {
    let all = attempts(fx);
    let last = all.last().unwrap_or_else(|| panic!("no delivery record"));
    assert_eq!(last["response_effect"], "refused", "{all:?}");
}

fn invoke(id: u64, arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "t", "arguments": arguments}}})
    .to_string()
}

/// A modern call to `alpha:t` declaring no input capability, on `/mcp` or
/// the direct route.
fn undeclaring(route: &str) -> (&'static str, String) {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {"name": "LateRefusals", "version": "1.0.0"}
    });
    let (uri, params) = if route == "meta" {
        (
            "/mcp",
            json!({"name": "gateway_invoke", "_meta": meta,
                   "arguments": {"server": "alpha", "tool": "t", "arguments": {}}}),
        )
    } else {
        (
            "/mcp/alpha",
            json!({"name": "t", "_meta": meta, "arguments": {}}),
        )
    };
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params});
    (uri, body.to_string())
}

/// The backend's question: an elicitation the caller did not declare.
fn question() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {
            "method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
        }},
        "requestState": "backend-state",
        "content": [{"type": "text", "text": "a question"}]
    })
}

/// Site 1: relay detection blocks a `/mcp` call carrying text another caller
/// was delivered, before it is sent.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_relay_block_on_meta_records_refused() {
    let fx = fixture(Setup {
        reply: Some(json!({"content": [{"type": "text", "text": PROSE}], "isError": false})),
        tenant_limit: Some(0),
        relay: Relay::On,
        ..Setup::default()
    })
    .await;
    let (_, first) = post_to(&fx, "/mcp", &invoke(4, &json!({})), &Caller::Oidc).await;
    assert!(first.get("result").is_some(), "premise: delivered: {first}");
    let relayed = invoke(5, &json!({"note": PROSE}));
    let (_, body) = post_to(&fx, "/mcp", &relayed, &Caller::Anonymous).await;
    assert_eq!(
        body["error"]["code"], -32002,
        "premise: relay block: {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: never sent");
    assert_last_refused(&fx);
}

/// Site 7: under `require`, the gateway refuses the backend's unchained
/// answer after the call was sent.
#[tokio::test]
async fn an_unchained_answer_refused_on_meta_records_refused() {
    let fx = fixture(Setup {
        chain: crate::config::ChainMode::Require,
        ..Setup::default()
    })
    .await;
    let (status, body) = post_to(&fx, "/mcp", &invoke(5, &json!({})), &Caller::Anonymous).await;
    assert!(
        body.get("error").is_some(),
        "premise: refused: {status} {body}"
    );
    assert_eq!(fx.calls.load(Ordering::SeqCst), 1, "premise: sent once");
    assert_last_refused(&fx);
}

/// Sites 8 and 10: the backend asks a question the caller never declared it
/// could answer; the gateway refuses it after the call was sent.
#[tokio::test]
async fn an_undeclared_question_records_refused_on_both_routes() {
    for route in ["meta", "direct"] {
        let fx = fixture(Setup {
            reply: Some(question()),
            ..Setup::default()
        })
        .await;
        let (uri, body) = undeclaring(route);
        let (status, answer) = post_modern_as(&fx, uri, &body, &Caller::ModernOidc).await;
        assert!(
            answer.get("error").is_some(),
            "{route} premise: refused: {status} {answer}"
        );
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{route} premise: sent once"
        );
        assert_last_refused(&fx);
    }
}
