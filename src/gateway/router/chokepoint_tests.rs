// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8137 P1-route-b1: the dispatch chokepoint (design r2.2 C1'). Every
//! backend send passes one check that re-runs target authorization and the
//! request firewall on the bytes actually sent, against the policy in force at
//! dispatch, whoever asked for the send.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::{BACKENDS, code, dispatched, state_of};
use super::direct_guards_fixture::{Answer, Fx, send_with_headers};

/// `gateway_invoke read` on `/mcp` as `key`, a modern request declaring form
/// elicitation, with `extra` in the params.
async fn invoke(fx: &Fx, (key, backend): (&str, &str), extra: Value) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": backend, "tool": "read", "arguments": {}},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    send_with_headers(fx, "/mcp", key, "tools/call", params, None, &headers).await
}

/// A shell-injection argument the input scanner blocks (a High finding).
const BLOCKED: &str = "; rm -rf / ";

/// The answers to the fixture's one question, `k1`, accepting `account`.
fn answering(account: &str) -> Value {
    json!({"k1": {"action": "accept", "content": {"account": account}}})
}

/// F4: a continuation retry under an unchanged policy whose redeemed answers
/// break the request firewall is refused before its backend: the verdict the
/// first round earned is never reused on different outbound bytes. The honest
/// retry beside it still reaches the backend, so the scan refuses the answer,
/// not the retry. Mutant: the chokepoint scanning the arguments only.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f4_a_retry_whose_answers_break_the_firewall_is_refused_at_dispatch() {
    use super::direct_guards_fixture::fixture_firewalled;
    for backend in BACKENDS {
        let who = ("k-std", backend);
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = invoke(&fx, who, json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
        let (_, honest) = invoke(&fx, who, retry).await;
        assert!(honest.get("error").is_none(), "{backend}: {honest}");
        assert_eq!(dispatched(&fx), 2, "{backend}: the honest retry was sent");

        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = invoke(&fx, who, json!({})).await;
        let hostile = answering(BLOCKED);
        let retry = json!({"requestState": state_of(&asked), "inputResponses": hostile});
        let (_, refused) = invoke(&fx, who, retry).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert_eq!(dispatched(&fx), 1, "{backend}: the hostile answer was sent");
    }
}

/// F6 (lead, b1): a playbook whose own call is clean but whose step argument
/// carries a blocked pattern is refused before the step's backend. The route
/// scanned `gateway_run_playbook {name}`, never the step's arguments, which
/// come from the playbook definition. The step's error stays the neutral
/// playbook refusal (A3: a step's reason may name an operator-defined target);
/// the operator tells it apart by the one `dispatch` audit row, `source: step`.
/// Mutant: the chokepoint skipping the firewall rescan.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f6_a_playbook_step_carrying_a_blocked_pattern_is_refused_at_dispatch() {
    use super::direct_guards_fixture::{fixture_firewalled_audited, send};
    let playbook = format!(
        "name: hostile\ndescription: one step the firewall blocks\non_error: continue\n\
         steps:\n  - name: read\n    server: alpha\n    tool: read\n    arguments:\n      \
         cmd: {BLOCKED:?}\n"
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let audit = dir.path().join("audit.jsonl");
    let fx = fixture_firewalled_audited(Answer::Ok, audit.clone()).await;
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(serde_yaml::from_str(&playbook).expect("the playbook parses"));
    fx.state.meta_mcp.set_playbook_engine(engine);
    let params = json!({"name": "gateway_run_playbook", "arguments": {"name": "hostile"}});
    let (_, ran) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    let report: Value = ran["result"]["content"][0]["text"]
        .as_str()
        .and_then(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| panic!("premise: the playbook ran and reports its steps: {ran}"));
    assert_eq!(
        dispatched(&fx),
        0,
        "the blocked step reached its backend: {report}"
    );
    assert_eq!(report["steps_failed"], json!(["read"]), "{report}");
    assert_eq!(
        report["step_errors"]["read"], "step not permitted for this caller",
        "a step's refusal stays neutral (A3): {report}"
    );
    let rows = dispatch_rows(&audit);
    assert_eq!(rows.len(), 1, "one dispatch row per blocked send: {rows:?}");
    assert_eq!(
        (&rows[0]["source"], &rows[0]["action"], &rows[0]["tool"]),
        (&json!("step"), &json!("block"), &json!("read")),
        "{rows:?}"
    );
    // The row carries no caller content (gpt i1 HIGH on #3688): no fragment
    // of the argument and no argument key, only the finding's type.
    let row = rows[0].to_string();
    assert!(
        !row.contains(BLOCKED.trim()),
        "a fragment was logged: {row}"
    );
    assert!(!row.contains("cmd"), "the argument key was logged: {row}");
    let finding = &rows[0]["findings"][0];
    assert_eq!(
        (&finding["matched"], &finding["description"]),
        (&json!(""), &json!("")),
        "{row}"
    );
}

/// The chokepoint's `dispatch` rows in the firewall audit log at `path`.
#[cfg(feature = "firewall")]
fn dispatch_rows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "dispatch")
        .collect()
}

/// F7 (MIK-8226 STRARGS.SCAN.1-3, perflane): `arguments` sent as a JSON string
/// is judged as the object it parses to and is dispatched as. On
/// `gateway_invoke` and on a `gateway_execute` chain step, the string form of a
/// blocked payload is refused exactly like the object form: the same error and
/// the same route audit record (action, finding count, argument hash), and no
/// backend is reached. Base scanned the raw string and so let it through.
/// Mutant: the route target built from the raw `arguments`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f7_string_form_arguments_are_judged_as_the_object_they_dispatch() {
    use super::direct_guards_fixture::{fixture_firewalled_audited, send};
    let object = json!({"cmd": BLOCKED});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    let invoke = |arguments: &Value| {
        json!({"name": "gateway_invoke", "arguments": {
            "server": "alpha", "tool": "read", "arguments": arguments
        }})
    };
    let chain = |arguments: &Value| {
        json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": "alpha:read", "arguments": arguments}
        ]}})
    };
    for (shape, build) in [
        ("invoke", &invoke as &dyn Fn(&Value) -> Value),
        ("chain step", &chain),
    ] {
        let mut seen = Vec::new();
        for form in [&object, &stringly] {
            let dir = tempfile::tempdir().expect("tempdir");
            let audit = dir.path().join("audit.jsonl");
            let fx = fixture_firewalled_audited(Answer::Ok, audit.clone()).await;
            let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", build(form), None).await;
            assert_eq!(dispatched(&fx), 0, "{shape} {form}: sent: {body}");
            assert!(
                body.to_string().contains("Firewall blocked"),
                "{shape} {form}: refused by the firewall: {body}"
            );
            let request = request_rows(&audit)
                .into_iter()
                .find(|row| row["action"] == "block")
                .unwrap_or_else(|| panic!("{shape} {form}: a blocking request row"));
            seen.push((
                body["error"].clone(),
                request["findings_count"].clone(),
                request["args_hash"].clone(),
            ));
        }
        assert_eq!(
            seen[0], seen[1],
            "{shape}: the string form judged unlike the object form"
        );
    }
}

/// The route scan's `request` rows in the firewall audit log at `path`.
#[cfg(feature = "firewall")]
fn request_rows(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row["event"] == "request")
        .collect()
}

/// F7b (MIK-8226, lead): string-form `arguments` that parse to something other than
/// an object (an array, a number) are refused -32602 before any dispatch, on
/// `gateway_invoke` and on a chain step. They are not passed through: no gate
/// can judge a non-object as tool arguments, and a backend expects an object.
#[tokio::test]
async fn f7b_string_arguments_that_parse_to_a_non_object_are_refused() {
    use super::direct_guards_fixture::{fixture, send};
    for stringly in ["[1, 2]", "7"] {
        let invoke = json!({"name": "gateway_invoke", "arguments": {
            "server": "alpha", "tool": "read", "arguments": stringly
        }});
        let chain = json!({"name": "gateway_execute", "arguments": {"chain": [
            {"tool": "alpha:read", "arguments": stringly}
        ]}});
        for (shape, params) in [("invoke", invoke), ("chain step", chain)] {
            let fx = fixture(Answer::Ok, |_| {}).await;
            let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
            assert_eq!(dispatched(&fx), 0, "{shape} {stringly}: sent: {body}");
            assert!(
                body.to_string()
                    .contains("expected object or JSON object string"),
                "{shape} {stringly}: refused as invalid arguments: {body}"
            );
        }
    }
}
