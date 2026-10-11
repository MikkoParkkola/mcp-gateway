// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8351 (with MIK-8154 SAN.3 and MIK-8226 SCAN.4): the direct route
//! `/mcp/{name}` sends `tools/call` through the dispatch chokepoint, on the
//! bytes it sends, redeemed answers included; string-form `arguments` are the
//! object the backend receives. Test plan: lead-decisions scratch
//! secD-8351-t1.md (t1, t2).

#[cfg(feature = "firewall")]
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::dispatched;
#[cfg(feature = "firewall")]
use super::direct_continuation_tests::{BACKENDS, code, state_of};
use super::direct_guards_fixture::Answer;
#[cfg(feature = "firewall")]
use super::direct_guards_fixture::{Fx, send_with_headers};

/// A shell-injection argument the input scanner blocks (a High finding).
#[cfg(feature = "firewall")]
const BLOCKED: &str = "; rm -rf / ";

/// A modern `tools/call` of `read` on `/mcp/{backend}` as `key`, declaring
/// form elicitation, with `arguments` and `extra` in the params.
#[cfg(feature = "firewall")]
async fn direct(
    fx: &Fx,
    (key, backend): (&str, &str),
    arguments: Value,
    extra: Value,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "read",
        "arguments": arguments,
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
        ("mcp-name", "read"),
    ];
    let uri = format!("/mcp/{backend}");
    send_with_headers(fx, &uri, key, "tools/call", params, None, &headers).await
}

/// The answers to the fixture's one question, `k1`, accepting `account`.
#[cfg(feature = "firewall")]
fn answering(account: &str) -> Value {
    json!({"k1": {"action": "accept", "content": {"account": account}}})
}

/// F2d on both backend kinds (sanitized `alpha`, passthrough `alpha-pt`): an
/// honest redeemed direct retry is sent; a hostile one (clean arguments,
/// BLOCKED in the answers) is refused at the chokepoint and only the question
/// reached the backend. Red on base: the direct send skipped the chokepoint.
/// Mutants: the permit minted with `answers: None`; the answers rescan removed.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn f2d_a_redeemed_direct_retry_whose_answers_break_the_firewall_is_refused() {
    use super::direct_guards_fixture::fixture_firewalled;
    for backend in BACKENDS {
        let who = ("k-std", backend);
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
        let (_, honest) = direct(&fx, who, json!({}), retry).await;
        assert!(honest.get("error").is_none(), "{backend}: {honest}");
        assert_eq!(dispatched(&fx), 2, "{backend}: the honest retry was sent");

        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, json!({}), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering(BLOCKED)});
        let (_, refused) = direct(&fx, who, json!({}), retry).await;
        assert_eq!(code(&refused), Some(-32600), "{backend}: {refused}");
        assert_eq!(dispatched(&fx), 1, "{backend}: the hostile answer was sent");
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

/// SCAN.4 (MIK-8226): on `/mcp/{name}`, `arguments` sent as a JSON string
/// carrying a blocked payload is refused exactly like the object form: the
/// same error and the same route `request` record (action, finding count,
/// argument hash), and no backend is reached. Red on base: the entry scan
/// pattern-scans objects only, so the string went through.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_string_form_direct_arguments_are_judged_as_their_object() {
    use super::direct_guards_fixture::fixture_firewalled_audited;
    let object = json!({"cmd": BLOCKED});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    let mut seen = Vec::new();
    for form in [&object, &stringly] {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit = dir.path().join("audit.jsonl");
        let fx = fixture_firewalled_audited(Answer::Ok, audit.clone()).await;
        let (_, body) = direct(&fx, ("k-std", "alpha"), form.clone(), json!({})).await;
        assert_eq!(dispatched(&fx), 0, "{form}: sent: {body}");
        let request = request_rows(&audit)
            .into_iter()
            .find(|row| row["action"] == "block")
            .unwrap_or_else(|| panic!("{form}: a blocking request row; {body}"));
        seen.push((
            body["error"].clone(),
            request["findings_count"].clone(),
            request["args_hash"].clone(),
        ));
    }
    assert_eq!(
        seen[0], seen[1],
        "the string form was judged unlike the object form"
    );
}

/// SCAN.4-clean (kills "scan the parse, forward the string"): a clean
/// string-form `arguments` on a sanitized and a passthrough backend is sent
/// once, and the backend receives the parsed object, not the string. Red on
/// base: the string was forwarded as sent.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_a_clean_string_form_call_reaches_the_backend_as_its_object() {
    use super::direct_guards_fixture::fixture_firewalled;
    let object = json!({"q": "x"});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    for backend in BACKENDS {
        let fx = fixture_firewalled(Answer::Ok).await;
        let (_, body) = direct(&fx, ("k-std", backend), stringly.clone(), json!({})).await;
        assert!(body.get("error").is_none(), "{backend}: {body}");
        assert_eq!(dispatched(&fx), 1, "{backend}: sent once");
        let sent = fx.seen.lock().expect("seen lock").last().cloned();
        assert_eq!(
            sent.as_ref().map(|params| &params["arguments"]),
            Some(&object),
            "{backend}: the backend did not receive the parsed object: {sent:?}"
        );
    }
}

/// SCAN.4-retry: a clean string-form retry's redeemed send carries the parsed
/// object too, on both backend kinds.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn scan4_a_clean_string_form_retry_is_sent_as_its_object() {
    use super::direct_guards_fixture::fixture_firewalled;
    let object = json!({"q": "x"});
    let stringly = json!(serde_json::to_string(&object).expect("serializes"));
    for backend in BACKENDS {
        let who = ("k-std", backend);
        let fx = fixture_firewalled(Answer::AskOnce).await;
        let (_, asked) = direct(&fx, who, stringly.clone(), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answering("work")});
        let (_, answered) = direct(&fx, who, stringly.clone(), retry).await;
        assert!(answered.get("error").is_none(), "{backend}: {answered}");
        let sent = fx.seen.lock().expect("seen lock").last().cloned();
        assert_eq!(
            sent.as_ref().map(|params| &params["arguments"]),
            Some(&object),
            "{backend}: the redeemed send did not carry the parsed object: {sent:?}"
        );
    }
}

/// F7b-direct: string-form `arguments` parsing to a non-object (an array, a
/// number) are refused -32602 before anything is sent, as on the meta route.
#[tokio::test]
async fn f7b_direct_string_arguments_that_parse_to_a_non_object_are_refused() {
    use super::direct_guards_fixture::{fixture, send};
    for stringly in ["[1, 2]", "7"] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let params = json!({"name": "read", "arguments": stringly});
        let (_, body) = send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None).await;
        assert_eq!(dispatched(&fx), 0, "{stringly}: sent: {body}");
        assert_eq!(body["error"]["code"], -32602, "{stringly}: {body}");
    }
}

/// Absent `arguments` (guard and hostile pin): a clean call with no
/// `arguments` is sent unchanged; one carrying a blocked pattern in another
/// params field is refused at entry, because with no `arguments` the entry
/// scan judges the whole params (backend_handlers.rs:96). Mutant: absent
/// arguments judged as `{}`.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn absent_direct_arguments_keep_the_whole_params_scan() {
    use super::direct_guards_fixture::{fixture_firewalled, send};
    let fx = fixture_firewalled(Answer::Ok).await;
    let (_, clean) = send(
        &fx,
        "/mcp/alpha",
        "k-std",
        "tools/call",
        json!({"name": "read"}),
        None,
    )
    .await;
    assert!(clean.get("error").is_none(), "clean: {clean}");
    assert_eq!(dispatched(&fx), 1, "clean: sent once");

    let fx = fixture_firewalled(Answer::Ok).await;
    let hostile = json!({"name": "read", "note": BLOCKED});
    let (_, refused) = send(&fx, "/mcp/alpha", "k-std", "tools/call", hostile, None).await;
    assert_eq!(dispatched(&fx), 0, "hostile: sent: {refused}");
    assert!(
        refused.to_string().contains("Firewall blocked"),
        "hostile: refused by the entry scan: {refused}"
    );
}

/// A `tools/call` spelled in another letter case is refused -32601 and never
/// forwarded: the only door to a backend for a tool call is the one that
/// takes the chokepoint's permit (upgrading.d/8351.md). Red on base: the
/// variant was forwarded unchecked.
#[tokio::test]
async fn a_case_variant_tools_call_is_refused_not_forwarded() {
    use super::direct_guards_fixture::{fixture, send};
    for method in ["TOOLS/CALL", "Tools/Call"] {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let params = json!({"name": "read", "arguments": {}});
        let (_, body) = send(&fx, "/mcp/alpha", "k-std", method, params, None).await;
        assert_eq!(dispatched(&fx), 0, "{method}: forwarded: {body}");
        assert_eq!(body["error"]["code"], -32601, "{method}: {body}");
    }
}

/// Guard (grok t1): a non-call method is not a tool send, so it takes no
/// permit and no dispatch rescan; a blocked pattern in `ping` params is still
/// forwarded, as before. The send count, not the absence of a dispatch row,
/// is the oracle: an allowed send writes no dispatch row either.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_non_call_method_is_forwarded_without_a_permit() {
    use super::direct_guards_fixture::{fixture_firewalled, send};
    let fx = fixture_firewalled(Answer::Ok).await;
    let params = json!({"note": BLOCKED});
    let (_, body) = send(&fx, "/mcp/alpha", "k-std", "ping", params, None).await;
    assert_eq!(dispatched(&fx), 1, "ping was not forwarded: {body}");
}
