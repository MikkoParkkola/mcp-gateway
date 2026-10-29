// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Secret injection under a root rule, end to end (R41, R41b, R41c, I8): a
//! secret rule that owns a declared path argument, or an ancestor of one,
//! refuses the call before injection rewrites what was checked, whatever
//! the credential resolves to. The injected value is never logged.
//! Batch 5e.

use serde_json::{Value, json};

use super::allowed_root_routes::{Routes, Setup};

const SENTINEL: &str = "SENTINEL-8939-secret";

fn invoke(arguments: Value) -> Value {
    json!({"name": "gateway_invoke", "arguments": {
        "server": "fs", "tool": "read_file", "arguments": arguments}})
}

fn refused_as_injected(routes: &Routes, row: &str, answer: &Value) {
    let text = answer.to_string();
    assert!(
        answer.get("error").is_some() || answer["result"]["isError"] == json!(true),
        "{row}: refused: {text}"
    );
    assert!(
        text.contains("injected_path_argument"),
        "{row}: names the code: {text}"
    );
    assert!(
        routes.received().is_empty(),
        "{row}: the backend saw a call"
    );
    for place in [text, routes.audited(), routes.received()] {
        assert!(
            !place.contains(SENTINEL),
            "{row}: the injected value leaked: {place}"
        );
    }
}

/// R41, I8: a secret owning `path` refuses the call, with an empty
/// credential (which deletes the caller's value) and with a real one.
#[tokio::test]
async fn r41_secret_owning_the_path_argument_refuses() {
    for (row, value) in [("R41 empty", ""), ("R41 sentinel", SENTINEL)] {
        let routes = Routes::build(Setup {
            secret_key: Some("path"),
            secret_value: value,
            ..Setup::default()
        })
        .await;
        let inside = routes.path("safe/f");
        let answer = routes
            .post("/mcp", "tools/call", invoke(json!({"path": inside})))
            .await;
        refused_as_injected(&routes, row, &answer);
    }
}

/// R41b: a secret owning `a` while `a.b` is a declared path argument
/// refuses: injection would drop or replace the whole object.
#[tokio::test]
async fn r41b_secret_owning_an_ancestor_refuses() {
    let routes = Routes::build(Setup {
        path_args: "\"a.b?\"",
        secret_key: Some("a"),
        secret_value: SENTINEL,
        ..Setup::default()
    })
    .await;
    let inside = routes.path("safe/f");
    let answer = routes
        .post("/mcp", "tools/call", invoke(json!({"a": {"b": inside}})))
        .await;
    refused_as_injected(&routes, "R41b", &answer);
}

/// R41c: a secret owning `token` leaves an inside call to pass, as checked.
#[tokio::test]
async fn r41c_secret_owning_another_key_passes() {
    let routes = Routes::build(Setup {
        secret_key: Some("token"),
        secret_value: SENTINEL,
        ..Setup::default()
    })
    .await;
    let inside = routes.path("safe/f");
    let answer = routes
        .post("/mcp", "tools/call", invoke(json!({"path": inside})))
        .await;
    assert!(answer.get("error").is_none(), "R41c: allowed: {answer}");
    let sent = serde_json::to_string(&inside).expect("a path serialises");
    assert!(
        routes.received().contains(&sent),
        "R41c: {}",
        routes.received()
    );
    assert!(
        !routes.audited().contains(SENTINEL),
        "R41c: the injected value was audited"
    );
}
