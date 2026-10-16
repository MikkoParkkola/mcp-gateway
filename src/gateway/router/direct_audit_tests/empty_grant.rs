// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8441: a key whose `backends` grant is empty reaches no backend, so a
//! registered name and an unregistered one get one answer on every route:
//! the documented grant refusal (403, -32003, docs/UPGRADING-4.0.md section
//! 32). It is decided before any backend lookup, so it says nothing about
//! which backends exist (lead ruling on MIK-8387.EMPTY.2).

use super::*;

/// Registered in the fixture.
const REGISTERED: [&str; 2] = ["alpha", "beta"];
/// Never registered.
const UNREGISTERED: &str = "nosuch";
/// What every backend name is replaced with before answers are compared.
const NAME: &str = "<backend>";
/// The grant refusal's own words (auth.rs `backend_refusal`).
const NO_GRANT: &str = "has no backends granted";

/// The route a row calls `server`'s tool `t` on.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// `/mcp`, `gateway_invoke`.
    Invoke,
    /// `/mcp`, `gateway_execute` with a one-step chain.
    Execute,
    /// `/mcp/{server}`, `tools/call`.
    Direct,
}

/// One key, `k`, named so it holds no backend name, granted `backends`.
async fn granted(backends: &[&str]) -> Fixture {
    let mut auth = key_for_alpha(None);
    auth.api_keys[0].name = "grant-client".to_string();
    auth.api_keys[0].backends = backends.iter().map(ToString::to_string).collect();
    fixture(Setup {
        auth: Some(auth),
        ..Setup::default()
    })
    .await
}

/// Drop every trace id, so two calls compare on what they say.
fn without_trace(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| !key.to_ascii_lowercase().contains("trace"));
            map.values_mut().for_each(without_trace);
        }
        Value::Array(items) => items.iter_mut().for_each(without_trace),
        _ => {}
    }
}

/// Call `server`'s tool `t` on `route` as key `k`: the status and the body,
/// trace ids dropped and `server` replaced by [`NAME`].
async fn answer(fx: &Fixture, route: Route, server: &str) -> (StatusCode, String) {
    let (uri, body) = match route {
        Route::Invoke => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_invoke",
                              "arguments": {"server": server, "tool": "t", "arguments": {}}}}),
        ),
        Route::Execute => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_execute",
                              "arguments": {"chain": [{"tool": format!("{server}:t"),
                                                       "arguments": {}}]}}}),
        ),
        Route::Direct => (
            format!("/mcp/{server}"),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "t", "arguments": {}}}),
        ),
    };
    let (status, mut body) = post_to(fx, &uri, &body.to_string(), &Caller::Key).await;
    without_trace(&mut body);
    (status, body.to_string().replace(server, NAME))
}

/// EMPTY.1 + EMPTY.2: on `route`, an empty grant answers both registered
/// names and the unregistered one with the grant refusal, byte for byte.
async fn assert_one_grant_refusal(route: Route) {
    let mut answers = Vec::new();
    for name in REGISTERED.into_iter().chain([UNREGISTERED]) {
        let fx = granted(&[]).await;
        answers.push((name, answer(&fx, route, name).await));
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "{route:?} {name}: a backend was called"
        );
    }
    let (_, expected) = &answers[2];
    for (name, got) in &answers[..2] {
        assert_eq!(got, expected, "{route:?}: {name} differs from {UNREGISTERED}");
    }
    let (status, body) = expected;
    assert_eq!(*status, StatusCode::FORBIDDEN, "{route:?}: {body}");
    assert!(body.contains("-32003"), "{route:?}: {body}");
    assert!(body.contains(NO_GRANT), "{route:?}: {body}");
}

/// MIK-8387.EMPTY.1 on `/mcp` `gateway_invoke`.
#[tokio::test]
async fn empty_grant_answers_every_name_alike_on_invoke() {
    assert_one_grant_refusal(Route::Invoke).await;
}

/// MIK-8387.EMPTY.1 on `/mcp` `gateway_execute`, the chain form.
#[tokio::test]
async fn empty_grant_answers_every_name_alike_on_execute() {
    assert_one_grant_refusal(Route::Execute).await;
}

/// MIK-8387.EMPTY.1 on the direct route `/mcp/{name}`.
#[tokio::test]
async fn empty_grant_answers_every_name_alike_on_the_direct_route() {
    assert_one_grant_refusal(Route::Direct).await;
}

/// MIK-8387.EMPTY.4 control: a non-empty grant keeps its own answers. The
/// granted backend dispatches, and a registered one outside the grant is
/// answered as an absent tool on `/mcp`, never with the empty-grant message.
#[tokio::test]
async fn a_non_empty_grant_is_untouched_by_the_empty_grant_answer() {
    let fx = granted(&["alpha"]).await;
    let (status, body) = answer(&fx, Route::Invoke, "alpha").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "alpha not dispatched: {body}"
    );

    let fx = granted(&["alpha"]).await;
    let (status, body) = answer(&fx, Route::Invoke, "beta").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.contains("the backend does not list a tool named `t`"),
        "{body}"
    );
    assert!(!body.contains(NO_GRANT), "{body}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "beta dispatched: {body}"
    );
}
