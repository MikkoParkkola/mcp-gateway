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
/// The capability backend's name, registered by the capability-name row.
const CAPS: &str = "caps";
/// What every backend name is replaced with before answers are compared.
const NAME: &str = "<backend>";
/// The grant refusal's own words (auth.rs `backend_refusal`).
const NO_GRANT: &str = "has no backends granted";
/// The whole documented grant refusal for `grant-client`, written out so a
/// change to `backend_refusal` cannot move the answer and the pin together.
const GRANT_REFUSAL: &str = "Client 'grant-client' has no backends granted: an empty \
     `backends` list reaches none (docs/UPGRADING-4.0.md section 32)";

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

/// Drop the per-call trace id (`result.trace_id`, `error.data.trace_id`),
/// so two calls compare on what they say.
fn without_trace(body: &mut Value) {
    if let Some(result) = body.get_mut("result").and_then(Value::as_object_mut) {
        result.remove("trace_id");
    }
    if let Some(data) = body
        .get_mut("error")
        .and_then(|error| error.get_mut("data"))
        .and_then(Value::as_object_mut)
    {
        data.remove("trace_id");
    }
}

/// `body` is the grant refusal, exactly: code -32003 and the whole message.
fn assert_grant_refusal(context: &str, (status, body): &(StatusCode, String)) {
    assert_eq!(*status, StatusCode::FORBIDDEN, "{context}: {body}");
    let parsed: Value = serde_json::from_str(body).expect("the answer is JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32003),
        "{context}: {body}"
    );
    assert_eq!(
        parsed["error"]["message"].as_str(),
        Some(GRANT_REFUSAL),
        "{context}: {body}"
    );
}

/// Call `server`'s tool `t` on `route` as key `k`: the status and the body,
/// trace ids dropped and every backend name replaced by [`NAME`].
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
    // Every backend name, not just the called one: a refusal that names
    // another backend must not split two answers that agree.
    let mut text = body.to_string().replace(server, NAME);
    for name in REGISTERED.into_iter().chain([UNREGISTERED, CAPS]) {
        text = text.replace(name, NAME);
    }
    (status, text)
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
        assert_eq!(
            got, expected,
            "{route:?}: {name} differs from {UNREGISTERED}"
        );
    }
    assert_grant_refusal(&format!("{route:?}"), expected);
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

/// MIK-8387.EMPTY.4 control: a non-empty grant keeps its own answers on
/// every route. The granted backend dispatches, and a registered one outside
/// the grant reaches no backend and never gets the empty-grant message; on
/// `/mcp` it is answered as an absent tool.
#[tokio::test]
async fn a_non_empty_grant_is_untouched_by_the_empty_grant_answer() {
    for route in [Route::Invoke, Route::Execute, Route::Direct] {
        let fx = granted(&["alpha"]).await;
        let (status, body) = answer(&fx, route, "alpha").await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            1,
            "{route:?}: alpha not dispatched: {body}"
        );

        let fx = granted(&["alpha"]).await;
        let (status, body) = answer(&fx, route, "beta").await;
        assert!(!body.contains(NO_GRANT), "{route:?}: {body}");
        if matches!(route, Route::Direct) {
            // The direct route's scope refusal, before any lookup.
            assert_eq!(status, StatusCode::FORBIDDEN, "{route:?}: {body}");
            let parsed: Value = serde_json::from_str(&body).expect("the answer is JSON");
            assert_eq!(parsed["error"]["code"].as_i64(), Some(-32003), "{body}");
        } else {
            assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
            assert!(
                body.contains("the backend does not list a tool named `t`"),
                "{route:?}: {body}"
            );
        }
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "{route:?}: beta dispatched: {body}"
        );
    }
}

/// MIK-8387.EMPTY.1, capability backend: its name is registered too, so an
/// empty grant answers it on `route` with the grant refusal an unregistered
/// name gets, never the capability's `ToolNotFound`.
async fn assert_capability_name_answers_as_an_unregistered_one(route: Route) {
    let fx = granted(&[]).await;
    fx.state
        .meta_mcp
        .set_capabilities(Arc::new(crate::capability::CapabilityBackend::new(
            CAPS,
            Arc::new(crate::capability::CapabilityExecutor::new()),
        )));
    let caps = answer(&fx, route, CAPS).await;
    let nosuch = answer(&fx, route, UNREGISTERED).await;
    assert_eq!(
        caps, nosuch,
        "{route:?}: {CAPS} differs from {UNREGISTERED}"
    );
    assert_grant_refusal(&format!("{route:?} {CAPS}"), &caps);
}

/// MIK-8387.EMPTY.1, capability name, `/mcp` `gateway_invoke`.
#[tokio::test]
async fn capability_name_answers_as_an_unregistered_one_on_invoke() {
    assert_capability_name_answers_as_an_unregistered_one(Route::Invoke).await;
}

/// MIK-8387.EMPTY.1, capability name, `/mcp` `gateway_execute`.
#[tokio::test]
async fn capability_name_answers_as_an_unregistered_one_on_execute() {
    assert_capability_name_answers_as_an_unregistered_one(Route::Execute).await;
}
