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

/// The per-call trace ids in `raw` (`result._trace_id`, `error.data.trace_id`),
/// masked in place, so two calls compare on what they say, byte for byte.
fn without_trace(raw: &str) -> String {
    let parsed: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
    let ids = [
        &parsed["result"]["_trace_id"],
        &parsed["error"]["data"]["trace_id"],
    ];
    ids.iter()
        .filter_map(|id| id.as_str())
        .fold(raw.to_string(), |text, id| {
            text.replace(&format!("\"{id}\""), "\"<trace>\"")
        })
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

/// Call `server`'s tool `t` on `route` as key `k` with no arguments.
async fn answer(fx: &Fixture, route: Route, server: &str) -> (StatusCode, String) {
    answer_with(fx, route, server, &json!({})).await
}

/// Call `server`'s tool `t` on `route` as key `k`: the status and the raw
/// response bytes, trace ids masked and every backend name replaced by
/// [`NAME`]. Never parsed and re-serialised, so whitespace and member order
/// are compared too.
async fn answer_with(
    fx: &Fixture,
    route: Route,
    server: &str,
    arguments: &Value,
) -> (StatusCode, String) {
    let (uri, body) = match route {
        Route::Invoke => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_invoke",
                              "arguments": {"server": server, "tool": "t", "arguments": arguments}}}),
        ),
        Route::Execute => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_execute",
                              "arguments": {"chain": [{"tool": format!("{server}:t"),
                                                       "arguments": arguments}]}}}),
        ),
        Route::Direct => (
            format!("/mcp/{server}"),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "t", "arguments": arguments}}),
        ),
    };
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", "Bearer k")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let raw = String::from_utf8(bytes.to_vec()).expect("the answer is UTF-8");
    // Every backend name, not just the called one: a refusal that names
    // another backend must not split two answers that agree.
    let mut text = without_trace(&raw).replace(server, NAME);
    for name in REGISTERED.into_iter().chain([UNREGISTERED, CAPS]) {
        text = text.replace(name, NAME);
    }
    (status, text)
}

/// EMPTY.1 + EMPTY.2: on `route`, an empty grant answers both registered
/// names and the unregistered one with the grant refusal, byte for byte.
async fn assert_one_grant_refusal(route: Route) {
    // One gateway for every name, so the answers compare in one state.
    let fx = granted(&[]).await;
    let mut answers = Vec::new();
    for name in REGISTERED.into_iter().chain([UNREGISTERED]) {
        answers.push((name, answer(&fx, route, name).await));
    }
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "{route:?}: a backend was called"
    );
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
            // MIK-8387: a backend outside the scope answers as a missing one.
            assert_eq!(status, StatusCode::NOT_FOUND, "{route:?}: {body}");
            let parsed: Value = serde_json::from_str(&body).expect("the answer is JSON");
            assert_eq!(parsed["error"]["code"].as_i64(), Some(-32001), "{body}");
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

/// MIK-8387.EMPTY.4 control, in scope: a non-empty grant whose own tool
/// scope denies `alpha:t` keeps the absent-tool answer on `/mcp`. The empty
/// grant's strict refusal is for the empty grant alone.
#[tokio::test]
async fn a_non_empty_grant_refusing_a_tool_in_scope_answers_it_as_absent() {
    let mut auth = key_for_alpha(Some(vec!["t".to_string()]));
    auth.api_keys[0].name = "grant-client".to_string();
    let fx = fixture(Setup {
        auth: Some(auth),
        ..Setup::default()
    })
    .await;
    for route in [Route::Invoke, Route::Execute] {
        let (status, body) = answer(&fx, route, "alpha").await;
        assert_eq!(status, StatusCode::OK, "{route:?}: {body}");
        assert!(
            body.contains("the backend does not list a tool named `t`"),
            "{route:?}: {body}"
        );
    }
    assert_eq!(fx.calls.load(Ordering::SeqCst), 0, "alpha:t dispatched");
}

/// An empty-grant fixture with `security.sanitize_input` on, `beta`
/// re-registered `passthrough: true` and the capability backend named
/// [`CAPS`].
async fn sanitized_passthrough() -> Fixture {
    let mut auth = key_for_alpha(None);
    auth.api_keys[0].name = "grant-client".to_string();
    auth.api_keys[0].backends = Vec::new();
    let fx = fixture(Setup {
        auth: Some(auth),
        sanitize: Sanitize::On,
        ..Setup::default()
    })
    .await;
    assert!(fx.state.backends.remove("beta"), "the fixture has beta");
    let beta = Arc::new(Backend::new(
        "beta",
        BackendConfig {
            passthrough: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    beta.set_transport_for_test(Arc::new(Scripted {
        calls: Arc::clone(&fx.calls),
        lists: Arc::default(),
        extras: &[],
        error: None,
        fail: None,
        reply: None,
        notify_refused: false,
    }));
    assert!(fx.state.backends.register(beta), "beta re-registers");
    fx.state
        .meta_mcp
        .set_capabilities(Arc::new(crate::capability::CapabilityBackend::new(
            CAPS,
            Arc::new(crate::capability::CapabilityExecutor::new()),
        )));
    fx
}

/// MIK-8387.EMPTY.1 with sanitize on: a NUL in the arguments gets one answer
/// for a registered passthrough backend (`beta`), a registered plain one
/// (`alpha`), the capability name and an unregistered name. The passthrough
/// exemption must not single out `beta`; every name is sanitized alike (the
/// 400 a scoped key's absent names get, MIK-8387 N1).
async fn assert_nul_answers_every_name_alike(route: Route) {
    let nul = json!({"q": "a\u{0}b"});
    let fx = sanitized_passthrough().await;
    let mut answers = Vec::new();
    for name in ["beta", "alpha", CAPS, UNREGISTERED] {
        answers.push((name, answer_with(&fx, route, name, &nul).await));
    }
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        0,
        "{route:?}: a backend was called"
    );
    let (_, expected) = &answers[3];
    for (name, got) in &answers[..3] {
        assert_eq!(
            got, expected,
            "{route:?}: {name} differs from {UNREGISTERED}: {answers:?}"
        );
    }
    assert_eq!(
        expected.0,
        StatusCode::BAD_REQUEST,
        "{route:?}: {answers:?}",
    );
}

/// The NUL row on `/mcp` `gateway_invoke`.
#[tokio::test]
async fn a_nul_gets_one_answer_for_every_name_on_invoke() {
    assert_nul_answers_every_name_alike(Route::Invoke).await;
}

/// The NUL row on `/mcp` `gateway_execute`.
#[tokio::test]
async fn a_nul_gets_one_answer_for_every_name_on_execute() {
    assert_nul_answers_every_name_alike(Route::Execute).await;
}

/// The NUL row on `/mcp/{name}`, which sanitizes before its scope check.
#[tokio::test]
async fn a_nul_gets_one_answer_for_every_name_per_backend_route() {
    assert_nul_answers_every_name_alike(Route::Direct).await;
}

/// The Empty-only arms cannot fire for a caller with no backend scope: with
/// authentication off the caller is unscoped (as stdio's always is), so a
/// registered backend dispatches, and a passthrough one stays exempt from
/// sanitize, NUL and all.
#[tokio::test]
async fn an_unscoped_caller_is_untouched_by_the_empty_grant_arms() {
    let fx = fixture(Setup::default()).await;
    let (status, body) = answer(&fx, Route::Invoke, "alpha").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "alpha not dispatched: {body}",
    );

    let fx = fixture(Setup {
        sanitize: Sanitize::On,
        ..Setup::default()
    })
    .await;
    assert!(fx.state.backends.remove("beta"), "the fixture has beta");
    let beta = Arc::new(Backend::new(
        "beta",
        BackendConfig {
            passthrough: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    beta.set_transport_for_test(Arc::new(Scripted {
        calls: Arc::clone(&fx.calls),
        lists: Arc::default(),
        extras: &[],
        error: None,
        fail: None,
        reply: None,
        notify_refused: false,
    }));
    assert!(fx.state.backends.register(beta), "beta re-registers");
    let nul = json!({"q": "a\u{0}b"});
    let (status, body) = answer_with(&fx, Route::Invoke, "beta", &nul).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "passthrough beta was sanitized: {body}",
    );
    assert_eq!(
        fx.calls.load(Ordering::SeqCst),
        1,
        "beta not dispatched: {body}",
    );
}
