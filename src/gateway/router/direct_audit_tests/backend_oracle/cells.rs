// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 d5 rows that vary the key or the registry, on one request each:
//! O2s, O5, K1(a), N1, F1, U1, V1 and the rest of O3m.

use super::*;

/// `name` as the fixture builds its backends, with `config`, counting its
/// calls in `calls`.
pub(super) fn scripted(
    name: &str,
    config: BackendConfig,
    calls: &Arc<AtomicUsize>,
) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    backend.set_transport_for_test(Arc::new(Scripted {
        calls: Arc::clone(calls),
        lists: Arc::default(),
        extras: &[],
        error: None,
        fail: None,
        reply: None,
        notify_refused: false,
    }));
    backend
}

/// The three cells' answers on `route`, each from its own fixture.
async fn cells<F, Fut>(
    route: Route,
    make: F,
    arguments: &Value,
) -> Vec<(&'static str, (StatusCode, String))>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Fixture>,
{
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = make().await;
        answers.push((name, answer_with(&fx, route, name, arguments).await));
    }
    answers
}

/// O2s (d4): single-call `gateway_execute {tool}` answers exactly as
/// `gateway_invoke` does, for all three cells.
#[tokio::test]
async fn o2s_single_call_execute_answers_an_unreachable_backend_as_an_absent_one() {
    assert_one_answer(|| MetaMode::CodeMode, Route::ExecuteSingle).await;
}

/// O5 (d3, GPT F1): a tool-restricted key (`allowed_tools: ["alpha:t"]`).
/// At the tip `ghost:t` meets the client tool-scope check (-32600) while
/// `beta`/`nosuch` meet the backend scope.
#[tokio::test]
async fn o5_a_tool_restricted_key_answers_an_unreachable_backend_as_an_absent_one() {
    let make = || {
        let mut auth = scoped_key();
        auth.api_keys[0].allowed_tools = Some(vec!["alpha:t".to_string()]);
        fixture(Setup {
            auth: Some(auth),
            ..Setup::default()
        })
    };
    assert_one_answer_in(Route::Invoke, make, &json!({})).await;
}

/// K1(a) (design r2, GPT-2): `beta` kill-switched. The kill switch is read
/// by name after the gate (`dispatch_tools_call.rs:461`), so it must not give
/// `beta` an answer the absent names do not get.
#[tokio::test]
async fn k1a_a_kill_switched_backend_answers_as_an_absent_one() {
    let make = || async {
        let fx = scoped_fixture(MetaMode::Plain).await;
        fx.state.meta_mcp.kill_switch().kill(WITHHELD);
        fx
    };
    assert_one_answer_in(Route::Invoke, make, &json!({})).await;
}

/// N1 (d2, GPT-1): sanitize on, and `beta` is `passthrough: true`, so at
/// the tip a NUL in its arguments skips sanitize and reaches the scope
/// answer, while `nosuch` and `ghost` are refused by sanitize (400). The
/// exemption must be judged through the caller's scope. Both routes; every
/// route's cells are collected before any assertion, so one route's answer
/// cannot hide the other's.
#[tokio::test]
async fn n1_a_passthrough_backend_outside_the_scope_is_sanitized_as_an_absent_one() {
    let make = || async {
        let fx = fixture(Setup {
            auth: Some(scoped_key()),
            sanitize: Sanitize::On,
            ..Setup::default()
        })
        .await;
        assert!(fx.state.backends.remove(WITHHELD), "fixture has beta");
        let config = BackendConfig {
            passthrough: true,
            ..BackendConfig::default()
        };
        assert!(
            fx.state
                .backends
                .register(scripted(WITHHELD, config, &fx.calls))
        );
        fx
    };
    let nul = json!({"q": "a\u{0}b"});
    let mut by_route = Vec::new();
    for route in [Route::Direct, Route::Invoke] {
        let control_fx = make().await;
        let (status, control) = answer(&control_fx, route, "alpha").await;
        assert_eq!(status, StatusCode::OK, "control on {route:?}: {control}");
        by_route.push((route, cells(route, make, &nul).await));
    }
    for (route, answers) in &by_route {
        assert_cells_equal(&format!("N1 {route:?} (all routes: {by_route:?})"), answers);
        assert_eq!(
            answers[0].1.0,
            StatusCode::BAD_REQUEST,
            "N1 {route:?}: {answers:?}"
        );
    }
}

/// F1 (new): the log fails closed and its next append fails. The three cells
/// must still answer alike: at the tip `nosuch` reaches `refused.answer` and
/// answers 503 while `ghost` answers the miss.
#[tokio::test]
async fn f1_a_failing_log_answers_every_unreachable_backend_alike() {
    let make = || async {
        let fx = fixture(Setup {
            auth: Some(scoped_key()),
            fail_closed: true,
            ..Setup::default()
        })
        .await;
        fx.log.fail_next_append_for_test();
        fx
    };
    for route in [Route::Invoke, Route::Direct] {
        let answers = cells(route, make, &json!({})).await;
        assert_cells_equal(&format!("F1 {route:?}"), &answers);
        let (status, body) = &answers[0].1;
        assert_eq!(
            *status,
            StatusCode::SERVICE_UNAVAILABLE,
            "F1 {route:?}: {answers:?}"
        );
        let body: Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(body["error"]["code"], -32005, "F1 {route:?}: {answers:?}");
    }
}

/// U1 (narrowing guard): a `*` key keeps today's deep answer for a name that
/// is not registered: the dispatch's `isError` result with `_recovery`, not
/// the gate's early miss.
#[tokio::test]
async fn u1_an_unscoped_key_keeps_the_deep_miss_for_an_unregistered_name() {
    for name in [GHOST, NOSUCH] {
        let mut auth = key_for_alpha(None);
        auth.api_keys[0].backends = vec!["*".to_string()];
        let fx = fixture(Setup {
            auth: Some(auth),
            ..Setup::default()
        })
        .await;
        let (status, body) = answer(&fx, Route::Invoke, name).await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
        assert!(
            body.contains("_recovery") && body.contains("Backend not found"),
            "U1 {name}: the unscoped deep miss changed: {body}"
        );
    }
}

/// V1 (guard against the r3 regression, muse HIGH 1): search never lists a
/// backend outside the key's scope, even with its tools cached.
#[tokio::test]
async fn v1_search_never_lists_a_backend_outside_the_scope() {
    let fx = scoped_fixture(MetaMode::Plain).await;
    let listed = [json!({"name": "t", "description": "Reads a record.",
                         "inputSchema": {"type": "object"}})];
    for name in ["alpha", WITHHELD] {
        let backend = fx.state.backends.get(name).expect("fixture backend");
        backend.remember_listed_tools(None, false, &listed);
    }
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "gateway_search_tools",
                                 "arguments": {"query": "record"}}});
    let (status, value) = post_to(&fx, "/mcp", &body.to_string(), &Caller::Key).await;
    let text = value.to_string();
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(
        text.contains("alpha"),
        "control: the key's own backend is found: {text}"
    );
    assert!(
        !text.contains(WITHHELD),
        "V1: search listed `{WITHHELD}`: {text}"
    );
}

/// O3m, d5 (§2a cell 15): `tasks/get` on `/mcp/{X}` passes the same
/// envelope check as every other method.
#[tokio::test]
async fn o3m_direct_tasks_get_answers_as_an_absent_one() {
    // No control: `tasks/get` of a task no one made is refused on `alpha` too.
    let route = Route::DirectMethod("tasks/get");
    let answers = cells(route, || scoped_fixture(MetaMode::Plain), &json!({})).await;
    assert_cells_equal("O3m tasks/get", &answers);
    assert_eq!(Some(answers[0].1.clone()), pinned(route), "O3m tasks/get");
}

/// POST `body` to `uri` as key `k` on the 2026-07-28 revision, with the
/// headers that revision requires, so only the route's own checks answer.
async fn post_keyed_direct(fx: &Fixture, uri: &str, body: &str) -> (StatusCode, Value) {
    let mut call: Value = serde_json::from_str(body).unwrap();
    let meta = &mut call["params"]["_meta"];
    meta["io.modelcontextprotocol/protocolVersion"] =
        json!(crate::protocol::meta::MODERN_VERSIONS[0]);
    meta["io.modelcontextprotocol/clientCapabilities"] = json!({});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(
            "mcp-protocol-version",
            crate::protocol::meta::MODERN_VERSIONS[0],
        )
        .header("authorization", "Bearer k")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "t")
        .body(axum::body::Body::from(call.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// O3m, d5 (§2a cell 15), keyed half: a keyed `tools/call` sent twice on
/// `/mcp/{X}` answers the miss both times, never reaching
/// `idempotency_outcome` (`direct_dispatch.rs:257`).
#[tokio::test]
async fn o3m_a_keyed_direct_retry_answers_as_an_absent_one() {
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = scoped_fixture(MetaMode::Idempotent).await;
        let call = direct_call("tenant-a", Some("k-8387-o3m"));
        let uri = format!("/mcp/{name}");
        let first = post_keyed_direct(&fx, &uri, &call).await;
        let second = post_keyed_direct(&fx, &uri, &call).await;
        let masked =
            |(status, value): (StatusCode, Value)| (status, masked(&value.to_string(), name));
        let (first, second) = (masked(first), masked(second));
        assert_eq!(
            first, second,
            "O3m keyed retry, {name}: the retry answered otherwise"
        );
        answers.push((name, second));
    }
    assert_cells_equal("O3m keyed retry", &answers);
    assert_eq!(
        answers[0].1.0,
        StatusCode::NOT_FOUND,
        "O3m keyed retry: {answers:?}"
    );
}
