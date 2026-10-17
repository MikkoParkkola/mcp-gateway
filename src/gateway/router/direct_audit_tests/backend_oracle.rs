// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387: a key whose `backends` scope excludes a name gets the answer an
//! unregistered name gets, on every route, so its answers do not reveal which
//! backends exist (design r1, D1). Three names per row: `ghost` is in the
//! key's scope and not registered, `beta` is registered and out of scope,
//! `nosuch` is neither. Answers are compared with the name factored out.

use super::*;

mod cells;
mod gaps;
mod keyed;
#[cfg(feature = "firewall")]
mod reload;
mod resume;
mod tasks;

/// In the key's scope, never registered.
const GHOST: &str = "ghost";
/// Registered, outside the key's scope.
const WITHHELD: &str = "beta";
/// Not registered, outside the key's scope.
const NOSUCH: &str = "nosuch";
/// The absent-tool text every pin builds on, written out so a change to
/// `text_absent` cannot move the answers and the pins together (O1 ties the
/// helper to it).
const ABSENT_T: &str = "the backend does not list a tool named `t`";
/// What every name is replaced with before two answers are compared.
const NAME: &str = "<backend>";

/// `alpha-client` (bearer `k`), scoped to `alpha` and the unregistered `ghost`.
fn scoped_key() -> AuthConfig {
    let mut auth = key_for_alpha(None);
    auth.api_keys[0].backends = vec!["alpha".to_string(), GHOST.to_string()];
    auth
}

async fn scoped_fixture(meta_mode: MetaMode) -> Fixture {
    fixture(Setup {
        auth: Some(scoped_key()),
        meta_mode,
        ..Setup::default()
    })
    .await
}

/// The route a row calls `server`'s tool `t` on.
#[derive(Clone, Copy, Debug)]
enum Route {
    /// `/mcp`, `gateway_invoke`.
    Invoke,
    /// `/mcp`, `gateway_execute` with a one-step chain.
    Execute,
    /// `/mcp`, `gateway_execute` with a single `{tool}`: delegated straight
    /// to `invoke_tool` (`search.rs:460`), never through `step_failure`.
    ExecuteSingle,
    /// `/mcp/{server}`, `tools/call`.
    Direct,
    /// `/mcp/{server}`, another method (MIK-8387 r2 F4): the envelope's scope
    /// check runs for every method.
    DirectMethod(&'static str),
    /// `/mcp`, `prompts/get` of `server/p`.
    MetaPrompt,
    /// `/mcp`, `gateway_list_tools` of `server`.
    MetaList,
}

/// Call `server`'s tool `t` on `route` as the scoped key: the HTTP status and
/// the body, with `server` replaced by [`NAME`] wherever it appears.
async fn answer(fx: &Fixture, route: Route, server: &str) -> (StatusCode, String) {
    answer_with(fx, route, server, &json!({})).await
}

/// [`answer`], with `arguments` as the tool's arguments.
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
        Route::ExecuteSingle => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_execute",
                              "arguments": {"tool": format!("{server}:t"),
                                            "arguments": arguments}}}),
        ),
        Route::Direct => (
            format!("/mcp/{server}"),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "t", "arguments": arguments}}),
        ),
        Route::DirectMethod(method) => (
            format!("/mcp/{server}"),
            json!({"jsonrpc": "2.0", "id": 7, "method": method,
                   "params": direct_params(method)}),
        ),
        Route::MetaList => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": "gateway_list_tools", "arguments": {"server": server}}}),
        ),
        Route::MetaPrompt => (
            "/mcp".to_string(),
            json!({"jsonrpc": "2.0", "id": 7, "method": "prompts/get",
                   "params": {"name": format!("{server}/p")}}),
        ),
    };
    let (status, value) = post_to(fx, &uri, &body.to_string(), &Caller::Key).await;
    (status, masked(&value.to_string(), server))
}

/// The params a direct `method` row sends.
fn direct_params(method: &str) -> Value {
    match method {
        "prompts/get" => json!({"name": "p"}),
        "resources/read" => json!({"uri": "file:///r"}),
        "tasks/get" => json!({"taskId": "task-8387"}),
        _ => json!({}),
    }
}

/// `text` with the gateway's version, then `server`, then every trace id
/// masked. The version first: `4.0.0-beta.3` holds the name `beta`.
fn masked(text: &str, server: &str) -> String {
    let text = text.replace(env!("CARGO_PKG_VERSION"), "<version>");
    mask_trace_ids(&text.replace(server, NAME))
}

/// A modern `/mcp` answer as JSON: the `data:` line of a one-event stream
/// (the client offered `text/event-stream`), or the body itself.
fn sse_or_json(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let json = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap_or(&text);
    serde_json::from_str(json).unwrap_or(Value::Null)
}

/// Replace every per-call trace id (`gw-` and a 36-character UUID) with one
/// placeholder: two calls never share one, so it is no part of the answer a
/// row compares.
fn mask_trace_ids(text: &str) -> String {
    static TRACE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new("gw-[0-9a-fA-F-]{36}").expect("trace id pattern")
    });
    TRACE.replace_all(text, "gw-<trace>").into_owned()
}

/// The one answer every absent name gets on `route`, with the name replaced
/// by [`NAME`] (design d6, lead ruling on step 1b): on `/mcp` it is the answer
/// a registered backend outside the scope (`beta`) gets at 1577d7ff6, so the
/// fix makes `ghost` and `nosuch` answer as `beta` does; on the direct route
/// and `prompts/get` it is today's backend miss. `None`: a guard row, no pin.
fn pinned(route: Route) -> Option<(StatusCode, String)> {
    let absent = ABSENT_T;
    let wrapped = json!({"id": 7, "jsonrpc": "2.0", "result": {"content": [{
        "text": serde_json::to_string_pretty(
            &json!({"content": [{"text": absent, "type": "text"}], "isError": true}),
        ).expect("JSON"),
        "type": "text"}], "isError": true}});
    let miss = |id: Value| {
        json!({"error": {"code": -32001, "message": format!("Backend not found: {NAME}")},
               "id": id, "jsonrpc": "2.0"})
        .to_string()
    };
    Some(match route {
        Route::Invoke | Route::ExecuteSingle => (StatusCode::OK, wrapped.to_string()),
        Route::Execute => (
            StatusCode::OK,
            json!({"error": {"code": -32603, "message": format!(
                       "JSON-RPC error -32603: Chain step 0 ({NAME}:t) failed: {absent}")},
                   "id": 7, "jsonrpc": "2.0"})
            .to_string(),
        ),
        Route::Direct | Route::DirectMethod(_) => (StatusCode::NOT_FOUND, miss(Value::Null)),
        Route::MetaPrompt => (StatusCode::OK, miss(json!(7))),
        Route::MetaList => return None,
    })
}

/// The three answers on `route` must be one answer. The control first: the
/// key's own registered backend is served, so three equal refusals cannot
/// come from a route that refuses everything.
async fn assert_one_answer(meta_mode: fn() -> MetaMode, route: Route) {
    assert_one_answer_in(route, || scoped_fixture(meta_mode()), &json!({})).await;
}

/// [`assert_one_answer`] over fixtures `make` builds, calling with
/// `arguments`: one fixture per name, so no state from one call reaches the
/// next; then the pinned answer, so three cells that agree on a wrong
/// answer cannot pass.
async fn assert_one_answer_in<F, Fut>(route: Route, make: F, arguments: &Value)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Fixture>,
{
    let control_fx = make().await;
    let (status, control) = answer_with(&control_fx, route, "alpha", arguments).await;
    assert_eq!(status, StatusCode::OK, "control on {route:?}: {control}");
    assert!(
        !control.contains("\"error\"") && !control.contains("\"isError\":true"),
        "control on {route:?} was refused: {control}"
    );
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        let fx = make().await;
        answers.push((name, answer_with(&fx, route, name, arguments).await));
        assert_eq!(
            fx.calls.load(Ordering::SeqCst),
            0,
            "{route:?}: `{name}` was dispatched"
        );
    }
    assert_cells_equal(&format!("{route:?}"), &answers);
    if let Some(pin) = pinned(route) {
        assert_eq!(
            answers[0].1, pin,
            "{route:?}: the cells agree on an unpinned answer"
        );
    }
}

/// Every cell's answer equals the first's.
fn assert_cells_equal<T: PartialEq + std::fmt::Debug>(row: &str, answers: &[(&str, T)]) {
    let (_, first) = &answers[0];
    for (name, other) in &answers[1..] {
        assert_eq!(
            other, first,
            "{row}: `{name}` answers differently from `{GHOST}` (in scope, unregistered), \
             so a scoped key can tell which backends exist: {answers:?}"
        );
    }
}

/// MIK-8387.ORACLE.1/.3, `/mcp` `gateway_invoke`.
#[tokio::test]
async fn o1_invoke_answers_an_unreachable_backend_as_an_absent_one() {
    // The pins are written from `ABSENT_T`; the production text must match.
    assert_eq!(crate::backend::text_absent("t"), ABSENT_T);
    assert_one_answer(|| MetaMode::Plain, Route::Invoke).await;
}

/// MIK-8387.ORACLE.1/.3, `/mcp` `gateway_execute` (one-step chain).
#[tokio::test]
async fn o2_execute_answers_an_unreachable_backend_as_an_absent_one() {
    assert_one_answer(|| MetaMode::CodeMode, Route::Execute).await;
}

/// MIK-8387.ORACLE.1/.3, the direct route `/mcp/{name}`.
#[tokio::test]
async fn o3_direct_answers_an_unreachable_backend_as_an_absent_one() {
    assert_one_answer(|| MetaMode::Plain, Route::Direct).await;
}

/// MIK-8387.ORACLE.4: a verified caller (the scoped API key) on `/mcp/{name}`
/// gets byte-identical answers for a backend that does not exist and for a
/// registered backend withheld from it. Green on the tip by construction (the
/// scope check runs before the lookup, `direct_caller.rs` D2-b); a mutant that
/// moves it after the lookup must turn this row red.
#[tokio::test]
async fn o4_direct_missing_and_withheld_backends_answer_alike_for_a_verified_caller() {
    let missing_fx = scoped_fixture(MetaMode::Plain).await;
    let missing = answer(&missing_fx, Route::Direct, NOSUCH).await;
    let withheld_fx = scoped_fixture(MetaMode::Plain).await;
    let withheld = answer(&withheld_fx, Route::Direct, WITHHELD).await;
    assert_eq!(
        missing, withheld,
        "a verified caller tells a missing backend from a withheld one on /mcp/{{name}}"
    );
    assert_eq!(
        withheld_fx.calls.load(Ordering::SeqCst),
        0,
        "the withheld backend was dispatched"
    );
}

/// MIK-8387.ORACLE.2: the wire hides why, the record does not. Each
/// out-of-scope call writes one `denied` record carrying the scope refusal's
/// code, whatever the caller was told.
#[tokio::test]
async fn a1_the_record_keeps_the_scope_refusal_for_every_out_of_scope_name() {
    for route in [Route::Invoke, Route::Direct] {
        for name in [WITHHELD, NOSUCH] {
            let fx = scoped_fixture(MetaMode::Plain).await;
            let _ = answer(&fx, route, name).await;
            let entry = only_invocation(&fx);
            assert_eq!(entry["outcome"], "denied", "{route:?} {name}: {entry}");
            assert_eq!(entry["error_code"], -32003, "{route:?} {name}: {entry}");
            assert_eq!(entry["server"], name, "{route:?} {name}: {entry}");
        }
    }
}

/// MIK-8387.ORACLE.1 (r2 F4): every method on `/mcp/{name}` passes the same
/// envelope scope check, so each has the same split.
#[tokio::test]
async fn o3m_every_direct_method_answers_an_unreachable_backend_as_an_absent_one() {
    for method in ["tools/list", "prompts/get", "resources/read"] {
        assert_one_answer(|| MetaMode::Plain, Route::DirectMethod(method)).await;
    }
}

/// MIK-8387 D7: `/mcp` `prompts/get` of `server/p` checks scope first, then
/// looks the backend up, so it has the same split.
#[tokio::test]
async fn p1_meta_prompt_answers_an_unreachable_backend_as_an_absent_one() {
    assert_one_answer(|| MetaMode::Plain, Route::MetaPrompt).await;
}

/// The ticket that owns the empty-grant split (lead ruling on MIK-8387 stop 2).
const EMPTY_GRANT_TICKET: &str = "MIK-8441";

/// The answers an empty-grant key (`backends: []`) gets on `route` for
/// `alpha` (registered), `beta` (registered) and `nosuch` (unregistered).
async fn empty_grant_answers(route: Route) -> Vec<(&'static str, (StatusCode, String))> {
    let mut answers = Vec::new();
    for name in ["alpha", WITHHELD, NOSUCH] {
        let mut auth = key_for_alpha(None);
        auth.api_keys[0].backends = Vec::new();
        // No backend name inside the key's name: the answer replaces it.
        auth.api_keys[0].name = "grant-client".to_string();
        let fx = fixture(Setup {
            auth: Some(auth),
            ..Setup::default()
        })
        .await;
        answers.push((name, answer(&fx, route, name).await));
    }
    answers
}

/// MIK-8387.EMPTY.3 (flipped by [`EMPTY_GRANT_TICKET`]): on `/mcp` an empty
/// grant answers a registered name as it answers an unregistered one, with
/// the grant message (UPGRADING-4.0 section 32), decided before any lookup.
#[tokio::test]
async fn e1_an_empty_grant_answers_every_mcp_name_alike_with_its_grant_message() {
    let answers = empty_grant_answers(Route::Invoke).await;
    assert_cells_equal("Invoke, empty grant", &answers);
    // The exact pin `empty_grant.rs` holds, so the two cannot drift.
    let (status, body) = &answers[0].1;
    assert_eq!(
        *status,
        StatusCode::FORBIDDEN,
        "{EMPTY_GRANT_TICKET}: {body}",
    );
    let parsed: Value = serde_json::from_str(body).expect("the answer is JSON");
    assert_eq!(
        parsed["error"]["code"].as_i64(),
        Some(-32003),
        "{EMPTY_GRANT_TICKET}: {body}"
    );
    assert_eq!(
        parsed["error"]["message"].as_str(),
        Some(
            "Client 'grant-client' has no backends granted: an empty `backends` list \
             reaches none (docs/UPGRADING-4.0.md section 32)"
        ),
        "{EMPTY_GRANT_TICKET}: {body}"
    );
}

/// MIK-8387 D2, direct route: a key with `backends: []` reaches nothing, so
/// every name gets the one grant message, which names no backend and keeps
/// its upgrade pointer. Guards that PR-A leaves the envelope branch alone.
#[tokio::test]
async fn e1_an_empty_grant_answers_every_direct_name_alike_with_its_grant_message() {
    let answers = empty_grant_answers(Route::Direct).await;
    assert!(
        answers[0].1.1.contains("has no backends granted"),
        "the empty-grant message is gone: {answers:?}"
    );
    assert_cells_equal("Direct, empty grant", &answers);
}

/// MIK-8387 D7 regression guard: `gateway_list_tools` already answers a
/// backend outside the scope as an absent one (A3, `search.rs:475-480`).
#[tokio::test]
async fn l1_listing_already_answers_an_unreachable_backend_as_an_absent_one() {
    assert_one_answer(|| MetaMode::Plain, Route::MetaList).await;
}
