// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387: a key whose `backends` scope excludes a name gets the answer an
//! unregistered name gets, on every route, so its answers do not reveal which
//! backends exist (design r1, D1). Three names per row: `ghost` is in the
//! key's scope and not registered, `beta` is registered and out of scope,
//! `nosuch` is neither. Answers are compared with the name factored out.

use super::*;

/// In the key's scope, never registered.
const GHOST: &str = "ghost";
/// Registered, outside the key's scope.
const WITHHELD: &str = "beta";
/// Not registered, outside the key's scope.
const NOSUCH: &str = "nosuch";
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
    /// `/mcp/{server}`, `tools/call`.
    Direct,
}

/// Call `server`'s tool `t` on `route` as the scoped key: the HTTP status and
/// the body, with `server` replaced by [`NAME`] wherever it appears.
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
    let (status, value) = post_to(fx, &uri, &body.to_string(), &Caller::Key).await;
    (status, value.to_string().replace(server, NAME))
}

/// The three answers on `route` must be one answer. The control first: the
/// key's own registered backend is served, so three equal refusals cannot
/// come from a route that refuses everything.
async fn assert_one_answer(meta_mode: fn() -> MetaMode, route: Route) {
    let control_fx = scoped_fixture(meta_mode()).await;
    let (status, control) = answer(&control_fx, route, "alpha").await;
    assert_eq!(status, StatusCode::OK, "control on {route:?}: {control}");
    assert!(
        !control.contains("\"error\"") && !control.contains("\"isError\":true"),
        "control on {route:?} was refused: {control}"
    );
    let mut answers = Vec::new();
    for name in [GHOST, WITHHELD, NOSUCH] {
        // A fresh fixture per name: no state from one call reaches the next.
        let fx = scoped_fixture(meta_mode()).await;
        answers.push((name, answer(&fx, route, name).await));
    }
    let (_, first) = &answers[0];
    for (name, other) in &answers[1..] {
        assert_eq!(
            other, first,
            "{route:?}: `{name}` answers differently from `{GHOST}` (in scope, unregistered), \
             so a scoped key can tell which backends exist: {answers:?}"
        );
    }
}

/// MIK-8387.ORACLE.1/.3, `/mcp` `gateway_invoke`.
#[tokio::test]
async fn o1_invoke_answers_an_unreachable_backend_as_an_absent_one() {
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
/// scope check runs before the lookup, direct_caller.rs D2-b); a mutant that
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
