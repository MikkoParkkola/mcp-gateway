// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3, C9: HTTP `/mcp` `tools/call` of a surfaced tool on
//! a managed-account backend whose caller slot is cold, where the caller's
//! first `tools/list` gets HTTP 401. The managed-401 recovery runs exactly
//! once, the answer is a failed backend (never the unknown-name -32601), and
//! no `tools/call` is sent.
//!
//! The caller is the sole operator of a `single_user` HTTP deployment (the
//! managed-account fixture behind the real router and auth middleware, as
//! `direct_sole_operator_tests`). The shared slot holds the tool with a valid
//! schema, so the call is not refused before the caller's slot is reached.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::config::{ApiKeyConfig, AuthConfig, SurfacedToolConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway, PERSONAL_BACKEND, Second,
};
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

const OPERATOR_KEY: &str = "sole-operator-key";
const TOOL: &str = "read";

fn sole_operator() -> AuthConfig {
    operator_granted(&["*"])
}

/// The sole operator, whose key grants only `backends`.
fn operator_granted(backends: &[&str]) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(OPERATOR_KEY.as_bytes())),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: backends.iter().map(|b| (*b).to_string()).collect(),
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
            ..Default::default()
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

struct Fx {
    router: axum::Router,
    /// The Meta-MCP the router serves (its kill switch, MIK-8439).
    meta: Arc<crate::gateway::meta_mcp::MetaMcp>,
    /// The router's state (its task store, MIK-8439 R7).
    state: Arc<super::AppState>,
    dirs: (tempfile::TempDir, crate::gateway::router::tests::FixtureDir),
    /// Last: it owns the Meta-MCP's audit log, which must outlive every
    /// field above that holds the logger.
    gateway: DirectAccountGateway,
}

/// The router over the sole operator's managed backend, [`TOOL`] surfaced,
/// the shared slot warm with a valid [`TOOL`] and the operator's slot cold.
async fn fixture() -> Fx {
    fixture_with(&Binding::Connected).await
}

/// [`fixture`] with the operator's grant in state `binding`.
async fn fixture_with(binding: &Binding) -> Fx {
    fixture_armed(binding, |_| {}).await
}

/// [`fixture_with`], `arm` applied to the Meta-MCP before it is shared.
async fn fixture_armed(
    binding: &Binding,
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Fx {
    fixture_for(sole_operator(), binding, arm).await
}

/// [`fixture_armed`] for the operator `auth` describes.
async fn fixture_for(
    auth: AuthConfig,
    binding: &Binding,
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Fx {
    let gateway = DirectAccountGateway::new(auth.clone(), binding);
    fixture_on(gateway, &auth, &[(BACKEND, TOOL)], arm).await
}

/// The router over `gateway`, [`TOOL`] surfaced on each of `surfaced`, each
/// one's shared slot warm with a valid [`TOOL`] and the operator's slots cold.
async fn fixture_on(
    mut gateway: DirectAccountGateway,
    auth: &AuthConfig,
    surfaced: &[(&str, &str)],
    arm: impl FnOnce(&mut crate::gateway::meta_mcp::MetaMcp),
) -> Fx {
    let audit = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: audit
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "8356-c9".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    let (mut state, store) = super::tests::test_router_app_state_with_auth(auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway.take_meta().with_surfaced_tools(
        surfaced
            .iter()
            .map(|(server, tool)| SurfacedToolConfig {
                server: (*server).to_string(),
                tool: (*tool).to_string(),
            })
            .collect(),
    );
    meta.enable_transparency_log(Arc::clone(&log));
    arm(&mut meta);
    let meta = Arc::new(meta);
    state_mut.meta_mcp = Arc::clone(&meta);
    state_mut.transparency_log = Some(log);
    for (server, tool) in surfaced {
        let tool: crate::protocol::Tool = serde_json::from_value(json!({
            "name": tool, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
        }))
        .expect("a tool");
        gateway
            .backends()
            .get(server)
            .expect("the backend")
            .store_shared_tools_for_test(vec![tool]);
    }
    Fx {
        router: create_router(Arc::clone(&state)),
        gateway,
        meta,
        state,
        dirs: (audit, store),
    }
}

async fn call(fx: &Fx) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"folder": "inbox"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// C9 (absence): the cold caller slot's first `tools/list` gets 401. The
/// managed-401 recovery runs exactly once (custody's forced-refresh count),
/// nothing is dispatched, and the answer is not the unknown-name -32601.
/// The premise call proves the fixture reaches the operator's slot first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c9_per_user_cold_caller_managed_401_recovers() {
    let control = fixture().await;
    let answer = call(&control).await;
    assert_eq!(
        control.gateway.tool_calls().len(),
        1,
        "premise: the sole operator's cold-slot call did not dispatch: {answer}"
    );

    let fx = fixture().await;
    fx.gateway.answer_lists_with(&[401]);
    let (refreshes, sent) = (fx.gateway.refreshes(), fx.gateway.tool_calls().len());
    let answer = call(&fx).await;
    assert_eq!(
        fx.gateway.refreshes(),
        refreshes + 1,
        "C9: the managed-401 recovery did not run exactly once: {answer}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "C9: dispatched after a refused fill: {answer}"
    );
    assert_ne!(
        answer.pointer("/error/code"),
        Some(&json!(-32601)),
        "C9: a failed fill answered as an unknown name: {answer}"
    );
}

async fn rpc(fx: &Fx, id: u64, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Whether the surfaced [`TOOL`] in `tools/list` carries the shared slot's
/// schema B (a `folder` property) rather than the fill's schema A.
async fn listed_schema_has_folder(fx: &Fx, id: u64) -> bool {
    let answer = rpc(fx, id, "tools/list", json!({})).await;
    let entry = answer
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .and_then(|tools| tools.iter().find(|t| t["name"] == TOOL))
        .unwrap_or_else(|| panic!("premise: tools/list surfaces {TOOL}: {answer}"));
    entry.pointer("/inputSchema/properties/folder").is_some()
}

/// A rotated grant's slot is never a listing view (HTTP). The operator's slot
/// is warmed by a real `gateway_list_tools` fill (schema A, no properties);
/// the shared slot holds schema B. After the grant rotates the old slot is
/// still warm and indexed, but `tools/list` must not serve it: the now-cold
/// caller's view is re-established under the current grant, a fresh fill on a
/// slot of its own, and never the shared view B. RED without the
/// recheck.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_list_never_serves_a_rotated_grants_slot_http() {
    let fx = fixture().await;
    let filled = rpc(
        &fx,
        1,
        "tools/call",
        json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
    )
    .await;
    let old = DirectAccountGateway::operator_binding();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: a real fill warmed the operator's slot: {filled}"
    );
    assert!(
        !listed_schema_has_folder(&fx, 2).await,
        "premise: before rotation tools/list serves the caller's slot (schema A)"
    );
    fx.gateway.rotate_operator_grant().await;
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: rotation leaves the old slot warm, so this is the listing's check"
    );
    // The rotated grant selects a new slot: attach its upstream there.
    let binding = fx
        .state
        .meta_mcp
        .account_strategies()
        .managed_vault(Some("work-gmail"))
        .expect("the managed vault")
        .view_binding(crate::personal_accounts::identity::Principal::SoleOperator)
        .await
        .expect("premise: the rotated grant has a view");
    assert_ne!(binding, old, "premise: rotation selects a new slot");
    fx.gateway.rearm_operator_slot_at_for_test(&binding);
    let fills = fx.gateway.lists_to(BACKEND);
    assert!(
        !listed_schema_has_folder(&fx, 3).await,
        "tools/list served the shared view B to a backend with per-user sessions only"
    );
    assert_eq!(
        fx.gateway.lists_to(BACKEND),
        fills + 1,
        "the rotated caller's view was not re-established by a fresh fill"
    );
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .iter()
            .any(|binding| *binding != old),
        "the fresh fill did not land on the current grant's own slot"
    );
}

/// The first line of `initialize`'s greeting: "This server manages {count}
/// across {n} backends."
async fn greeting_count(fx: &Fx, id: u64) -> String {
    let params = json!({"protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "mik-8356", "version": "1"}});
    let answer = rpc(fx, id, "initialize", params).await;
    answer
        .pointer("/result/instructions")
        .and_then(Value::as_str)
        .and_then(|text| text.lines().next())
        .unwrap_or_else(|| panic!("premise: initialize carries a greeting: {answer}"))
        .to_owned()
}

/// A rotated grant's slot never feeds `initialize`'s count (HTTP; lead
/// ruling 2026-10-11). A count read from it tells the caller how many tools
/// the old grant had. After the rotation the caller is cold, so its count is
/// the cold rule's (SLOTVIS.6: the per-user backend contributes nothing),
/// the same greeting a caller whose slot was never filled gets. RED without
/// the initialize recheck.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initialize_never_counts_a_rotated_grants_slot_http() {
    let cold = greeting_count(&fixture().await, 1).await;
    let fx = fixture().await;
    let filled = rpc(
        &fx,
        1,
        "tools/call",
        json!({"name": "gateway_list_tools", "arguments": {"server": BACKEND}}),
    )
    .await;
    let warm = greeting_count(&fx, 2).await;
    assert_ne!(
        warm, cold,
        "premise: the warm slot's count differs from the cold rule's: {filled}"
    );
    fx.gateway.rotate_operator_grant().await;
    let old = DirectAccountGateway::operator_binding();
    let backend = fx.gateway.backends().get(BACKEND).expect("the backend");
    assert!(
        backend
            .populated_per_user_bindings_for_test()
            .contains(&old),
        "premise: rotation leaves the old slot warm, so this is initialize's check"
    );
    assert_eq!(
        greeting_count(&fx, 3).await,
        cold,
        "initialize counted the rotated grant's stale slot"
    );
}

/// Whether the sole operator's plain `tools/list` shows the surfaced [`TOOL`].
async fn lists_tool(fx: &Fx, id: u64) -> bool {
    let answer = rpc(fx, id, "tools/list", json!({})).await;
    answer
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t["name"] == TOOL))
}

/// L9-managed (lead ruling 2026-10-11, design R3.7): the sole operator of a
/// managed-account backend with no current grant has no view of it, so its
/// plain `tools/list` does not show the backend's surfaced tool, though the
/// shared slot holds it. The cold rule's shared view is for a caller whose
/// own slot is merely not loaded yet (control: the connected operator, cold,
/// is shown it). RED before `NoView`: the shared entry is shown to both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tools_list_hides_the_surfaced_tool_from_an_operator_with_no_grant() {
    let connected = fixture().await;
    assert!(
        lists_tool(&connected, 1).await,
        "premise: the connected operator, cold, is shown the shared surfaced entry"
    );
    let unconnected = fixture_with(&Binding::Unconnected).await;
    assert!(
        !lists_tool(&unconnected, 2).await,
        "L9-managed: an operator with no grant is shown the surfaced tool"
    );
}

/// `gateway_invoke` of `tool` on [`BACKEND`] as the sole operator.
async fn invoke_named(fx: &Fx, id: u64, tool: &str) -> Value {
    rpc(
        fx,
        id,
        "tools/call",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": tool, "arguments": {"folder": "inbox"}}}),
    )
    .await
}

/// L9-managed call (lead ruling 2026-10-11; design R3.7; MIK-6745 consent
/// journey section 9.2): the sole operator of a managed-account backend with
/// no current grant has no view of it.
/// - By surfaced name, which names no backend, the call answers -32601,
///   exactly as an unknown name: no connect offer, nothing dispatched.
/// - Through `gateway_invoke` naming the backend, the account's connect
///   offer is the answer (predicate D), and it is the same for the surfaced
///   tool and for a name the backend does not have: the offer tells the
///   operator about its own account, never about the tool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_grant_operator_call_by_name_is_absent_and_invoke_offer_ignores_the_tool() {
    let fx = fixture_with(&Binding::Unconnected).await;
    let by_name = rpc(
        &fx,
        1,
        "tools/call",
        json!({"name": TOOL, "arguments": {"folder": "inbox"}}),
    )
    .await;
    let unknown = rpc(
        &fx,
        2,
        "tools/call",
        json!({"name": "no_such_tool", "arguments": {"folder": "inbox"}}),
    )
    .await;
    assert_eq!(
        by_name.pointer("/error/code"),
        Some(&json!(-32601)),
        "L9-managed call: the surfaced name is not answered as absent: {by_name}"
    );
    assert_eq!(
        by_name.pointer("/error/code"),
        unknown.pointer("/error/code"),
        "L9-managed call: {by_name} vs unknown {unknown}"
    );
    assert!(
        !by_name.to_string().to_lowercase().contains("connect"),
        "L9-managed call: a call by surfaced name carried a connect offer: {by_name}"
    );
    let offered = invoke_named(&fx, 3, TOOL).await;
    let offered_missing = invoke_named(&fx, 4, "no_such_tool").await;
    assert_ne!(
        offered.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: an explicit dispatch to the backend keeps its account answer: {offered}"
    );
    // The connect journey stays: an explicit-backend dispatch tells the
    // operator its account is not connected (MIK-6745 section 9.2, D and R).
    assert!(
        offered.to_string().contains("no connected account"),
        "L9-managed invoke: the account-not-connected answer is gone: {offered}"
    );
    assert_eq!(
        offered.pointer("/error/code"),
        offered_missing.pointer("/error/code"),
        "L9-managed invoke: the account answer differs by tool: {offered} vs {offered_missing}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        0,
        "L9-managed: a no-grant call reached the backend"
    );
}

/// A keyed modern task `tools/call` of `name` as the sole operator, with the
/// headers a 2026-07-28 client sends.
async fn task_call(fx: &Fx, id: u64, name: &str) -> Value {
    let mut meta = super::tests::modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(format!("h1-{name}"));
    let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {"name": name, "arguments": {"folder": "inbox"}, "task": {}, "_meta": meta}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// H1 (L9-managed, task envelope; design R3.7): the sole operator of a
/// managed-account backend with no current grant makes a keyed modern task
/// call of the surfaced [`TOOL`] by name. It is answered exactly as the same
/// call of a name the gateway does not know: no confirmation prompt, no
/// task, nothing dispatched. RED before the fix: the caller verdict lets the
/// call proceed unrecorded, so the task route makes a task first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h1_no_grant_operator_surfaced_task_call_answers_as_unknown() {
    let fx = fixture_with(&Binding::Unconnected).await;
    let by_name = task_call(&fx, 1, TOOL).await;
    let unknown = task_call(&fx, 1, "no_such_tool").await;
    assert!(
        by_name.pointer("/result/taskId").is_none(),
        "H1: a task was made for a backend the operator has no view of: {by_name}"
    );
    assert_eq!(
        by_name.pointer("/error/code"),
        Some(&json!(-32601)),
        "H1: the surfaced name is not answered as absent: {by_name}"
    );
    assert_eq!(
        by_name.to_string(),
        unknown.to_string().replace("no_such_tool", TOOL),
        "H1: {by_name} vs unknown {unknown}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        0,
        "H1: a no-grant call reached the backend"
    );
}

/// MIK-8361 A5 ruling B: with no view of a managed backend, a name the policy
/// withholds (`run_command`, on the default deny list) named through
/// `gateway_invoke` gets the connect offer a missing name gets, byte for byte
/// with the tool name factored out. A caller with no view cannot tell names
/// apart, so the offer reveals nothing; nothing reaches the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_grant_operator_invoke_offer_is_the_same_for_a_withheld_name() {
    let fx = fixture_with(&Binding::Unconnected).await;
    let withheld = invoke_named(&fx, 1, "run_command").await;
    let missing = invoke_named(&fx, 1, "no_such_tool").await;
    assert!(
        missing.to_string().contains("no connected account"),
        "premise: the missing name gets the account answer: {missing}"
    );
    assert_eq!(
        withheld.to_string().replace("run_command", "<tool>"),
        missing.to_string().replace("no_such_tool", "<tool>"),
        "the withheld name's answer differs from the missing name's"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        0,
        "a no-grant call reached the backend"
    );
}

/// What one direct `tools/call` of `tool` on `/mcp/{BACKEND}` as the sole
/// operator left behind: the HTTP status, the body bytes with the tool name
/// factored out, and the `idp_refuse` rows and custody reads it added.
#[derive(Debug, PartialEq)]
struct DirectCall {
    status: axum::http::StatusCode,
    body: String,
    idp_refusals: usize,
    resolves: usize,
}

/// The `idp_refuse` rows the transparency log holds for [`BACKEND`].
fn idp_refusals(fx: &Fx) -> usize {
    let path = fx.dirs.0.path().join("audit.jsonl");
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    raw.lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("log line is JSON"))
        .filter(|entry| entry["action"] == "idp_refuse" && entry["backend"] == BACKEND)
        .count()
}

async fn direct_named(fx: &Fx, tool: &str) -> DirectCall {
    let (rows, reads) = (idp_refusals(fx), fx.gateway.resolves());
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": tool, "arguments": {"folder": "inbox"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    DirectCall {
        status,
        body: String::from_utf8_lossy(&bytes).replace(tool, "<tool>"),
        idp_refusals: idp_refusals(fx) - rows,
        resolves: fx.gateway.resolves() - reads,
    }
}

/// #3872 product review (oracle 2): ruling B on the direct route. A caller
/// with no view of a managed backend gets, for a name the policy withholds,
/// exactly the answer a missing name gets (the account's connect offer):
/// status and body bytes with the tool name factored out and the same
/// `idp_refuse` rows. Nothing reaches the backend. The withheld name may
/// read custody once more (the no-view check before the credential step),
/// which the caller cannot observe: residual MIK-8361.GAP.13.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_grant_operator_direct_call_is_the_same_for_a_withheld_name() {
    let fx = fixture_with(&Binding::Unconnected).await;
    let withheld = direct_named(&fx, "run_command").await;
    let missing = direct_named(&fx, "no_such_tool").await;
    assert!(missing.idp_refusals > 0, "premise: {missing:?}");
    assert_eq!(
        (withheld.status, &withheld.body, withheld.idp_refusals),
        (missing.status, &missing.body, missing.idp_refusals),
        "direct route: the withheld name's answer differs from the missing name's"
    );
    assert!(
        (missing.resolves..=missing.resolves + 1).contains(&withheld.resolves),
        "custody reads: withheld {withheld:?}, missing {missing:?}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        0,
        "a no-grant call reached the backend"
    );
}

#[path = "slot_verdict_g2_managed_http_noview_cooldown_tests.rs"]
mod noview_cooldown;

#[path = "slot_verdict_g2_managed_http_listing_tests.rs"]
mod listing;

#[path = "slot_verdict_g2_managed_http_held_view_tests.rs"]
mod held_view;
