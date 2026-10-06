// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-connection tool lists and FSM state on the modern path.

use super::*;

// ============================================================================
// MIK-7272.ORDER.2b — a connection's tool set must not vary as a side effect
// of other requests on that same connection.
//
// Plan: docs/design/2026-09-06-order-2-per-connection-list-variance-test-plan.md
// ============================================================================

/// A mock streamable-http MCP backend that answers `tools/list` and
/// `tools/call`, so a promotion can be driven through the production
/// `gateway_invoke` path instead of by calling `promote_tool_for_session`.
#[cfg(feature = "spec-preview")]
async fn start_invokable_mock() -> String {
    use axum::Json;
    use axum::Router;
    use axum::routing::post;

    async fn handle(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let id = req["id"].clone();
        let resp = match req["method"].as_str().unwrap_or("") {
            "initialize" => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {"listChanged": true}},
                    "serverInfo": {"name": "mock", "version": "0.1.0"},
                }
            }),
            "tools/list" => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"tools": [{
                    "name": "echo",
                    "description": "echo the arguments back",
                    "inputSchema": {"type": "object", "properties": {}},
                }]}
            }),
            "tools/call" => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"content": [{"type": "text", "text": "ok"}]}
            }),
            _ => serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": "Method not found"}
            }),
        };
        Json(resp)
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/mcp", post(handle));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/mcp")
}

/// The tool names in a `tools/list` response, in the order returned.
#[cfg(feature = "spec-preview")]
fn tools_list_names(resp: &JsonRpcResponse) -> Vec<String> {
    resp.result.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

/// B-10 — `tools/list` → successful `gateway_invoke` → `tools/list`, on one
/// connection declaring MCP 2026-07-28.
///
/// Both lists are asserted against the SAME pinned literal rather than against
/// each other: comparing the two observations would pass when the invoke
/// silently failed (nothing promoted, so nothing changed) and when a
/// regression moved both lists in step. The invoke is separately asserted to
/// have succeeded for the same reason.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn b10_a_successful_invoke_does_not_change_the_connections_tool_list() {
    let url = start_invokable_mock().await;
    let meta = meta_with_backend(&url, Duration::from_secs(5));

    // Production prefetches every backend's tools at startup; without a warm
    // cache `promoted_tools_for_session` silently omits the promoted entry and
    // the case could not fail whatever the promotion did.
    meta.list_tools_anon(&json!({"server": "mock"}), MODERN_SESSIONLESS)
        .await
        .expect("the mock backend's tools must be fetchable");

    let before = tools_list_names(&meta.handle_tools_list_for_session(
        RequestId::Number(1),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    let invoked = meta
        .invoke_tool(
            &json!({"server": "mock", "tool": "echo", "arguments": {}}),
            MODERN_SESSIONLESS,
            &allow_all_ctx(),
        )
        .await;
    assert!(
        invoked.is_ok(),
        "the invoke must succeed or nothing is promoted and the case proves nothing: {invoked:?}"
    );

    let after = tools_list_names(&meta.handle_tools_list_for_session(
        RequestId::Number(2),
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    assert_eq!(
        before, B10_EXPECTED_TOOLS,
        "the list before any invoke is not the pinned set"
    );
    assert_eq!(
        after, B10_EXPECTED_TOOLS,
        "a successful gateway_invoke changed what this connection is shown"
    );
}

/// The tool-name set a modern sessionless connection is shown, pinned.
///
/// `meta_with_backend` configures no cost registry, no playbooks and no
/// routing profiles, so those six tools are gated off the listing here
/// (`NFR.PERF.4`). They remain callable by name; this pins disclosure.
#[cfg(feature = "spec-preview")]
const B10_EXPECTED_TOOLS: &[&str] = &[
    "gateway_list_servers",
    "gateway_list_tools",
    "gateway_search_tools",
    "gateway_invoke",
    "gateway_kill_server",
    "gateway_revive_server",
    "gateway_list_disabled_capabilities",
    "gateway_set_state",
    "gateway_reload_capabilities",
];

// ============================================================================
// MIK-7272.ORDER.2a — a tool promoted for one connection must not surface on
// another connection's list.
//
// Plan: docs/design/2026-08-31-cluster-b-connection-invariance-test-plan.md
// ============================================================================

/// A gateway whose mock backend is invokable but absent from a filtered
/// `tools/list`, because its tool cache is POPULATED AND STALE.
///
/// Something must keep `echo` out of the ordinary enumeration or the case
/// cannot fail: `collect_filtered_backend_tools` returns it for any query
/// matching it, promotion or no promotion, and the promoted-tool merge below
/// only adds names the enumeration did not already produce
/// (`spec_preview.rs:114`). The tool has to be reachable through the promoted
/// merge alone for a leak to be visible at all.
///
/// A stale cache is what buys that, and it is the one asymmetry between the two
/// paths that production actually has. The enumeration skips a backend whose
/// cache is not fresh (`spec_preview.rs:89` -> `has_cached_tools`, which is
/// TTL-aware: `backend/metadata.rs:30-32`), while the promoted entry is
/// resolved by `get_cached_tool` (`mod.rs:1048`), which reads the stored value
/// and ignores the TTL (`backend/metadata.rs:78-82`). `Duration::ZERO` makes
/// the cache stale the instant it is filled, so the state is not timing
/// dependent — staleness only grows. The device is the one
/// `gateway_search_includes_stale_non_empty_backend_cache` already uses, and
/// the two assertions below pin both halves of it here as it does there.
///
/// A ROUTING PROFILE CANNOT DO THIS JOB, which is what the first CI run of this
/// case proved: `spec_preview.rs:98` and `invoke.rs:1133` consult the same
/// compiled `tool_filter`, so a profile that hides `echo` from the list also
/// refuses the `gateway_invoke` that promotes it — the promotion the case
/// exists to observe could never be made, on either the modern connection or
/// the legacy control.
///
/// Nothing here can make the assertion true by itself: the cache is filled
/// through the same `get_tools` call the startup prefetch and
/// `list_tools_single_server` make, and the control at the end of the case
/// shows `echo` reaching a filtered list through the promoted merge.
#[cfg(feature = "spec-preview")]
async fn meta_with_echo_hidden_by_a_stale_cache(url: &str) -> MetaMcp {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, TransportConfig};

    let config = BackendConfig {
        description: String::new(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        stop_when_idle_for: None,
        max_frame_bytes: None,
        timeout: Duration::from_secs(5),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "mock",
        config,
        &crate::config::FailsafeConfig::default(),
        Duration::ZERO,
    ));

    // Production prefetches every backend's tools at startup; without a filled
    // cache `promoted_tools_for_session` resolves the promoted key to nothing
    // and the case could not fail whatever the promotion did.
    backend
        .get_tools()
        .await
        .expect("the mock backend's tools must be fetchable");
    assert_eq!(
        backend.cached_tools_count(),
        1,
        "the promoted entry is resolved out of this cache, so it must be filled"
    );
    assert!(
        !backend.has_cached_tools(),
        "zero TTL should make the cache stale immediately, or the enumeration \
         returns `echo` on its own and the assertions below cannot fail"
    );

    let registry = Arc::new(BackendRegistry::new());
    let _ = registry.register(backend);
    MetaMcp::new(registry).with_prompts_resources_fetch_timeout(Duration::from_secs(5))
}

/// B-07 — a tool promoted by connection A's own successful `gateway_invoke`
/// must not appear on A's next modern list, nor make A's list differ from a
/// second modern connection's.
///
/// `params.query` is set on every list read, so `spec_preview.rs:111` — the
/// filtered promoted-tool merge — is the executing line. Without the query the
/// unfiltered merge runs instead, which B-10 already covers, and the filtered
/// merge could be deleted with the suite green.
///
/// The promotion is driven through the production invoke path. A fixture
/// calling `promote_tool_for_session` directly would supply the session id
/// itself and so bypass the defect, which is the ARGUMENT `invoke.rs` passes,
/// not the store beneath it. The invoke is asserted to have succeeded because
/// an errored one promotes nothing and would leave the case green having
/// exercised none of the path.
///
/// Both modern reads are pinned to the same literal rather than compared with
/// each other: a leak that reaches every connection keying to the empty
/// session id moves both lists in step, and an A-vs-B equality assertion
/// passes on exactly that.
///
/// HONEST LIMIT, so this is not read as a duplicate of B-10: today A and B are
/// indistinguishable by construction — the router spells a modern connection's
/// absent session as the empty id, so both read the same key. That
/// indistinguishability is the condition the criterion forbids, not an
/// accident of the fixture, and the two connections separate the moment modern
/// connections carry distinct ids.
///
/// The control at the end is what rules out a green run bought by a dead
/// fixture: the same promotion driven over a LEGACY connection, whose own next
/// filtered list must contain `echo`. `session_key` filters the empty string
/// only, so a non-empty legacy id survives the ORDER.2 fix and its promotion
/// stays observable. Without it, an empty modern list would be equally
/// consistent with the merge never running at all.
#[cfg(feature = "spec-preview")]
#[tokio::test]
async fn b07_a_promotion_on_one_modern_connection_does_not_surface_on_another() {
    // Control: the same promotion over a legacy connection, which keeps its own
    // session id, must be visible to that connection.
    const LEGACY: Option<&str> = Some("legacy-a");

    let url = start_invokable_mock().await;
    let meta = meta_with_echo_hidden_by_a_stale_cache(&url).await;

    // Connection A promotes, through its own successful invoke.
    let invoked = meta
        .invoke_tool(
            &json!({"server": "mock", "tool": "echo", "arguments": {}}),
            MODERN_SESSIONLESS,
            &allow_all_ctx(),
        )
        .await;
    assert!(
        invoked.is_ok(),
        "the invoke must succeed or nothing is promoted and the case proves nothing: {invoked:?}"
    );

    let promoter = tools_list_names(&meta.handle_tools_list_filtered(
        RequestId::Number(1),
        "echo",
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    let bystander = tools_list_names(&meta.handle_tools_list_filtered(
        RequestId::Number(2),
        "echo",
        MODERN_SESSIONLESS,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));

    assert_eq!(
        promoter, B07_EXPECTED_FILTERED,
        "the promoting connection was shown a tool no enumeration of its \
         backends produces"
    );
    assert_eq!(
        bystander, B07_EXPECTED_FILTERED,
        "another connection was shown a tool promoted for someone else"
    );

    // Control: the same promotion over a legacy connection, which keeps its own
    // session id, must be visible to that connection.
    let legacy_invoked = meta
        .invoke_tool(
            &json!({"server": "mock", "tool": "echo", "arguments": {}}),
            LEGACY,
            &allow_all_ctx(),
        )
        .await;
    assert!(
        legacy_invoked.is_ok(),
        "the control's invoke must succeed or it controls for nothing: {legacy_invoked:?}"
    );

    let legacy_list = tools_list_names(&meta.handle_tools_list_filtered(
        RequestId::Number(3),
        "echo",
        LEGACY,
        crate::gateway::meta_mcp::InvokeScope::allow_all(CallerStanding::Admin),
    ));
    assert!(
        legacy_list.iter().any(|name| name == "echo"),
        "the promotion is observable nowhere, so the assertions above are \
         satisfied by a silent no-op rather than by per-connection isolation: \
         {legacy_list:?}"
    );
}

/// What a modern sessionless connection is shown for the query `echo`, pinned.
///
/// Empty because a filtered response carries backend tools alone — no
/// meta-tools — and the mock's stale cache keeps its only tool out of the
/// enumeration. The literal is thin on its own; the control above is what
/// gives it force.
#[cfg(feature = "spec-preview")]
const B07_EXPECTED_FILTERED: &[&str] = &[];

// ============================================================================
// MIK-7272.ORDER.2 — FSM workflow state (B-08, B-09)
// ============================================================================

/// Proof that the staging holds: the staged capability set really does move
/// with the FSM state, on the same discovery entry points the leak cases use.
///
/// Driven from a **session-bearing** connection, never a modern sessionless
/// one. Under option (c) a modern HTTP connection cannot hold a non-default
/// state at all — that is what (c) is for — so a staging proof phrased as a
/// call from the connection under test would be unsatisfiable after the fix
/// and the case would be red forever. A session-bearing connection's
/// `gateway_set_state` is refused under neither answer to Q4.
#[tokio::test]
async fn b08_staging_the_capability_set_moves_with_the_fsm_state() {
    let meta = meta_with_state_staged_capabilities().await;
    let sess = Some("session-bearing");

    assert_eq!(
        discovery_names(&meta.list_tools_anon(&json!({}), sess).await.unwrap()),
        STAGED_DEFAULT_TOOLS,
        "the staged set in the default state is not what the cases pin"
    );

    let set = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_set_state",
        json!({"state": TARGET_STATE}),
        sess,
        allow_all_ctx(),
    ))
    .await;
    assert!(
        set.error.is_none(),
        "a session-bearing connection must be able to hold a state, or the \
         staging cannot be proved at all: {:?}",
        set.error
    );

    assert_eq!(
        discovery_names(&meta.list_tools_anon(&json!({}), sess).await.unwrap()),
        STAGED_OTHER_STATE_TOOLS,
        "gateway_list_tools does not honour the FSM state, so the staging is \
         not what B-08/B-09 assume"
    );
    assert_eq!(
        discovery_names(
            &meta
                .search_tools_anon(&json!({"query": "staged"}), sess)
                .await
                .unwrap()
        ),
        STAGED_OTHER_STATE_TOOLS,
        "gateway_search_tools does not honour the FSM state"
    );
    assert_eq!(
        discovery_names(
            &meta
                .list_tools_anon(&json!({"server": "staged"}), sess)
                .await
                .unwrap()
        ),
        STAGED_OTHER_STATE_TOOLS,
        "list_tools_single_server does not honour the FSM state"
    );
}

/// B-09 — ORDER.2b on the FSM leg: a `gateway_set_state` must not change what
/// the connection that issued it is subsequently shown.
///
/// Every observation is pinned to the same default-state literal rather than
/// compared with the one before it: comparing two observations would pass both
/// when the `set_state` silently did nothing and when a regression moved both
/// lists in step.
///
/// MIK-7272.ORDER2.FSM.2 — Q4, whether `gateway_set_state` is refused outright
/// on a sessionless modern connection, was ratified 2026-09-06: it is refused.
/// Both halves are pinned here, the call's outcome as well as the lists, and
/// the outcome pin is not redundant with them. Measured: with the refusal guard
/// removed from `set_state`, every list assertion below still passes, because
/// unchanged lists are equally what an accepted-then-silently-dropped write
/// produces. Only the outcome pin tells the two apart.
#[tokio::test]
async fn b09_a_set_state_does_not_change_the_connections_discovery_set() {
    let meta = meta_with_state_staged_capabilities().await;

    let list_before = discovery_names(
        &meta
            .list_tools_anon(&json!({}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let search_before = discovery_names(
        &meta
            .search_tools_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let single_before = discovery_names(
        &meta
            .list_tools_anon(&json!({"server": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let code_mode_before = discovery_names(
        &meta
            .code_mode_search_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );

    // Driven through the real meta-tool, not `SessionStateStore::set_state`:
    // the defect is the argument passed at `mod.rs:1689`, and a fixture
    // touching the store directly bypasses the line under test.
    let set = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_set_state",
        json!({"state": TARGET_STATE}),
        MODERN_SESSIONLESS,
        allow_all_ctx(),
    ))
    .await;
    order2_fsm::assert_refusal(&meta, &set);

    // Q4: the write is refused, not filtered on read.
    let refusal = set
        .error
        .expect("a sessionless modern connection has no state to set");
    assert!(
        refusal.message.contains("no session"),
        "the refusal must name the missing session rather than fail for some \
         unrelated reason: {}",
        refusal.message
    );

    let list_after = discovery_names(
        &meta
            .list_tools_anon(&json!({}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let search_after = discovery_names(
        &meta
            .search_tools_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let single_after = discovery_names(
        &meta
            .list_tools_anon(&json!({"server": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let code_mode_after = discovery_names(
        &meta
            .code_mode_search_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );

    for (label, observed) in [
        ("gateway_list_tools, before", &list_before),
        ("gateway_search_tools, before", &search_before),
        ("gateway_list_tools server=staged, before", &single_before),
        ("gateway_search, before", &code_mode_before),
        ("gateway_list_tools, after", &list_after),
        ("gateway_search_tools, after", &search_after),
        ("gateway_list_tools server=staged, after", &single_after),
        ("gateway_search, after", &code_mode_after),
    ] {
        assert_eq!(
            observed, STAGED_DEFAULT_TOOLS,
            "{label}: a gateway_set_state on this connection changed what it is shown"
        );
    }
}

/// B-08 — ORDER.2a on the FSM leg: a `gateway_set_state` issued by one modern
/// connection must not change what a *different* modern connection is shown.
///
/// A and B carry the same session tuple here, and that is not a shortcut in
/// the fixture — it is the defect. A modern HTTP connection presents
/// `Some("")` (`server/mod.rs` supplies the empty string), so at every seam
/// below the transport, two independent connections are one key. After (c)
/// `session_key` maps that key to `None` and neither connection can hold a
/// state at all, which is why the same tuple stops being a shared entry.
///
/// What distinguishes this case from B-09 is therefore not the fixture but the
/// claim: B issues no `gateway_set_state` of its own and is still shown the
/// state A selected. B-09 asserts the same connection is unaffected by its own
/// call; this asserts a bystander is unaffected by someone else's.
///
/// MIK-7272.ORDER2.FSM.1 — the Q4 outcome pin, whether A's call is refused
/// outright, is asserted on the same terms as B-09's: ratified 2026-09-06, and
/// load-bearing rather than redundant, since B's unchanged lists are equally
/// what a silently-dropped write would produce. The bystander stays in the
/// default state after that refused mutation.
#[tokio::test]
async fn b08_one_connections_set_state_does_not_change_another_connections_set() {
    let meta = meta_with_state_staged_capabilities().await;

    // Connection A. Driven through the real meta-tool: the defect is the
    // argument passed at `mod.rs:1689`, and a fixture touching
    // `SessionStateStore::set_state` directly bypasses the line under test.
    let set = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_set_state",
        json!({"state": TARGET_STATE}),
        MODERN_SESSIONLESS,
        allow_all_ctx(),
    ))
    .await;
    order2_fsm::assert_refusal(&meta, &set);

    // Q4: A's write is refused outright, not accepted and dropped.
    let refusal = set
        .error
        .expect("a sessionless modern connection has no state to set");
    assert!(
        refusal.message.contains("no session"),
        "the refusal must name the missing session rather than fail for some \
         unrelated reason: {}",
        refusal.message
    );

    // Connection B, which has issued no state change of its own.
    let list = discovery_names(
        &meta
            .list_tools_anon(&json!({}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let search = discovery_names(
        &meta
            .search_tools_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let single = discovery_names(
        &meta
            .list_tools_anon(&json!({"server": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );
    let code_mode = discovery_names(
        &meta
            .code_mode_search_anon(&json!({"query": "staged"}), MODERN_SESSIONLESS)
            .await
            .unwrap(),
    );

    for (label, observed) in [
        ("gateway_list_tools", &list),
        ("gateway_search_tools", &search),
        ("gateway_list_tools server=staged", &single),
        ("gateway_search", &code_mode),
    ] {
        assert_eq!(
            observed, STAGED_DEFAULT_TOOLS,
            "{label}: another connection's gateway_set_state changed what this \
             connection is shown"
        );
    }
}
