// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio dispatcher: parsing, protocol counters, confirmation, discovery
//! and authorization (moved from `server/mod.rs`, MIK-8144).

use super::*;

#[tokio::test]
async fn dispatch_single_reuses_shared_request_parser_for_missing_id() {
    let response = Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({"jsonrpc": "2.0", "method": "ping"}),
        "stdio-session",
    )
    .await
    .expect("request without id should return an error response");

    assert_eq!(response["error"]["code"], -32600);
    assert_eq!(response["error"]["message"], "Missing id");
}

#[tokio::test]
async fn stdio_initialize_records_requested_revision() {
    let before = crate::protocol_revision_telemetry::global_snapshot();
    let response = Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({
            "jsonrpc": "2.0",
            "id": 7218,
            "method": "initialize",
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "Claude Code"}
            },
            "params": {
                "protocolVersion": "2025-06-18",
                "clientInfo": {"name": "ignored-by-meta"}
            }
        }),
        "stdio-session-mik-7218",
    )
    .await
    .expect("initialize returns a response");

    assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    let after = crate::protocol_revision_telemetry::global_snapshot();
    assert!(
        after.by_revision.get("2026-07-28").copied().unwrap_or(0)
            > before.by_revision.get("2026-07-28").copied().unwrap_or(0)
    );
    assert!(
        after.by_transport.get("stdio").copied().unwrap_or(0)
            > before.by_transport.get("stdio").copied().unwrap_or(0)
    );
    assert!(
        after.by_client.get("claude").copied().unwrap_or(0)
            > before.by_client.get("claude").copied().unwrap_or(0)
    );
}

#[tokio::test]
async fn stdio_dispatch_persists_operator_readable_protocol_counters() {
    let data_dir = tempfile::tempdir().expect("temporary data directory");
    let sink = super::super::StdioTelemetry::new(Some(
        crate::protocol_revision_telemetry::DurableTelemetrySink::open(data_dir.path())
            .expect("open durable telemetry sink"),
    ));
    Gateway::persist_stdio_protocol_telemetry(&sink);

    Gateway::dispatch_single_with_sink(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        json!({
            "jsonrpc": "2.0",
            "id": 7219,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "Codex"}
            }
        }),
        super::super::StdioClient {
            session_id: "stdio-durable-window-test",
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            modern: false,
        },
        &sink,
    )
    .await
    .expect("initialize returns a response");

    let window = crate::protocol_revision_telemetry::load_durable_window(data_dir.path())
        .expect("load durable stdio aggregate");
    assert!(window.snapshot.total >= 1);
    assert!(
        window
            .snapshot
            .by_transport
            .get("stdio")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        window
            .snapshot
            .by_revision
            .get("2025-11-25")
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

// -- MIK-7246.CONFIRM.1a: the destructive gate over stdio ---------------
//
// In-crate and at the dispatcher, deliberately. `MetaMcpCallerContext`
// borrows a `pub(crate)` trait object, so it cannot be built from `tests/`
// -- and widening that visibility to let it would be the wrong trade
// twice: a visibility change is a design shift, and a hand-built context
// is one no production caller constructs. `dispatch_single` is what the
// stdio read loop calls, so this is the path a spawned client takes.
//
// Stdio refuses unconditionally rather than consulting `is_modern`. The
// reason `for_modern()` refuses is not that the request is modern; it is
// that no asker can exist. On HTTP the revision is what removed the asker,
// so the revision is a serviceable proxy. Stdio reaches the same condition
// by a different route -- there is no session and never will be -- and the
// criterion is written about the condition, not the route.
// Row 19: the marker that keeps a refusal out of failure accounting is
// internal, and internal has to mean both directions. A stamp inside
// `error.data` would satisfy the accounting and leak the gateway's own
// bookkeeping to the caller; a plain field that serde still reads would let
// a caller mint the marker by sending its name.
#[tokio::test]
async fn ac_confirm_1a_the_refusal_marker_never_reaches_the_wire() {
    let meta = test_meta_mcp();
    let tool_policy = test_tool_policy();
    let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
        tool_policy: tool_policy.as_ref(),
    };
    // Built by the gate itself, not by hand: a hand-made response would
    // only prove that serde skips a field, never that the refusal the
    // gateway actually emits carries it.
    let marked = Box::pin(meta.handle_tools_call(
        RequestId::Number(19),
        "gateway_kill_server",
        json!({ "server": "row19-sentinel" }),
        Some("stdio-session"),
        super::super::stdio_caller_context(&authorizer, crate::protocol::meta::Era::Legacy),
    ))
    .await;

    // (b) in-process, the accounting can see it.
    assert!(
        marked.confirmation_refusal,
        "the gate's refusal must be marked, or failure accounting cannot              tell it from a client error"
    );

    // (a) on the wire, nothing can. Two responses differing only in the
    // marker serialize identically.
    let mut unmarked = marked.clone();
    unmarked.confirmation_refusal = false;
    assert_eq!(
        serde_json::to_string(&marked).expect("a refusal must serialize"),
        serde_json::to_string(&unmarked).expect("a refusal must serialize"),
        "the marker must not be observable in the response the caller reads"
    );

    // (c) inbound, a wire key of that name cannot set it. Read back the
    // frame the gateway just emitted, with the key added.
    let mut frame: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&marked).expect("serialize"))
            .expect("a refusal must be valid JSON");
    frame["confirmation_refusal"] = json!(true);
    let ingested: crate::protocol::JsonRpcResponse =
        serde_json::from_value(frame).expect("a response frame must deserialize");
    assert!(
        !ingested.confirmation_refusal,
        "a caller must not be able to mint the marker by naming it"
    );
}

/// SUB.4.MALFORMED.1, stdio leg. The §P3 design event: a retry field the
/// parser cannot use is REFUSED with -32602 rather than run on as an
/// unprotected fresh call. Before this the key was simply dropped and the
/// caller kept believing it had replay protection.
#[tokio::test]
async fn stdio_refuses_a_malformed_idempotency_key() {
    let meta = test_meta_mcp();
    let response = Gateway::dispatch_single(
        &meta,
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "gateway_list_servers",
                "arguments": {},
                // A non-string key: present, unusable, and therefore
                // recorded in `RetryFields::malformed`.
                "_meta": { crate::protocol::mrtr::IDEMPOTENCY_KEY_META: 42 }
            }
        }),
        "stdio-session",
    )
    .await
    .expect("a tools/call carrying an id must return a response");

    assert_eq!(
        response
            .pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32602),
        "an unusable idempotency key must be refused as an invalid param, \
         not silently dropped: {response}"
    );
    assert!(
        response
            .pointer("/error/message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| m.starts_with("malformed request fields:")),
        "the refusal must name the malformed fields, the same wording the \
         HTTP route uses: {response}"
    );
}

#[tokio::test]
async fn ac_confirm_1a_stdio_refuses_a_destructive_call_it_cannot_confirm() {
    // Bound rather than inlined: the kill switch is the execution sentinel,
    // and reading it afterwards requires the same instance the call ran on.
    let meta = test_meta_mcp();
    let response = Gateway::dispatch_single(
        &meta,
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({
            "jsonrpc": "2.0",
            "id": 16,
            "method": "tools/call",
            "params": {
                "name": "gateway_kill_server",
                // `describe_destructive_action` reads `arguments.server`
                // (router/handlers.rs:1582). Passing `name` instead yields
                // the generic fallback, and the verbatim assertion below
                // would then fail for a fixture reason rather than a real
                // one.
                "arguments": { "server": "row16-sentinel" }
            }
        }),
        "stdio-session",
    )
    .await
    .expect("a tools/call carrying an id must return a response");

    assert_eq!(
        response
            .pointer("/error/code")
            .and_then(serde_json::Value::as_i64),
        Some(-32001),
        "stdio has nobody to elicit over, so a destructive call cannot be \
         confirmed and must be refused: {response}"
    );
    let message = response
        .pointer("/error/message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        message.starts_with("Destructive action requires confirmation and none could be obtained:"),
        "the refusal must be the unconfirmable branch, worded as the HTTP \
         path words it -- one gate, one string: {message}"
    );
    assert!(
        message.contains("row16-sentinel"),
        "the refusal must name what it refused to act on: {message}"
    );
    assert!(
        response.get("result").is_none(),
        "a refused destructive call must not also return a result: {response}"
    );
    // The sentinel, and the point of the row: a gate that answers -32001
    // after the tool has already run has refused nothing.
    assert!(
        !meta.kill_switch().is_killed("row16-sentinel"),
        "the backend must be untouched by a refused call: {response}"
    );
}

// ── MIK-7217: server/discover over stdio ───────────────────────────────
//
// Dispatcher-level on purpose. Both dispatchers call one builder, so a test
// that calls the builder proves nothing about whether either `match` routes
// to it — and a missing arm is exactly the regression this guards.

#[tokio::test]
async fn ac_discover_1_stdio_dispatch_answers_server_discover() {
    let response = Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
        "stdio-session",
    )
    .await
    .expect("server/discover must return a response");

    assert!(
        response.get("error").is_none(),
        "server/discover must not error on stdio: {response}"
    );
    let result = &response["result"];
    assert!(
        result.get("supportedVersions").is_some(),
        "discovery must advertise supportedVersions: {response}"
    );
    assert!(
        result.get("capabilities").is_some(),
        "discovery must advertise capabilities: {response}"
    );
    assert!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"].is_object(),
        "discovery must identify the server in _meta: {response}"
    );
}

#[tokio::test]
async fn ac_discover_2_stdio_discovery_needs_no_prior_initialize() {
    // The session argument is what the transport supplies today; the point
    // is that no `initialize` ran before this call, and discovery answers
    // anyway. Under 2026-07-28 there is no handshake to run.
    let response = Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({"jsonrpc": "2.0", "id": 7, "method": "server/discover"}),
        "never-initialized",
    )
    .await
    .expect("discovery must answer without a handshake");

    assert!(
        response["result"].get("supportedVersions").is_some(),
        "discovery must answer on a connection that never handshook: {response}"
    );
}

// NFR.OBS.2, stdio. The record of which filters shaped a `tools/list`
// lives at the site that assembles the list
// (`MetaMcp::shadow_tools_list_assembly`), not at each transport, so it
// reads the profile the session actually resolves rather than a constant
// the transport asserts. This pins that a stdio dispatch reaches that
// site; which filters it reports for a given profile is pinned beside the
// assembly itself, in `gateway::meta_mcp::tests`.
#[tokio::test]
async fn stdio_tools_list_is_observed_at_the_assembly_site() {
    use crate::protocol_revision_telemetry::{ListFilters, global_shadow_count};

    let unfiltered = ListFilters::default();
    let before = global_shadow_count(unfiltered);

    Gateway::dispatch_single(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        &json!({"jsonrpc": "2.0", "id": 9, "method": "tools/list"}),
        "stdio-session-obs-2",
    )
    .await
    .expect("tools/list must answer over stdio");

    assert!(
        global_shadow_count(unfiltered) > before,
        "a stdio `tools/list` must be observed where the list is assembled"
    );
}

// ── MIK-7252: stdio authorization ──────────────────────────────────────
//
// Before this change stdio checked the tool policy for `gateway_invoke`
// alone, so a stdio playbook or code-mode step reached a backend with no
// policy check at all. The inline check is replaced by an authorizer at the
// dispatch chokepoint, which every shape passes through.

/// A policy that denies one tool by name.
fn policy_denying(tool: &str) -> Arc<ToolPolicy> {
    Arc::new(ToolPolicy::from_config(
        &crate::security::ToolPolicyConfig {
            enabled: true,
            deny: vec![tool.to_string()],
            ..crate::security::ToolPolicyConfig::default()
        },
    ))
}

/// Register a one-step playbook on a meta instance and return it.
fn meta_with_step(server: &str, tool: &str) -> Arc<MetaMcp> {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let yaml = format!(
        "name: p\ndescription: one step\non_error: abort\nsteps:\n  - name: s\n    server: {server}\n    tool: {tool}\n"
    );
    let definition: crate::playbook::PlaybookDefinition =
        serde_yaml::from_str(&yaml).expect("playbook fixture must parse");
    let mut engine = crate::playbook::PlaybookEngine::new();
    engine.register(definition);
    meta.set_playbook_engine(engine);
    Arc::new(meta)
}

fn run_playbook_over_stdio(
    meta: &Arc<MetaMcp>,
    policy: &Arc<ToolPolicy>,
    mtls: &Arc<MtlsPolicy>,
) -> serde_json::Value {
    futures::executor::block_on(Gateway::dispatch_single(
        meta,
        policy,
        mtls,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "gateway_run_playbook",
                "arguments": { "name": "p", "arguments": {} }
            }
        }),
        "stdio-session",
    ))
    .expect("a tools/call must produce a response")
}

/// AUTHZ.15 — a stdio playbook step hitting a policy-denied tool is
/// refused. There was no coverage of this before: the inline check ran for
/// `gateway_invoke` only, so this step reached dispatch unchecked.
#[tokio::test]
async fn authz_15_stdio_playbook_step_denied_by_tool_policy() {
    let meta = meta_with_step("alpha", "blocked_tool");
    let response =
        run_playbook_over_stdio(&meta, &policy_denying("blocked_tool"), &test_mtls_policy());

    let text = response.to_string();
    assert!(
        response["error"].is_object(),
        "a policy-denied stdio step must be refused: {text}"
    );
    assert!(
        text.contains("step not permitted for this caller"),
        "the refusal is recorded neutrally (A3): {text}"
    );
}

/// AUTHZ.15a — a permitted tool is not refused. Without this, a stdio
/// authorizer that denied every backend target would pass AUTHZ.15 and
/// AUTHZ.16 on its own.
#[tokio::test]
async fn authz_15a_stdio_playbook_step_permitted_is_not_refused() {
    let meta = meta_with_step("alpha", "permitted_tool");
    let response =
        run_playbook_over_stdio(&meta, &policy_denying("blocked_tool"), &test_mtls_policy());

    // A POSITIVE oracle, not the absence of a phrase: the step must have
    // reached dispatch, which it can only do if the policy check passed.
    // The backend does not exist, so dispatch is what fails — and saying so
    // is proof the call got that far. Asserting "no refusal text" would
    // stay green if the refusal were ever worded differently.
    let text = response.to_string();
    assert!(
        text.contains("not found") || text.contains("missing"),
        "a permitted tool must reach dispatch and fail there, not be \
         refused before it: {text}"
    );
}

/// AUTHZ.22 — with certificate rules configured, stdio calls are still not
/// refused.
///
/// `MtlsPolicy::evaluate` returns `Deny` for a `None` identity once the
/// policy is enabled, and stdio presents no certificate. An implementation
/// that handed stdio the certificate policy would therefore refuse every
/// call — this is the row that catches it.
#[tokio::test]
async fn authz_22_stdio_is_not_refused_by_certificate_policy() {
    let meta = meta_with_step("alpha", "permitted_tool");
    let mtls = Arc::new(MtlsPolicy::from_config(&MtlsConfig {
        enabled: true,
        ..MtlsConfig::default()
    }));

    let response = run_playbook_over_stdio(&meta, &policy_denying("blocked_tool"), &mtls);

    // Same positive oracle: the call must reach dispatch. With the
    // certificate policy wrongly applied, `evaluate(None)` returns `Deny`
    // and the step is refused before dispatch, so this assertion fails.
    let text = response.to_string();
    assert!(
        text.contains("not found") || text.contains("missing"),
        "stdio presents no certificate, so a configured mTLS policy must \
         not stop the call reaching dispatch: {text}"
    );
}

#[tokio::test]
async fn dispatch_batch_returns_invalid_request_for_empty_batch() {
    // Boxed: the dispatch future carries the whole request path and sits
    // just over the `large_futures` threshold on the test stack.
    let responses = Box::pin(Gateway::dispatch_batch(
        &test_meta_mcp(),
        &test_tool_policy(),
        &test_mtls_policy(),
        json!([]),
        "stdio-session",
    ))
    .await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], -32600);
    assert_eq!(responses[0]["error"]["message"], "Invalid Request");
}
