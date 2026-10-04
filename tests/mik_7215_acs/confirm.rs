// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

/// MIK-7246.CONFIRM.1 — the gate must REFUSE when confirmation cannot be
/// obtained, and must not proceed on a warning.
///
/// The policy itself is already covered as a pure function in
/// `mik_7215_controls_acs.rs`. That is a weaker claim than the criterion
/// makes: a policy nothing consults refuses nothing. This crosses the
/// handler branch that consults it (`router/handlers.rs:1139-1170`), by the
/// only route a modern caller has.
///
/// A modern request cannot carry a session -- this revision deleted them --
/// so there is nobody to elicit over and `Unsupported` is the outcome every
/// time. That is precisely the case the legacy path answers with a warning.
#[tokio::test]
async fn ac_confirm_1_a_modern_destructive_call_with_nobody_to_ask_is_refused() {
    // Admin, because `gateway_kill_server` -- the only tool this build
    // annotates `destructiveHint: true` -- is refused for everyone else by
    // the admin check, which runs *before* the confirmation gate. A
    // non-admin caller never reaches the code this criterion is about.
    let auth = mcp_gateway::config::AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            serde_json::from_value(serde_json::json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(b"admin-key"),
                "name": "admin-client", "backends": ["*"], "admin": true
            }))
            .expect("api key fixture"),
        ],
        public_paths: Vec::new(),
        ..mcp_gateway::config::AuthConfig::default()
    };
    let (state, _store_dir) = state_with(true, auth).await;
    let (status, _session, body) = post_mcp_authed(
        state,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "gateway_kill_server",
                "arguments": { "server": "any-backend" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    // Without this the call is refused for a missing
                    // idempotency key before it reaches the confirmation
                    // branch this row is about.
                    IDEMPOTENCY_KEY_META: "acs-confirm-1",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient", "version": "1.0.0"
                    }
                }
            }
        }),
        Some("admin-key"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::OK,
        "JSON-RPC reports errors in the body: {body}"
    );
    // A modern caller has no session to hold an elicitation open, but it
    // can be asked in band: the gate answers with the confirmation
    // question and the caller confirms by retrying with the answer
    // (`destructive_confirmation.rs:137`). The refusal branch belongs to a
    // caller nobody can ask at all — the stdio dispatcher
    // (`server/mod.rs:2856`) and the task route
    // (`router/handlers/tasks.rs:301`) carry that channel.
    //
    // What this row asserts either way: the call was answered by the gate
    // and the destructive action did not run.
    assert_eq!(
        body.pointer("/result/resultType").and_then(Value::as_str),
        Some("input_required"),
        "an unconfirmed destructive call must be asked about, not run: {body}"
    );
    // Distinguishes the question from any other `input_required` exit on
    // the path: the ask must be the destructive-confirmation one.
    assert!(
        body.pointer("/result/inputRequests/io.mcp-gateway.destructive-confirmation.v1")
            .is_some(),
        "the ask must be the destructive-confirmation one: {body}"
    );
    // Guards two things at once, both invisible to every other assertion
    // here. (1) The fixture's `arguments` key must be the one production
    // reads (`server`), or the description degrades to the fallback text.
    // (2) The ask must actually interpolate the description, so deleting
    // `{action_desc}` from it leaves the title, the shape, and the
    // describer's own unit tests all green. `docs/DEPLOYMENT.md` promises
    // the gate names the action, so this asserts the whole action phrase,
    // not just the argument inside it.
    let description = body
        .pointer("/result/inputRequests/io.mcp-gateway.destructive-confirmation.v1/description")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        description.contains("kill server 'any-backend'"),
        "the ask must name the action it is about, not the fallback text: {description}"
    );
    assert!(
        body.pointer("/result/content").is_none(),
        "an unconfirmed destructive call must not also return a tool result: {body}"
    );
}

/// MIK-7364 `DISC.2`, on the exposure route — a meta-tool an operator has
/// hidden with `exposed_meta_tools` must answer as if it did not exist,
/// even for the admin who would otherwise be allowed to run it.
///
/// `DISC.2` is written against the admin-gate route: a non-admin naming a
/// hidden admin tool. This drives the exposure check instead, with an
/// *admin* caller precisely so the admin gate cannot be what answers.
/// Admin is the harder case, not a weaker one: the exposure check runs
/// first (`src/gateway/meta_mcp/mod.rs:1350`, ahead of the admin gate at
/// `:1365`), so the caller who would clear every remaining gate is the one
/// with the most to learn from a different answer — and still gets none. The
/// criterion is the same one — indistinguishable from an absent tool, same
/// code and same message — proved on the other of the two routes the
/// ticket lists. The admin-gate half is not covered here and still owes a
/// test.
///
/// The confirmation gate and the exposure allow-list would both refuse this
/// call, with different wording, and only one of them may answer. `-32001`
/// ("requires confirmation") tells the caller the tool is real, is
/// destructive, and was withheld deliberately — which is the disclosure the
/// allow-list exists to prevent. `-32601` is the same answer a name nobody
/// implemented gets, and tells the caller nothing.
///
/// Admin, deliberately: a non-admin is refused by the admin gate at
/// `router/handlers.rs:1069` and never reaches either branch, so the test
/// would go green while proving nothing.
#[tokio::test]
async fn mik_7364_a_hidden_destructive_meta_tool_is_not_disclosed() {
    let auth = mcp_gateway::config::AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            serde_json::from_value(serde_json::json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(b"admin-key"),
                "name": "admin-client", "backends": ["*"], "admin": true
            }))
            .expect("api key fixture"),
        ],
        public_paths: Vec::new(),
        ..mcp_gateway::config::AuthConfig::default()
    };
    // The allow-list names one unrelated meta-tool, so it is non-empty — an
    // empty list exposes everything — and `gateway_kill_server` is absent.
    let (state, _store_dir) =
        state_with_exposure(true, auth, &["gateway_invoke".to_string()]).await;
    let (status, _session, body) = post_mcp_authed(
        Arc::clone(&state),
        modern_tools_call(
            18,
            "gateway_kill_server",
            json!({ "server": "row18-sentinel" }),
        ),
        Some("admin-key"),
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a hidden tool answers with the modern revision's not-found status, as any \
         unimplemented name does (handlers.rs:1396-1410): {body}"
    );
    let code = body.pointer("/error/code").and_then(Value::as_i64);
    assert_ne!(
        code,
        Some(-32001),
        "a hidden tool must not confirm its own existence by asking for confirmation to run it: {body}"
    );
    assert_eq!(
        code,
        Some(-32601),
        "a hidden meta-tool answers exactly as a name nobody implemented does: {body}"
    );
    let hidden_message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    assert!(
        body.get("result").is_none(),
        "a hidden tool must not run: {body}"
    );

    // The row claims the hidden tool answers *exactly as* an unimplemented
    // name does. Asserting one status and one code does not prove that --
    // it proves this response's shape, and leaves "the same as what?"
    // to the reader. So ask a name nobody implemented, on the same state,
    // and compare. Same fixture, so this is a second request rather than a
    // second row. Goes red if a later edit gives hidden tools any answer of
    // their own: a distinct status, a distinct code, or a message that
    // says "hidden" where the other says "Unknown tool".
    let (control_status, _session, control_body) = post_mcp_authed(
        state,
        modern_tools_call(1801, "row18_nobody_implemented_this", json!({})),
        Some("admin-key"),
    )
    .await;

    assert_eq!(
        control_status, status,
        "a hidden tool and an unimplemented name must answer with the same status: {control_body}"
    );
    assert_eq!(
        control_body.pointer("/error/code").and_then(Value::as_i64),
        code,
        "a hidden tool and an unimplemented name must answer with the same code: {control_body}"
    );
    let control_message = control_body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // `meta_mcp/mod.rs` commits to this in its own words: the hidden-tool
    // refusal is "worded exactly like the unrecognised-tool fallback", built
    // and returned through the same helper "so the two answers are
    // byte-identical", because a message without the error type's prefix
    // "was itself the disclosure". This does not propose that requirement --
    // it checks an invariant the source already claims. Compared modulo the
    // name so it holds whichever wording both paths settle on; pinning a
    // literal would fail on a prefix change that disclosed nothing.
    assert_eq!(
        hidden_message.replace("gateway_kill_server", "row18_nobody_implemented_this"),
        control_message,
        "a hidden tool and an unimplemented name must be worded identically, or the difference is the disclosure: hidden={hidden_message}"
    );
    assert!(
        control_message.ends_with("Unknown tool: row18_nobody_implemented_this"),
        "the control must itself reach the unrecognised-name fallback, or it \
         agrees with the hidden tool for some other reason: {control_message}"
    );
}

/// MIK-7246.CONFIRM.1a — a confirmation refusal is the gate working, not the
/// caller misbehaving, so it is excluded from the caller's dispatch
/// accounting in BOTH directions.
///
/// Both arms, not just the failure one: `record_client_success` resets the
/// consecutive-failure count, so booking a refusal as a success would clear
/// a breaker the caller had genuinely tripped. A test pinning one arm pins
/// half a rule, and the half it leaves open is the one that loses state.
///
/// The count is read by TITRATION rather than by a getter, because
/// `ResolvedAuthConfig` exposes `client_circuit_state` and no accessor for
/// the current failure count (`src/gateway/auth.rs:272-304`). With the
/// threshold at two, how many further failures it takes to trip IS the
/// count, and the read-out discriminates all three implementations the plan
/// names: counted trips at the refusal (first assertion), erased needs two
/// more failures to trip (last assertion), excluded needs exactly one.
/// Deviation from the plan row's "threshold above two": that spelling needs
/// a production accessor this test would have to widen the API to get.
///
/// The first request is not setup, it is the negative control. It proves
/// this client resolves and that the failure arm records over this exact
/// HTTP path — without it, a fixture where `client` never resolves would
/// pass every assertion below while pinning nothing.
#[tokio::test]
async fn ac_confirm_1a_a_refusal_is_excluded_from_both_accounting_arms() {
    let auth = mcp_gateway::config::AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![
            serde_json::from_value(serde_json::json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(b"admin-key"),
                "name": "row17-client", "backends": ["*"], "admin": true
            }))
            .expect("api key fixture"),
        ],
        public_paths: Vec::new(),
        client_circuit_breaker: Some(mcp_gateway::config::CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: std::time::Duration::from_secs(60),
        }),
        ..mcp_gateway::config::AuthConfig::default()
    };
    let (state, _store_dir) = state_with(true, auth).await;
    let accounting = Arc::clone(&state.auth_config);

    // Control: one genuine failure over this path, as this client.
    let mut unknown = modern_tools_list(1701);
    unknown["method"] = json!("row17/does-not-exist");
    let (_, _, body) = post_mcp_authed(Arc::clone(&state), unknown, Some("admin-key")).await;
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "the control must be an ordinary error, or it is not exercising the failure arm: {body}"
    );
    assert_eq!(
        accounting.client_circuit_state("row17-client"),
        Some(mcp_gateway::failsafe::CircuitState::Closed),
        "one failure of two must leave the breaker closed, or the fixture's threshold is wrong"
    );

    // The refusal itself.
    let (_, _, refusal) = post_mcp_authed(
        Arc::clone(&state),
        json!({
            "jsonrpc": "2.0",
            "id": 1702,
            "method": "tools/call",
            "params": {
                "name": "gateway_kill_server",
                "arguments": { "server": "row17-sentinel" },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    // Without this the call is refused for a missing
                    // idempotency key before it reaches the confirmation
                    // branch this row is about.
                    IDEMPOTENCY_KEY_META: "acs-confirm-1",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "ExampleClient", "version": "1.0.0"
                    }
                }
            }
        }),
        Some("admin-key"),
    )
    .await;
    assert!(
        refusal
            .pointer("/result/inputRequests/io.mcp-gateway.destructive-confirmation.v1")
            .is_some(),
        "this row observes the unconfirmed branch; another exit proves nothing about it: {refusal}"
    );
    assert_eq!(
        accounting.client_circuit_state("row17-client"),
        Some(mcp_gateway::failsafe::CircuitState::Closed),
        "a refusal counted as a failure takes the count to two and trips the breaker: {refusal}"
    );

    // One more genuine failure. It reaches two only if the refusal left the
    // count at one -- a refusal booked as a SUCCESS would have reset it, and
    // this failure would be the first of two rather than the second.
    let mut unknown_again = modern_tools_list(1703);
    unknown_again["method"] = json!("row17/does-not-exist");
    let (_, _, body) = post_mcp_authed(Arc::clone(&state), unknown_again, Some("admin-key")).await;
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601),
        "{body}"
    );
    assert_eq!(
        accounting.client_circuit_state("row17-client"),
        Some(mcp_gateway::failsafe::CircuitState::Open),
        "a refusal booked as a success reset the count, so this failure is the first of two, not the second"
    );
}
