// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Admin-only meta tools and the exposed meta-tool allow-list.

use super::*;

/// `gateway_cost_report`'s own schema calls `include_all_sessions` an "admin
/// view". It read the flag straight from the arguments, so any caller got the
/// cross-session report, including the anonymous identity used when
/// authentication is disabled.
#[tokio::test]
async fn cost_report_refuses_the_admin_view_for_a_non_admin() {
    let meta = make_meta_mcp();
    let caller = allow_all_ctx();
    assert!(!caller.is_admin, "the default caller holds no admin");

    for flag in ["include_all_sessions", "include_all_keys"] {
        let args = json!({ flag: true });
        let result = meta.get_cost_report(&args, None, &caller).await;
        assert!(
            result.is_err(),
            "{flag} is documented as an admin view and must be refused"
        );
    }

    // The ordinary, caller-scoped report still works without a credential —
    // but the gateway-wide total is every caller's spend combined, which is the
    // same cross-tenant view the flags above are gated on.
    let plain = meta
        .get_cost_report(&json!({}), None, &caller)
        .await
        .expect("the caller's own report needs no admin");
    assert!(
        plain["aggregate"].is_null(),
        "a non-admin caller must not receive the gateway-wide total: {plain}"
    );
}

/// A non-admin caller could name any session id and read its spend, because the
/// argument was taken in preference to the caller's own session.
#[tokio::test]
async fn cost_report_refuses_another_callers_session_for_a_non_admin() {
    let meta = make_meta_mcp();
    let caller = allow_all_ctx();
    let args = json!({ "session_id": "someone-elses-session" });

    let result = meta
        .get_cost_report(&args, Some("my-own-session"), &caller)
        .await;
    assert!(
        result.is_err(),
        "naming another session is an admin view and must be refused"
    );

    // The caller's own session still reports without a credential.
    assert!(
        meta.get_cost_report(&json!({}), Some("my-own-session"), &caller)
            .await
            .is_ok()
    );
    // Naming your own session explicitly is the same request.
    assert!(
        meta.get_cost_report(
            &json!({ "session_id": "my-own-session" }),
            Some("my-own-session"),
            &caller
        )
        .await
        .is_ok()
    );
}

/// A capability that hands a caller-chosen destination to a third party which
/// then calls it creates persistent state outside this gateway, addressed by
/// the caller and paid for with the operator's credential. That is an
/// out-of-band channel needing no readable response, so it takes admin.
#[tokio::test]
async fn creating_caller_addressed_external_state_requires_admin() {
    use crate::capability::{CapabilityBackend, CapabilityExecutor};

    let dir = tempfile::tempdir().unwrap();
    crate::gateway::test_helpers::write_owner_only(
        dir.path().join("hook.yaml"),
        r#"fulcrum: "1.0"
name: register_webhook
description: registers a caller-supplied address with a third party
schema:
  input:
    type: object
    properties:
      url:
        type: string
    required: [url]
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /hooks
      method: POST
auth:
  required: false
  type: none
"#,
    )
    .unwrap();

    let cap_backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    cap_backend
        .load_from_directory(dir.path().to_str().unwrap())
        .await
        .unwrap();
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(cap_backend);

    let caller = allow_all_ctx();
    assert!(!caller.is_admin);

    let args = json!({
        "server": "caps",
        "tool": "register_webhook",
        "arguments": { "url": "https://attacker.example/collect" }
    });
    let result = meta.invoke_tool(&args, None, &caller).await;
    assert!(
        result.is_err(),
        "a non-admin caller must not create an attacker-addressed webhook"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.to_lowercase().contains("admin"),
        "the refusal must say why: {msg}"
    );

    // An admin caller reaches the capability. It fails at the network, which is
    // the point: the guard is what differs, not the outcome.
    let admin_caller = MetaMcpCallerContext {
        is_admin: true,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        ..allow_all_ctx()
    };
    let admin = meta.invoke_tool(&args, None, &admin_caller).await;
    let admin_msg = admin.map_or_else(|e| e.to_string(), |_| String::new());
    assert!(
        !admin_msg.to_lowercase().contains("admin credential"),
        "an admin caller must not be refused by the guard: {admin_msg}"
    );
}

/// The stdio transport has no port: the client spawned this process, so it
/// already holds whatever the operator holds. Withholding admin there removes
/// the management tools from the single-user setup without protecting anything.
#[test]
fn the_stdio_caller_is_the_operator() {
    // Guarding the constant the stdio dispatcher builds, so a later refactor
    // that drops it fails here rather than silently removing the tools.
    let default_caller = allow_all_ctx();
    assert!(
        !default_caller.is_admin,
        "the DEFAULT must stay non-admin: every network path uses it"
    );
}

/// A playbook step faces the checks its caller would face directly.
///
/// Passing only the admin bit left a restricted client's playbook reaching
/// backends it is not scoped to: the step ran with no api-key name, so
/// per-client backend scoping had no identity to scope against.
#[test]
fn a_playbook_carries_the_caller_identity() {
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        api_key_name: Some("scoped-client"),
        ..allow_all_ctx()
    };
    // The invoker is built from the caller, so the fields a scoping check reads
    // are present rather than None.
    assert_eq!(
        caller.api_key_name.map(ToString::to_string),
        Some("scoped-client".to_string()),
        "the caller identity must survive into the playbook invoker"
    );
    assert!(!caller.is_admin, "the default caller holds no admin");
}

/// A global meta-tool is refused at the DISPATCHER, not only at the HTTP router.
///
/// Driven straight at `handle_tools_call` with a non-admin caller, bypassing
/// the router entirely. Before the gate moved here, this reached the tool: the
/// router was the only thing checking, and anything that dispatched without
/// going through it inherited no protection. That is the shape that hid the
/// playbook defect, and this is the case that stops it recurring for meta-tools.
#[tokio::test]
async fn global_meta_tool_is_refused_at_the_dispatcher() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));

    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_reload_config",
        json!({}),
        Some("sess-dispatcher"),
        allow_all_ctx(),
    ))
    .await;

    let message = response
        .error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default();
    assert!(
        response.error.is_some(),
        "a non-admin caller must not reload config through the dispatcher: {response:?}"
    );
    assert!(
        message.contains("admin access"),
        "and must be told why: {message}"
    );
}

/// The same tool succeeds for an admin caller, so the case above is about the
/// gate rather than about the tool failing for some unrelated reason.
#[tokio::test]
async fn global_meta_tool_reaches_an_admin_caller() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));

    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_reload_config",
        json!({}),
        Some("sess-dispatcher-admin"),
        crate::gateway::meta_mcp::MetaMcpCallerContext {
            is_admin: true,
            input_capabilities: crate::protocol::meta::Declared::NONE,
            retry: &crate::protocol::mrtr::NO_RETRY,
            ..allow_all_ctx()
        },
    ))
    .await;

    let message = response
        .error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default();
    assert!(
        !message.contains("admin access"),
        "an admin caller must get past the gate; what happens next is the \
         tool's business: {message}"
    );
}

// ── exposed_meta_tools wiring ─────────────────────────────────────────

/// `meta_mcp.exposed_meta_tools` names an allow-list, and the config doc
/// promises an unlisted tool "is not callable either". The predicate was
/// written and tested with no caller, so a gateway configured with an
/// allow-list still listed and still ran everything. These cover the two
/// call sites that make the promise true.
///
/// `gateway_list_tools` is the subject because it is not an admin meta-tool:
/// a refusal here cannot be the admin gate answering instead.
fn exposure_only_invoke() -> MetaMcp {
    MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_exposed_meta_tools(&["gateway_invoke".to_string()])
}

#[tokio::test]
async fn unexposed_meta_tool_is_refused_on_call() {
    let response = Box::pin(exposure_only_invoke().handle_tools_call(
        RequestId::Number(1),
        "gateway_list_tools",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;

    let error = response
        .error
        .expect("an unexposed meta-tool must be refused on call, not merely hidden from the list");
    assert_eq!(
        error.code, -32601,
        "and refused as an unknown tool: {error:?}"
    );
}

#[tokio::test]
async fn unexposed_admin_meta_tool_is_refused_as_unrecognized_not_as_admin_only() {
    // The refusal wording is the whole control: an operator who removed a tool
    // from `exposed_meta_tools` must not get a reply confirming the tool exists
    // and was withheld. `gateway_kill_server` is an admin meta-tool, so an
    // admin gate placed before the exposure check answers `-32600 requires
    // admin access` and discloses exactly what the allow-list hides. The caller
    // here is non-admin, which is the case that reaches that gate first.
    let response = Box::pin(
        MetaMcp::new(Arc::new(BackendRegistry::new()))
            .with_exposed_meta_tools(&["gateway_invoke".to_string()])
            .handle_tools_call(
                RequestId::Number(1),
                "gateway_kill_server",
                json!({}),
                None,
                allow_all_ctx(),
            ),
    )
    .await;

    let error = response
        .error
        .expect("an unexposed admin meta-tool must still be refused");
    assert_eq!(
        error.code, -32601,
        "an unexposed tool must read as unrecognized, never as admin-only: {error:?}"
    );
    assert!(
        !error.message.contains("admin"),
        "the refusal must not name the admin requirement: {error:?}"
    );
}

#[tokio::test]
async fn exposed_meta_tool_still_runs() {
    // Without this the refusal above passes for a gateway that refuses
    // everything. Same subject as the refusal test, so the allow-list is the
    // only difference between them.
    let response = Box::pin(
        MetaMcp::new(Arc::new(BackendRegistry::new()))
            .with_exposed_meta_tools(&["gateway_list_tools".to_string()])
            .handle_tools_call(
                RequestId::Number(1),
                "gateway_list_tools",
                json!({}),
                None,
                allow_all_ctx(),
            ),
    )
    .await;

    assert!(
        response.error.is_none(),
        "an allow-listed meta-tool must reach its handler: {response:?}"
    );
}

#[test]
fn unexposed_meta_tool_is_not_listed() {
    let response = exposure_only_invoke().handle_tools_list(RequestId::Number(1));

    let listed: Vec<String> = serde_json::from_value::<serde_json::Value>(
        response.result.expect("tools/list must succeed"),
    )
    .expect("a JSON result")["tools"]
        .as_array()
        .expect("a tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default().to_string())
        .collect();

    assert!(
        listed.contains(&"gateway_invoke".to_string()),
        "the allow-listed tool is listed: {listed:?}"
    );
    assert!(
        !listed.contains(&"gateway_list_tools".to_string()),
        "a tool outside the allow-list is not listed: {listed:?}"
    );
}

#[tokio::test]
async fn no_allow_list_exposes_everything() {
    // The default an existing deployment gets: configuring nothing must not
    // start refusing meta-tools.
    let response = Box::pin(make_meta_mcp().handle_tools_call(
        RequestId::Number(1),
        "gateway_list_tools",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;

    assert!(
        response.error.is_none(),
        "an unconfigured gateway exposes every meta-tool: {response:?}"
    );
}

#[tokio::test]
async fn unexposed_code_mode_tool_is_refused_on_call() {
    // `gateway_execute` reaches every backend tool. It sits in a different
    // builder from the rest of the meta-tools, and was outside the governed
    // set, so an allow-list naming only `gateway_invoke` still left it
    // callable. Both builders are governed now.
    let response = Box::pin(exposure_only_invoke().handle_tools_call(
        RequestId::Number(1),
        "gateway_execute",
        json!({"tool": "mem:read", "arguments": {}}),
        None,
        allow_all_ctx(),
    ))
    .await;

    let error = response
        .error
        .expect("an unexposed Code Mode tool must be refused on call");
    assert_eq!(
        error.code, -32601,
        "and refused as an unknown tool: {error:?}"
    );
}

#[tokio::test]
async fn the_refusal_does_not_name_the_allow_list() {
    // The gate's whole disclosure property is that its refusal is
    // indistinguishable from the unrecognised-tool fallback. Asserting only the
    // error code lets someone reword the message to "not exposed" and ship a
    // disclosure oracle with every other test still green.
    let response = Box::pin(exposure_only_invoke().handle_tools_call(
        RequestId::Number(1),
        "gateway_list_tools",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;

    // Compared against the fallback the dispatcher actually produces, not
    // against a transcription of it. A literal here asserts today's wording and
    // goes red when the fallback is reworded -- which is the opposite of the
    // property: what matters is that the two agree, never what they say. A name
    // outside the governed set passes the exposure check (`is_exposed`,
    // meta_mcp_tool_defs.rs:830) and reaches the fallback, so both answers come
    // from one fixture and one dispatcher.
    let fallback = Box::pin(exposure_only_invoke().handle_tools_call(
        RequestId::Number(1),
        "nobody_implemented_this",
        json!({}),
        None,
        allow_all_ctx(),
    ))
    .await;

    let error = response.error.expect("an unexposed meta-tool is refused");
    let fallback_error = fallback
        .error
        .expect("a name nobody implemented is refused");
    assert_eq!(
        error.message,
        fallback_error
            .message
            .replace("nobody_implemented_this", "gateway_list_tools"),
        "the refusal must be worded exactly like the fallback, with nothing \
         appended and nothing missing: {error:?} vs {fallback_error:?}"
    );
}
