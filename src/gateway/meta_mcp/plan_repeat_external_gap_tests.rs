// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8406 gap pin (lead ruling 2026-10-12): on MIK-8392 STORED.1's code, a
//! repeated plan task whose recorded target is an EXTERNAL account is let
//! through by the repeated-call judgement, while the same call made live is
//! refused. That target stays in the catalogue, so `refuse_stored_repeat`
//! never withholds it, and plan tools skip STORED.2's account check, so the
//! stored output is served. MIK-8406 flips this row; until then it pins the
//! gap. No network: the judgement is called directly.

use serde_json::json;

use super::MetaMcpCallerContext;
use super::account_resolver_fixture::direct_bridge::{
    Binding, DirectAccountGateway, EXTERNAL_BACKEND, Second,
};
use crate::gateway::task_service::{CommittedTask, Target, Task};
use crate::protocol::RequestId;

static ALLOW_ALL: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

/// An anonymous caller with no verified identity, as the fixture's own
/// `caller_as(None, None)` builds it.
fn anonymous() -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        task: None,
        signing: None,
        execution: None,
        credential_principal: None,
        authentication: super::Authentication::Anonymous,
        credential_kind: crate::security::audit::CredentialKind::None,
        is_modern: false,
        protocol_revision: Some(crate::protocol::PROTOCOL_VERSION),
        authorizer: &ALLOW_ALL,
        stdio_nonce: None,
        caller_key: None,
        verified_identity: None,
        api_key_name: None,
        agent_id: None,
        agent_declared: None,
        grant_subject: None,
        is_admin: false,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
        input_capabilities: crate::protocol::meta::Declared::NONE,
        retry: &crate::protocol::mrtr::NO_RETRY,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        era: crate::protocol::meta::Era::Legacy,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    }
}

/// A finished `gateway_run_playbook` task whose one recorded call went to
/// the external backend.
fn finished_plan_task() -> CommittedTask {
    let mut task = Task::create("gateway_run_playbook");
    task.complete(json!({"content": [{"type": "text", "text": "stored plan output"}]}));
    CommittedTask {
        task,
        revision: 1,
        targets: vec![Target {
            server: EXTERNAL_BACKEND.to_owned(),
            tool: "read".to_owned(),
        }],
        targets_recorded: true,
        output_free: false,
        error_author: None,
        owner_digest: String::new(),
        gateway_writes: crate::gateway::gateway_writes::WriteRecord::default(),
    }
}

/// Guard (lead ruling 2026-10-12): for a caller the catalogue does not show
/// the external tool to, the repeated plan task answers exactly what its live
/// twin answers (-32601 with the tool withheld today). Proven on STORED.1's
/// code; the open gap is the visible-tool case (router row
/// `plan_repeat_unavailable_account_is_mik_8406_gap`).
#[tokio::test]
async fn plan_repeat_hidden_external_tool_answers_as_its_live_twin() {
    let auth = crate::config::AuthConfig::default();
    let mut gateway =
        DirectAccountGateway::with_second(auth, &Binding::Connected, Second::External);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "read", "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(EXTERNAL_BACKEND)
        .expect("the external backend is registered")
        .store_shared_tools_for_test(vec![tool]);
    let meta = gateway.take_meta();
    let caller = anonymous();
    let live = meta
        .invoke_tool(
            &json!({"server": EXTERNAL_BACKEND, "tool": "read", "arguments": {"folder": "inbox"}}),
            None,
            &caller,
        )
        .await;
    let Err(crate::Error::JsonRpc {
        code: live_code,
        message: live_message,
        ..
    }) = live
    else {
        panic!("premise: the live call is refused with a JSON-RPC error: {live:?}");
    };
    assert_eq!(
        gateway.tool_calls_to(EXTERNAL_BACKEND),
        0,
        "premise: the live call sent nothing"
    );
    let repeat = meta.refuse_stored_repeat(
        &RequestId::Number(1),
        &finished_plan_task(),
        None,
        None,
        &caller,
    );
    let error = repeat
        .and_then(|response| response.error)
        .unwrap_or_else(|| {
            panic!("the repeat let the stored plan task through; its live twin refused")
        });
    assert_eq!(
        error.code, live_code,
        "the repeat and its live twin differ in code"
    );
    assert!(
        error.message.ends_with(&live_message),
        "the repeat and its live twin differ: {} vs {live_message}",
        error.message
    );
}
