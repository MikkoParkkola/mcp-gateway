// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio task worker re-checks the current tool policy at run time
//! (route-check-parity P3, r2.1 H1): the route stage refuses a denied tool at
//! submit, and the dispatch chokepoint refuses it again when a task reaches
//! its worker. On the stdio task fixture (`owner2_stdio_tasks`).

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, DENIED, fixture, intent, keyed, wait_terminal};
use crate::gateway::Gateway;
use crate::gateway::meta_mcp::LOCAL_OPERATOR_PRINCIPAL;
use crate::protocol::RequestId;
use crate::protocol::meta::Declared;
use crate::security::{ToolPolicy, ToolPolicyConfig};

/// U5b: the worker re-checks the current tool policy at run time (the dispatch
/// chokepoint; r2.1 H1). U5's denied tool is now refused at submit, so this
/// row submits the task below the route stage, as a task admitted before a
/// policy change arrives at its worker: it settles failed, never sent.
#[tokio::test]
async fn a_stdio_task_worker_refuses_a_tool_the_current_policy_denies() {
    let denying = ToolPolicy::from_config(&ToolPolicyConfig {
        deny: vec![DENIED.to_string()],
        ..ToolPolicyConfig::default()
    });
    let fixture = Box::pin(fixture(Some(denying))).await;
    let retry = keyed("u5b");
    let authorizer = crate::gateway::authz::ToolPolicyAuthorizer {
        tool_policy: &fixture.policy,
    };
    let mut caller = Gateway::build_stdio_caller_context(
        true,
        None,
        &authorizer,
        &retry,
        &crate::protocol::meta::RequestShape::Legacy,
        super::super::StdioClient {
            session_id: super::super::STDIO_SESSION_ID,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: Declared::NONE,
            tasks: Some(&fixture.tasks),
            modern: false,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
    );
    caller.task = Some(intent(&fixture.tasks, DENIED, &retry));
    let arguments = json!({"server": BACKEND, "tool": DENIED, "arguments": {}});
    let created = fixture
        .meta
        .handle_tools_call_ref(
            RequestId::Number(1),
            "gateway_invoke",
            std::borrow::Cow::Borrowed(&arguments),
            Some(super::super::STDIO_SESSION_ID),
            caller,
        )
        .await;
    let id = created
        .result
        .as_ref()
        .and_then(|result| result.get("taskId"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("a task handle: {created:?}"))
        .to_owned();
    let id = wait_terminal(&fixture, id).await;
    let task = fixture
        .tasks
        .service
        .get(LOCAL_OPERATOR_PRINCIPAL, &id)
        .expect("the local operator owns its task");
    assert!(
        matches!(
            task.task.status(),
            crate::protocol::tasks::TaskStatus::Failed
        ),
        "the worker did not refuse the denied tool: {:?}",
        task.task.status()
    );
    assert_eq!(
        fixture.rounds.load(Ordering::SeqCst),
        0,
        "the denied call was sent"
    );
}
