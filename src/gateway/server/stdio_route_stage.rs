// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The route stage stdio runs before admission, in `/mcp`'s order
//! (route-check-parity P3; MIK-8149, MIK-8160, MIK-8326): authorize every
//! target, scan it with the request firewall, then X14 for a task-augmented
//! call. A refusal here has taken no idempotency key, lease or task. The
//! signing nonce is admitted before this stage (a bad nonce stays cheap to
//! refuse, MIK-7377.SIGNING.5 row 40), and the caller gives it back when this
//! stage answers (lead ruling, P3). The dispatch chokepoint re-runs
//! authorization and the stateless content scan at send time, as it does for
//! every route.

use serde_json::Value;

use super::{Gateway, StdioClient};
use crate::gateway::meta_mcp::invoke::RouteRefusal;
use crate::gateway::meta_mcp::{
    LOCAL_OPERATOR_PRINCIPAL, MetaMcp, MetaMcpCallerContext, TaskConfirmation,
    TaskConfirmationRequest, error_response_preserving_status,
};
use crate::protocol::mrtr::RetryFields;
use crate::protocol::{JsonRpcResponse, RequestId};

/// What the route stage decided for one stdio `tools/call`.
pub(super) enum RouteStage {
    /// Admit the call. `Some` carries X14's granted retry fields, with the
    /// confirmation metadata stripped, for admission to key on.
    Proceed(Option<RetryFields>),
    /// Answer with this and admit nothing.
    Answer(JsonRpcResponse),
}

impl Gateway {
    /// Run the route stage for one stdio `tools/call` of `tool_name` with its
    /// merged `arguments` and its `task` member, if any.
    pub(super) async fn stdio_route_stage(
        meta_mcp: &MetaMcp,
        id: &RequestId,
        (tool_name, arguments, task): (&str, &Value, Option<&Value>),
        caller: &MetaMcpCallerContext<'_>,
        client: StdioClient<'_>,
    ) -> RouteStage {
        let session_id = client.session_id;
        let scope = caller.scope();
        let targets =
            crate::gateway::router::backend_tool_targets_for_call(meta_mcp, tool_name, arguments);
        for target in &targets {
            let checked = target.as_target();
            // The one route-stage authorize `/mcp` also runs. A surfaced name
            // this caller may not invoke answers as a name that matches no
            // tool, so neither the firewall nor X14 can confirm it exists.
            if let Err(RouteRefusal::Withheld(error) | RouteRefusal::Refused(error)) = meta_mcp
                .authorize_route_target(
                    scope,
                    Some(session_id),
                    tool_name,
                    (checked.server, checked.tool),
                    checked.arguments,
                )
            {
                return RouteStage::Answer(error_response_preserving_status(id.clone(), &error));
            }
            // The stateful controls key on the one client this process
            // serves; an empty identity would refuse every call unscored.
            #[cfg(feature = "firewall")]
            if let Some((code, message)) = meta_mcp.route_request_scan(
                session_id,
                (checked.server, checked.tool, checked.arguments),
                (
                    super::STDIO_CREDENTIAL_PRINCIPAL,
                    super::STDIO_CREDENTIAL_PRINCIPAL,
                ),
            ) {
                let refusal = crate::Error::Forbidden {
                    code,
                    status: 400,
                    message,
                };
                return RouteStage::Answer(error_response_preserving_status(id.clone(), &refusal));
            }
        }
        // X14 decides a task-augmented call, so it needs the session's task
        // store; without one the call is synchronous and X14 has nothing to say.
        let Some(tasks) = client.tasks else {
            return RouteStage::Proceed(None);
        };
        let confirmation = meta_mcp
            .confirm_destructive_task(&TaskConfirmationRequest {
                id: id.clone(),
                tool_name,
                arguments,
                task,
                retry: caller.retry,
                // The derivation continuations bind stdio by (`Stdio { nonce }`),
                // so a grant and a continuation name one caller one way.
                principal: caller.principal_source(None),
                // The owner stdio admits its tasks under (`stdio_tasks::intent`).
                admission_actor: Some(LOCAL_OPERATOR_PRINCIPAL),
                scope,
                session_id: Some(session_id),
                input_capabilities: caller.input_capabilities,
                is_modern: caller.is_modern,
                admission: tasks.service.admission(),
            })
            .await;
        match confirmation {
            TaskConfirmation::NotRequired => RouteStage::Proceed(None),
            TaskConfirmation::Granted(granted) => RouteStage::Proceed(Some(granted)),
            TaskConfirmation::Answer(answer) => RouteStage::Answer(*answer),
        }
    }
}
