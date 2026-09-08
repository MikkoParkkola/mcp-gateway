// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task eligibility, wire envelopes, and the three `tasks/*` arms.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{AppState, missing_task_error, task_id_param};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::{OwnedCallerContext, ServiceError, TaskIntent};
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::tasks::{Task, TaskOptions};
use crate::protocol::{JsonRpcResponse, RequestId};

/// Tools that may be handed to the worker after the confirmation gate.
fn is_task_dispatchable(meta_mcp: &MetaMcp, tool_name: &str) -> bool {
    matches!(
        tool_name,
        "gateway_invoke" | "gateway_execute" | "gateway_run_playbook"
    ) || meta_mcp.surfaced_tool_server(tool_name).is_some()
}

/// Admission principal: verified identity when present, else the session key.
pub(super) fn task_principal(
    verified_identity: Option<&VerifiedIdentity>,
    owner_key: &str,
) -> String {
    verified_identity
        .map(VerifiedIdentity::stable_actor_id)
        .unwrap_or_else(|| owner_key.to_owned())
}

/// The owner a gateway with authentication switched off records tasks under.
///
/// A gateway-internal constant, never anything the request carried: an owner
/// derived from request data would let a caller name its own bucket. It cannot
/// collide with a verified identity (`stable_actor_id` always prefixes `oidc:`)
/// nor with a session key (`credential:`), and it is non-empty because the
/// admission request refuses an empty principal.
pub(super) const AUTH_DISABLED_TASK_OWNER: &str = "local:auth-disabled:tasks:v1";

/// The ONE owner every task-touching arm of a request uses.
///
/// Resolved once per request and then reused for create, get, update, cancel,
/// idempotent replay and subscription ownership. Two renderings of one caller
/// is how a task is created under one string and looked up under another.
pub(super) fn route_task_owner(
    state: &AppState,
    verified_identity: Option<&VerifiedIdentity>,
    owner_key: &str,
) -> String {
    match verified_identity {
        Some(identity) => identity.stable_actor_id(),
        // No identity exists to be kept apart when authentication is off, and
        // pooling those callers is the operator's own configuration choice.
        // With authentication ON the session key decides, and an empty one is
        // refused upstream rather than pooled here.
        None if !state.auth_config.enabled => AUTH_DISABLED_TASK_OWNER.to_owned(),
        None => task_principal(None, owner_key),
    }
}

/// `Task::wire()` plus the envelope discriminator the arm supplies.
pub(super) fn task_envelope(task: &Task, result_type: &str) -> Value {
    let mut value = serde_json::to_value(task.wire()).unwrap_or(Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("resultType".into(), json!(result_type));
    }
    value
}

fn ack_complete() -> Value {
    json!({ "resultType": "complete" })
}

fn store_unavailable(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(Some(id), -32603, "task store unavailable")
}

/// Build a `'static` intent, or a refusal, or `None` for the ordinary path.
pub(super) fn task_intent_for_call(
    state: &Arc<AppState>,
    id: RequestId,
    tool_name: &str,
    arguments: &Value,
    is_modern: bool,
    retry: &RetryFields,
    verified_identity: Option<&VerifiedIdentity>,
    owner: &str,
    client: Option<&AuthenticatedClient>,
    oauth_agent_identity: Option<&OAuthAgentIdentity>,
    cert_identity: Option<&CertIdentity>,
    api_key_name: Option<&str>,
    agent_id: Option<&str>,
    grant_subject: Option<crate::identity_grants::GrantSubject>,
    is_admin: bool,
    input_capabilities: Declared,
    session_id: Option<&str>,
) -> Result<Option<TaskIntent>, JsonRpcResponse> {
    if !is_modern {
        return Ok(None);
    }
    if retry.request_state.is_some() || retry.input_responses.is_some() {
        return Ok(None);
    }
    if !is_task_dispatchable(&state.meta_mcp, tool_name) {
        return Ok(None);
    }
    // A gateway that HAS identities must not create a task for a caller that
    // presented none: the record would answer to whatever key the unattributed
    // path resolves, and every other unattributed caller reads it. With
    // authentication off there are no identities to confuse, and the owner
    // resolved for this request is the gateway's own constant.
    if state.auth_config.enabled && verified_identity.is_none() {
        return Err(JsonRpcResponse::error(
            Some(id),
            -32600,
            "task creation requires a verified caller identity",
        ));
    }
    let Some(key) = retry.idempotency_key.as_deref() else {
        return Err(JsonRpcResponse::error(
            Some(id),
            -32602,
            "task creation requires an idempotency key",
        ));
    };
    let tasks = state.live_config.get();
    let options = TaskOptions {
        ttl_ms: (tasks.tasks.default_ttl_ms > 0).then_some(tasks.tasks.default_ttl_ms),
        poll_interval_ms: (tasks.tasks.poll_interval_ms > 0)
            .then_some(tasks.tasks.poll_interval_ms),
    };
    Ok(Some(TaskIntent {
        executor: Arc::clone(&state.task_executor),
        owned: OwnedCallerContext::new(
            Arc::downgrade(state),
            OwnedRouterAuthorizer::capture(client, oauth_agent_identity, cert_identity),
            api_key_name.map(str::to_owned),
            agent_id.map(str::to_owned),
            grant_subject,
            // No identity is invented for the auth-disabled caller: the owner
            // is a routing decision, and a fake VerifiedIdentity here would
            // reach every control that keys on a *verified* caller.
            verified_identity.cloned(),
            is_admin,
            input_capabilities,
            session_id.filter(|id| !id.is_empty()).map(str::to_owned),
        ),
        // One builder, shared with the confirmation gate's read-only committed
        // lookup, and the SAME owner string the read arms use. Two renderings
        // of one caller is how an accepted retry's replay misses the task it
        // already owns and starts a second one.
        request: crate::gateway::meta_mcp::task_admission_request(
            owner.to_owned(),
            key.to_owned(),
            tool_name,
            arguments,
        ),
        options,
    }))
}

pub(super) fn tasks_get(
    state: &AppState,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(task_id) = task_id_param(params) else {
        return missing_task_error(id);
    };
    match state.tasks.get(owner, task_id) {
        Ok(committed) => JsonRpcResponse::success(id, task_envelope(&committed.task, "complete")),
        Err(ServiceError::NotFound) => missing_task_error(id),
        Err(_) => store_unavailable(id),
    }
}

pub(super) async fn tasks_update(
    state: &AppState,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(task_id) = task_id_param(params) else {
        return missing_task_error(id);
    };
    if input_responses_nonempty(params) {
        return JsonRpcResponse::error(
            Some(id),
            -32602,
            "inputResponses are not accepted until an input round is outstanding",
        );
    }
    match state.tasks.update(owner, task_id, 0, json!({})).await {
        Ok(_) => JsonRpcResponse::success(id, ack_complete()),
        Err(ServiceError::NotFound) => missing_task_error(id),
        Err(_) => store_unavailable(id),
    }
}

pub(super) async fn tasks_cancel(
    state: &AppState,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(task_id) = task_id_param(params) else {
        return missing_task_error(id);
    };
    let committed = match state.tasks.get(owner, task_id) {
        Ok(committed) => committed,
        Err(ServiceError::NotFound) => return missing_task_error(id),
        Err(_) => return store_unavailable(id),
    };
    match state
        .task_executor
        .cancel(owner, task_id, committed.revision)
        .await
    {
        Ok(_) => JsonRpcResponse::success(id, ack_complete()),
        Err(ServiceError::NotFound) => missing_task_error(id),
        Err(_) => store_unavailable(id),
    }
}

fn input_responses_nonempty(params: Option<&Value>) -> bool {
    params
        .and_then(|params| params.get("inputResponses"))
        .is_some_and(|value| match value {
            Value::Object(map) => !map.is_empty(),
            Value::Array(items) => !items.is_empty(),
            Value::Null => false,
            _ => true,
        })
}
