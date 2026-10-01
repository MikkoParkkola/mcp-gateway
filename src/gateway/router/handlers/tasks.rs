// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task eligibility, wire envelopes, and the three `tasks/*` arms.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{AppState, missing_task_error, task_id_param};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::invoke::audit::{DispatchNotes, SettledTask};
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_service::{InputOutcome, OwnedCallerContext, ServiceError, TaskIntent};
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::tasks::{Task, TaskOptions, TaskTransition};
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
    verified_identity.map_or_else(|| owner_key.to_owned(), VerifiedIdentity::stable_actor_id)
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

/// Everything the task-intent decision reads about one `tools/call`.
///
/// Deliberately has **no `Default`**: every field either selects the task path
/// or attributes the durable record, so a defaulted one would let a
/// construction site acquire an unattributed caller by omission.
pub(super) struct TaskIntentRequest<'a> {
    /// Backend tool the call targets; decides task dispatchability.
    pub tool_name: &'a str,
    /// Call arguments, recorded verbatim on the admission request.
    pub arguments: &'a Value,
    /// False for protocol revisions predating tasks, which never create one.
    pub is_modern: bool,
    /// Retry and idempotency fields; a resumed call is not a new task.
    pub retry: &'a RetryFields,
    /// The authenticated caller, absent only when authentication is disabled.
    pub verified_identity: Option<&'a VerifiedIdentity>,
    /// The owner the durable record is admitted under.
    pub owner: &'a str,
    /// Authenticated client, captured into the owned authorizer.
    pub client: Option<&'a AuthenticatedClient>,
    /// `OAuth` agent identity, captured into the owned authorizer.
    pub oauth_agent_identity: Option<&'a OAuthAgentIdentity>,
    /// Client-certificate identity, captured into the owned authorizer.
    pub cert_identity: Option<&'a CertIdentity>,
    /// Name of the API key the caller presented, if any.
    pub api_key_name: Option<&'a str>,
    /// Agent identifier the caller presented, if any.
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// The caller's declared agent label, audited on the task's calls (#2259).
    pub agent_declared: Option<crate::security::DeclaredAgentLabel<'a>>,
    /// Grant subject the worker re-authorizes against.
    pub grant_subject: Option<crate::identity_grants::GrantSubject>,
    /// Whether the caller holds admin rights on this gateway.
    pub is_admin: bool,
    /// Capabilities the client declared on initialize.
    pub input_capabilities: Declared,
    /// Session the call arrived on; an empty one is treated as absent.
    pub session_id: Option<&'a str>,
    /// Protocol revision negotiated for this session.
    pub protocol_revision: Option<&'a str>,
}

/// Build a `'static` intent, or a refusal, or `None` for the ordinary path.
pub(super) fn task_intent_for_call(
    state: &Arc<AppState>,
    id: RequestId,
    req: TaskIntentRequest<'_>,
) -> Result<Option<TaskIntent>, Box<JsonRpcResponse>> {
    if !req.is_modern {
        return Ok(None);
    }
    if req.retry.request_state.is_some() || req.retry.input_responses.is_some() {
        return Ok(None);
    }
    if !is_task_dispatchable(&state.meta_mcp, req.tool_name) {
        return Ok(None);
    }
    // A gateway that HAS identities must not create a task for a caller that
    // presented none: the record would answer to whatever key the unattributed
    // path resolves, and every other unattributed caller reads it. With
    // authentication off there are no identities to confuse, and the owner
    // resolved for this request is the gateway's own constant.
    if state.auth_config.enabled && req.verified_identity.is_none() {
        return Err(Box::new(JsonRpcResponse::error(
            Some(id),
            -32600,
            "task creation requires a verified caller identity",
        )));
    }
    let Some(key) = req.retry.idempotency_key.as_deref() else {
        return Err(Box::new(JsonRpcResponse::error(
            Some(id),
            -32602,
            "task creation requires an idempotency key",
        )));
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
            OwnedRouterAuthorizer::capture(req.client, req.oauth_agent_identity, req.cert_identity),
            req.api_key_name.map(str::to_owned),
            req.agent_id.map(crate::security::OwnedProvenAgentId::from),
            req.agent_declared.map(|label| label.as_str().to_owned()),
            req.grant_subject,
            // No identity is invented for the auth-disabled caller: the owner
            // is a routing decision, and a fake VerifiedIdentity here would
            // reach every control that keys on a *verified* caller.
            req.verified_identity.cloned(),
            // The same owner the durable record is admitted under, handed over
            // rather than re-derived, so the worker's caller and the task agree.
            req.owner.to_owned(),
            crate::gateway::meta_mcp::Authentication::of(req.client),
            crate::security::audit::CredentialKind::of(req.client),
            req.is_admin,
            req.input_capabilities,
            req.session_id
                .filter(|id| !id.is_empty())
                .map(str::to_owned),
            req.protocol_revision.map(str::to_owned),
            req.retry.attestation.clone(),
        ),
        // One builder, shared with the confirmation gate's read-only committed
        // lookup, and the SAME owner string the read arms use. Two renderings
        // of one caller is how an accepted retry's replay misses the task it
        // already owns and starts a second one.
        request: crate::gateway::meta_mcp::task_admission_request(
            req.owner.to_owned(),
            key.to_owned(),
            req.tool_name,
            req.arguments,
        ),
        options,
    }))
}

/// The caller-side context an upstream recovery read re-authorizes with.
///
/// Every field is THIS request's live context. Nothing here is restored from
/// the record: the durable descriptor supplies the target, and the target is
/// then judged against the caller in front of us.
pub(super) struct RecoveryCaller<'a> {
    pub client: Option<&'a AuthenticatedClient>,
    pub oauth_agent_identity: Option<&'a OAuthAgentIdentity>,
    pub cert_identity: Option<&'a CertIdentity>,
    pub api_key_name: Option<&'a str>,
    pub agent_id: Option<crate::security::ProvenAgentId<'a>>,
    /// The request's own declared label: audit attribution only (#2430).
    pub agent_declared: Option<crate::security::DeclaredAgentLabel<'a>>,
    pub grant_subject: Option<crate::identity_grants::GrantSubject>,
    pub verified_identity: Option<&'a VerifiedIdentity>,
    pub is_admin: bool,
    pub input_capabilities: Declared,
    pub session_id: Option<&'a str>,
}

/// Run `check` against THIS request's live policy caller context.
///
/// Every field is the request's own; nothing is restored from a record: a
/// record supplies the target, and the target is then judged against the caller
/// in front of us. Shared by the recovery read and the delivery check so the
/// two cannot build different callers. No prepared-signing context is carried,
/// which is what keeps `check_invocation_policy` running.
fn with_policy_caller<R>(
    state: &Arc<AppState>,
    caller: &RecoveryCaller<'_>,
    check: impl FnOnce(&crate::gateway::meta_mcp::MetaMcpCallerContext<'_>) -> R,
) -> R {
    let router_authorizer = OwnedRouterAuthorizer::capture(
        caller.client,
        caller.oauth_agent_identity,
        caller.cert_identity,
    );
    let borrowed = router_authorizer.borrow(state);
    let authorizer: &(dyn crate::gateway::authz::ToolAuthorizer + Sync) = &borrowed;
    let policy_caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        is_modern: true,
        // This context checks authorization only; it never accesses a cache.
        protocol_revision: None,
        credential_principal: caller.client.map(|client| client.principal.as_str()),
        authentication: crate::gateway::meta_mcp::Authentication::of(caller.client),
        credential_kind: crate::security::audit::CredentialKind::of(caller.client),
        execution: None,
        signing: None,
        authorizer,
        api_key_name: caller.api_key_name,
        agent_id: caller.agent_id,
        agent_declared: None,
        grant_subject: caller.grant_subject.clone(),
        stdio_nonce: None,
        verified_identity: caller.verified_identity,
        is_admin: caller.is_admin,
        input_capabilities: caller.input_capabilities,
        confirmation: crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
        retry: &crate::protocol::mrtr::NO_RETRY,
        task: None,
        era: crate::protocol::meta::Era::Modern,
        channel: &crate::gateway::input_bridge::NoClientChannel,
    };
    check(&policy_caller)
}

pub(super) async fn tasks_get(
    state: &Arc<AppState>,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) -> JsonRpcResponse {
    let Some(task_id) = task_id_param(params) else {
        return missing_task_error(id);
    };
    // The existing owner-scoped lookup FIRST. A foreign or missing identity gets
    // the existing absence response and causes zero upstream calls, because
    // there is nothing below this line for it to reach.
    let committed = match state.tasks.get(owner, task_id) {
        Ok(committed) => committed,
        Err(ServiceError::NotFound) => return missing_task_error(id),
        Err(_) => return store_unavailable(id),
    };
    if committed.task.status() == crate::protocol::tasks::TaskStatus::Working {
        recover_from_upstream(state, owner, task_id, params, caller).await;
    }
    // ONE read after recovery: the snapshot that is authorized is the snapshot
    // returned, so a task that turned terminal during recovery or through a
    // concurrent worker is checked too.
    match state.tasks.get(owner, task_id) {
        Ok(current) => {
            let refusal = with_policy_caller(state, caller, |policy_caller| {
                state.meta_mcp.refuse_stored_delivery(
                    &id,
                    &current,
                    crate::gateway::meta_mcp::upstream::recovery_attestation(params),
                    caller.session_id,
                    policy_caller,
                )
            });
            refusal.unwrap_or_else(|| {
                JsonRpcResponse::success(id, task_envelope(&current.task, "complete"))
            })
        }
        Err(ServiceError::NotFound) => missing_task_error(id),
        Err(_) => store_unavailable(id),
    }
}

/// Re-authorize the ORIGINAL target against THIS caller, then allow at most one
/// bounded read-only upstream query.
///
/// Zero queries when: no adapter claims the backend, the row carries no
/// consistent durable handle, or the current `RouterAuthorizer`, tool policy,
/// active profile or attestation checker refuses the original target. A
/// gateway-owned upstream credential grants the caller no authority, and
/// authorizing `tasks/get` alone is explicitly not enough — the check below is
/// the invocation check for the original call.
async fn recover_from_upstream(
    state: &Arc<AppState>,
    owner: &str,
    task_id: &str,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) {
    let Ok(task_owner) = state.tasks.owner(owner) else {
        return;
    };
    let executor = &state.task_executor;
    let Ok(target) = executor.recovery_target(task_owner.as_digest(), task_id) else {
        return;
    };

    // Scoped inside the helper: the rebuilt authorizer and caller context exist
    // only for the verdict, and are gone before the query's await.
    let authorized = with_policy_caller(state, caller, |policy_caller| {
        // A fresh token for THIS read, from the gateway-namespaced recovery
        // field. Missing or expired denies before any query; nothing spent is
        // restored, and no saved prepared-signing context is reconstructed.
        let policy_args = crate::gateway::meta_mcp::upstream::recovery_policy_args(
            &target.backend,
            &target.tool,
            &target.arguments,
            crate::gateway::meta_mcp::upstream::recovery_attestation(params),
        );
        state
            .meta_mcp
            .check_invocation_policy(&policy_args, caller.session_id, policy_caller)
            .is_ok()
    });
    if !authorized {
        tracing::info!(
            task_id,
            "recovery read refused by current policy; zero upstream queries"
        );
    }

    let (server, tool) = (target.backend.clone(), target.tool.clone());
    let meta_mcp = Arc::clone(&state.meta_mcp);
    let api_key_name = caller.api_key_name.map(str::to_owned);
    let trace = task_id.to_owned();
    // The failure half of the same processing, from the same implementation.
    let error_policy = {
        let (meta_mcp, server, tool) = (Arc::clone(&state.meta_mcp), server.clone(), tool.clone());
        let (api_key_name, trace) = (api_key_name.clone(), trace.clone());
        move |error| {
            meta_mcp.recover_task_error(&server, &tool, api_key_name.as_deref(), &trace, error)
        }
    };
    // MIN.1 gap 1: the settlement record, written before the commit and
    // attributed to the principal the task was admitted under.
    let settle = {
        let (meta_mcp, server, tool) = (Arc::clone(&state.meta_mcp), server.clone(), tool.clone());
        let (task_id, owner) = (task_id.to_owned(), owner.to_owned());
        move |event: TaskTransition, notes: DispatchNotes| async move {
            let task = SettledTask {
                server: &server,
                tool: &tool,
                id: &task_id,
            };
            meta_mcp.audit_settlement(task, event, &notes, &owner).await
        }
    };
    let _ = executor
        .recover_upstream_read(
            task_owner.as_digest(),
            task_id,
            authorized,
            move |result| {
                // The same output/firewall/contract/inspection processing a live
                // dispatch applies, from the same implementation.
                meta_mcp
                    .recover_task_result(&server, &tool, api_key_name.as_deref(), &trace, result)
                    .map_err(|error| crate::protocol::JsonRpcError {
                        code: -32603,
                        message: error.to_string(),
                        data: None,
                    })
            },
            error_policy,
            settle,
            crate::gateway::meta_mcp::upstream::QUERY_DEADLINE,
        )
        .await;
}

pub(super) async fn tasks_update(
    state: &Arc<AppState>,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) -> JsonRpcResponse {
    let Some(task_id) = task_id_param(params) else {
        return missing_task_error(id);
    };
    let answers = params.and_then(|params| params.get("inputResponses"));
    if !crate::protocol::mrtr::input_responses_nonempty(answers) {
        return match state.tasks.update(owner, task_id, 0, json!({})).await {
            Ok(_) => JsonRpcResponse::success(id, ack_complete()),
            Err(ServiceError::NotFound) => missing_task_error(id),
            Err(_) => store_unavailable(id),
        };
    }
    let Some(Value::Object(answers)) = answers.cloned() else {
        return JsonRpcResponse::error(Some(id), -32602, "inputResponses must be an object");
    };
    // Owner-scoped first: a foreign or absent task is answered as absent
    // before anything about a round is said.
    match state.tasks.get(owner, task_id) {
        Ok(current)
            if current.task.status() == crate::protocol::tasks::TaskStatus::InputRequired => {}
        Ok(current) => return settled_or_no_round(id, &current.task),
        Err(ServiceError::NotFound) => return missing_task_error(id),
        Err(_) => return store_unavailable(id),
    }
    let outcome = state
        .task_executor
        .provide_input(
            update_caller(state, owner, params, caller),
            owner,
            task_id,
            answers,
        )
        .await;
    match outcome {
        InputOutcome::Accepted => JsonRpcResponse::success(id, ack_complete()),
        // A cancel may have landed between the look-up above and the write.
        InputOutcome::NotOutstanding => match state.tasks.get(owner, task_id) {
            Ok(current) => settled_or_no_round(id, &current.task),
            Err(ServiceError::NotFound) => missing_task_error(id),
            Err(_) => store_unavailable(id),
        },
        InputOutcome::TooLarge => JsonRpcResponse::error(
            Some(id),
            -32602,
            "inputResponses exceed the task record size limit",
        ),
        InputOutcome::Busy => JsonRpcResponse::error(Some(id), -32603, "task busy, retry"),
        InputOutcome::PoolFull => {
            JsonRpcResponse::error(Some(id), -32603, "task worker pool is full, retry")
        }
        InputOutcome::Closed(closed) => JsonRpcResponse::error(
            Some(id),
            -32602,
            format!(
                "inputResponses refused: {}; the round is closed",
                closed.reason()
            ),
        ),
        InputOutcome::NotFound => missing_task_error(id),
        InputOutcome::Unavailable => store_unavailable(id),
    }
}

/// A late answer to a settled task is told how it settled, with the reason it
/// carries (#2429); a live task without a round gets the plain refusal.
fn settled_or_no_round(id: RequestId, task: &Task) -> JsonRpcResponse {
    let wire = serde_json::to_value(task.wire()).unwrap_or_default();
    let status = wire
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !matches!(status, "completed" | "failed" | "cancelled") {
        return no_round(id);
    }
    let reason = wire
        .get("statusMessage")
        .and_then(Value::as_str)
        .map_or_else(String::new, |message| format!(": {message}"));
    JsonRpcResponse::error(
        Some(id),
        -32602,
        format!("inputResponses refused: the task is {status}{reason}"),
    )
}

fn no_round(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(
        Some(id),
        -32602,
        "inputResponses are not accepted until an input round is outstanding",
    )
}

/// The resume's caller: THIS update request's live identity, the bundle
/// `tasks/get` re-authorizes with, never the context that created the task.
fn update_caller(
    state: &Arc<AppState>,
    owner: &str,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) -> OwnedCallerContext {
    OwnedCallerContext::new(
        Arc::downgrade(state),
        OwnedRouterAuthorizer::capture(
            caller.client,
            caller.oauth_agent_identity,
            caller.cert_identity,
        ),
        caller.api_key_name.map(str::to_owned),
        caller
            .agent_id
            .map(crate::security::OwnedProvenAgentId::from),
        caller.agent_declared.map(|label| label.as_str().to_owned()),
        caller.grant_subject.clone(),
        caller.verified_identity.cloned(),
        owner.to_owned(),
        crate::gateway::meta_mcp::Authentication::of(caller.client),
        crate::security::audit::CredentialKind::of(caller.client),
        caller.is_admin,
        caller.input_capabilities,
        caller
            .session_id
            .filter(|id| !id.is_empty())
            .map(str::to_owned),
        // No classifier revision: a resumed result is never response-cached.
        None,
        RetryFields::from_params(params).attestation,
    )
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
