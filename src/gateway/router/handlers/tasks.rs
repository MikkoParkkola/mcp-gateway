// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task eligibility, the task intent, and the HTTP glue of the three `tasks/*` arms.

use std::sync::Arc;

use serde_json::Value;

use super::AppState;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::audit::{DispatchNotes, SettledTask};
use crate::gateway::oauth::AgentIdentity as OAuthAgentIdentity;
use crate::gateway::router::OwnedRouterAuthorizer;
use crate::gateway::task_route::{TaskOwnerText, TaskRoute, is_task_dispatchable};
use crate::gateway::task_service::{OwnedCallerContext, TaskIntent};
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::meta::Declared;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::tasks::{TaskOptions, TaskTransition};
use crate::protocol::{JsonRpcResponse, RequestId};

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

/// The owner key of a stateless task: the validated API-key credential. Only
/// `route_task_owner` reads it (the firewall keys on `identity::caller_key`);
/// tasks keep this encoding so an upgrade does not orphan stored ones. Empty
/// when the caller is unauthenticated: that is not an identity.
pub(super) fn session_owner_key(
    client: Option<&crate::gateway::auth::AuthenticatedClient>,
) -> String {
    client.map_or_else(String::new, |c| {
        if c.authenticated && !c.principal.is_empty() {
            format!(
                "{}{}",
                crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,
                c.principal
            )
        } else {
            String::new()
        }
    })
}

/// The owner key a task records when the caller has no OIDC identity: the
/// proven subject when one resolved, else the credential.
///
/// A subject outranks the credential as it does for sessions
/// (`handlers::owner::owner_of`), so two people a trusted proxy, Cloudflare
/// Access or a client certificate names behind one shared key never own one
/// task (MIK-7967). A subject only SPLITS a credential's bucket: with no
/// credential the key stays empty, so a subject header alone owns nothing and
/// the unattributed gate still refuses it.
pub(super) fn task_owner_key(
    subject: Option<&crate::identity_grants::GrantSubject>,
    cert: Option<&CertIdentity>,
    client: Option<&AuthenticatedClient>,
) -> String {
    let credential = session_owner_key(client);
    if credential.is_empty() {
        return credential;
    }
    super::super::identity::subject_key(subject, cert).unwrap_or(credential)
}

/// The ONE owner every task-touching arm of a request uses.
///
/// Resolved once per request and then reused for create, get, update, cancel,
/// idempotent replay and subscription ownership. Two renderings of one caller
/// is how a task is created under one string and looked up under another.
pub(super) fn route_task_owner(
    state: &AppState,
    verified_identity: Option<&VerifiedIdentity>,
    agent: Option<&OAuthAgentIdentity>,
    owner_key: &str,
) -> String {
    match verified_identity {
        Some(identity) => identity.stable_actor_id(),
        // Agent auth runs whether or not gateway auth does, so with gateway
        // auth off a validated agent JWT is still an identity: pooling it with
        // every other agent would let one read and cancel another's tasks
        // (MIK-8031).
        None if !state.auth_config.enabled => agent.map_or_else(
            || AUTH_DISABLED_TASK_OWNER.to_owned(),
            |agent| agent_task_owner(&agent.client_id),
        ),
        // With authentication ON the owner key decides (`task_owner_key`:
        // proven subject, else credential), and an empty one is refused
        // upstream rather than pooled here.
        None => task_principal(None, owner_key),
    }
}

/// The owner of a validated agent's tasks on a gateway with auth off.
///
/// The `client_id` enters as its SHA-256 digest: a fixed 74-byte owner fits task
/// admission's metadata bound whatever the id's length, and no `client_id` can
/// spell another's owner. Prefixed apart from `oidc:`, `credential:`,
/// `subject:` and `local:`. `client_id` is the agent registry's key, so two
/// agents never share one owner.
fn agent_task_owner(client_id: &str) -> String {
    format!(
        "agent-jwt:{}",
        crate::hashing::sha256_hex(client_id.as_bytes())
    )
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
    /// The request's meta-tool surface, which the task's recovery hints follow.
    pub surface_request: crate::gateway::recovery::SurfaceRequest,
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
    // path resolves, and every other unattributed caller reads it. "None" is
    // an EMPTY resolved owner, not a missing OIDC identity: an API-key caller
    // owns its tasks as `credential:<principal>` (`route_task_owner`), and
    // checking the same string the record is admitted under keeps one
    // rendering of the caller (MIK-7967). With authentication off the owner
    // is a validated agent's own key or the gateway's constant, never empty.
    if state.auth_config.enabled && req.owner.is_empty() {
        return Err(Box::new(JsonRpcResponse::error(
            Some(id),
            -32600,
            "task creation requires an authenticated caller",
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
    let caller_key = super::super::identity::caller_key(
        req.grant_subject.as_ref(),
        req.cert_identity,
        req.client,
    );
    Ok(Some(TaskIntent {
        executor: Arc::clone(&state.task_executor),
        owned: OwnedCallerContext::new(
            crate::gateway::task_service::host::TaskHost::Http(Arc::downgrade(state)),
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
        )
        .with_caller_key(Some(caller_key))
        .with_surface_request(req.surface_request),
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
    let caller_key = super::super::identity::caller_key(
        caller.grant_subject.as_ref(),
        caller.cert_identity,
        caller.client,
    );
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
        caller_key: Some(caller_key.as_str()).filter(|key| !key.is_empty()),
        verified_identity: caller.verified_identity,
        is_admin: caller.is_admin,
        surface_request: crate::gateway::recovery::SurfaceRequest::Configured,
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
    let owner_text = TaskOwnerText::Http(owner.to_owned());
    route(state, &owner_text)
        .get(
            id.clone(),
            params,
            |task_id| recover_from_upstream(state, owner, task_id, params, caller),
            |current| {
                with_policy_caller(state, caller, |policy_caller| {
                    state.meta_mcp.refuse_stored_delivery(
                        &id,
                        current,
                        crate::gateway::meta_mcp::upstream::recovery_attestation(params),
                        caller.session_id,
                        policy_caller,
                    )
                })
            },
            |current, frame| state.meta_mcp.scan_task_read(current, frame),
        )
        .await
}

fn route<'a>(state: &'a Arc<AppState>, owner: &'a TaskOwnerText) -> TaskRoute<'a> {
    TaskRoute {
        service: &state.tasks,
        executor: &state.task_executor,
        owner,
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
            meta_mcp.recover_task_error_with(&server, &tool, api_key_name.as_deref(), &trace, error)
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
            meta_mcp
                .audit_settlement_kept(task, event, &notes, &owner)
                .await
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
                    .map_err(|error| {
                        crate::gateway::meta_mcp::response_security::recovered_result_error(&error)
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
    // The update request's own `?codemode=`, which the resumed call's hints follow.
    (params, surface_request): (Option<&Value>, crate::gateway::recovery::SurfaceRequest),
    caller: &RecoveryCaller<'_>,
) -> JsonRpcResponse {
    let owner_text = TaskOwnerText::Http(owner.to_owned());
    route(state, &owner_text)
        .update(id, params, |owner| {
            update_caller(state, owner, params, caller).with_surface_request(surface_request)
        })
        .await
}

/// The resume's caller: THIS update request's live identity, the bundle
/// `tasks/get` re-authorizes with, never the context that created the task.
fn update_caller(
    state: &Arc<AppState>,
    owner: &str,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) -> OwnedCallerContext {
    let resume_key = super::super::identity::caller_key(
        caller.grant_subject.as_ref(),
        caller.cert_identity,
        caller.client,
    );
    // A resume is activity: renew the deadline that reclaims this caller's
    // hint state, as a direct call does, so a task parked past the idle sweep
    // does not write under a key nothing tracks.
    if let Some(ref lifecycle) = state.session_lifecycle
        && !resume_key.is_empty()
    {
        use crate::gateway::session_lifecycle::{IDLE_TTL, now_unix};
        lifecycle.track(resume_key.clone(), now_unix() + IDLE_TTL.as_secs());
    }
    OwnedCallerContext::new(
        crate::gateway::task_service::host::TaskHost::Http(Arc::downgrade(state)),
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
    // The resuming request's own key, as everything else here (G4).
    .with_caller_key(Some(resume_key))
}

pub(super) async fn tasks_cancel(
    state: &Arc<AppState>,
    owner: &str,
    id: RequestId,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let owner_text = TaskOwnerText::Http(owner.to_owned());
    route(state, &owner_text).cancel(id, params).await
}

#[cfg(test)]
mod agent_owner_tests;
#[cfg(test)]
mod frame_subject_tests;
#[cfg(test)]
mod intent_tests;
#[cfg(test)]
mod scope_tests;

/// The frames a listener that named tasks receives for `notifications/tasks`.
///
/// Owns what the stream needs after the request that opened it is gone: the
/// owner, the immutable identity facts, and the state. The credential is NOT
/// snapshotted: each delivery is handed the client the listener's credential
/// resolves to at that moment, so a revoked role or narrowed scope applies to
/// the very next frame. (MIK-7778 PAYLOAD.1)
struct TaskFrameSource {
    state: Arc<AppState>,
    owner: String,
    oauth_agent_identity: Option<OAuthAgentIdentity>,
    cert_identity: Option<CertIdentity>,
    agent_id: Option<crate::security::OwnedProvenAgentId>,
    grant_subject: Option<crate::identity_grants::GrantSubject>,
    verified_identity: Option<VerifiedIdentity>,
    input_capabilities: Declared,
    session_id: Option<String>,
    /// The principal the stream was opened as. The credential is re-resolved
    /// at delivery by the listener's own precedence (a dashboard session
    /// before a bearer), which the HTTP middleware does not share; a reader
    /// who now resolves to anyone else is sent task id and status only.
    principal: Option<String>,
    /// The caller's identity came from something nothing re-validates after
    /// the stream opened (an agent token, a proxy or gateway assertion), so
    /// such a reader is sent task id and status only. An API key, a
    /// certificate and a verified bearer re-resolve at delivery.
    status_only: bool,
}

pub(super) fn task_frames(
    state: &Arc<AppState>,
    owner: &str,
    caller: &RecoveryCaller<'_>,
) -> Arc<dyn crate::gateway::streaming::TaskFrames> {
    Arc::new(TaskFrameSource {
        state: Arc::clone(state),
        owner: owner.to_owned(),
        oauth_agent_identity: caller.oauth_agent_identity.cloned(),
        cert_identity: caller.cert_identity.cloned(),
        agent_id: caller
            .agent_id
            .map(crate::security::OwnedProvenAgentId::from),
        grant_subject: caller.grant_subject.clone(),
        verified_identity: caller.verified_identity.cloned(),
        input_capabilities: caller.input_capabilities,
        session_id: caller.session_id.map(str::to_owned),
        principal: caller.client.map(|client| client.principal.clone()),
        // What cannot be re-proven at delivery is not trusted at delivery: an
        // agent token, or a grant subject that is not the API key, the
        // connection's certificate, or the verified bearer identity (whose
        // bearer is re-checked at delivery); in particular a subject asserted
        // by a trusted proxy or an access gateway.
        status_only: caller.oauth_agent_identity.is_some()
            || caller.grant_subject.as_ref().is_some_and(|subject| {
                !matches!(subject.authority.as_str(), "api_key" | "mtls")
                    && caller
                        .verified_identity
                        .is_none_or(|verified| verified.issuer != subject.authority)
            }),
    })
}

#[async_trait::async_trait]
impl crate::gateway::streaming::TaskFrames for TaskFrameSource {
    async fn frame(
        &self,
        notification: &Value,
        subscription: &crate::protocol::subscriptions::SubscriptionId,
        reader: &AuthenticatedClient,
    ) -> Option<crate::gateway::streaming::TaskFrame> {
        // Owner-scoped read: a task this reader does not own is absence, and
        // absence gets the notification as published (id and status only).
        let stored = notification
            .pointer("/params/taskId")
            .and_then(Value::as_str)
            .filter(|_| {
                !self.status_only
                    && self
                        .principal
                        .as_ref()
                        .is_none_or(|opened_as| *opened_as == reader.principal)
            })
            .and_then(|id| self.state.tasks.get(&self.owner, id).ok());
        let live = RecoveryCaller {
            client: Some(reader),
            oauth_agent_identity: self.oauth_agent_identity.as_ref(),
            cert_identity: self.cert_identity.as_ref(),
            api_key_name: Some(reader.name.as_str()),
            agent_id: self
                .agent_id
                .as_ref()
                .map(crate::security::OwnedProvenAgentId::as_proven),
            agent_declared: None,
            grant_subject: self.grant_subject.clone(),
            verified_identity: self.verified_identity.as_ref(),
            is_admin: reader.admin,
            input_capabilities: self.input_capabilities,
            session_id: self.session_id.as_deref(),
        };
        let request = RequestId::Number(0);
        let refused = |stored: &crate::gateway::task_service::CommittedTask| {
            with_policy_caller(&self.state, &live, |policy| {
                self.state
                    .meta_mcp
                    .refuse_stored_delivery(&request, stored, None, live.session_id, policy)
                    .is_some()
            })
        };
        let pending = self
            .state
            .meta_mcp
            .task_notification_frame(notification, stored.as_ref(), refused, subscription)
            .await?;
        Some(crate::gateway::streaming::TaskFrame {
            frame: pending.frame.clone(),
            restored_output: pending.restored_output,
            delivery: Box::new(FrameDelivery {
                state: Arc::clone(&self.state),
                pending,
                caller: reader.name.clone(),
                session_id: self.session_id.clone().unwrap_or_default(),
                subject: self.grant_subject.clone(),
            }),
        })
    }
}

/// The delivery record of one built frame, written when the stream is about to
/// send it.
struct FrameDelivery {
    state: Arc<AppState>,
    pending: crate::gateway::meta_mcp::task_notify::PendingTaskFrame,
    caller: String,
    session_id: String,
    subject: Option<crate::identity_grants::GrantSubject>,
}

#[async_trait::async_trait]
impl crate::gateway::streaming::TaskFrameDelivery for FrameDelivery {
    async fn delivered(self: Box<Self>, sent: &Value) -> bool {
        let Self {
            state,
            pending,
            caller,
            session_id,
            subject,
        } = *self;
        let who = crate::gateway::meta_mcp::task_notify::Reader {
            caller: &caller,
            session_id: &session_id,
            subject: subject.as_ref(),
        };
        state.meta_mcp.finish_task_frame(pending, sent, &who).await
    }
}
