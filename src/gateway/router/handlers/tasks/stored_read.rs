// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The account pre-pass of a stored task read on HTTP (MIK-8392): who the
//! read is judged as, and filling its account outcomes before the route's
//! synchronous delivery check reads them.

use std::sync::Arc;

use serde_json::Value;

use super::RecoveryCaller;
use crate::gateway::router::AppState;

/// Fill the request's account outcomes for the named task's recorded
/// targets (MIK-8392). An owner-scoped read: a task this caller does not own,
/// or that is absent, is left to the route's own answer. Runs under the
/// request's live policy caller, so a cold claim already refused is skipped
/// before it resolves (F4).
pub(super) async fn prepare_stored_read(
    state: &Arc<AppState>,
    owner: &str,
    params: Option<&Value>,
    caller: &RecoveryCaller<'_>,
) {
    let Some(task_id) = crate::gateway::task_route::task_id_param(params) else {
        return;
    };
    if let Ok(stored) = state.tasks.get(owner, task_id) {
        super::prepare_stored_read_with_policy(state, &stored, caller).await;
    }
}

/// The stored-read pre-pass under THIS request's live policy caller
/// (MIK-8392 F4): the same context [`with_policy_caller`] builds, held
/// across the pre-pass's await so a cold claim already refused without
/// the caller's catalogue is skipped before it resolves. Kept identical
/// to that context field for field; change both together.
pub(super) async fn prepare_stored_read_with_policy(
    state: &Arc<AppState>,
    stored: &crate::gateway::task_service::CommittedTask,
    caller: &RecoveryCaller<'_>,
) {
    let router_authorizer = crate::gateway::router::OwnedRouterAuthorizer::capture(
        caller.client,
        caller.oauth_agent_identity,
        caller.cert_identity,
    );
    let borrowed = router_authorizer.borrow(state);
    let authorizer: &(dyn crate::gateway::authz::ToolAuthorizer + Sync) = &borrowed;
    let caller_key = crate::gateway::router::identity::caller_key(
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
    state
        .meta_mcp
        .prepare_stored_read(stored, policy_caller.scope(), caller.session_id)
        .await;
}
