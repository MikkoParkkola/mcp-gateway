// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant, policy and decision writes: request shapes, RBAC checks and the store apply.

use super::super::super::auth::AuthenticatedClient;
use super::super::super::router::AppState;
use super::super::access_table::CpCheck;
use super::super::guard::Guard;
use crate::config_reload::Generation;
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneActor, ControlPlaneAuditEvent, ControlPlaneDecisionTargetKind,
    ControlPlaneGrant, ControlPlaneMutation, ControlPlanePolicy, ControlPlaneRole,
    ControlPlaneRoleMappingConfig, ControlPlaneRollbackPlan, ControlPlaneStore,
};
use crate::gateway::authz::AdminStanding;
use crate::key_server::oidc::VerifiedIdentity;
use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request body for a grant upsert mutation.
#[derive(Debug, Deserialize)]
pub(super) struct GrantMutationRequest {
    /// The grant to upsert (insert/replace).
    pub(super) grant: ControlPlaneGrant,
    /// Reason (ticket id) for the audit trail.
    pub(super) reason: String,
    /// Rollback plan recorded with the audit event.
    pub(super) rollback: ControlPlaneRollbackPlan,
}

/// Request body for a policy upsert mutation.
#[derive(Debug, Deserialize)]
pub(super) struct PolicyMutationRequest {
    /// The policy to upsert (insert/replace).
    pub(super) policy: ControlPlanePolicy,
    /// Reason (ticket id) for the audit trail.
    pub(super) reason: String,
    /// Rollback plan recorded with the audit event.
    pub(super) rollback: ControlPlaneRollbackPlan,
}

/// Result of a governance mutation.
#[derive(Debug, Serialize)]
pub(super) struct MutationResponse {
    pub(super) ok: bool,
    pub(super) reason_code: String,
    pub(super) reason: String,
}

/// The actor and the action its row authorizes, derived where the handler
/// always derived its actor: the RBAC check itself stays in
/// `validate_for_actor`, after the store check. The role is the one the
/// request's pinned generation maps (ADR-023).
fn admitted_actor(
    generation: &Generation,
    guard: &Guard,
) -> Result<(crate::control_plane::ControlPlaneActor, ControlPlaneAction), super::super::guard::Early>
{
    guard.admit_control_plane(|client, identity, check| match check {
        CpCheck::Action(action) => Ok((
            actor_from_client(
                client,
                identity,
                &generation.config().control_plane.role_mapping,
            ),
            action,
        )),
        CpCheck::Read | CpCheck::FromBody(_) => Err(Box::new(
            super::super::guard::Refused::AdminRequired.into_response(),
        )),
    })
}

/// POST a grant upsert: RBAC via `validate_for_actor`, then 409. Dispatch
/// enforces grants from the identity-grants file, never from this store.
pub(super) async fn mutate_grant(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Json(req): Json<GrantMutationRequest>,
) -> axum::response::Response {
    let (actor, action) = match admitted_actor(&generation, &guard) {
        Ok(admitted) => admitted,
        Err(refused) => return *refused,
    };
    let target_id = req.grant.grant_id.clone();
    apply_mutation(
        control_plane_store(&state),
        &actor,
        action,
        target_id,
        format!("upsert grant {}", req.grant.grant_id),
        req.reason,
        req.rollback,
        &GRANT_WRITES_REFUSED,
    )
}

/// POST a policy upsert: RBAC, then 409, whether or not the store is
/// available (ADR-029); unlike [`mutate_grant`], no 503 first. Dispatch
/// enforces policies from gateway config, never from this store.
pub(super) async fn mutate_policy(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Json(req): Json<PolicyMutationRequest>,
) -> axum::response::Response {
    let (actor, action) = match admitted_actor(&generation, &guard) {
        Ok(admitted) => admitted,
        Err(refused) => return *refused,
    };
    let target_id = req.policy.policy_id.clone();
    apply_mutation(
        control_plane_store(&state),
        &actor,
        action,
        target_id,
        format!("upsert policy {}", req.policy.policy_id),
        req.reason,
        req.rollback,
        &POLICY_WRITES_REFUSED,
    )
}

/// Approve/deny decision on a queued item.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Approve,
    Deny,
}

/// Request body for resolving a decision-queue item.
#[derive(Debug, Deserialize)]
pub(super) struct DecisionRequest {
    /// Kind of the queued item (only `grant`/`policy` are actionable today).
    pub(super) target_kind: ControlPlaneDecisionTargetKind,
    /// Id of the grant/policy the decision resolves.
    pub(super) target_id: String,
    /// Approve or deny.
    pub(super) decision: Decision,
    /// Reason (ticket id) for the audit trail.
    pub(super) reason: String,
    /// Rollback plan recorded with the audit event.
    pub(super) rollback: ControlPlaneRollbackPlan,
}

/// POST a decision on a queued item: load the target grant/policy, apply the
/// approve/deny effect, and route it through the SAME `validate_for_actor` +
/// audited-commit path as a direct mutation (MIK-6687). Items whose kind has no
/// durable store target (server/trust-evaluation/runtime-health) are not
/// actionable here yet and return 422.
pub(super) async fn resolve_decision(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    Json(req): Json<DecisionRequest>,
) -> axum::response::Response {
    // Only a body-chosen row admits here; the action is checked below.
    let actor = match guard.admit_control_plane(|client, identity, check| match check {
        CpCheck::FromBody(_) => Ok(actor_from_client(
            client,
            identity,
            &generation.config().control_plane.role_mapping,
        )),
        CpCheck::Read | CpCheck::Action(_) => Err(Box::new(
            super::super::guard::Refused::AdminRequired.into_response(),
        )),
    }) {
        Ok(actor) => actor,
        Err(refused) => return *refused,
    };
    resolve_decision_core(control_plane_store(&state), &actor, req)
}

/// Why governance mutation is off, for the admin API; `None` when it is on.
/// Read from the config the process started with, which decided the store.
pub(super) fn mutation_disabled_reason(state: &AppState) -> Option<&'static str> {
    match state.control_plane_store {
        Some(_) => None,
        None if !state.live_config.running().auth.enabled => Some("auth_off"),
        None => Some("store_unavailable"),
    }
}

/// The durable store, or the 503 reason naming why it is absent and, when the
/// store could not open, where it was looked for.
pub(super) fn control_plane_store(state: &AppState) -> Result<&Arc<dyn ControlPlaneStore>, String> {
    if let Some(store) = &state.control_plane_store {
        return Ok(store);
    }
    if !state.live_config.running().auth.enabled {
        return Err("Control-plane store is disabled: auth is off".to_string());
    }
    let path = state
        .control_plane_base
        .as_ref()
        .map_or_else(String::new, |base| base.path.display().to_string());
    Err(format!(
        "Control-plane store at '{path}' could not be opened; set control_plane.store_dir to a writable directory"
    ))
}

/// The audit event both handlers build to authorize with. Neither applies a
/// mutation or writes an audit event (they refuse after RBAC), so the id is
/// fixed and reads no clock (MIK-8202).
const PREFLIGHT_EVENT_ID: &str = "cpa-validation-only";

// Test hook: the event ids the validation-only preflights built, newest last.
#[cfg(test)]
thread_local! {
    pub(super) static PREFLIGHT_EVENT_IDS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn note_preflight_event_id(id: &str) {
    PREFLIGHT_EVENT_IDS.with(|ids| ids.borrow_mut().push(id.to_owned()));
}

pub(super) fn store_unavailable(reason: String) -> axum::response::Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(MutationResponse {
            ok: false,
            reason_code: "CONTROL_STORE_UNAVAILABLE".to_string(),
            reason,
        }),
    )
        .into_response()
}

/// Sync core of [`resolve_decision`] (testable without a router). Other kinds
/// return 422 first. A grant decision then answers 503 if the store is
/// unavailable ([`StoreCheck::First`]); a policy decision never consults it
/// (ADR-029). Then RBAC, so a non-admin gets 403, then a grant or policy
/// decision is refused with 409 before any store read or audit write: the
/// store is not what dispatch enforces (E2-min).
pub(super) fn resolve_decision_core(
    store: Result<&Arc<dyn ControlPlaneStore>, String>,
    actor: &ControlPlaneActor,
    req: DecisionRequest,
) -> axum::response::Response {
    // Map kind -> action; reject unsupported kinds with a static 422 (no
    // resource lookup, so no information leak).
    let (action, kind_label, refusal) = match req.target_kind {
        ControlPlaneDecisionTargetKind::Grant => (
            ControlPlaneAction::MutateGrant,
            "grant",
            &GRANT_WRITES_REFUSED,
        ),
        ControlPlaneDecisionTargetKind::Policy => (
            ControlPlaneAction::MutatePolicy,
            "policy",
            &POLICY_WRITES_REFUSED,
        ),
        other => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(MutationResponse {
                    ok: false,
                    reason_code: "CONTROL_DECISION_KIND_UNSUPPORTED".to_string(),
                    reason: format!(
                        "decision target kind {other:?} is not actionable via this endpoint"
                    ),
                }),
            )
                .into_response();
        }
    };
    if let (StoreCheck::First, Err(reason)) = (refusal.store, store) {
        return store_unavailable(reason);
    }
    let approve = req.decision == Decision::Approve;
    let verb = if approve { "approve" } else { "deny" };

    // Build the audited mutation and authorize it first, so a non-admin gets
    // RBAC's 403 rather than the 409 below.
    let event = ControlPlaneAuditEvent {
        grant_change: None,
        event_id: PREFLIGHT_EVENT_ID.to_string(),
        actor_id: actor.actor_id.clone(),
        action,
        target_id: req.target_id.clone(),
        reason: req.reason,
        rollback: req.rollback,
    };
    #[cfg(test)]
    note_preflight_event_id(&event.event_id);
    let mutation = ControlPlaneMutation {
        action,
        target_id: req.target_id.clone(),
        summary: format!("{verb} {kind_label} {}", req.target_id),
        audit_event: Some(event),
    };
    let report = mutation.validate_for_actor(actor);
    if !report.allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(MutationResponse {
                ok: false,
                reason_code: report.reason_code,
                reason: report.reason,
            }),
        )
            .into_response();
    }

    refusal.response()
}

/// Why an authorized grant or policy write is refused, and where to make it.
///
/// Names config keys, never a resolved filesystem path, because authenticated
/// non-admins can read this API.
pub(super) struct WriteRefusal {
    pub(super) reason_code: &'static str,
    pub(super) reason: &'static str,
    pub(super) store: StoreCheck,
}

/// Whether an unavailable store answers 503 before the refusal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StoreCheck {
    /// The store's 503 comes first, then RBAC, then the refusal.
    First,
    /// The store is never consulted: RBAC, then the refusal. ADR-029: a
    /// policy write is refused whether or not the store is available, since
    /// the store never enforces policy.
    Never,
}

impl WriteRefusal {
    pub(super) fn response(&self) -> axum::response::Response {
        (
            StatusCode::CONFLICT,
            Json(MutationResponse {
                ok: false,
                reason_code: self.reason_code.to_string(),
                reason: self.reason.to_string(),
            }),
        )
            .into_response()
    }
}

pub(super) const GRANT_WRITES_REFUSED: WriteRefusal = WriteRefusal {
    reason_code: "grants_managed_in_identity_grants_file",
    reason: "Grants are enforced from the file named by security.identity_grants.path; \
             change them with `mcp-gateway identity grants`. This store is not enforced.",
    store: StoreCheck::First,
};

pub(super) const POLICY_WRITES_REFUSED: WriteRefusal = WriteRefusal {
    reason_code: "policies_managed_in_gateway_config",
    // Every gateway.yaml key ADR-029's decision table places policy in, in its
    // order.
    reason: "Policies are enforced from gateway config: security.tool_policy, \
             security.firewall.rules, security.firewall.credential_redaction, \
             security.firewall.collusion, security.sanitize_input and \
             security.ssrf_protection. This store is not enforced.",
    store: StoreCheck::Never,
};

/// Shared write path: answer 503 for an unavailable store only when the
/// refusal says [`StoreCheck::First`]; build the audited mutation and authorize
/// it with `validate_for_actor`, so a non-admin gets RBAC's 403; then refuse
/// with 409 before any store or audit write, because dispatch never reads this
/// store.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_mutation(
    store: Result<&Arc<dyn ControlPlaneStore>, String>,
    actor: &ControlPlaneActor,
    action: ControlPlaneAction,
    target_id: String,
    summary: String,
    reason: String,
    rollback: ControlPlaneRollbackPlan,
    refusal: &WriteRefusal,
) -> axum::response::Response {
    if let (StoreCheck::First, Err(reason)) = (refusal.store, store) {
        return store_unavailable(reason);
    }

    let event = ControlPlaneAuditEvent {
        grant_change: None,
        event_id: PREFLIGHT_EVENT_ID.to_string(),
        actor_id: actor.actor_id.clone(),
        action,
        target_id: target_id.clone(),
        reason,
        rollback,
    };
    #[cfg(test)]
    note_preflight_event_id(&event.event_id);
    let mutation = ControlPlaneMutation {
        action,
        target_id,
        summary,
        audit_event: Some(event),
    };

    let report = mutation.validate_for_actor(actor);
    if !report.allowed {
        return (
            StatusCode::FORBIDDEN,
            Json(MutationResponse {
                ok: false,
                reason_code: report.reason_code,
                reason: report.reason,
            }),
        )
            .into_response();
    }
    refusal.response()
}

/// Resolve the control-plane actor.
///
/// When a verified identity is present, the role comes from the issuer-scoped
/// role mapping; an identity that matches no rule gets `Viewer`, which reads
/// only its own grants and audit events. With no verified identity, an admin
/// key is `Admin` and any other caller `Viewer`. `Auditor` is otherwise only
/// an explicit role rule, since it reads every principal's rows.
///
/// `Admin` is gateway-wide: a caller whose UI scope is not every
/// backend, by its key or its token's policy, is capped at `Auditor`, read
/// breadth that the scoped snapshot bounds to its backends.
pub(in crate::gateway::ui) fn actor_from_client(
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
    role_mapping: &ControlPlaneRoleMappingConfig,
) -> ControlPlaneActor {
    if let Some(id) = identity {
        let mut role = role_mapping
            .resolve_role(id)
            .unwrap_or(ControlPlaneRole::Viewer);
        let scoped = client.is_some_and(|c| {
            crate::gateway::authz::BackendGrant::for_ui(Some(c))
                != crate::gateway::authz::BackendGrant::Unscoped
        });
        if scoped && role == ControlPlaneRole::Admin {
            role = ControlPlaneRole::Auditor;
        }
        let display_name = id.name().unwrap_or_else(|| id.email()).to_owned();
        return ControlPlaneActor {
            actor_id: id.stable_actor_id(),
            display_name,
            role,
            group_ids: id.groups().to_vec(),
        };
    }

    let (name, role, group_id) = match client.map(|c| (c, c.admin_standing())) {
        Some((client, AdminStanding::Gateway)) => (
            client.name.clone(),
            ControlPlaneRole::Admin,
            "local-admins".to_string(),
        ),
        Some((client, AdminStanding::InScope)) => (
            client.name.clone(),
            ControlPlaneRole::Auditor,
            "local-admins".to_string(),
        ),
        Some((client, AdminStanding::None)) => (
            client.name.clone(),
            ControlPlaneRole::Viewer,
            "local-viewers".to_string(),
        ),
        None => (
            "anonymous".to_string(),
            ControlPlaneRole::Viewer,
            "local-viewers".to_string(),
        ),
    };

    ControlPlaneActor {
        actor_id: format!("gateway-client:{name}"),
        display_name: name,
        role,
        group_ids: vec![group_id],
    }
}
