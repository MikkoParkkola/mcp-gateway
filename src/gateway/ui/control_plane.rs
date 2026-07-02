//! Read-only control-plane API surface.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::super::auth::AuthenticatedClient;
use super::super::router::AppState;
use super::errors::auth_required;
use crate::control_plane::{
    AuditFilter, ControlPlaneAction, ControlPlaneActor, ControlPlaneAuditEvent,
    ControlPlaneAuthorization, ControlPlaneDecisionQueue, ControlPlaneDecisionTargetKind,
    ControlPlaneDomainCoverage, ControlPlaneFeature, ControlPlaneGrant, ControlPlaneGrantStatus,
    ControlPlaneHealth, ControlPlaneLicenseTier, ControlPlaneMutation, ControlPlanePolicy,
    ControlPlaneRbac, ControlPlaneReadOnlyView, ControlPlaneRole, ControlPlaneRoleMappingConfig,
    ControlPlaneRollbackPlan, ControlPlaneRuntimeHealth, ControlPlaneServer,
    ControlPlaneServerStatus, ControlPlaneSnapshot, ControlPlaneStore, ControlPlaneTool,
    ControlPlaneTrustCard, ControlPlaneUser,
};
use crate::discovery::AutoDiscovery;
use crate::discovery::shadow::{
    SHADOW_HANDOFF_SCHEMA_VERSION, SHADOW_REPORT_SCHEMA_VERSION, ShadowControlPlaneAsset,
    ShadowEnterpriseBoundary, ShadowScanReport, ShadowScanSummary,
};
use crate::hashing::canonical_json_sha256;
use crate::key_server::oidc::VerifiedIdentity;
use crate::trust::TrustCard;

/// Build the control-plane API router: a read-only snapshot plus governance
/// mutation routes (grants/policies) gated by RBAC + mandatory audit (MIK-6686).
pub fn control_plane_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ui/api/control-plane", get(control_plane_snapshot))
        .route("/ui/api/control-plane/grants", post(mutate_grant))
        .route("/ui/api/control-plane/policies", post(mutate_policy))
        .route("/ui/api/control-plane/decisions", post(resolve_decision))
}

async fn control_plane_snapshot(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(client)| client);
    let identity = identity.map(|Extension(id)| id);
    let actor = actor_from_client(
        client.as_ref(),
        identity.as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    let (snapshot, store_read_degraded) = local_runtime_snapshot(&state, client.as_ref(), &actor);
    let shadow_radar = local_shadow_radar(&state).await;

    let Some(view) = snapshot.read_only_view(&actor) else {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    };
    let Some(decision_queue) = snapshot.decision_queue(&actor) else {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    };

    let response = ControlPlaneApiResponse::from_snapshot(
        actor,
        &snapshot,
        view,
        decision_queue,
        shadow_radar,
        state.control_plane_store.is_some(),
        store_read_degraded,
    );
    Json(response).into_response()
}

/// Request body for a grant upsert mutation.
#[derive(Debug, Deserialize)]
struct GrantMutationRequest {
    /// The grant to upsert (insert/replace).
    grant: ControlPlaneGrant,
    /// Reason (ticket id) for the audit trail.
    reason: String,
    /// Rollback plan recorded with the audit event.
    rollback: ControlPlaneRollbackPlan,
}

/// Request body for a policy upsert mutation.
#[derive(Debug, Deserialize)]
struct PolicyMutationRequest {
    /// The policy to upsert (insert/replace).
    policy: ControlPlanePolicy,
    /// Reason (ticket id) for the audit trail.
    reason: String,
    /// Rollback plan recorded with the audit event.
    rollback: ControlPlaneRollbackPlan,
}

/// Result of a governance mutation.
#[derive(Debug, Serialize)]
struct MutationResponse {
    ok: bool,
    reason_code: String,
    reason: String,
}

/// POST a grant upsert: RBAC plus mandatory audit via `validate_for_actor`,
/// then persist to the control-plane store and append the audit event.
async fn mutate_grant(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Json(req): Json<GrantMutationRequest>,
) -> impl IntoResponse {
    let actor = actor_from_client(
        client.map(|Extension(c)| c).as_ref(),
        identity.map(|Extension(id)| id).as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    let target_id = req.grant.grant_id.clone();
    apply_mutation(
        state.control_plane_store.as_ref(),
        &actor,
        ControlPlaneAction::MutateGrant,
        target_id,
        format!("upsert grant {}", req.grant.grant_id),
        req.reason,
        req.rollback,
        |store, event| store.commit_grant_audited(req.grant.clone(), event),
    )
}

/// POST a policy upsert: same RBAC plus audit contract as [`mutate_grant`].
async fn mutate_policy(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Json(req): Json<PolicyMutationRequest>,
) -> impl IntoResponse {
    let actor = actor_from_client(
        client.map(|Extension(c)| c).as_ref(),
        identity.map(|Extension(id)| id).as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    let target_id = req.policy.policy_id.clone();
    apply_mutation(
        state.control_plane_store.as_ref(),
        &actor,
        ControlPlaneAction::MutatePolicy,
        target_id,
        format!("upsert policy {}", req.policy.policy_id),
        req.reason,
        req.rollback,
        |store, event| store.commit_policy_audited(req.policy.clone(), event),
    )
}

/// Approve/deny decision on a queued item.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Approve,
    Deny,
}

/// Request body for resolving a decision-queue item.
#[derive(Debug, Deserialize)]
struct DecisionRequest {
    /// Kind of the queued item (only `grant`/`policy` are actionable today).
    target_kind: ControlPlaneDecisionTargetKind,
    /// Id of the grant/policy the decision resolves.
    target_id: String,
    /// Approve or deny.
    decision: Decision,
    /// Reason (ticket id) for the audit trail.
    reason: String,
    /// Rollback plan recorded with the audit event.
    rollback: ControlPlaneRollbackPlan,
}

/// POST a decision on a queued item: load the target grant/policy, apply the
/// approve/deny effect, and route it through the SAME `validate_for_actor` +
/// audited-commit path as a direct mutation (MIK-6687). Items whose kind has no
/// durable store target (server/trust-evaluation/runtime-health) are not
/// actionable here yet and return 422.
async fn resolve_decision(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Json(req): Json<DecisionRequest>,
) -> axum::response::Response {
    let actor = actor_from_client(
        client.map(|Extension(c)| c).as_ref(),
        identity.map(|Extension(id)| id).as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    resolve_decision_core(state.control_plane_store.as_ref(), &actor, req)
}

/// Sync core of [`resolve_decision`] (testable without a router). Authorizes
/// FIRST (before any store read, so 403-vs-404 cannot leak target existence),
/// then applies a field-only, audited status change through the store's
/// re-read-under-lock primitive (no stale-clone lost update). Kinds without a
/// durable store target return 422.
fn resolve_decision_core(
    store: Option<&Arc<dyn ControlPlaneStore>>,
    actor: &ControlPlaneActor,
    req: DecisionRequest,
) -> axum::response::Response {
    let Some(store) = store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(MutationResponse {
                ok: false,
                reason_code: "CONTROL_STORE_UNAVAILABLE".to_string(),
                reason: "Control-plane store is not configured".to_string(),
            }),
        )
            .into_response();
    };

    // Map kind -> action; reject unsupported kinds with a static 422 (no
    // resource lookup, so no information leak).
    let (action, kind_label) = match req.target_kind {
        ControlPlaneDecisionTargetKind::Grant => (ControlPlaneAction::MutateGrant, "grant"),
        ControlPlaneDecisionTargetKind::Policy => (ControlPlaneAction::MutatePolicy, "policy"),
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
    let approve = req.decision == Decision::Approve;
    let verb = if approve { "approve" } else { "deny" };

    // Build the audited mutation and authorize BEFORE touching the store, so a
    // non-admin cannot use 403-vs-404 as an existence oracle.
    let event = ControlPlaneAuditEvent {
        event_id: format!("cpa-{}-{}", Utc::now().timestamp_millis(), req.target_id),
        actor_id: actor.actor_id.clone(),
        action,
        target_id: req.target_id.clone(),
        reason: req.reason,
        rollback: req.rollback,
    };
    let mutation = ControlPlaneMutation {
        action,
        target_id: req.target_id.clone(),
        summary: format!("{verb} {kind_label} {}", req.target_id),
        audit_event: Some(event.clone()),
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

    // Apply the field-only, audited status change (re-read under the store lock).
    let applied = match req.target_kind {
        ControlPlaneDecisionTargetKind::Grant => {
            let status = if approve {
                ControlPlaneGrantStatus::Approved
            } else {
                ControlPlaneGrantStatus::Revoked
            };
            store.set_grant_status_audited(&req.target_id, status, &event)
        }
        ControlPlaneDecisionTargetKind::Policy => {
            store.set_policy_enforced_audited(&req.target_id, approve, &event)
        }
        _ => unreachable!("non grant/policy kinds returned 422 above"),
    };
    match applied {
        Ok(true) => (
            StatusCode::OK,
            Json(MutationResponse {
                ok: true,
                reason_code: report.reason_code,
                reason: report.reason,
            }),
        )
            .into_response(),
        Ok(false) => decision_not_found(kind_label, &req.target_id),
        Err(e) => internal_error("CONTROL_STORE_WRITE_FAILED", &e),
    }
}

fn decision_not_found(kind: &str, id: &str) -> axum::response::Response {
    (
        StatusCode::NOT_FOUND,
        Json(MutationResponse {
            ok: false,
            reason_code: "CONTROL_DECISION_TARGET_NOT_FOUND".to_string(),
            reason: format!("no {kind} '{id}' in the control-plane store"),
        }),
    )
        .into_response()
}

/// Shared mutation path: build the audited mutation, authorize it with
/// `validate_for_actor`, then commit it as one audited unit (write-ahead audit
/// plus persistence under a single lock, provided by the store).
#[allow(clippy::too_many_arguments)]
fn apply_mutation(
    store: Option<&Arc<dyn ControlPlaneStore>>,
    actor: &ControlPlaneActor,
    action: ControlPlaneAction,
    target_id: String,
    summary: String,
    reason: String,
    rollback: ControlPlaneRollbackPlan,
    commit: impl FnOnce(
        &Arc<dyn ControlPlaneStore>,
        &ControlPlaneAuditEvent,
    ) -> Result<(), crate::control_plane::StoreError>,
) -> axum::response::Response {
    let Some(store) = store else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(MutationResponse {
                ok: false,
                reason_code: "CONTROL_STORE_UNAVAILABLE".to_string(),
                reason: "Control-plane store is not configured".to_string(),
            }),
        )
            .into_response();
    };

    // event_id embeds a millisecond timestamp, giving both a unique id and a
    // coarse time for the audit trail (the hash chain provides ordering).
    let event = ControlPlaneAuditEvent {
        event_id: format!("cpa-{}-{target_id}", Utc::now().timestamp_millis()),
        actor_id: actor.actor_id.clone(),
        action,
        target_id: target_id.clone(),
        reason,
        rollback,
    };
    let mutation = ControlPlaneMutation {
        action,
        target_id,
        summary,
        audit_event: Some(event.clone()),
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

    // The store commits the write-ahead audit and the persistence as one
    // serialized, ordered unit (see `commit_grant_audited`).
    if let Err(e) = commit(store, &event) {
        return internal_error("CONTROL_MUTATION_WRITE_FAILED", &e);
    }

    (
        StatusCode::OK,
        Json(MutationResponse {
            ok: true,
            reason_code: report.reason_code,
            reason: report.reason,
        }),
    )
        .into_response()
}

/// Log the underlying error server-side and return a generic client message, so
/// filesystem paths and other internals are not leaked in the HTTP response.
fn internal_error(code: &str, err: &crate::control_plane::StoreError) -> axum::response::Response {
    tracing::error!(reason_code = code, error = %err, "control-plane mutation failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(MutationResponse {
            ok: false,
            reason_code: code.to_string(),
            reason: "Control-plane mutation could not be persisted".to_string(),
        }),
    )
        .into_response()
}

/// Resolve the control-plane actor.
///
/// When a verified identity is present, the role comes from the issuer-scoped
/// role mapping (MIK-6688); an identity that matches no rule gets `Auditor`
/// (least privilege). With no verified identity, the legacy admin-key
/// projection applies (admin key -> Admin, else Auditor) — backward compatible.
fn actor_from_client(
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
    role_mapping: &ControlPlaneRoleMappingConfig,
) -> ControlPlaneActor {
    if let Some(id) = identity {
        let role = role_mapping
            .resolve_role(id)
            .unwrap_or(ControlPlaneRole::Auditor);
        let display_name = id.name.clone().unwrap_or_else(|| id.email.clone());
        return ControlPlaneActor {
            actor_id: id.stable_actor_id(),
            display_name,
            role,
            group_ids: id.groups.clone(),
        };
    }

    let (name, role, group_id) = match client {
        Some(client) if client.admin => (
            client.name.clone(),
            ControlPlaneRole::Admin,
            "local-admins".to_string(),
        ),
        Some(client) => (
            client.name.clone(),
            ControlPlaneRole::Auditor,
            "local-auditors".to_string(),
        ),
        None => (
            "anonymous".to_string(),
            ControlPlaneRole::Auditor,
            "local-auditors".to_string(),
        ),
    };

    ControlPlaneActor {
        actor_id: format!("gateway-client:{name}"),
        display_name: name,
        role,
        group_ids: vec![group_id],
    }
}

/// Build the local runtime snapshot for the control-plane API.
///
/// Returns the snapshot plus a `store_read_degraded` flag: `true` when a durable
/// store is configured but at least one read failed, so the view fell back to
/// the local projection (MIK-6701).
fn local_runtime_snapshot(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    actor: &ControlPlaneActor,
) -> (ControlPlaneSnapshot, bool) {
    let mut snapshot = ControlPlaneSnapshot::default();
    snapshot.users.push(ControlPlaneUser {
        user_id: actor.actor_id.clone(),
        display_name: actor.display_name.clone(),
        role: actor.role,
    });

    for group_id in &actor.group_ids {
        snapshot
            .groups
            .push(crate::control_plane::ControlPlaneGroup {
                group_id: group_id.clone(),
                display_name: group_id.replace('-', " "),
                member_user_ids: vec![actor.actor_id.clone()],
            });
    }

    snapshot.policies = local_policy_rows(state);

    let backends = state.backends.all();
    for backend in backends {
        if !can_view_backend(client, &backend.name) {
            continue;
        }

        let status = backend.status();
        let server_id = format!("backend:{}", status.name);
        snapshot.servers.push(ControlPlaneServer {
            server_id: server_id.clone(),
            name: status.name.clone(),
            owner_group_id: actor
                .group_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "local-auditors".to_string()),
            status: server_status_from_backend(&status),
        });

        snapshot.runtime_health.push(ControlPlaneRuntimeHealth {
            server_id: server_id.clone(),
            provider: status.transport.clone(),
            health: runtime_health_from_backend(&status),
        });

        for tool in backend.get_cached_tools_snapshot().iter() {
            snapshot.tools.push(ControlPlaneTool {
                tool_id: format!("backend:{}:tool:{}", status.name, tool.name),
                server_id: server_id.clone(),
                name: tool.name.clone(),
                high_impact: is_high_impact_tool(tool),
            });
            let trust_card = TrustCard::from_tool(&status.name, tool).with_validation();
            snapshot.trust_cards.push(ControlPlaneTrustCard {
                server_id: server_id.clone(),
                trust_card_digest_sha256: trust_card_digest_sha256(&trust_card),
                schema_version: trust_card.schema_version,
            });
        }
    }

    // Project the live identity-grant store into the read-only inventory so the
    // "grants" governance view reflects actual local grants instead of an empty
    // table (MIK-6558). Status is derived from revocation/expiry; local grants
    // have no "requested" state, so an active grant reads as Approved.
    let now = chrono::Utc::now();
    for grant in state.meta_mcp.identity_grant_rows() {
        snapshot
            .grants
            .push(control_plane_grant_from_identity(grant, now));
    }

    // Reflect the durable governance store (MIK-6701): persisted grants/policies
    // are merged in (store rows win by id over the local projection), and the
    // audit-events view is populated from the store. Read errors degrade to the
    // local projection rather than breaking the whole snapshot (fail-soft read),
    // and the degraded flag is surfaced so an empty view is not mistaken for an
    // authoritative empty result.
    let store_read_degraded = state
        .control_plane_store
        .as_ref()
        .is_some_and(|store| merge_store_into_snapshot(store.as_ref(), &mut snapshot));

    (snapshot, store_read_degraded)
}

/// Merge persisted control-plane store rows into a runtime snapshot: grants and
/// policies upsert by id (store wins), and `audit_events` are taken from the
/// store's tamper-evident log.
///
/// Returns `true` if any store read failed (the view is then degraded: it falls
/// back to the local projection and the audit view may be incomplete). The
/// caller surfaces this so a client cannot mistake a failed read for an
/// authoritative empty result (MIK-6701).
#[must_use]
fn merge_store_into_snapshot(
    store: &dyn ControlPlaneStore,
    snapshot: &mut ControlPlaneSnapshot,
) -> bool {
    let mut degraded = false;
    match store.list_grants() {
        Ok(grants) => {
            for g in grants {
                if let Some(existing) = snapshot
                    .grants
                    .iter_mut()
                    .find(|x| x.grant_id == g.grant_id)
                {
                    *existing = g;
                } else {
                    snapshot.grants.push(g);
                }
            }
        }
        Err(e) => {
            degraded = true;
            tracing::warn!(error = %e, "control-plane store list_grants failed; using local projection");
        }
    }
    match store.list_policies() {
        Ok(policies) => {
            for p in policies {
                if let Some(existing) = snapshot
                    .policies
                    .iter_mut()
                    .find(|x| x.policy_id == p.policy_id)
                {
                    *existing = p;
                } else {
                    snapshot.policies.push(p);
                }
            }
        }
        Err(e) => {
            degraded = true;
            tracing::warn!(error = %e, "control-plane store list_policies failed; using local projection");
        }
    }
    match store.read_audit(&AuditFilter::new(200)) {
        Ok(events) => snapshot.audit_events = events,
        Err(e) => {
            degraded = true;
            tracing::warn!(error = %e, "control-plane store read_audit failed; audit view left empty");
        }
    }
    degraded
}

/// Project a local [`IdentityGrant`] into a read-only [`ControlPlaneGrant`].
///
/// Local grants have no "requested" state: a grant that is neither revoked nor
/// past its expiry reads as `Approved`; otherwise `Revoked`.
fn control_plane_grant_from_identity(
    grant: crate::identity_grants::IdentityGrant,
    now: chrono::DateTime<chrono::Utc>,
) -> ControlPlaneGrant {
    let revoked =
        grant.revoked_at.is_some() || grant.expires_at.is_some_and(|expiry| expiry <= now);
    ControlPlaneGrant {
        grant_id: grant.grant_id,
        subject_id: grant
            .subject
            .label
            .clone()
            .unwrap_or_else(|| format!("{}:{}", grant.subject.authority, grant.subject.subject)),
        server_id: format!("capability:{}", grant.capability),
        tool_id: grant.tool,
        status: if revoked {
            ControlPlaneGrantStatus::Revoked
        } else {
            ControlPlaneGrantStatus::Approved
        },
    }
}

fn trust_card_digest_sha256(card: &TrustCard) -> String {
    let json_value = serde_json::to_value(card).unwrap_or(serde_json::Value::Null);
    canonical_json_sha256(&json_value)
}

async fn local_shadow_radar(state: &AppState) -> ControlPlaneShadowRadar {
    let registered_names: HashSet<String> = state
        .backends
        .all()
        .into_iter()
        .map(|backend| backend.name.clone())
        .collect();
    let discovery = AutoDiscovery::new();

    let Ok(discovered) = discovery.discover_all().await else {
        return ControlPlaneShadowRadar::scan_unavailable();
    };

    let report = ShadowScanReport::from_discovered(
        &discovered,
        &registered_names,
        state.config_path.as_deref(),
    );
    ControlPlaneShadowRadar::from_report(&report)
}

fn local_policy_rows(state: &AppState) -> Vec<crate::control_plane::ControlPlanePolicy> {
    vec![
        crate::control_plane::ControlPlanePolicy {
            policy_id: "local:input_sanitization".to_string(),
            name: "Input sanitization".to_string(),
            enforced: state.sanitize_input,
        },
        crate::control_plane::ControlPlanePolicy {
            policy_id: "local:ssrf_protection".to_string(),
            name: "SSRF protection".to_string(),
            enforced: state.ssrf_protection,
        },
    ]
}

fn can_view_backend(client: Option<&AuthenticatedClient>, backend_name: &str) -> bool {
    client.is_some_and(|client| client.admin || client.can_access_backend(backend_name))
}

fn server_status_from_backend(status: &crate::backend::BackendStatus) -> ControlPlaneServerStatus {
    if status.circuit_state == "Open" {
        ControlPlaneServerStatus::Blocked
    } else {
        ControlPlaneServerStatus::Enabled
    }
}

fn runtime_health_from_backend(status: &crate::backend::BackendStatus) -> ControlPlaneHealth {
    if status.circuit_state == "Open" {
        ControlPlaneHealth::Down
    } else if !status.running {
        ControlPlaneHealth::Unknown
    } else if status.healthy {
        ControlPlaneHealth::Healthy
    } else {
        ControlPlaneHealth::Degraded
    }
}

fn is_high_impact_tool(tool: &crate::protocol::Tool) -> bool {
    tool.annotations.as_ref().is_some_and(|annotations| {
        annotations.destructive_hint.unwrap_or(false)
            || annotations.open_world_hint.unwrap_or(false)
            || matches!(annotations.idempotent_hint, Some(false))
    })
}

#[derive(Debug, Serialize)]
struct ControlPlaneApiResponse {
    schema_version: &'static str,
    source: &'static str,
    route: ControlPlaneRouteMode,
    actor: ControlPlaneActor,
    features: Vec<ControlPlaneFeatureEntitlement>,
    authorizations: ControlPlaneAuthorizationSet,
    coverage: ControlPlaneDomainCoverage,
    coverage_complete: bool,
    inventory_counts: ControlPlaneInventoryCounts,
    shadow_radar: ControlPlaneShadowRadar,
    /// `true` when a durable store is configured but a read failed, so `view`,
    /// `inventory_counts`, and `decision_queue` fell back to the local
    /// projection and may be incomplete. Distinguishes "no rows" from
    /// "store unreadable" (MIK-6701).
    store_read_degraded: bool,
    view: ControlPlaneReadOnlyView,
    decision_queue: ControlPlaneDecisionQueue,
    current_limits: Vec<&'static str>,
}

impl ControlPlaneApiResponse {
    fn from_snapshot(
        actor: ControlPlaneActor,
        snapshot: &ControlPlaneSnapshot,
        view: ControlPlaneReadOnlyView,
        decision_queue: ControlPlaneDecisionQueue,
        shadow_radar: ControlPlaneShadowRadar,
        mutation_enabled: bool,
        store_read_degraded: bool,
    ) -> Self {
        let coverage = snapshot.domain_coverage();
        let inventory_counts = ControlPlaneInventoryCounts::from_snapshot(snapshot, &shadow_radar);
        let current_limits = if mutation_enabled {
            vec![
                "local_runtime_only",
                "mutation_endpoint_active",
                "no_enterprise_export",
            ]
        } else {
            vec![
                "read_only_api",
                "local_runtime_only",
                "no_persistence",
                "no_mutation_endpoint",
                "no_enterprise_export",
            ]
        };
        Self {
            schema_version: "control_plane.api.v1",
            source: "local_runtime_snapshot",
            route: ControlPlaneRouteMode {
                read_only: !mutation_enabled,
                mutation_endpoint: mutation_enabled,
                mutating_actions_require_audit: true,
            },
            features: feature_entitlements(mutation_enabled),
            authorizations: ControlPlaneAuthorizationSet::for_actor(&actor),
            coverage,
            coverage_complete: coverage.is_complete(),
            inventory_counts,
            shadow_radar,
            store_read_degraded,
            actor,
            view,
            decision_queue,
            current_limits,
        }
    }
}

#[derive(Debug, Serialize)]
struct ControlPlaneShadowRadar {
    schema_version: String,
    source_report_schema: String,
    source: &'static str,
    scan_status: &'static str,
    passive: bool,
    tools_invoked: bool,
    summary: ShadowScanSummary,
    control_plane_assets: Vec<ShadowControlPlaneAsset>,
    enterprise_boundary: ShadowEnterpriseBoundary,
    trustcard_input_count: usize,
    doctor_finding_count: usize,
}

impl ControlPlaneShadowRadar {
    fn from_report(report: &ShadowScanReport) -> Self {
        let summary = report.summary.clone();
        let handoff = report.consumer_handoff();
        Self {
            schema_version: handoff.schema_version,
            source_report_schema: handoff.source_report_schema,
            source: "local_passive_discovery",
            scan_status: "ok",
            passive: handoff.passive,
            tools_invoked: handoff.tools_invoked,
            summary,
            control_plane_assets: handoff.control_plane_assets,
            enterprise_boundary: handoff.enterprise_boundary,
            trustcard_input_count: handoff.trustcard_inputs.len(),
            doctor_finding_count: handoff.doctor_findings.len(),
        }
    }

    fn scan_unavailable() -> Self {
        let summary = ShadowScanSummary {
            discovered_total: 0,
            managed_total: 0,
            unmanaged_total: 0,
            high_or_critical_total: 0,
            adoptable_total: 0,
            network_exposed_total: 0,
        };
        let enterprise_boundary = ShadowEnterpriseBoundary::local_passive(&summary);
        Self {
            schema_version: SHADOW_HANDOFF_SCHEMA_VERSION.to_string(),
            source_report_schema: SHADOW_REPORT_SCHEMA_VERSION.to_string(),
            source: "local_passive_discovery",
            scan_status: "unavailable",
            passive: true,
            tools_invoked: false,
            summary,
            control_plane_assets: Vec::new(),
            enterprise_boundary,
            trustcard_input_count: 0,
            doctor_finding_count: 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct ControlPlaneRouteMode {
    read_only: bool,
    mutation_endpoint: bool,
    mutating_actions_require_audit: bool,
}

impl Default for ControlPlaneRouteMode {
    fn default() -> Self {
        Self {
            read_only: true,
            mutation_endpoint: false,
            mutating_actions_require_audit: true,
        }
    }
}

#[derive(Debug, Serialize)]
struct ControlPlaneFeatureEntitlement {
    feature: ControlPlaneFeature,
    license_tier: ControlPlaneLicenseTier,
    available_in_this_route: bool,
}

/// Report which control-plane features are usable on the current route.
///
/// `LocalStatus` is always available (read surface); `GovernanceMutation` is
/// available when the mutation endpoint is active (CP.READ.3 — the entitlement
/// must track `route.mutation_endpoint`, not report read-only unconditionally).
/// `FleetInventory` and `EvidenceExport` are enterprise features not served by
/// this local route.
fn feature_entitlements(mutation_enabled: bool) -> Vec<ControlPlaneFeatureEntitlement> {
    [
        ControlPlaneFeature::LocalStatus,
        ControlPlaneFeature::FleetInventory,
        ControlPlaneFeature::GovernanceMutation,
        ControlPlaneFeature::EvidenceExport,
    ]
    .into_iter()
    .map(|feature| ControlPlaneFeatureEntitlement {
        feature,
        license_tier: feature.license_tier(),
        available_in_this_route: match feature {
            ControlPlaneFeature::LocalStatus => true,
            ControlPlaneFeature::GovernanceMutation => mutation_enabled,
            ControlPlaneFeature::FleetInventory | ControlPlaneFeature::EvidenceExport => false,
        },
    })
    .collect()
}

#[derive(Debug, Serialize)]
struct ControlPlaneAuthorizationSet {
    read_inventory: ControlPlaneAuthorization,
    read_evidence: ControlPlaneAuthorization,
    review_evidence: ControlPlaneAuthorization,
    mutate_grant: ControlPlaneAuthorization,
    mutate_policy: ControlPlaneAuthorization,
    approve_server: ControlPlaneAuthorization,
}

impl ControlPlaneAuthorizationSet {
    fn for_actor(actor: &ControlPlaneActor) -> Self {
        Self {
            read_inventory: ControlPlaneRbac::authorize(actor, ControlPlaneAction::ReadInventory),
            read_evidence: ControlPlaneRbac::authorize(actor, ControlPlaneAction::ReadEvidence),
            review_evidence: ControlPlaneRbac::authorize(actor, ControlPlaneAction::ReviewEvidence),
            mutate_grant: ControlPlaneRbac::authorize(actor, ControlPlaneAction::MutateGrant),
            mutate_policy: ControlPlaneRbac::authorize(actor, ControlPlaneAction::MutatePolicy),
            approve_server: ControlPlaneRbac::authorize(actor, ControlPlaneAction::ApproveServer),
        }
    }
}

#[derive(Debug, Serialize)]
struct ControlPlaneInventoryCounts {
    servers: usize,
    tools: usize,
    trust_cards: usize,
    trust_evaluations: usize,
    requested_grants: usize,
    policies: usize,
    users: usize,
    groups: usize,
    runtime_health: usize,
    audit_events: usize,
    shadow_assets: usize,
    shadow_high_or_critical_assets: usize,
}

impl ControlPlaneInventoryCounts {
    fn from_snapshot(
        snapshot: &ControlPlaneSnapshot,
        shadow_radar: &ControlPlaneShadowRadar,
    ) -> Self {
        Self {
            servers: snapshot.servers.len(),
            tools: snapshot.tools.len(),
            trust_cards: snapshot.trust_cards.len(),
            trust_evaluations: snapshot.trust_evaluations.len(),
            requested_grants: snapshot
                .grants
                .iter()
                .filter(|grant| grant.status == ControlPlaneGrantStatus::Requested)
                .count(),
            policies: snapshot.policies.len(),
            users: snapshot.users.len(),
            groups: snapshot.groups.len(),
            runtime_health: snapshot.runtime_health.len(),
            audit_events: snapshot.audit_events.len(),
            shadow_assets: shadow_radar.summary.unmanaged_total,
            shadow_high_or_critical_assets: shadow_radar.summary.high_or_critical_total,
        }
    }
}

#[cfg(test)]
mod grant_projection_tests {
    use super::control_plane_grant_from_identity;
    use crate::control_plane::ControlPlaneGrantStatus;
    use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};
    use chrono::{Duration, Utc};

    fn grant() -> IdentityGrant {
        IdentityGrant {
            grant_id: "g-1".to_string(),
            subject: GrantSubject::new("oidc", "sub-123", Some("alice@corp".to_string())),
            agent: GrantAgent::Any,
            capability: "gmail".to_string(),
            tool: Some("send".to_string()),
            scope: GrantScope::Execute,
            owner: None,
            expires_at: None,
            revoked_at: None,
            provenance: "local-file".to_string(),
            reason: "test".to_string(),
        }
    }

    #[test]
    fn active_grant_projects_as_approved_with_label_and_capability() {
        let row = control_plane_grant_from_identity(grant(), Utc::now());
        assert_eq!(row.grant_id, "g-1");
        assert_eq!(row.subject_id, "alice@corp");
        assert_eq!(row.server_id, "capability:gmail");
        assert_eq!(row.tool_id.as_deref(), Some("send"));
        assert_eq!(row.status, ControlPlaneGrantStatus::Approved);
    }

    #[test]
    fn revoked_grant_projects_as_revoked() {
        let mut g = grant();
        g.revoked_at = Some(Utc::now());
        assert_eq!(
            control_plane_grant_from_identity(g, Utc::now()).status,
            ControlPlaneGrantStatus::Revoked
        );
    }

    #[test]
    fn expired_grant_projects_as_revoked() {
        let mut g = grant();
        g.expires_at = Some(Utc::now() - Duration::hours(1));
        assert_eq!(
            control_plane_grant_from_identity(g, Utc::now()).status,
            ControlPlaneGrantStatus::Revoked
        );
    }

    #[test]
    fn subject_id_falls_back_to_authority_subject_without_label() {
        let mut g = grant();
        g.subject = GrantSubject::new("oidc", "sub-123", None);
        assert_eq!(
            control_plane_grant_from_identity(g, Utc::now()).subject_id,
            "oidc:sub-123"
        );
    }
}

#[cfg(test)]
mod mutation_tests {
    use super::apply_mutation;
    use crate::control_plane::{
        AuditFilter, ControlPlaneAction, ControlPlaneActor, ControlPlaneDecisionTargetKind,
        ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlaneRole, ControlPlaneRollbackPlan,
        ControlPlaneStore, InMemoryControlPlaneStore,
    };
    use axum::http::StatusCode;
    use std::sync::Arc;

    fn actor(role: ControlPlaneRole) -> ControlPlaneActor {
        ControlPlaneActor {
            actor_id: "gateway-client:tester".to_string(),
            display_name: "tester".to_string(),
            role,
            group_ids: vec!["g".to_string()],
        }
    }

    fn grant() -> ControlPlaneGrant {
        ControlPlaneGrant {
            grant_id: "grant-1".to_string(),
            subject_id: "user-1".to_string(),
            server_id: "srv-1".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Approved,
        }
    }

    fn rollback() -> ControlPlaneRollbackPlan {
        ControlPlaneRollbackPlan {
            summary: "revert".to_string(),
            step: "restore prior grant".to_string(),
        }
    }

    // MIK-6686.CP.2 — an admin mutation is authorized, persisted, and audited.
    #[test]
    fn admin_grant_mutation_persists_and_audits() {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
        let g = grant();
        let resp = apply_mutation(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            ControlPlaneAction::MutateGrant,
            g.grant_id.clone(),
            "upsert".to_string(),
            "MIK-1".to_string(),
            rollback(),
            |s, event| s.commit_grant_audited(g.clone(), event),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(store.list_grants().unwrap().len(), 1);
        let audit = store.read_audit(&AuditFilter::new(10)).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, ControlPlaneAction::MutateGrant);
        assert_eq!(audit[0].actor_id, "gateway-client:tester");
    }

    // MIK-6686.CP.2 — a non-admin is denied; nothing is persisted or audited.
    #[test]
    fn auditor_grant_mutation_is_denied_with_no_side_effects() {
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
        let g = grant();
        let resp = apply_mutation(
            Some(&store),
            &actor(ControlPlaneRole::Auditor),
            ControlPlaneAction::MutateGrant,
            g.grant_id.clone(),
            "upsert".to_string(),
            "MIK-1".to_string(),
            rollback(),
            |s, event| s.commit_grant_audited(g.clone(), event),
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(store.list_grants().unwrap().is_empty());
        assert!(store.read_audit(&AuditFilter::new(10)).unwrap().is_empty());
    }

    // MIK-6686.CP.2 — with no store configured the route reports 503.
    #[test]
    fn mutation_without_store_returns_503() {
        let resp = apply_mutation(
            None,
            &actor(ControlPlaneRole::Admin),
            ControlPlaneAction::MutateGrant,
            "grant-1".to_string(),
            "upsert".to_string(),
            "MIK-1".to_string(),
            rollback(),
            |_s, _event| Ok(()),
        );
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // MIK-6687.CP.3 — an admin decision on a queued grant flips its status
    // through the audited-commit path (approve -> Approved, deny -> Revoked).
    #[test]
    fn decision_resolves_grant_through_audited_path() {
        use super::{Decision, DecisionRequest, resolve_decision_core};
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
        let mut g = grant();
        g.status = ControlPlaneGrantStatus::Requested;
        store.put_grant(g).unwrap();

        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::Grant,
                target_id: "grant-1".to_string(),
                decision: Decision::Approve,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            store.get_grant("grant-1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Approved
        );
        assert_eq!(store.read_audit(&AuditFilter::new(10)).unwrap().len(), 1);

        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::Grant,
                target_id: "grant-1".to_string(),
                decision: Decision::Deny,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            store.get_grant("grant-1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Revoked
        );
        // Deny is also audited: two decisions -> two audit entries.
        assert_eq!(store.read_audit(&AuditFilter::new(10)).unwrap().len(), 2);
    }

    // MIK-6687.CP.3 — a policy decision flips `enforced` through the audited path.
    #[test]
    fn decision_resolves_policy_through_audited_path() {
        use super::{Decision, DecisionRequest, resolve_decision_core};
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
        store
            .put_policy(crate::control_plane::ControlPlanePolicy {
                policy_id: "pol-1".to_string(),
                name: "p".to_string(),
                enforced: false,
            })
            .unwrap();

        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::Policy,
                target_id: "pol-1".to_string(),
                decision: Decision::Approve,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(store.get_policy("pol-1").unwrap().unwrap().enforced);
        assert_eq!(store.read_audit(&AuditFilter::new(10)).unwrap().len(), 1);
    }

    // MIK-6687.CP.3 — decision guards: non-admin denied (no state change), a
    // missing target returns 404, an unsupported kind returns 422.
    #[test]
    fn decision_guards_rbac_missing_and_unsupported() {
        use super::{Decision, DecisionRequest, resolve_decision_core};
        let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
        let mut g = grant();
        g.status = ControlPlaneGrantStatus::Requested;
        store.put_grant(g).unwrap();

        // Auditor is denied; grant stays Requested; no audit entry.
        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Auditor),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::Grant,
                target_id: "grant-1".to_string(),
                decision: Decision::Approve,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            store.get_grant("grant-1").unwrap().unwrap().status,
            ControlPlaneGrantStatus::Requested
        );
        assert!(store.read_audit(&AuditFilter::new(10)).unwrap().is_empty());

        // Missing target -> 404.
        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::Policy,
                target_id: "absent".to_string(),
                decision: Decision::Approve,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // Unsupported kind -> 422.
        let resp = resolve_decision_core(
            Some(&store),
            &actor(ControlPlaneRole::Admin),
            DecisionRequest {
                target_kind: ControlPlaneDecisionTargetKind::RuntimeHealth,
                target_id: "srv-1".to_string(),
                decision: Decision::Approve,
                reason: "MIK-1".to_string(),
                rollback: rollback(),
            },
        );
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}

#[cfg(test)]
mod role_wiring_tests {
    use super::actor_from_client;
    use crate::control_plane::{
        ControlPlaneAction, ControlPlaneRbac, ControlPlaneRole, ControlPlaneRoleMappingConfig,
        ControlPlaneRoleRule,
    };
    use crate::gateway::auth::AuthenticatedClient;
    use crate::key_server::oidc::VerifiedIdentity;

    fn client(admin: bool) -> AuthenticatedClient {
        AuthenticatedClient {
            name: "c".to_string(),
            rate_limit: 0,
            backends: Vec::new(),
            allowed_tools: None,
            denied_tools: None,
            admin,
        }
    }

    fn identity(issuer: &str, groups: &[&str]) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: "s".to_string(),
            email: "a@corp".to_string(),
            name: None,
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            issuer: issuer.to_string(),
        }
    }

    // MIK-6688.ROLE.3 — no verified identity -> legacy admin-key projection.
    #[test]
    fn no_identity_uses_legacy_admin_key_projection() {
        let empty = ControlPlaneRoleMappingConfig::default();
        assert_eq!(
            actor_from_client(Some(&client(true)), None, &empty).role,
            ControlPlaneRole::Admin
        );
        assert_eq!(
            actor_from_client(Some(&client(false)), None, &empty).role,
            ControlPlaneRole::Auditor
        );
        assert_eq!(
            actor_from_client(None, None, &empty).role,
            ControlPlaneRole::Auditor
        );
    }

    // MIK-6688.ROLE.2 — a verified identity with no matching rule is Auditor,
    // even when an admin API key is also present (identity path wins).
    #[test]
    fn verified_identity_without_rule_is_auditor_not_admin() {
        let empty = ControlPlaneRoleMappingConfig::default();
        let actor = actor_from_client(
            Some(&client(true)),
            Some(&identity("https://idp", &["x"])),
            &empty,
        );
        assert_eq!(actor.role, ControlPlaneRole::Auditor);
        // Collision-safe length-prefixed id (MIK-6702 CP.ID.1): issuer len 11, subject len 1.
        assert_eq!(actor.actor_id, "oidc:11:https://idp:1:s");
    }

    // MIK-6688.ROLE.6 — a mapped SecurityReviewer can read evidence but cannot mutate.
    #[test]
    fn mapped_security_reviewer_reads_but_cannot_mutate() {
        let mapping = ControlPlaneRoleMappingConfig {
            rules: vec![ControlPlaneRoleRule {
                issuer: "https://idp".to_string(),
                group: Some("sec".to_string()),
                email: None,
                domain: None,
                role: ControlPlaneRole::SecurityReviewer,
            }],
        };
        let actor = actor_from_client(None, Some(&identity("https://idp", &["sec"])), &mapping);
        assert_eq!(actor.role, ControlPlaneRole::SecurityReviewer);
        assert!(ControlPlaneRbac::authorize(&actor, ControlPlaneAction::ReadEvidence).allowed);
        assert!(!ControlPlaneRbac::authorize(&actor, ControlPlaneAction::MutateGrant).allowed);
    }

    // MIK-6702.CP.ID.1 — actor_id is collision-safe: two distinct (issuer,
    // subject) pairs that collide under the naive `oidc:{issuer}:{subject}`
    // format (issuer containing ':') now map to DISTINCT ids.
    #[test]
    fn actor_id_is_collision_safe() {
        let a = identity("https://idp/a", &[]); // subject "s"
        let mut b = identity("https://idp/a:1", &[]);
        b.subject = "s".to_string();
        // Naive format: both would render "oidc:https://idp/a:1:s" for some
        // subject split; the length-prefixed form keeps them distinct.
        let id_a =
            actor_from_client(None, Some(&a), &ControlPlaneRoleMappingConfig::default()).actor_id;
        let id_b =
            actor_from_client(None, Some(&b), &ControlPlaneRoleMappingConfig::default()).actor_id;
        assert_ne!(id_a, id_b, "distinct identities must not collide");
        // Sanity: the control-plane id matches the key-server key for one identity.
        assert_eq!(id_a, a.stable_actor_id());
    }

    // MIK-6702.CP.RELOAD.1 — the role mapping is read live: a reload that
    // removes an admin rule stops granting Admin without a restart. Simulates
    // the reload by swapping the LiveConfig the handler reads through.
    #[test]
    fn role_mapping_reload_revokes_admin_without_restart() {
        use crate::config::Config;
        use crate::config_reload::LiveConfig;

        let admin_id = identity("https://idp", &["admins"]);
        let mut cfg = Config::default();
        cfg.control_plane.role_mapping = ControlPlaneRoleMappingConfig {
            rules: vec![ControlPlaneRoleRule {
                issuer: "https://idp".to_string(),
                group: Some("admins".to_string()),
                email: None,
                domain: None,
                role: ControlPlaneRole::Admin,
            }],
        };
        let live = LiveConfig::new(cfg);

        // Before reload: the mapping grants Admin.
        let before = actor_from_client(
            None,
            Some(&admin_id),
            &live.get().control_plane.role_mapping,
        );
        assert_eq!(before.role, ControlPlaneRole::Admin);

        // Reload removes the admin rule (empty mapping).
        live.set(Config::default());

        // After reload: reading through the SAME handle, Admin is revoked.
        let after = actor_from_client(
            None,
            Some(&admin_id),
            &live.get().control_plane.role_mapping,
        );
        assert_eq!(
            after.role,
            ControlPlaneRole::Auditor,
            "a removed admin rule must stop granting Admin after reload"
        );
    }
}

#[cfg(test)]
mod read_reflect_tests {
    use super::merge_store_into_snapshot;
    use crate::control_plane::{
        AuditFilter, ControlPlaneAction, ControlPlaneActor, ControlPlaneAuditEvent,
        ControlPlaneGrant, ControlPlaneGrantStatus, ControlPlanePolicy, ControlPlaneRole,
        ControlPlaneRollbackPlan, ControlPlaneSnapshot, ControlPlaneStore,
        InMemoryControlPlaneStore, StoreError, StoreResult,
    };

    fn auditor() -> ControlPlaneActor {
        ControlPlaneActor {
            actor_id: "auditor".to_string(),
            display_name: "auditor".to_string(),
            role: ControlPlaneRole::Auditor,
            group_ids: vec![],
        }
    }

    /// A store whose every read fails — used to prove the degraded flag.
    struct FailingStore;
    impl ControlPlaneStore for FailingStore {
        fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn get_grant(&self, _id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn put_grant(&self, _grant: ControlPlaneGrant) -> StoreResult<()> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn delete_grant(&self, _id: &str) -> StoreResult<()> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn get_policy(&self, _id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn put_policy(&self, _policy: ControlPlanePolicy) -> StoreResult<()> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn delete_policy(&self, _id: &str) -> StoreResult<()> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn append_audit(&self, _event: &ControlPlaneAuditEvent) -> StoreResult<()> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
        fn read_audit(&self, _filter: &AuditFilter) -> StoreResult<Vec<ControlPlaneAuditEvent>> {
            Err(StoreError::Corrupt("boom".to_string()))
        }
    }

    // MIK-6701.CP.READ.1/2 — persisted store rows are reflected in the snapshot:
    // grants/policies upsert by id (store wins), audit_events come from the store.
    #[test]
    fn store_rows_reflected_and_upserted() {
        let store = InMemoryControlPlaneStore::new();
        store
            .put_grant(ControlPlaneGrant {
                grant_id: "g1".to_string(),
                subject_id: "store-user".to_string(),
                server_id: "srv".to_string(),
                tool_id: None,
                status: ControlPlaneGrantStatus::Approved,
            })
            .unwrap();
        store
            .put_policy(ControlPlanePolicy {
                policy_id: "p1".to_string(),
                name: "p".to_string(),
                enforced: true,
            })
            .unwrap();
        store
            .append_audit(&ControlPlaneAuditEvent {
                event_id: "e1".to_string(),
                actor_id: "alice".to_string(),
                action: ControlPlaneAction::MutateGrant,
                target_id: "g1".to_string(),
                reason: "MIK-1".to_string(),
                rollback: ControlPlaneRollbackPlan {
                    summary: "revert".to_string(),
                    step: "restore".to_string(),
                },
            })
            .unwrap();

        // A snapshot that already has a LOCAL projection of g1 (different status).
        let mut snapshot = ControlPlaneSnapshot::default();
        snapshot.grants.push(ControlPlaneGrant {
            grant_id: "g1".to_string(),
            subject_id: "local-projection".to_string(),
            server_id: "srv".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Requested,
        });

        let degraded = merge_store_into_snapshot(&store, &mut snapshot);
        assert!(!degraded, "a healthy store read must not report degraded");

        // Store row wins by id — no duplicate, status reflects the store.
        assert_eq!(
            snapshot
                .grants
                .iter()
                .filter(|g| g.grant_id == "g1")
                .count(),
            1
        );
        let g = snapshot.grants.iter().find(|g| g.grant_id == "g1").unwrap();
        assert_eq!(g.status, ControlPlaneGrantStatus::Approved);
        assert_eq!(g.subject_id, "store-user");
        // Policy + audit reflected.
        assert!(
            snapshot
                .policies
                .iter()
                .any(|p| p.policy_id == "p1" && p.enforced)
        );
        assert_eq!(snapshot.audit_events.len(), 1);
        assert_eq!(snapshot.audit_events[0].event_id, "e1");
        // AuditFilter is exercised via read_audit inside the merge.
        assert!(store.read_audit(&AuditFilter::new(10)).is_ok());
    }

    // A grant present only locally (not in the store) is preserved.
    #[test]
    fn local_only_grant_is_kept() {
        let store: &dyn ControlPlaneStore = &InMemoryControlPlaneStore::new();
        let mut snapshot = ControlPlaneSnapshot::default();
        snapshot.grants.push(ControlPlaneGrant {
            grant_id: "local-1".to_string(),
            subject_id: "u".to_string(),
            server_id: "s".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Approved,
        });
        let degraded = merge_store_into_snapshot(store, &mut snapshot);
        assert!(!degraded);
        assert!(snapshot.grants.iter().any(|g| g.grant_id == "local-1"));
    }

    // MIK-6701.CP.READ.1 (API contract) — the store's approved grant + enforced
    // policy are exposed as ROWS in the read-only view (not just as a count).
    // This is the API contract the direct-helper test above cannot see: before
    // the fix the view had no grants/policies fields, so a persisted approved
    // grant/enforced policy was invisible on GET except in derived counts.
    #[test]
    fn read_only_view_exposes_store_grants_and_policies_as_rows() {
        let store = InMemoryControlPlaneStore::new();
        store
            .put_grant(ControlPlaneGrant {
                grant_id: "g-approved".to_string(),
                subject_id: "u".to_string(),
                server_id: "srv".to_string(),
                tool_id: None,
                status: ControlPlaneGrantStatus::Approved,
            })
            .unwrap();
        store
            .put_policy(ControlPlanePolicy {
                policy_id: "p-enforced".to_string(),
                name: "p".to_string(),
                enforced: true,
            })
            .unwrap();

        let mut snapshot = ControlPlaneSnapshot::default();
        let degraded = merge_store_into_snapshot(&store, &mut snapshot);
        assert!(!degraded);

        let view = snapshot
            .read_only_view(&auditor())
            .expect("auditor can read inventory + evidence");
        assert!(
            view.grants.iter().any(|g| g.grant_id == "g-approved"),
            "approved grant must be a row in the view"
        );
        assert!(
            view.policies.iter().any(|p| p.policy_id == "p-enforced"),
            "enforced policy must be a row in the view"
        );

        // The serialized JSON must carry the row arrays (not just counts).
        let json = serde_json::to_value(&view).unwrap();
        assert!(json["grants"].is_array());
        assert!(json["policies"].is_array());
        assert_eq!(json["grants"][0]["grant_id"], "g-approved");
        assert_eq!(json["policies"][0]["policy_id"], "p-enforced");
    }

    // MIK-6701.CP.READ.2 (failure mode) — a store read failure sets the degraded
    // flag so an empty/stale view is not mistaken for an authoritative empty
    // result.
    #[test]
    fn store_read_failure_marks_degraded() {
        let mut snapshot = ControlPlaneSnapshot::default();
        let degraded = merge_store_into_snapshot(&FailingStore, &mut snapshot);
        assert!(degraded, "a failing store read must report degraded");
    }

    // MIK-6701.CP.READ.3 — feature entitlements report GovernanceMutation as
    // available exactly when the mutation endpoint is active, instead of always
    // reporting only LocalStatus.
    #[test]
    fn governance_mutation_entitlement_tracks_mutation_route() {
        use super::feature_entitlements;
        use crate::control_plane::ControlPlaneFeature;

        let read_only = feature_entitlements(false);
        let gov = read_only
            .iter()
            .find(|e| e.feature == ControlPlaneFeature::GovernanceMutation)
            .expect("GovernanceMutation entitlement present");
        assert!(
            !gov.available_in_this_route,
            "GovernanceMutation must be unavailable on a read-only route"
        );

        let mutating = feature_entitlements(true);
        let gov = mutating
            .iter()
            .find(|e| e.feature == ControlPlaneFeature::GovernanceMutation)
            .expect("GovernanceMutation entitlement present");
        assert!(
            gov.available_in_this_route,
            "GovernanceMutation must be available when the mutation endpoint is active"
        );
        // LocalStatus stays available on both routes.
        assert!(
            mutating
                .iter()
                .any(|e| e.feature == ControlPlaneFeature::LocalStatus
                    && e.available_in_this_route)
        );
    }
}
