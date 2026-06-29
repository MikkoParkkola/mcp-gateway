//! Read-only control-plane API surface.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use super::super::auth::AuthenticatedClient;
use super::super::router::AppState;
use super::errors::auth_required;
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneActor, ControlPlaneAuthorization, ControlPlaneDecisionQueue,
    ControlPlaneDomainCoverage, ControlPlaneFeature, ControlPlaneGrantStatus, ControlPlaneHealth,
    ControlPlaneLicenseTier, ControlPlaneRbac, ControlPlaneReadOnlyView, ControlPlaneRole,
    ControlPlaneRuntimeHealth, ControlPlaneServer, ControlPlaneServerStatus, ControlPlaneSnapshot,
    ControlPlaneTool, ControlPlaneUser,
};
use crate::discovery::AutoDiscovery;
use crate::discovery::shadow::{
    SHADOW_HANDOFF_SCHEMA_VERSION, SHADOW_REPORT_SCHEMA_VERSION, ShadowControlPlaneAsset,
    ShadowScanReport, ShadowScanSummary,
};

/// Build the read-only control-plane API router.
pub fn control_plane_router() -> Router<Arc<AppState>> {
    Router::new().route("/ui/api/control-plane", get(control_plane_snapshot))
}

async fn control_plane_snapshot(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(client)| client);
    let actor = actor_from_client(client.as_ref());
    let snapshot = local_runtime_snapshot(&state, client.as_ref(), &actor);
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
    );
    Json(response).into_response()
}

fn actor_from_client(client: Option<&AuthenticatedClient>) -> ControlPlaneActor {
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

fn local_runtime_snapshot(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    actor: &ControlPlaneActor,
) -> ControlPlaneSnapshot {
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
        snapshot.servers.push(ControlPlaneServer {
            server_id: format!("backend:{}", status.name),
            name: status.name.clone(),
            owner_group_id: actor
                .group_ids
                .first()
                .cloned()
                .unwrap_or_else(|| "local-auditors".to_string()),
            status: server_status_from_backend(&status),
        });

        snapshot.runtime_health.push(ControlPlaneRuntimeHealth {
            server_id: format!("backend:{}", status.name),
            provider: status.transport.clone(),
            health: runtime_health_from_backend(&status),
        });

        for tool in backend.get_cached_tools_snapshot().iter() {
            snapshot.tools.push(ControlPlaneTool {
                tool_id: format!("backend:{}:tool:{}", status.name, tool.name),
                server_id: format!("backend:{}", status.name),
                name: tool.name.clone(),
                high_impact: is_high_impact_tool(tool),
            });
        }
    }

    snapshot
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
    ) -> Self {
        let coverage = snapshot.domain_coverage();
        let inventory_counts = ControlPlaneInventoryCounts::from_snapshot(snapshot, &shadow_radar);
        Self {
            schema_version: "control_plane.api.v1",
            source: "local_runtime_snapshot",
            route: ControlPlaneRouteMode::default(),
            features: feature_entitlements(),
            authorizations: ControlPlaneAuthorizationSet::for_actor(&actor),
            coverage,
            coverage_complete: coverage.is_complete(),
            inventory_counts,
            shadow_radar,
            actor,
            view,
            decision_queue,
            current_limits: vec![
                "read_only_api",
                "local_runtime_only",
                "no_persistence",
                "no_mutation_endpoint",
                "no_enterprise_export",
            ],
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
            trustcard_input_count: handoff.trustcard_inputs.len(),
            doctor_finding_count: handoff.doctor_findings.len(),
        }
    }

    fn scan_unavailable() -> Self {
        Self {
            schema_version: SHADOW_HANDOFF_SCHEMA_VERSION.to_string(),
            source_report_schema: SHADOW_REPORT_SCHEMA_VERSION.to_string(),
            source: "local_passive_discovery",
            scan_status: "unavailable",
            passive: true,
            tools_invoked: false,
            summary: ShadowScanSummary {
                discovered_total: 0,
                managed_total: 0,
                unmanaged_total: 0,
                high_or_critical_total: 0,
                adoptable_total: 0,
                network_exposed_total: 0,
            },
            control_plane_assets: Vec::new(),
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

fn feature_entitlements() -> Vec<ControlPlaneFeatureEntitlement> {
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
        available_in_this_route: feature == ControlPlaneFeature::LocalStatus,
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
