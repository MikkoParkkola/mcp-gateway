// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Snapshot assembly: local runtime view, store merge and the response types.

use super::super::super::auth::AuthenticatedClient;
use super::super::super::router::AppState;
use crate::control_plane::role_mapping::ControlPlaneBaseSource;
use crate::control_plane::{
    AuditFilter, ControlPlaneAction, ControlPlaneActor, ControlPlaneAuthorization,
    ControlPlaneDecisionQueue, ControlPlaneDomainCoverage, ControlPlaneFeature, ControlPlaneGrant,
    ControlPlaneGrantStatus, ControlPlaneHealth, ControlPlaneLicenseTier, ControlPlaneRbac,
    ControlPlaneReadOnlyView, ControlPlaneRuntimeHealth, ControlPlaneServer,
    ControlPlaneServerStatus, ControlPlaneSnapshot, ControlPlaneStore, ControlPlaneTool,
    ControlPlaneTrustCard, ControlPlaneUser,
};
use crate::discovery::AutoDiscovery;
use crate::discovery::shadow::{
    SHADOW_HANDOFF_SCHEMA_VERSION, SHADOW_REPORT_SCHEMA_VERSION, ShadowControlPlaneAsset,
    ShadowEnterpriseBoundary, ShadowScanReport, ShadowScanSummary,
};
use crate::hashing::canonical_json_sha256;
use crate::trust::TrustCard;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;

/// Build the local runtime snapshot for the control-plane API.
///
/// Returns the snapshot plus a `store_read_degraded` flag: `true` when a durable
/// store is configured but at least one read failed, so the view fell back to
/// the local projection (MIK-6701).
pub(super) fn local_runtime_snapshot(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    actor: &ControlPlaneActor,
    now: chrono::DateTime<chrono::Utc>,
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
    for grant in state.meta_mcp.identity_grant_rows() {
        snapshot
            .grants
            .push(control_plane_grant_from_identity(grant, now));
    }

    // The durable governance store populates the audit-events view (MIK-6701).
    // Its grant and policy rows are not merged: dispatch never reads them, so
    // showing them would present unenforced rows as live, or mask an enforced
    // row with the same id (E2-min). A read error leaves the audit view empty
    // and is surfaced so an empty view is not mistaken for an authoritative one.
    let store_read_degraded = state
        .control_plane_store
        .as_ref()
        .is_some_and(|store| merge_store_into_snapshot(store.as_ref(), &mut snapshot));

    (snapshot, store_read_degraded)
}

/// Fill a runtime snapshot's `audit_events` from the store's tamper-evident
/// log. Grants and policies are left as the enforced projections: the store's
/// rows for those kinds are never enforced (E2-min).
///
/// Returns `true` if the audit read failed, so a client cannot mistake a failed
/// read for an authoritative empty result (MIK-6701).
#[must_use]
pub(super) fn merge_store_into_snapshot(
    store: &dyn ControlPlaneStore,
    snapshot: &mut ControlPlaneSnapshot,
) -> bool {
    let mut degraded = false;
    // One bounded page: the newest 200 events, newest first. The view never
    // walks the whole log, however long it has grown.
    match store.read_audit(&AuditFilter::new(200)) {
        Ok(page) => snapshot.audit_events = page.events,
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
pub(super) fn control_plane_grant_from_identity(
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

pub(super) fn trust_card_digest_sha256(card: &TrustCard) -> String {
    let json_value = serde_json::to_value(card).unwrap_or(serde_json::Value::Null);
    canonical_json_sha256(&json_value)
}

pub(super) async fn local_shadow_radar(state: &AppState) -> ControlPlaneShadowRadar {
    let registered_names: HashSet<String> = state
        .backends
        .all()
        .into_iter()
        .map(|backend| backend.name.clone())
        .collect();
    let discovery = match &state.env {
        Some(env) => AutoDiscovery::new().with_env(Arc::clone(env)),
        None => AutoDiscovery::new(),
    };

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

pub(super) fn local_policy_rows(state: &AppState) -> Vec<crate::control_plane::ControlPlanePolicy> {
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

pub(super) fn can_view_backend(client: Option<&AuthenticatedClient>, backend_name: &str) -> bool {
    client.is_some_and(|client| {
        // Backend ACCESS is not inventory VISIBILITY. The anonymous identity
        // used when authentication is disabled carries `backends: ["*"]` so
        // that ordinary tool invocation keeps working, which handed it the
        // whole control-plane inventory through `can_access_backend`. A scoped
        // API key still sees the backends it is scoped to.
        client.admin || (client.authenticated && client.can_access_backend(backend_name))
    })
}

pub(super) fn server_status_from_backend(
    status: &crate::backend::BackendStatus,
) -> ControlPlaneServerStatus {
    if status.circuit_state == crate::failsafe::CircuitState::Open {
        ControlPlaneServerStatus::Blocked
    } else {
        ControlPlaneServerStatus::Enabled
    }
}

pub(super) fn runtime_health_from_backend(
    status: &crate::backend::BackendStatus,
) -> ControlPlaneHealth {
    if status.circuit_state == crate::failsafe::CircuitState::Open {
        ControlPlaneHealth::Down
    } else if !status.running {
        ControlPlaneHealth::Unknown
    } else if status.healthy {
        ControlPlaneHealth::Healthy
    } else {
        ControlPlaneHealth::Degraded
    }
}

pub(super) fn is_high_impact_tool(tool: &crate::protocol::Tool) -> bool {
    tool.annotations.as_ref().is_some_and(|annotations| {
        annotations.destructive_hint.unwrap_or(false)
            || annotations.open_world_hint.unwrap_or(false)
            || matches!(annotations.idempotent_hint, Some(false))
    })
}

#[derive(Debug, Serialize)]
pub(super) struct ControlPlaneApiResponse {
    pub(super) schema_version: &'static str,
    pub(super) source: &'static str,
    pub(super) route: ControlPlaneRouteMode,
    pub(super) actor: ControlPlaneActor,
    pub(super) features: Vec<ControlPlaneFeatureEntitlement>,
    pub(super) authorizations: ControlPlaneAuthorizationSet,
    pub(super) coverage: ControlPlaneDomainCoverage,
    pub(super) coverage_complete: bool,
    pub(super) inventory_counts: ControlPlaneInventoryCounts,
    pub(super) shadow_radar: ControlPlaneShadowRadar,
    /// `true` when a durable store is configured but its audit read failed, so
    /// `view.audit_events` may be incomplete. Distinguishes "no rows" from
    /// "store unreadable" (MIK-6701).
    pub(super) store_read_degraded: bool,
    /// Why no store is open: `auth_off` or `store_unavailable` (MIK-7570 F6).
    /// Absent when a store is open; writes are then refused with 409, and
    /// `authority` says where to make them (E2-min).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) mutation_disabled_reason: Option<&'static str>,
    /// Whether the store base came from `control_plane.store_dir` (`explicit`)
    /// or from the config file's location (`default`).
    pub(super) base_source: ControlPlaneBaseSource,
    pub(super) view: ControlPlaneReadOnlyView,
    pub(super) decision_queue: ControlPlaneDecisionQueue,
    pub(super) current_limits: Vec<&'static str>,
    /// Where grants and policies are enforced from. The control-plane store is
    /// not an authority for either (E2-min).
    pub(super) authority: ControlPlaneAuthority,
}

/// The config each governance kind is enforced from, for the API response.
#[derive(Debug, Serialize)]
pub(super) struct ControlPlaneAuthority {
    pub(super) grants: &'static str,
    pub(super) policies: &'static str,
}

pub(super) const AUTHORITY: ControlPlaneAuthority = ControlPlaneAuthority {
    grants: "security.identity_grants.path",
    policies: "security.sanitize_input, security.ssrf_protection",
};

/// Boolean flags threaded into the control-plane API response, grouped to keep
/// [`ControlPlaneApiResponse::from_snapshot`] within the argument-count budget.
pub(super) struct ControlPlaneResponseFlags {
    /// Governance mutation endpoint is active. Always `false` since E2-min.
    pub(super) mutation_enabled: bool,
    /// A durable store read failed; the view fell back to the local projection.
    pub(super) store_read_degraded: bool,
    /// The SIEM export task is running.
    pub(super) export_configured: bool,
    /// See [`ControlPlaneApiResponse`].
    pub(super) mutation_disabled_reason: Option<&'static str>,
    /// See [`ControlPlaneApiResponse`].
    pub(super) base_source: ControlPlaneBaseSource,
}

impl ControlPlaneApiResponse {
    pub(super) fn from_snapshot(
        actor: ControlPlaneActor,
        snapshot: &ControlPlaneSnapshot,
        view: ControlPlaneReadOnlyView,
        decision_queue: ControlPlaneDecisionQueue,
        shadow_radar: ControlPlaneShadowRadar,
        flags: &ControlPlaneResponseFlags,
    ) -> Self {
        let &ControlPlaneResponseFlags {
            mutation_enabled,
            store_read_degraded,
            export_configured,
            mutation_disabled_reason,
            base_source,
        } = flags;
        let coverage = snapshot.domain_coverage();
        let inventory_counts = ControlPlaneInventoryCounts::from_snapshot(snapshot, &shadow_radar);
        let current_limits = if mutation_enabled {
            vec![
                "local_runtime_only",
                "mutation_endpoint_active",
                "no_enterprise_export",
            ]
        } else {
            let mut limits = vec![
                "read_only_api",
                "local_runtime_only",
                "no_persistence",
                "no_mutation_endpoint",
                "no_enterprise_export",
            ];
            // An open store (no disabled reason) still persists the audit log.
            if mutation_disabled_reason.is_none() {
                limits.retain(|limit| *limit != "no_persistence");
            }
            limits
        };
        Self {
            schema_version: "control_plane.api.v1",
            source: "local_runtime_snapshot",
            route: ControlPlaneRouteMode {
                read_only: !mutation_enabled,
                mutation_endpoint: mutation_enabled,
                mutating_actions_require_audit: true,
            },
            features: feature_entitlements(mutation_enabled, export_configured),
            authorizations: ControlPlaneAuthorizationSet::for_actor(&actor),
            coverage,
            coverage_complete: coverage.is_complete(),
            inventory_counts,
            shadow_radar,
            store_read_degraded,
            mutation_disabled_reason,
            base_source,
            actor,
            view,
            decision_queue,
            current_limits,
            authority: AUTHORITY,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ControlPlaneShadowRadar {
    pub(super) schema_version: String,
    pub(super) source_report_schema: String,
    pub(super) source: &'static str,
    pub(super) scan_status: &'static str,
    pub(super) passive: bool,
    pub(super) tools_invoked: bool,
    pub(super) summary: ShadowScanSummary,
    pub(super) control_plane_assets: Vec<ShadowControlPlaneAsset>,
    pub(super) enterprise_boundary: ShadowEnterpriseBoundary,
    pub(super) trustcard_input_count: usize,
    pub(super) doctor_finding_count: usize,
}

impl ControlPlaneShadowRadar {
    pub(super) fn from_report(report: &ShadowScanReport) -> Self {
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

    pub(super) fn scan_unavailable() -> Self {
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
pub(super) struct ControlPlaneRouteMode {
    pub(super) read_only: bool,
    pub(super) mutation_endpoint: bool,
    pub(super) mutating_actions_require_audit: bool,
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
pub(super) struct ControlPlaneFeatureEntitlement {
    pub(super) feature: ControlPlaneFeature,
    pub(super) license_tier: ControlPlaneLicenseTier,
    pub(super) available_in_this_route: bool,
}

/// Report which control-plane features are usable on the current route.
///
/// `LocalStatus` is always available (read surface); `GovernanceMutation` is
/// available when the mutation endpoint is active (CP.READ.3 — the entitlement
/// must track `route.mutation_endpoint`, not report read-only unconditionally).
/// `FleetInventory` and `EvidenceExport` are enterprise features not served by
/// this local route.
pub(super) fn feature_entitlements(
    mutation_enabled: bool,
    export_configured: bool,
) -> Vec<ControlPlaneFeatureEntitlement> {
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
            ControlPlaneFeature::EvidenceExport => export_configured,
            ControlPlaneFeature::FleetInventory => false,
        },
    })
    .collect()
}

#[derive(Debug, Serialize)]
pub(super) struct ControlPlaneAuthorizationSet {
    pub(super) read_inventory: ControlPlaneAuthorization,
    pub(super) read_evidence: ControlPlaneAuthorization,
    pub(super) review_evidence: ControlPlaneAuthorization,
    pub(super) mutate_grant: ControlPlaneAuthorization,
    pub(super) mutate_policy: ControlPlaneAuthorization,
    pub(super) approve_server: ControlPlaneAuthorization,
}

impl ControlPlaneAuthorizationSet {
    pub(super) fn for_actor(actor: &ControlPlaneActor) -> Self {
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
pub(super) struct ControlPlaneInventoryCounts {
    pub(super) servers: usize,
    pub(super) tools: usize,
    pub(super) trust_cards: usize,
    pub(super) trust_evaluations: usize,
    pub(super) requested_grants: usize,
    pub(super) policies: usize,
    pub(super) users: usize,
    pub(super) groups: usize,
    pub(super) runtime_health: usize,
    pub(super) audit_events: usize,
    pub(super) shadow_assets: usize,
    pub(super) shadow_high_or_critical_assets: usize,
}

impl ControlPlaneInventoryCounts {
    pub(super) fn from_snapshot(
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
