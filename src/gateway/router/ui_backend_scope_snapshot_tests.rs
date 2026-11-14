// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential's backend scope bounds the control-plane snapshot's
//! gateway-wide objects: identity grants, local policies, store audit events
//! and the shadow radar, and every count and coverage figure derived from
//! them. Each caller kind of the scope grid reads the snapshot with and
//! without a seeded store.

use super::*;
use crate::control_plane::{ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan};
use crate::discovery::shadow::{ShadowEnterpriseBoundary, ShadowScanSummary};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

/// The seeded audit events: (target, whether the Developer performed it).
/// No production writer targets a backend (every written action is a grant
/// or policy change, pinned in the store), so the two `backend:` targets are
/// fixture-only. A scoped reader is shown none of them, not even the event
/// about its own backend or one it performed itself: store audit events are
/// gateway-wide.
const EVENTS: [(&str, bool); 4] = [
    ("grant-seeded", false),
    ("backend:alpha", false),
    ("backend:beta", false),
    ("grant-dev", true),
];

fn grant(grant_id: &str, subject: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::for_test(ISSUER, subject, None),
        agent: GrantAgent::Any,
        capability: "matrix-capability".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "local-file".to_string(),
        reason: "scope grid".to_string(),
    }
}

/// Two identity grants, one under a subject no caller holds and one under
/// the Developer's, and the [`EVENTS`], by the Developer or by an actor no
/// caller is.
fn seed(state: &AppState, store: bool) {
    state
        .meta_mcp
        .set_identity_grants(LocalIdentityGrantStore::from_grants([
            grant("grant-seeded", "nobody-1"),
            grant("grant-dev", DEV),
        ]));
    if !store {
        return;
    }
    let developer = Who::Developer
        .identity()
        .expect("the Developer signs in")
        .stable_actor_id();
    let store = state.control_plane_store.as_ref().expect("a store");
    for (n, (target, by_developer)) in EVENTS.into_iter().enumerate() {
        store
            .append_audit(&ControlPlaneAuditEvent {
                grant_change: None,
                ui_decision: None,
                event_id: format!("scope-event-{n}"),
                actor_id: if by_developer {
                    developer.clone()
                } else {
                    "scope-grid-operator".to_string()
                },
                action: ControlPlaneAction::MutateGrant,
                target_id: target.to_string(),
                reason: "scope grid seed".to_string(),
                rollback: ControlPlaneRollbackPlan {
                    summary: "revert".to_string(),
                    step: "none".to_string(),
                },
            })
            .expect("the event is stored");
    }
}

/// Whether `radar` is a withheld scan: no asset, every summary total zero,
/// and the boundary a zero summary makes.
fn withheld(radar: &Value) -> bool {
    let zero = ShadowScanSummary {
        discovered_total: 0,
        managed_total: 0,
        unmanaged_total: 0,
        high_or_critical_total: 0,
        adoptable_total: 0,
        network_exposed_total: 0,
    };
    radar["control_plane_assets"]
        .as_array()
        .is_some_and(Vec::is_empty)
        && radar["summary"] == serde_json::to_value(&zero).expect("a summary")
        && radar["enterprise_boundary"]
            == serde_json::to_value(ShadowEnterpriseBoundary::local_passive(&zero))
                .expect("a boundary")
        && radar["trustcard_input_count"] == 0
        && radar["doctor_finding_count"] == 0
}

/// `who`'s snapshot as one cell: status; the grants, policies and audit
/// targets it shows; the policy and grant items of its decision queue; the
/// radar; the derived counts; the grants/policies coverage. Input
/// sanitization is off, so an unscoped reader's queue holds that policy's
/// item. The radar reads the host's real environment, so whether it ran is
/// pinned, all its counts when it did not, and in every cell that the
/// inventory counts are the radar's own.
async fn cell(who: Who, store: bool) -> String {
    let mut fx = scoped_fixture().await;
    let mut config = (*fx.state.live_config.get()).clone();
    config.security.sanitize_input = false;
    fx.state.live_config.set(config);
    if store {
        Arc::get_mut(&mut fx.state)
            .expect("state is unique")
            .control_plane_store = Some(Arc::new(
            crate::control_plane::InMemoryControlPlaneStore::new(),
        ));
    }
    seed(&fx.state, store);
    let router = create_router(Arc::clone(&fx.state));
    let (code, body) = send(&router, get(who, routes::UI_CONTROL_PLANE)).await;
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let view = &body["view"];
    // A list the answer leaves out reads MISSING, never as empty: a dropped
    // field must move a cell, not pass as "shown none".
    let len = |list: &str| {
        view[list]
            .as_array()
            .map_or_else(|| "MISSING".to_string(), |items| items.len().to_string())
    };
    let sorted = |list: &Value, field: &str, keep: &dyn Fn(&str) -> bool| {
        let Some(items) = list.as_array() else {
            return "MISSING".to_string();
        };
        let mut ids: Vec<&str> = items
            .iter()
            .filter_map(|item| item[field].as_str())
            .filter(|id| keep(id))
            .collect();
        ids.sort_unstable();
        ids.join(";")
    };
    let targets = sorted(&view["audit_events"], "target_id", &|_| true);
    let queue = sorted(&body["decision_queue"]["items"], "item_id", &|id| {
        id.starts_with("policy:") || id.starts_with("grant:")
    });
    let radar = &body["shadow_radar"];
    let counts = &body["inventory_counts"];
    let consistent = counts["shadow_assets"] == radar["summary"]["unmanaged_total"]
        && counts["shadow_high_or_critical_assets"] == radar["summary"]["high_or_critical_total"];
    // Only the two statuses a run produces read "ran"; any other status is
    // printed as itself, so an unknown one moves the cell.
    let radar = match radar["scan_status"].as_str() {
        Some("out_of_scope") => format!("out_of_scope:withheld={}", withheld(radar)),
        Some("ok" | "unavailable") => "ran".to_string(),
        other => format!("status:{other:?}"),
    };
    // Every inventory count, so a figure derived before narrowing moves the
    // cell. The two shadow counts read the host's real scan when it ran.
    let ran = radar == "ran";
    let field = |name: &str| {
        let value = &counts[name];
        if value.is_u64() {
            value.to_string()
        } else {
            format!("MISSING:{name}")
        }
    };
    let inventory = [
        "servers",
        "tools",
        "trust_cards",
        "trust_evaluations",
        "requested_grants",
        "policies",
        "users",
        "groups",
        "runtime_health",
        "audit_events",
        "shadow_assets",
        "shadow_high_or_critical_assets",
    ]
    .map(|name| {
        if ran && name.starts_with("shadow_") {
            "-".to_string()
        } else {
            field(name)
        }
    })
    .join("/");
    let all_principals = &body["authorizations"]["read_all_principals"];
    let all_principals = format!(
        "{}/{}",
        all_principals["allowed"], all_principals["reason_code"]
    );
    format!(
        "{}|grants:{}|policies:{}|audit:{targets}|queue:{queue}|radar:{radar}|counts:{}/{}/{consistent}|cov:{}/{}/{}|all:{all_principals}|inv:{inventory}",
        code.as_u16(),
        len("grants"),
        len("policies"),
        counts["policies"],
        counts["audit_events"],
        body["coverage"]["grants"],
        body["coverage"]["policies"],
        body["coverage"]["audit_events"],
    )
}

/// Every seeded event's target, sorted, as an all-principals reader sees them.
const ALL_EVENTS: &str = "backend:alpha;backend:beta;grant-dev;grant-seeded";

/// The policy queue items an unscoped reader gets: sanitization is off in
/// the fixture, and SSRF protection is off in every router fixture.
const SANITIZE_ITEM: &str =
    "policy:local:input_sanitization:not_enforced;policy:local:ssrf_protection:not_enforced";

/// What each caller is shown, without and with the seeded store. An
/// unscoped caller keeps today's snapshot, its own rows only when it reads
/// no other principal's; a scoped one is shown no grant, no policy, no store
/// audit event, no queue item for either and no radar, whatever its role.
fn expected(who: Who) -> [String; 2] {
    // servers/tools/trust_cards/trust_evaluations/requested_grants/policies/
    // users/groups/runtime_health/audit_events/shadow_assets/shadow_high.
    // The caller is the one user, in one group: an identity's, or the default
    // a key-only caller is given.
    let inventory = |servers: usize, policies: usize, events: usize, shadow: &str| {
        format!("{servers}/0/0/0/0/{policies}/1/1/{servers}/{events}/{shadow}")
    };
    let unscoped = |grants: usize, audit: &str, all: &str| {
        let events = audit.split(';').filter(|t| !t.is_empty()).count();
        [("", 0), (audit, events)].map(|(audit, events)| {
            format!(
                "200|grants:{grants}|policies:2|audit:{audit}|queue:{SANITIZE_ITEM}|radar:ran|counts:2/{events}/true|cov:{}/true/{}|all:{all}|inv:{}",
                grants > 0,
                events > 0,
                inventory(2, 2, events, "-/-"),
            )
        })
    };
    let scoped = |servers: usize| {
        let cell = format!(
            "200|grants:0|policies:0|audit:|queue:|radar:out_of_scope:withheld=true|counts:0/0/true|cov:false/false/false|all:false/\"CONTROL_BACKEND_SCOPE\"|inv:{}",
            inventory(servers, 0, 0, "0/0"),
        );
        [cell.clone(), cell]
    };
    match who {
        Who::AdminKey | Who::UiAdminKey => unscoped(2, ALL_EVENTS, r#"true/"CONTROL_RBAC_ADMIN""#),
        Who::Auditor => unscoped(2, ALL_EVENTS, r#"true/"CONTROL_RBAC_AUDITOR_READ""#),
        Who::Developer => unscoped(1, "grant-dev", r#"false/"CONTROL_RBAC_ACTION_DENIED""#),
        Who::ScopedKey
        | Who::ScopedAdminKey
        | Who::ScopedAuditor
        | Who::ScopedDeveloper
        | Who::ScopedRoleAdmin => scoped(1),
        Who::EmptyAuditor | Who::EmptyRoleAdmin => scoped(0),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_scope_bounds_the_snapshots_gateway_wide_objects() {
    let mut wrong = Vec::new();
    for who in WHO {
        let got = [cell(who, false).await, cell(who, true).await];
        let want = expected(who);
        if got != want {
            wrong.push(format!("{who:?}:\n  got  {got:?}\n  want {want:?}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} callers moved:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A failed audit read is still reported to a scoped caller: the store is
/// read for every caller, and only its events are withheld.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scoped_reader_still_learns_the_audit_read_failed() {
    for who in [Who::AdminKey, Who::ScopedAuditor] {
        let mut fx = scoped_fixture().await;
        Arc::get_mut(&mut fx.state)
            .expect("state is unique")
            .control_plane_store = Some(Arc::new(crate::control_plane::FailingStore));
        let router = create_router(Arc::clone(&fx.state));
        let (code, body) = send(&router, get(who, routes::UI_CONTROL_PLANE)).await;
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        assert_eq!(code, StatusCode::OK, "{who:?}: {body}");
        assert_eq!(body["store_read_degraded"], true, "{who:?}: {body}");
        assert_eq!(
            body["view"]["audit_events"],
            serde_json::json!([]),
            "{who:?}"
        );
    }
}
