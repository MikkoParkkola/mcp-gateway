// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A credential's backend scope bounds the control-plane snapshot's
//! gateway-wide objects: identity grants, local policies, store audit events
//! and the shadow radar, and every count and coverage figure derived from
//! them. Each caller kind of the scope grid reads the snapshot with and
//! without a seeded store.

use super::*;
use crate::control_plane::{ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

/// The seeded audit events' targets. No production writer targets a backend
/// (every written action is a grant or policy change, pinned in the store),
/// so the two `backend:` targets are fixture-only. A scoped reader is shown
/// none of the three, not even the event about its own backend: store audit
/// events are gateway-wide.
const TARGETS: [&str; 3] = ["grant-seeded", "backend:alpha", "backend:beta"];

/// One identity grant under a subject no caller holds, and an audit event per
/// [`TARGETS`] entry by an actor no caller is.
fn seed(state: &AppState, store: bool) {
    state
        .meta_mcp
        .set_identity_grants(LocalIdentityGrantStore::from_grants([IdentityGrant {
            grant_id: "grant-seeded".to_string(),
            subject: GrantSubject::new(ISSUER, "nobody-1", None),
            agent: GrantAgent::Any,
            capability: "matrix-capability".to_string(),
            tool: None,
            scope: GrantScope::Execute,
            owner: None,
            expires_at: None,
            revoked_at: None,
            provenance: "local-file".to_string(),
            reason: "scope grid".to_string(),
        }]));
    if !store {
        return;
    }
    let store = state.control_plane_store.as_ref().expect("a store");
    for (n, target) in TARGETS.into_iter().enumerate() {
        store
            .append_audit(&ControlPlaneAuditEvent {
                grant_change: None,
                event_id: format!("scope-event-{n}"),
                actor_id: "scope-grid-operator".to_string(),
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

/// `who`'s snapshot as one cell: status, then the grants, policies and audit
/// targets it shows, the radar, the derived counts and the grants/policies
/// coverage. The radar reads the host's real environment, so only whether it
/// ran is pinned, and its summary when it did not.
async fn cell(who: Who, store: bool) -> String {
    let mut fx = scoped_fixture().await;
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
    let len = |list: &str| view[list].as_array().map_or(0, Vec::len);
    let mut targets: Vec<&str> = view["audit_events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|event| event["target_id"].as_str())
        .collect();
    targets.sort_unstable();
    let radar = &body["shadow_radar"];
    let radar = if radar["scan_status"] == "out_of_scope" {
        format!(
            "out_of_scope:{}/{}",
            radar["summary"]["discovered_total"], radar["summary"]["unmanaged_total"]
        )
    } else {
        "ran".to_string()
    };
    let counts = &body["inventory_counts"];
    let shadow = if radar == "ran" {
        "-".to_string()
    } else {
        counts["shadow_assets"].to_string()
    };
    format!(
        "{}|grants:{}|policies:{}|audit:{}|radar:{radar}|counts:{}/{}/{shadow}|cov:{}/{}",
        code.as_u16(),
        len("grants"),
        len("policies"),
        targets.join(";"),
        counts["policies"],
        counts["audit_events"],
        body["coverage"]["grants"],
        body["coverage"]["policies"],
    )
}

/// What each caller is shown, without and with the seeded store. An
/// unscoped caller keeps today's snapshot; a scoped one is shown no grant,
/// no policy, no store audit event and no radar, whatever its role.
fn expected(who: Who) -> [String; 2] {
    let unscoped = |grants: usize, audit: &str| {
        [
            format!(
                "200|grants:{grants}|policies:2|audit:|radar:ran|counts:2/0/-|cov:{}/true",
                grants > 0
            ),
            format!(
                "200|grants:{grants}|policies:2|audit:{audit}|radar:ran|counts:2/{}/-|cov:{}/true",
                audit.split(';').filter(|t| !t.is_empty()).count(),
                grants > 0
            ),
        ]
    };
    let scoped = || {
        let cell =
            "200|grants:0|policies:0|audit:|radar:out_of_scope:0/0|counts:0/0/0|cov:false/false";
        [cell.to_string(), cell.to_string()]
    };
    let all = "backend:alpha;backend:beta;grant-seeded";
    match who {
        Who::AdminKey | Who::Auditor | Who::UiAdminKey => unscoped(1, all),
        Who::Developer => unscoped(0, ""),
        Who::ScopedKey
        | Who::ScopedAuditor
        | Who::ScopedDeveloper
        | Who::ScopedRoleAdmin
        | Who::ScopedAdminKey
        | Who::EmptyAuditor
        | Who::EmptyRoleAdmin => scoped(),
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
