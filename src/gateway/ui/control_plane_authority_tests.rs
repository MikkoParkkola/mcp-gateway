// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E2-min (MIK 7570.ADMINGRANT.1): the admin store may not mask what dispatch
//! enforces.
//!
//! Grants are enforced from the identity-grants file and policies from
//! `security.sanitize_input` / `security.ssrf_protection`. The control-plane
//! store holds rows dispatch never reads, so a store row that shares an
//! enforced row's id must not change what the view shows. The HTTP half (409
//! on writes, the page no longer advertising mutation) is in
//! `tests/e2min_control_plane_authority.rs`.

use super::{control_plane_grant_from_identity, merge_store_into_snapshot};
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneActor, ControlPlaneAuditEvent, ControlPlaneGrant,
    ControlPlaneGrantStatus, ControlPlanePolicy, ControlPlaneRole, ControlPlaneRollbackPlan,
    ControlPlaneSnapshot, ControlPlaneStore, InMemoryControlPlaneStore,
};
use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};

fn admin() -> ControlPlaneActor {
    ControlPlaneActor {
        actor_id: "admin".to_string(),
        display_name: "admin".to_string(),
        role: ControlPlaneRole::Admin,
        group_ids: vec![],
    }
}

/// An active grant from the identity-grants file: the one dispatch enforces.
fn enforced_grant() -> IdentityGrant {
    IdentityGrant {
        grant_id: "g-enforced".to_string(),
        subject: GrantSubject::new("oidc", "sub-1", Some("alice@corp".to_string())),
        agent: GrantAgent::Any,
        capability: "gmail".to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "local-file".to_string(),
        reason: "test".to_string(),
    }
}

/// The row `local_policy_rows` projects for `ssrf_protection: true`.
fn enforced_ssrf_policy() -> ControlPlanePolicy {
    ControlPlanePolicy {
        policy_id: "local:ssrf_protection".to_string(),
        name: "SSRF protection".to_string(),
        enforced: true,
    }
}

#[test]
fn a_store_row_cannot_mask_an_enforced_grant_in_the_view() {
    let store = InMemoryControlPlaneStore::new();
    store
        .put_grant(ControlPlaneGrant {
            grant_id: "g-enforced".to_string(),
            subject_id: "store-row".to_string(),
            server_id: "srv".to_string(),
            tool_id: None,
            status: ControlPlaneGrantStatus::Revoked,
        })
        .unwrap();
    let mut snapshot = ControlPlaneSnapshot::default();
    snapshot.grants.push(control_plane_grant_from_identity(
        enforced_grant(),
        chrono::Utc::now(),
    ));

    assert!(!merge_store_into_snapshot(&store, &mut snapshot));

    let view = snapshot.read_only_view(&admin()).expect("admin reads");
    let rows: Vec<_> = view
        .grants
        .iter()
        .filter(|g| g.grant_id == "g-enforced")
        .collect();
    assert_eq!(rows.len(), 1, "one row per enforced grant: {rows:?}");
    assert_eq!(
        rows[0].status,
        ControlPlaneGrantStatus::Approved,
        "dispatch enforces this grant, so the view must not read the store's Revoked"
    );
}

#[test]
fn a_store_row_cannot_mask_an_enforced_policy_in_the_view() {
    let store = InMemoryControlPlaneStore::new();
    store
        .put_policy(ControlPlanePolicy {
            policy_id: "local:ssrf_protection".to_string(),
            name: "store row".to_string(),
            enforced: false,
        })
        .unwrap();
    let mut snapshot = ControlPlaneSnapshot::default();
    snapshot.policies.push(enforced_ssrf_policy());

    assert!(!merge_store_into_snapshot(&store, &mut snapshot));

    let view = snapshot.read_only_view(&admin()).expect("admin reads");
    let rows: Vec<_> = view
        .policies
        .iter()
        .filter(|p| p.policy_id == "local:ssrf_protection")
        .collect();
    assert_eq!(rows.len(), 1, "one row per enforced policy: {rows:?}");
    assert!(
        rows[0].enforced,
        "security.ssrf_protection is on, so the view must not read the store's enforced: false"
    );
}

/// Positive control: the store stays wired for the audit log, so the mask rows
/// above pass because the merge dropped grants and policies, not because the
/// store was disconnected.
#[test]
fn store_audit_events_still_reach_the_view() {
    let store = InMemoryControlPlaneStore::new();
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
    let mut snapshot = ControlPlaneSnapshot::default();

    assert!(!merge_store_into_snapshot(&store, &mut snapshot));

    let view = snapshot.read_only_view(&admin()).expect("admin reads");
    assert_eq!(view.audit_events.len(), 1);
    assert_eq!(view.audit_events[0].event_id, "e1");
}
