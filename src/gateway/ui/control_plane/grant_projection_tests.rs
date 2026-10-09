// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::control_plane_grant_from_identity;
use crate::control_plane::ControlPlaneGrantStatus;
use crate::identity_grants::{GrantAgent, GrantScope, GrantSubject, IdentityGrant};
use chrono::Utc;

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
    g.expires_at = Some(Utc::now() - crate::duration_bound::delta!(hours, 1));
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
