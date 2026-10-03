// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::actor_from_client;
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneRbac, ControlPlaneRole, ControlPlaneRoleMappingConfig,
    ControlPlaneRoleRule,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::key_server::oidc::VerifiedIdentity;

fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: String::new(),
        quota_principal: None,
        name: "c".to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
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
    // issuer "https://idp/a" + subject "b:c" vs issuer "https://idp/a:b" +
    // subject "c" both render "oidc:https://idp/a:b:c" under the naive form.
    let mut a = identity("https://idp/a", &[]);
    a.subject = "b:c".to_string();
    let mut b = identity("https://idp/a:b", &[]);
    b.subject = "c".to_string();
    // Precondition: the naive format genuinely collides for this pair.
    assert_eq!(
        format!("oidc:{}:{}", a.issuer, a.subject),
        format!("oidc:{}:{}", b.issuer, b.subject),
        "test is only meaningful if the naive format collides here"
    );
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
