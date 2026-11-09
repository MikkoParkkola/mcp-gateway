// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::actor_from_client;
use crate::config::{KeyServerPolicyConfig, PolicyMatchConfig, PolicyScopesConfig};
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneRbac, ControlPlaneRole, ControlPlaneRoleMappingConfig,
    ControlPlaneRoleRule,
};
use crate::gateway::auth::AuthenticatedClient;
use crate::key_server::oidc::VerifiedIdentity;
use crate::key_server::policy::{PolicyEngine, RequestedScopes, ScopeRefusal};

fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
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
    VerifiedIdentity::for_test(
        "s".to_string(),
        "a@corp".to_string(),
        None,
        groups.iter().map(|g| (*g).to_string()).collect(),
        issuer.to_string(),
    )
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
        ControlPlaneRole::Viewer
    );
    assert_eq!(
        actor_from_client(None, None, &empty).role,
        ControlPlaneRole::Viewer
    );
}

// MIK-6688.ROLE.2 — a verified identity with no matching rule is Viewer (it
// reads only its own grants and audit events), even when an admin API key is
// also present (identity path wins). Auditor is only ever an explicit rule.
#[test]
fn verified_identity_without_rule_is_viewer_not_admin() {
    let empty = ControlPlaneRoleMappingConfig::default();
    let actor = actor_from_client(
        Some(&client(true)),
        Some(&identity("https://idp", &["x"])),
        &empty,
    );
    assert_eq!(actor.role, ControlPlaneRole::Viewer);
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
    a = a.with_subject("b:c");
    let mut b = identity("https://idp/a:b", &[]);
    b = b.with_subject("c");
    // Precondition: the naive format genuinely collides for this pair.
    assert_eq!(
        format!("oidc:{}:{}", a.issuer(), a.subject()),
        format!("oidc:{}:{}", b.issuer(), b.subject()),
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

// A reload that removes an admin rule stops granting Admin without a
// restart: the next request pins the new generation and is judged by its
// mapping (a request already in flight keeps the one it arrived under).
// Simulates the reload by reading the mapping before and after the swap, as
// each request's pin would.
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
        ControlPlaneRole::Viewer,
        "a removed admin rule must stop granting Admin after reload"
    );
}

/// A key whose `backends` names some backends, for the scope rows below.
fn client_on(admin: bool, backends: &[&str]) -> AuthenticatedClient {
    AuthenticatedClient {
        principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
        backends: backends.iter().map(|b| (*b).to_string()).collect(),
        ..client(admin)
    }
}

/// The control-plane actor's role follows the backend scope: Admin needs an
/// admin whose scope is every backend. A scoped admin, by its key or by its
/// identity's mapping, is capped at Auditor (read breadth inside its scope).
/// An unscoped identity on a non-admin key, the `[]` admin key and the
/// auth-off caller keep their roles.
#[test]
fn a_backend_scoped_admin_is_no_control_plane_admin() {
    let mapping = ControlPlaneRoleMappingConfig {
        rules: vec![ControlPlaneRoleRule {
            issuer: "https://idp".to_string(),
            group: Some("ops".to_string()),
            email: None,
            domain: None,
            role: ControlPlaneRole::Admin,
        }],
    };
    let admin_identity = identity("https://idp", &["ops"]);
    let role = |client: Option<&AuthenticatedClient>, id: Option<&VerifiedIdentity>| {
        actor_from_client(client, id, &mapping).role
    };
    let cells = [
        (
            "admin key, *",
            role(Some(&client_on(true, &["*"])), None),
            ControlPlaneRole::Admin,
        ),
        (
            "admin key, []",
            role(Some(&client_on(true, &[])), None),
            ControlPlaneRole::Admin,
        ),
        (
            "admin identity, unscoped non-admin key",
            role(Some(&client_on(false, &["*"])), Some(&admin_identity)),
            ControlPlaneRole::Admin,
        ),
        (
            "admin identity, no client",
            role(None, Some(&admin_identity)),
            ControlPlaneRole::Admin,
        ),
        (
            "admin key, [alpha]",
            role(Some(&client_on(true, &["alpha"])), None),
            ControlPlaneRole::Auditor,
        ),
        (
            "admin identity, key [alpha]",
            role(Some(&client_on(false, &["alpha"])), Some(&admin_identity)),
            ControlPlaneRole::Auditor,
        ),
    ];
    let wrong: Vec<String> = cells
        .iter()
        .filter(|(_, got, want)| got != want)
        .map(|(who, got, want)| format!("{who}: got {got:?}, want {want:?}"))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A key-only caller's default group (`local-admins`, `local-viewers`) is a
/// display label, never an authorization input: a role rule naming it grants
/// a key-only caller nothing, and a key-server policy naming it matches only
/// an identity that itself carries the group. Pinned because the backend
/// scope's safety for key-only callers rests on nothing authorizing by group.
#[test]
fn a_key_only_callers_default_group_grants_nothing() {
    let rule = |group: &str| ControlPlaneRoleRule {
        issuer: "https://idp".to_string(),
        group: Some(group.to_string()),
        email: None,
        domain: None,
        role: ControlPlaneRole::Admin,
    };
    let mapping = ControlPlaneRoleMappingConfig {
        rules: vec![rule("local-admins"), rule("local-viewers")],
    };
    let viewer = actor_from_client(Some(&client(false)), None, &mapping);
    assert_eq!(viewer.group_ids, ["local-viewers"]);
    assert_eq!(
        viewer.role,
        ControlPlaneRole::Viewer,
        "a rule naming the default group"
    );
    let admin = actor_from_client(Some(&client(true)), None, &mapping);
    assert_eq!(admin.group_ids, ["local-admins"]);
    assert_eq!(
        admin.role,
        ControlPlaneRole::Admin,
        "from the admin flag alone"
    );

    let engine = PolicyEngine::new(vec![KeyServerPolicyConfig {
        match_criteria: PolicyMatchConfig {
            issuer: "https://idp".to_string(),
            group: Some("local-admins".to_string()),
            ..PolicyMatchConfig::default()
        },
        scopes: PolicyScopesConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            rate_limit: 100,
        },
    }]);
    let requested = RequestedScopes::default();
    assert_eq!(
        engine
            .resolve_scopes(&identity("https://idp", &[]), &requested)
            .err(),
        Some(ScopeRefusal::Denied),
        "only an identity's own groups match"
    );
    assert!(
        engine
            .resolve_scopes(&identity("https://idp", &["local-admins"]), &requested)
            .is_ok(),
        "control: the rule matches an identity carrying the group"
    );
}
