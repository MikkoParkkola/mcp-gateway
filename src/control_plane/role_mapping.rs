//! Map a verified identity (OIDC/SCIM) to a control-plane role (MIK-6688).
//!
//! Mirrors the key-server policy engine (issuer/email/domain/group match,
//! first-match-wins) but with one hard rule: **every rule is issuer-scoped**.
//! A group (or email/domain) match is only honoured together with the exact
//! issuer, so a group name minted by one identity provider cannot map into a
//! privileged role via a different provider (cross-IdP collision).
//!
//! Fallbacks (resolved by the caller, not here):
//! - verified identity present but no rule matches -> `Auditor` (least privilege);
//! - no verified identity / no mapping configured  -> legacy admin-key behaviour.
//!
//! Admin is grantable only by an explicit `role: admin` rule; there is no
//! implicit path to Admin. Invalid config fails closed at load/reload.

use serde::{Deserialize, Serialize};

use crate::key_server::oidc::VerifiedIdentity;
use crate::{Error, Result};

use super::ControlPlaneRole;

/// Control-plane configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    /// Identity-to-role mapping for the governance surface.
    pub role_mapping: ControlPlaneRoleMappingConfig,
}

/// Ordered, first-match-wins identity-to-role rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneRoleMappingConfig {
    /// Rules evaluated in declaration order; the first match wins.
    pub rules: Vec<ControlPlaneRoleRule>,
}

/// One issuer-scoped identity-to-role rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneRoleRule {
    /// Exact OIDC issuer URL. **Required** — the rule only fires for this
    /// issuer, which blocks cross-provider group-name collisions.
    pub issuer: String,
    /// Optional group membership discriminator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Optional exact email discriminator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional email-domain discriminator (e.g. `"company.com"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Role granted when the rule matches.
    pub role: ControlPlaneRole,
}

impl ControlPlaneRoleRule {
    /// True when `identity` satisfies this rule: the issuer must match exactly
    /// AND every present discriminator must match.
    fn matches(&self, identity: &VerifiedIdentity) -> bool {
        if identity.issuer != self.issuer {
            return false;
        }
        if let Some(group) = &self.group
            && !identity.groups.iter().any(|g| g == group)
        {
            return false;
        }
        if let Some(email) = &self.email
            && &identity.email != email
        {
            return false;
        }
        if let Some(domain) = &self.domain {
            let email_domain = identity.email.split('@').next_back().unwrap_or("");
            if email_domain != domain {
                return false;
            }
        }
        true
    }
}

impl ControlPlaneRoleMappingConfig {
    /// Validate the mapping, failing closed on any unusable rule.
    ///
    /// Each rule must carry a non-empty issuer AND at least one discriminator
    /// (group/email/domain). A rule with no discriminator would map every
    /// identity from an issuer to a role — too broad to allow implicitly,
    /// especially for Admin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConfigValidation`] describing the first offending rule.
    pub fn validate(&self) -> Result<()> {
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.issuer.trim().is_empty() {
                return Err(Error::ConfigValidation(format!(
                    "control_plane.role_mapping rule {i} must set a non-empty issuer \
                     (issuer-scoped rules block cross-provider role escalation)"
                )));
            }
            let has_discriminator =
                rule.group.is_some() || rule.email.is_some() || rule.domain.is_some();
            if !has_discriminator {
                return Err(Error::ConfigValidation(format!(
                    "control_plane.role_mapping rule {i} (issuer '{}') must set at least one of \
                     group/email/domain; an issuer-only rule maps every identity to '{:?}'",
                    rule.issuer, rule.role
                )));
            }
        }
        Ok(())
    }

    /// Resolve the role for `identity` using first-match-wins. Returns `None`
    /// when no rule matches (the caller applies the least-privilege fallback).
    #[must_use]
    pub fn resolve_role(&self, identity: &VerifiedIdentity) -> Option<ControlPlaneRole> {
        self.rules
            .iter()
            .find(|rule| rule.matches(identity))
            .map(|rule| rule.role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(issuer: &str, email: &str, groups: &[&str]) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: "sub-1".to_string(),
            email: email.to_string(),
            name: None,
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            issuer: issuer.to_string(),
        }
    }

    fn rule(
        issuer: &str,
        group: Option<&str>,
        email: Option<&str>,
        domain: Option<&str>,
        role: ControlPlaneRole,
    ) -> ControlPlaneRoleRule {
        ControlPlaneRoleRule {
            issuer: issuer.to_string(),
            group: group.map(str::to_string),
            email: email.map(str::to_string),
            domain: domain.map(str::to_string),
            role,
        }
    }

    // MIK-6688.ROLE.1 — issuer-scoped group rule maps to a specific role.
    #[test]
    fn issuer_scoped_group_maps_to_role() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![
                rule(
                    "https://idp.corp",
                    Some("sec-review"),
                    None,
                    None,
                    ControlPlaneRole::SecurityReviewer,
                ),
                rule(
                    "https://idp.corp",
                    Some("devs"),
                    None,
                    None,
                    ControlPlaneRole::Developer,
                ),
                rule(
                    "https://idp.corp",
                    Some("cp-admins"),
                    None,
                    None,
                    ControlPlaneRole::Admin,
                ),
            ],
        };
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "a@corp", &["sec-review"])),
            Some(ControlPlaneRole::SecurityReviewer)
        );
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "a@corp", &["cp-admins"])),
            Some(ControlPlaneRole::Admin)
        );
    }

    // MIK-6688.ROLE.2 — no matching rule -> None (caller defaults to Auditor).
    // First-match-wins order is honoured.
    #[test]
    fn no_match_returns_none_and_first_match_wins() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![
                rule(
                    "https://idp.corp",
                    Some("multi"),
                    None,
                    None,
                    ControlPlaneRole::Developer,
                ),
                rule(
                    "https://idp.corp",
                    Some("multi"),
                    None,
                    None,
                    ControlPlaneRole::Admin,
                ),
            ],
        };
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "a@corp", &["other"])),
            None
        );
        // Identity in "multi" matches both rules; the first (Developer) wins.
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "a@corp", &["multi"])),
            Some(ControlPlaneRole::Developer)
        );
    }

    // MIK-6688.ROLE.4 — the same group name from a DIFFERENT issuer does not match.
    #[test]
    fn cross_idp_group_collision_is_blocked() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![rule(
                "https://trusted.idp",
                Some("cp-admins"),
                None,
                None,
                ControlPlaneRole::Admin,
            )],
        };
        // Same group name, attacker-controlled issuer -> no match.
        assert_eq!(
            m.resolve_role(&identity("https://evil.idp", "a@evil", &["cp-admins"])),
            None
        );
        // Correct issuer -> match.
        assert_eq!(
            m.resolve_role(&identity("https://trusted.idp", "a@corp", &["cp-admins"])),
            Some(ControlPlaneRole::Admin)
        );
    }

    // MIK-6688.ROLE.5 — invalid config fails closed: issuer-less and
    // discriminator-less rules are rejected.
    #[test]
    fn invalid_config_fails_closed() {
        let no_issuer = ControlPlaneRoleMappingConfig {
            rules: vec![rule("", Some("g"), None, None, ControlPlaneRole::Auditor)],
        };
        assert!(no_issuer.validate().is_err());

        let no_discriminator = ControlPlaneRoleMappingConfig {
            rules: vec![rule(
                "https://idp.corp",
                None,
                None,
                None,
                ControlPlaneRole::Admin,
            )],
        };
        assert!(no_discriminator.validate().is_err());

        let ok = ControlPlaneRoleMappingConfig {
            rules: vec![rule(
                "https://idp.corp",
                None,
                None,
                Some("corp"),
                ControlPlaneRole::Developer,
            )],
        };
        assert!(ok.validate().is_ok());
    }

    // Email + domain discriminators, still issuer-scoped.
    #[test]
    fn email_and_domain_discriminators() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![
                rule(
                    "https://idp.corp",
                    None,
                    Some("boss@corp.com"),
                    None,
                    ControlPlaneRole::Admin,
                ),
                rule(
                    "https://idp.corp",
                    None,
                    None,
                    Some("corp.com"),
                    ControlPlaneRole::Developer,
                ),
            ],
        };
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "boss@corp.com", &[])),
            Some(ControlPlaneRole::Admin)
        );
        assert_eq!(
            m.resolve_role(&identity("https://idp.corp", "staff@corp.com", &[])),
            Some(ControlPlaneRole::Developer)
        );
        // Right domain, wrong issuer -> no match.
        assert_eq!(
            m.resolve_role(&identity("https://other.idp", "staff@corp.com", &[])),
            None
        );
    }
}
