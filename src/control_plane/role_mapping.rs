// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

use crate::key_server::oidc::{VerifiedIdentity, email_domain};
use crate::{Error, Result};

use super::ControlPlaneRole;

/// Control-plane configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    /// Identity-to-role mapping for the governance surface.
    pub role_mapping: ControlPlaneRoleMappingConfig,
    /// SIEM evidence-export runtime configuration (MIK-6703). Opt-in.
    pub export: super::ExportConfig,
    /// Directory for the governance store (`store/`) and its audit log
    /// (`audit.jsonl`). Unset: `<config dir>/<config stem>-control-plane`, so
    /// existing installs do not move. Set: must be absolute after `~`
    /// expansion, and a start that cannot write it refuses to serve. The store
    /// takes no lease, so one gateway process per directory. Restart-required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_dir: Option<String>,
}

/// Where the control-plane store lives, resolved once at startup from
/// `store_dir` and the config path (MIK-7570 F6). The admin API reports it, so
/// it names the directory the running process chose, not a later reload's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneBaseInfo {
    /// Directory holding `store/` and `audit.jsonl`.
    pub path: std::path::PathBuf,
    /// Which setting chose `path`.
    pub source: ControlPlaneBaseSource,
}

/// Which setting chose the control-plane base directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneBaseSource {
    /// `control_plane.store_dir` names it.
    Explicit,
    /// Derived from the config file's location, as before `store_dir` existed.
    Default,
}

/// Ordered, first-match-wins identity-to-role rules.
///
/// Hot-reloadable (MIK-6702): a `/reload` that changes this section takes effect
/// without a restart — the control-plane handlers read the mapping through the
/// live config per request, so removing a `role: admin` rule revokes Admin on
/// the next request. The mapping is validated fail-closed on every load/reload,
/// so an invalid change is always rejected.
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
        if let Some(group) = &self.group {
            // Symmetric with email/domain: an empty rule group, or an empty
            // identity group entry, must never match.
            if group.is_empty() || !identity.groups.iter().any(|g| !g.is_empty() && g == group) {
                return false;
            }
        }
        if let Some(email) = &self.email {
            // An empty rule email (or a missing identity email) must never
            // match: a token with no `email` claim resolves to "" and must not
            // satisfy an email discriminator.
            if email.is_empty()
                || identity.email.is_empty()
                || !identity.email.eq_ignore_ascii_case(email)
            {
                return false;
            }
        }
        if let Some(domain) = &self.domain {
            // `email_domain` is `None` for a missing email or one without
            // exactly one `@`, so neither can satisfy a domain rule.
            if domain.is_empty()
                || !email_domain(&identity.email).is_some_and(|d| d.eq_ignore_ascii_case(domain))
            {
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
            // A discriminator that is present but empty/whitespace is rejected:
            // an empty `email`/`domain` would otherwise match a token that has
            // no email claim (email == ""), silently widening the rule.
            for (field, value) in [
                ("group", &rule.group),
                ("email", &rule.email),
                ("domain", &rule.domain),
            ] {
                if let Some(v) = value
                    && v.trim().is_empty()
                {
                    return Err(Error::ConfigValidation(format!(
                        "control_plane.role_mapping rule {i} (issuer '{}') has an empty '{field}' \
                         discriminator; omit it or give it a non-empty value",
                        rule.issuer
                    )));
                }
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
            if rule.role == ControlPlaneRole::Admin {
                // E1-b: "everyone at corp.com is a gateway admin" is almost
                // never the intent, the same class of mistake as A9 D3a.
                if rule.group.is_none() && rule.email.is_none() {
                    return Err(Error::ConfigValidation(format!(
                        "control_plane.role_mapping rule {i} (issuer '{}') grants admin by \
                         email domain alone; name the IdP's admin group (group) or an exact \
                         email instead",
                        rule.issuer
                    )));
                }
                // E1-g: announce the widening. Kind only: an email value is
                // personal data and never reaches the log.
                let discriminator = if rule.group.is_some() {
                    "group"
                } else {
                    "email"
                };
                let _ = discriminator;
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

    /// Whether `identity` is a gateway admin: the first matching rule says
    /// `role: admin` (E1-a).
    #[must_use]
    pub fn grants_admin(&self, identity: &VerifiedIdentity) -> bool {
        self.resolve_role(identity) == Some(ControlPlaneRole::Admin)
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

    // MIK-6688.ROLE.5 — an empty discriminator is rejected: an empty email/domain
    // would otherwise match a token with a missing email claim (email == "").
    #[test]
    fn empty_discriminator_rejected_and_missing_email_never_matches() {
        for bad in [
            rule(
                "https://idp.corp",
                None,
                Some(""),
                None,
                ControlPlaneRole::Admin,
            ),
            rule(
                "https://idp.corp",
                None,
                None,
                Some("  "),
                ControlPlaneRole::Admin,
            ),
            rule(
                "https://idp.corp",
                Some(""),
                None,
                None,
                ControlPlaneRole::Admin,
            ),
        ] {
            let m = ControlPlaneRoleMappingConfig { rules: vec![bad] };
            assert!(
                m.validate().is_err(),
                "empty discriminator must be rejected"
            );
        }

        // Defense in depth: even if an empty-email rule existed, a token with no
        // email claim must not match it.
        let sneaky = ControlPlaneRoleRule {
            issuer: "https://idp.corp".to_string(),
            group: None,
            email: Some(String::new()),
            domain: None,
            role: ControlPlaneRole::Admin,
        };
        let no_email = identity("https://idp.corp", "", &[]);
        assert!(!sneaky.matches(&no_email));

        // Group parity: an empty rule group never matches, and an identity group
        // entry that is empty cannot satisfy a group rule.
        let sneaky_group = ControlPlaneRoleRule {
            issuer: "https://idp.corp".to_string(),
            group: Some(String::new()),
            email: None,
            domain: None,
            role: ControlPlaneRole::Admin,
        };
        let empty_group_member = identity("https://idp.corp", "a@corp", &[""]);
        assert!(!sneaky_group.matches(&empty_group_member));
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

    // ── E1: admin rules grant gateway admin (4.0.0, MIK-7570.ADMINSSO.1) ──

    fn admin_by_domain() -> ControlPlaneRoleRule {
        rule(
            "https://idp.corp",
            None,
            None,
            Some("corp.com"),
            ControlPlaneRole::Admin,
        )
    }

    /// E1-T7: "everyone at corp.com is a gateway admin" fails to load, both as
    /// a mapping and through the whole config's validation.
    #[test]
    fn domain_only_admin_rule_fails_to_load() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![
                rule(
                    "https://idp.corp",
                    Some("ops"),
                    None,
                    None,
                    ControlPlaneRole::Auditor,
                ),
                admin_by_domain(),
            ],
        };
        let error = m
            .validate()
            .expect_err("a domain-only admin rule is refused");
        let text = error.to_string();
        assert!(
            text.contains("rule 1") && text.contains("domain"),
            "names the rule and the discriminator: {text}"
        );

        let config: crate::config::Config = serde_yaml::from_str(
            "control_plane:\n  role_mapping:\n    rules:\n      \
             - { issuer: \"https://idp.corp\", domain: \"corp.com\", role: admin }\n",
        )
        .expect("the YAML parses");
        assert!(
            config.validate().is_err(),
            "the whole config refuses to load"
        );
    }

    /// E1-T7b: the refusal is for admin-by-domain only. A domain rule for
    /// another role, or an admin rule that also names a group or an email,
    /// still loads.
    #[test]
    fn domain_rule_for_non_admin_role_loads() {
        for ok in [
            ControlPlaneRoleRule {
                role: ControlPlaneRole::Auditor,
                ..admin_by_domain()
            },
            ControlPlaneRoleRule {
                group: Some("ops-admins".to_string()),
                ..admin_by_domain()
            },
            ControlPlaneRoleRule {
                email: Some("boss@corp.com".to_string()),
                ..admin_by_domain()
            },
        ] {
            let m = ControlPlaneRoleMappingConfig { rules: vec![ok] };
            assert!(m.validate().is_ok(), "{:?}", m.rules[0]);
        }
    }

    /// E1-T14: each admin rule announces, once per load, that it now grants
    /// gateway admin everywhere: its index, issuer and discriminator kind,
    /// never an email value. A non-admin rule says nothing.
    #[test]
    fn admin_rule_widening_warns_at_load() {
        let m = ControlPlaneRoleMappingConfig {
            rules: vec![
                rule(
                    "https://idp.corp",
                    Some("ops-admins"),
                    None,
                    None,
                    ControlPlaneRole::Admin,
                ),
                rule(
                    "https://idp.corp",
                    Some("aud"),
                    None,
                    None,
                    ControlPlaneRole::Auditor,
                ),
                rule(
                    "https://other.idp",
                    None,
                    Some("boss@corp.com"),
                    None,
                    ControlPlaneRole::Admin,
                ),
            ],
        };
        let (result, logs) =
            crate::security::firewall::response_tests::audit::capture_warnings(|| m.validate());
        result.expect("the mapping is valid");
        assert_eq!(
            logs.matches("now grants gateway admin").count(),
            2,
            "one warning per admin rule: {logs}"
        );
        assert!(
            logs.contains("rule 0 (issuer https://idp.corp, group)"),
            "{logs}"
        );
        assert!(
            logs.contains("rule 2 (issuer https://other.idp, email)"),
            "{logs}"
        );
        assert!(
            !logs.contains("rule 1"),
            "an auditor rule is silent: {logs}"
        );
        assert!(!logs.contains("boss@corp.com"), "no email value: {logs}");
    }
}
