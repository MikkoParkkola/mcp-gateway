// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Access policy engine — maps OIDC identities to token scopes.
//!
//! # Design
//!
//! Policies are evaluated in declaration order. The **first matching rule**
//! wins (identical to the existing `ToolPolicy` evaluation order — operators
//! learn one pattern).
//!
//! ## Match criteria
//!
//! Each rule's `match` block names an `issuer` and may add any combination of
//! the other fields:
//!
//! | Field | Meaning |
//! |-------|---------|
//! | `issuer` | Exact OIDC issuer URL. **Required**, and must be a configured provider |
//! | `domain` | Exact email domain, ASCII case-insensitive (`"company.com"`; subdomains need their own rule) |
//! | `email` | Exact email address, ASCII case-insensitive |
//! | `group` | Any group in the identity's `groups` list |
//!
//! All present fields must match for the rule to fire. `email` and `domain`
//! only ever see a verified address: the OIDC verifier drops an email whose
//! `email_verified` claim is not true.
//!
//! ## Scope intersection
//!
//! If the client requests specific scopes, the engine intersects them with the
//! policy's granted scopes: the client receives only what the policy allows AND
//! what it asked for. Requesting no specific scopes grants everything the policy
//! allows (the common case).

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::KeyServerPolicyConfig;

use super::oidc::{VerifiedIdentity, email_domain};
use super::store::TokenScopes;

/// The access policy engine.
pub struct PolicyEngine {
    rules: Vec<KeyServerPolicyConfig>,
}

impl PolicyEngine {
    /// Build the engine from the ordered rule list from configuration.
    ///
    /// Warns once per rule that lists no backends: it now grants none
    /// (BACKENDGRANT.1), where 3.x read an empty list as all.
    #[must_use]
    pub fn new(rules: Vec<KeyServerPolicyConfig>) -> Self {
        for (index, rule) in rules.iter().enumerate() {
            if rule.scopes.backends.is_empty() {
                warn!(
                    "key_server.policies[{index}] (issuer {}) grants no backends, so the key server \
                     refuses its tokens; 3.x treated this as all. Set scopes.backends: [\"*\"] to keep that.",
                    rule.match_criteria.issuer
                );
            }
        }
        Self { rules }
    }

    /// Resolve the effective scopes for a verified identity.
    ///
    /// Evaluates rules in order and applies the first matching rule.
    ///
    /// # Errors
    ///
    /// [`ScopeRefusal::NoBackendsGranted`] when the matched grant reaches no
    /// backend; [`ScopeRefusal::Denied`] when no rule matches or the request
    /// has no overlap with the rule's tools.
    pub fn resolve_scopes(
        &self,
        identity: &VerifiedIdentity,
        requested: &RequestedScopes,
    ) -> Result<TokenScopes, ScopeRefusal> {
        for rule in &self.rules {
            let criteria = MatchCriteria {
                domain: rule.match_criteria.domain.clone(),
                issuer: rule.match_criteria.issuer.clone(),
                email: rule.match_criteria.email.clone(),
                group: rule.match_criteria.group.clone(),
            };
            let policy_scopes = PolicyScopes {
                backends: rule.scopes.backends.clone(),
                tools: rule.scopes.tools.clone(),
                rate_limit: rule.scopes.rate_limit,
            };
            if matches_rule(&criteria, identity) {
                debug!(
                    email = %identity.email,
                    issuer = %identity.issuer,
                    "Policy rule matched"
                );
                return apply_intersection(&policy_scopes, requested);
            }
        }
        debug!(email = %identity.email, "No policy rule matched");
        Err(ScopeRefusal::Denied)
    }
}

/// Why no token is issued for a verified identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRefusal {
    /// No rule matched, or the request has no overlap with the rule's tools.
    Denied,
    /// The matched grant reaches no backend: the rule lists none, or the
    /// request names none it lists. A token that reaches nothing is never
    /// minted.
    NoBackendsGranted,
}

/// Scopes requested by the client in the token exchange request.
///
/// An empty `Vec` means "grant everything the policy allows".
#[derive(Debug, Clone, Default)]
pub struct RequestedScopes {
    /// Requested backend names (empty = all).
    pub backends: Vec<String>,
    /// Requested tool names / patterns (empty = all).
    pub tools: Vec<String>,
}

/// Evaluate whether an identity matches the rule's match criteria.
fn matches_rule(criteria: &MatchCriteria, identity: &VerifiedIdentity) -> bool {
    // The issuer always applies; every other present criterion must match.
    if identity.issuer != criteria.issuer {
        return false;
    }

    if let Some(ref domain) = criteria.domain
        && !email_domain(&identity.email).is_some_and(|d| d.eq_ignore_ascii_case(domain))
    {
        return false;
    }

    if let Some(ref email) = criteria.email
        && (identity.email.is_empty() || !identity.email.eq_ignore_ascii_case(email))
    {
        return false;
    }

    if let Some(ref group) = criteria.group
        && !identity.groups.iter().any(|g| g == group)
    {
        return false;
    }

    true
}

/// Compute the intersection of policy-granted and client-requested scopes.
///
/// If the client requests a specific subset (`requested` is non-empty), only
/// grant what intersects. An empty `requested` means "grant everything".
///
/// Refuses with `NoBackendsGranted` whenever the result lists no backend,
/// whatever the cause: an empty backend list reaches nothing. Tools keep empty
/// = all, so a tool request that intersects to nothing is refused instead of
/// widened.
fn apply_intersection(
    policy: &PolicyScopes,
    requested: &RequestedScopes,
) -> Result<TokenScopes, ScopeRefusal> {
    let backends = intersect_scope_list(&policy.backends, &requested.backends);
    // An empty policy tool list still means every tool on the granted backends.
    let tools = if policy.tools.is_empty() {
        requested.tools.clone()
    } else {
        intersect_scope_list(&policy.tools, &requested.tools)
    };

    if backends.is_empty() {
        debug!("Matched policy grants no backend for this request");
        return Err(ScopeRefusal::NoBackendsGranted);
    }
    if tools.is_empty() && !requested.tools.is_empty() {
        debug!("Requested tools do not overlap the matched policy");
        return Err(ScopeRefusal::Denied);
    }

    Ok(TokenScopes {
        backends,
        tools,
        rate_limit: policy.rate_limit,
    })
}

/// Compute the intersection of two scope lists.
///
/// `policy` = what the policy grants.
/// `requested` = what the client asked for.
///
/// - An empty `policy` grants nothing; only `"*"` means "all", and then the
///   client gets whatever it requests (or `policy` itself if it requested
///   nothing).
/// - If `requested` is empty, the client wants everything the policy grants.
/// - Otherwise, return only items that appear in both lists (wildcards in
///   `policy` are respected).
fn intersect_scope_list(policy: &[String], requested: &[String]) -> Vec<String> {
    let policy_is_wildcard = policy.iter().any(|p| p == "*");

    if requested.is_empty() {
        // Client wants everything: return policy's list as-is.
        return policy.to_vec();
    }

    if policy_is_wildcard {
        // Policy allows everything: grant exactly what was requested.
        return requested.to_vec();
    }

    // Restrict to intersection.
    requested
        .iter()
        .filter(|r| policy.iter().any(|p| scope_matches(p, r)))
        .cloned()
        .collect()
}

/// Check if a `policy_item` (possibly with `*` wildcard) matches a `request_item`.
fn scope_matches(policy_item: &str, request_item: &str) -> bool {
    if let Some(prefix) = policy_item.strip_suffix('*') {
        request_item.starts_with(prefix)
    } else {
        policy_item == request_item
    }
}

/// Match criteria for a policy rule.
///
/// The issuer and every non-`None` field must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Exact email domain (e.g., `"company.com"`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// OIDC issuer URL
    pub issuer: String,
    /// Exact email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Group membership
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Scopes granted by a policy rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyScopes {
    /// Allowed backends (`["*"]` = all; empty = none).
    #[serde(default)]
    pub backends: Vec<String>,
    /// Allowed tools (empty or `["*"]` = all).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Rate limit (requests per minute; 0 = unlimited).
    #[serde(default)]
    pub rate_limit: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{KeyServerPolicyConfig, PolicyMatchConfig, PolicyScopesConfig};

    fn make_identity(email: &str, issuer: &str, groups: &[&str]) -> VerifiedIdentity {
        VerifiedIdentity {
            subject: "sub123".to_string(),
            email: email.to_string(),
            name: None,
            groups: groups
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            issuer: issuer.to_string(),
        }
    }

    fn make_engine(rules: Vec<KeyServerPolicyConfig>) -> PolicyEngine {
        PolicyEngine::new(rules)
    }

    fn company_rule() -> KeyServerPolicyConfig {
        KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                domain: Some("company.com".to_string()),
                issuer: "https://accounts.google.com".to_string(),
                email: None,
                group: None,
            },
            scopes: PolicyScopesConfig {
                backends: vec!["*".to_string()],
                tools: vec!["*".to_string()],
                rate_limit: 100,
            },
        }
    }

    fn github_actions_rule() -> KeyServerPolicyConfig {
        KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                domain: None,
                issuer: "https://token.actions.githubusercontent.com".to_string(),
                email: None,
                group: None,
            },
            scopes: PolicyScopesConfig {
                backends: vec!["tavily".to_string(), "brave".to_string()],
                tools: vec!["tavily-search".to_string(), "brave_*".to_string()],
                rate_limit: 50,
            },
        }
    }

    // ── PolicyEngine::resolve_scopes ──────────────────────────────────────

    #[test]
    fn resolve_scopes_matches_domain_rule() {
        // GIVEN: engine with a company domain rule
        let engine = make_engine(vec![company_rule()]);
        let identity = make_identity("alice@company.com", "https://accounts.google.com", &[]);

        // WHEN: resolve with no specific request
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: full access granted
        let scopes = scopes.unwrap();
        assert_eq!(scopes.backends, vec!["*"]);
        assert_eq!(scopes.rate_limit, 100);
    }

    #[test]
    fn resolve_scopes_matches_issuer_rule() {
        // GIVEN: engine with a GitHub Actions issuer rule
        let engine = make_engine(vec![github_actions_rule()]);
        let identity = make_identity(
            "runner@github.invalid",
            "https://token.actions.githubusercontent.com",
            &[],
        );

        // WHEN: resolve with no specific request
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: restricted access granted
        let scopes = scopes.unwrap();
        assert_eq!(scopes.backends, vec!["tavily", "brave"]);
        assert_eq!(scopes.rate_limit, 50);
    }

    #[test]
    fn resolve_scopes_first_match_wins() {
        // GIVEN: engine with two rules for the same issuer; company rule is first
        let mut company = company_rule();
        company.match_criteria.issuer = "https://token.actions.githubusercontent.com".to_string();
        let engine = make_engine(vec![company, github_actions_rule()]);
        let identity = make_identity(
            "alice@company.com",
            "https://token.actions.githubusercontent.com",
            &[],
        );

        // WHEN: resolve — identity matches both rules
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: first rule (company) wins
        let scopes = scopes.unwrap();
        assert_eq!(scopes.backends, vec!["*"]);
    }

    #[test]
    fn resolve_scopes_returns_none_when_no_match() {
        // GIVEN: engine with only a company domain rule
        let engine = make_engine(vec![company_rule()]);
        let identity = make_identity("external@other.com", "https://accounts.google.com", &[]);

        // WHEN: identity has a different domain
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: no match
        assert_eq!(scopes.err(), Some(ScopeRefusal::Denied));
    }

    #[test]
    fn resolve_scopes_matches_exact_email() {
        // GIVEN: a rule that matches a specific email
        let rule = KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                email: Some("admin@company.com".to_string()),
                domain: None,
                issuer: "https://accounts.google.com".to_string(),
                group: None,
            },
            scopes: PolicyScopesConfig {
                backends: vec!["*".to_string()],
                tools: vec!["*".to_string()],
                rate_limit: 0,
            },
        };
        let engine = make_engine(vec![rule]);
        let identity = make_identity("admin@company.com", "https://accounts.google.com", &[]);

        // WHEN: resolve
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: match
        assert!(scopes.is_ok());
        assert_eq!(scopes.unwrap().rate_limit, 0);
    }

    #[test]
    fn resolve_scopes_matches_group() {
        // GIVEN: a rule that matches a group
        let rule = KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                group: Some("ml-engineers".to_string()),
                domain: None,
                issuer: "https://accounts.google.com".to_string(),
                email: None,
            },
            scopes: PolicyScopesConfig {
                backends: vec!["*".to_string()],
                tools: vec!["*".to_string()],
                rate_limit: 0,
            },
        };
        let engine = make_engine(vec![rule]);
        let identity = make_identity(
            "alice@company.com",
            "https://accounts.google.com",
            &["ml-engineers", "developers"],
        );

        // WHEN: resolve
        let scopes = engine.resolve_scopes(&identity, &RequestedScopes::default());

        // THEN: match via group membership
        assert!(scopes.is_ok());
    }

    // ── intersect_scope_list ──────────────────────────────────────────────

    #[test]
    fn intersect_wildcard_policy_returns_requested() {
        // GIVEN: policy with wildcard, client requests specific backends
        let policy = vec!["*".to_string()];
        let requested = vec!["tavily".to_string(), "brave".to_string()];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: client's request is honored in full
        assert_eq!(result, vec!["tavily", "brave"]);
    }

    #[test]
    fn intersect_empty_policy_grants_nothing() {
        // BACKENDGRANT.1: an empty policy list grants none; only "*" is a
        // wildcard.
        let policy: Vec<String> = vec![];
        let requested = vec!["tavily".to_string()];
        assert!(intersect_scope_list(&policy, &requested).is_empty());
    }

    #[test]
    fn intersect_restricts_to_policy() {
        // GIVEN: policy allows only tavily; client requests tavily + brave
        let policy = vec!["tavily".to_string()];
        let requested = vec!["tavily".to_string(), "brave".to_string()];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: only tavily granted
        assert_eq!(result, vec!["tavily"]);
    }

    #[test]
    fn intersect_empty_requested_returns_policy_list() {
        // GIVEN: policy with specific backends; client requests nothing specific
        let policy = vec!["tavily".to_string(), "brave".to_string()];
        let requested: Vec<String> = vec![];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: full policy list granted
        assert_eq!(result, vec!["tavily", "brave"]);
    }

    #[test]
    fn intersect_glob_pattern_in_policy() {
        // GIVEN: policy allows tools matching brave_*; client requests brave_search + brave_images
        let policy = vec!["brave_*".to_string()];
        let requested = vec!["brave_search".to_string(), "brave_images".to_string()];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: both granted because policy glob matches
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn intersect_glob_policy_rejects_non_matching_request() {
        // GIVEN: policy allows brave_* only; client also requests tavily-search
        let policy = vec!["brave_*".to_string()];
        let requested = vec!["brave_search".to_string(), "tavily-search".to_string()];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: only brave_search granted
        assert_eq!(result, vec!["brave_search"]);
    }

    // ── Out-of-policy requests fail closed ────────────────────────────────

    fn resolve_restricted(backends: &[&str], tools: &[&str]) -> Result<TokenScopes, ScopeRefusal> {
        let engine = make_engine(vec![github_actions_rule()]);
        let identity = make_identity(
            "runner@github.invalid",
            "https://token.actions.githubusercontent.com",
            &[],
        );
        let requested = RequestedScopes {
            backends: backends.iter().map(|s| (*s).to_string()).collect(),
            tools: tools.iter().map(|s| (*s).to_string()).collect(),
        };
        engine.resolve_scopes(&identity, &requested)
    }

    #[test]
    fn resolve_scopes_rejects_backend_request_outside_restricted_policy() {
        // A request that intersects to no backend reaches nothing, so no
        // token is minted for it.
        let scopes = resolve_restricted(&["nope"], &[]);
        assert_eq!(scopes.err(), Some(ScopeRefusal::NoBackendsGranted));
    }

    #[test]
    fn resolve_scopes_rejects_tool_request_outside_restricted_policy() {
        let scopes = resolve_restricted(&[], &["nope"]);
        assert_eq!(scopes.err(), Some(ScopeRefusal::Denied));
    }

    #[test]
    fn resolve_scopes_partial_overlap_grants_only_the_overlap() {
        let scopes = resolve_restricted(&["tavily", "nope"], &["tavily-search", "nope"]).unwrap();
        assert_eq!(scopes.backends, vec!["tavily"]);
        assert_eq!(scopes.tools, vec!["tavily-search"]);
    }

    #[test]
    fn resolve_scopes_empty_request_keeps_restricted_policy_lists() {
        let scopes = resolve_restricted(&[], &[]).unwrap();
        assert_eq!(scopes.backends, vec!["tavily", "brave"]);
        assert_eq!(scopes.tools, vec!["tavily-search", "brave_*"]);
    }

    #[test]
    fn resolve_scopes_wildcard_policy_grants_exact_request() {
        let engine = make_engine(vec![company_rule()]);
        let identity = make_identity("alice@company.com", "https://accounts.google.com", &[]);
        let requested = RequestedScopes {
            backends: vec!["x".to_string()],
            tools: vec!["x".to_string()],
        };
        let scopes = engine.resolve_scopes(&identity, &requested).unwrap();
        assert_eq!(scopes.backends, vec!["x"]);
        assert_eq!(scopes.tools, vec!["x"]);
    }

    // ── BACKENDGRANT.1: an empty policy backend list grants none ─────────

    fn rule_with_backends(backends: &[&str]) -> KeyServerPolicyConfig {
        KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                issuer: "https://idp.invalid".to_string(),
                ..PolicyMatchConfig::default()
            },
            scopes: PolicyScopesConfig {
                backends: backends.iter().map(|b| (*b).to_string()).collect(),
                ..PolicyScopesConfig::default()
            },
        }
    }

    fn resolve_with(backends: &[&str], requested: &[&str]) -> Result<TokenScopes, ScopeRefusal> {
        let engine = make_engine(vec![rule_with_backends(backends)]);
        let identity = make_identity("u@corp.invalid", "https://idp.invalid", &[]);
        let requested = RequestedScopes {
            backends: requested.iter().map(|b| (*b).to_string()).collect(),
            tools: vec![],
        };
        engine.resolve_scopes(&identity, &requested)
    }

    #[test]
    fn policy_without_backends_grants_none() {
        let scopes = resolve_with(&[], &[]);
        assert_eq!(scopes.err(), Some(ScopeRefusal::NoBackendsGranted));
    }

    #[test]
    fn policy_without_backends_refuses_specific_request() {
        let scopes = resolve_with(&[], &["github"]);
        assert_eq!(scopes.err(), Some(ScopeRefusal::NoBackendsGranted));
    }

    #[test]
    fn policy_wildcard_still_grants_request() {
        let scopes = resolve_with(&["*"], &["github"]).expect("wildcard grants");
        assert_eq!(scopes.backends, vec!["github"]);
        let scopes = resolve_with(&["*"], &[]).expect("wildcard grants");
        assert_eq!(scopes.backends, vec!["*"]);
    }

    #[test]
    fn policy_rule_without_backends_warns_at_load() {
        let (_, logs) = crate::security::firewall::response_tests::audit::capture_warnings(|| {
            make_engine(vec![rule_with_backends(&["*"]), rule_with_backends(&[])])
        });
        assert_eq!(logs.matches("grants no backends").count(), 1, "{logs}");
        assert!(
            logs.contains("key_server.policies[1]") && logs.contains("https://idp.invalid"),
            "the WARN names the rule index and issuer: {logs}"
        );
    }
}
