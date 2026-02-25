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
//! Each rule's `match` block may contain any combination of:
//!
//! | Field | Meaning |
//! |-------|---------|
//! | `domain` | Email domain suffix (e.g., `"company.com"`) |
//! | `issuer` | Exact OIDC issuer URL |
//! | `email` | Exact email address |
//! | `group` | Any group in the identity's `groups` list |
//!
//! All non-`None` fields must match for the rule to fire.
//!
//! ## Scope intersection
//!
//! If the client requests specific scopes, the engine intersects them with the
//! policy's granted scopes: the client receives only what the policy allows AND
//! what it asked for. Requesting no specific scopes grants everything the policy
//! allows (the common case).

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::KeyServerPolicyConfig;

use super::oidc::VerifiedIdentity;
use super::store::TokenScopes;

/// The access policy engine.
pub struct PolicyEngine {
    rules: Vec<KeyServerPolicyConfig>,
}

impl PolicyEngine {
    /// Build the engine from the ordered rule list from configuration.
    #[must_use]
    pub fn new(rules: Vec<KeyServerPolicyConfig>) -> Self {
        Self { rules }
    }

    /// Resolve the effective scopes for a verified identity.
    ///
    /// Evaluates rules in order; returns the scopes of the first matching rule.
    /// If no rule matches, returns `None` (the caller should reject the request).
    #[must_use]
    pub fn resolve_scopes(
        &self,
        identity: &VerifiedIdentity,
        requested: &RequestedScopes,
    ) -> Option<TokenScopes> {
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
                return Some(apply_intersection(&policy_scopes, requested));
            }
        }
        debug!(email = %identity.email, "No policy rule matched");
        None
    }
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
    // All non-None criteria must match.
    if let Some(ref domain) = criteria.domain {
        let email_domain = identity.email.split('@').next_back().unwrap_or("");
        if email_domain != domain {
            return false;
        }
    }

    if let Some(ref issuer) = criteria.issuer {
        if &identity.issuer != issuer {
            return false;
        }
    }

    if let Some(ref email) = criteria.email {
        if &identity.email != email {
            return false;
        }
    }

    if let Some(ref group) = criteria.group {
        if !identity.groups.iter().any(|g| g == group) {
            return false;
        }
    }

    true
}

/// Compute the intersection of policy-granted and client-requested scopes.
///
/// If the client requests a specific subset (`requested` is non-empty), only
/// grant what intersects. An empty `requested` means "grant everything".
fn apply_intersection(policy: &PolicyScopes, requested: &RequestedScopes) -> TokenScopes {
    let backends = intersect_scope_list(&policy.backends, &requested.backends);
    let tools = intersect_scope_list(&policy.tools, &requested.tools);

    TokenScopes {
        backends,
        tools,
        rate_limit: policy.rate_limit,
    }
}

/// Compute the intersection of two scope lists.
///
/// `policy` = what the policy grants.
/// `requested` = what the client asked for.
///
/// - If `policy` is empty or contains `"*"`, it means "all" — so whatever the
///   client requests (or everything if client requested nothing).
/// - If `requested` is empty, the client wants everything the policy grants.
/// - Otherwise, return only items that appear in both lists (wildcards in
///   `policy` are respected).
fn intersect_scope_list(policy: &[String], requested: &[String]) -> Vec<String> {
    let policy_is_wildcard = policy.is_empty() || policy.iter().any(|p| p == "*");

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
/// All non-`None` fields must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchCriteria {
    /// Email domain (e.g., `"company.com"`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// OIDC issuer URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
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
    /// Allowed backends (empty or `["*"]` = all).
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
            groups: groups.iter().map(|s| s.to_string()).collect(),
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
                issuer: None,
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
                issuer: Some("https://token.actions.githubusercontent.com".to_string()),
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
        // GIVEN: engine with two rules; company rule is first
        let engine = make_engine(vec![company_rule(), github_actions_rule()]);
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
        assert!(scopes.is_none());
    }

    #[test]
    fn resolve_scopes_matches_exact_email() {
        // GIVEN: a rule that matches a specific email
        let rule = KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                email: Some("admin@company.com".to_string()),
                domain: None,
                issuer: None,
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
        assert!(scopes.is_some());
        assert_eq!(scopes.unwrap().rate_limit, 0);
    }

    #[test]
    fn resolve_scopes_matches_group() {
        // GIVEN: a rule that matches a group
        let rule = KeyServerPolicyConfig {
            match_criteria: PolicyMatchConfig {
                group: Some("ml-engineers".to_string()),
                domain: None,
                issuer: None,
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
        assert!(scopes.is_some());
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
    fn intersect_empty_policy_returns_requested() {
        // GIVEN: empty policy (meaning "all"), client requests specific
        let policy: Vec<String> = vec![];
        let requested = vec!["tavily".to_string()];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: policy is wildcard, grant what was requested
        assert_eq!(result, vec!["tavily"]);
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
        let requested = vec![
            "brave_search".to_string(),
            "tavily-search".to_string(),
        ];

        // WHEN: intersect
        let result = intersect_scope_list(&policy, &requested);

        // THEN: only brave_search granted
        assert_eq!(result, vec!["brave_search"]);
    }
}
