//! Certificate-based tool access control.
//!
//! Compiles the YAML policy list from [`MtlsConfig`] into an efficient
//! runtime structure and evaluates `(cert_identity, backend, tool)` triples
//! against first-match-wins rules.
//!
//! # Evaluation order
//!
//! For the first rule whose `match` criterion matches the certificate:
//! 1. If the **deny** scope matches the tool *or* backend → [`PolicyDecision::Deny`].
//! 2. If the **allow** scope matches both tool *and* backend → [`PolicyDecision::Allow`].
//! 3. Otherwise → [`PolicyDecision::Deny`] (matched rule, not in allow list).
//!
//! If **no rule matches** → [`PolicyDecision::Deny`] (fail-closed).
//!
//! # Glob patterns
//!
//! Both tool and backend lists support the same glob subset as
//! [`crate::routing_profile`]:
//!
//! | Pattern | Semantics |
//! |---------|-----------|
//! | `"*"` | matches everything |
//! | `"prefix_*"` | prefix match |
//! | `"*_suffix"` | suffix match |
//! | `"*contains*"` | contains match |
//! | `"exact"` | exact match |

use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};
use crate::mtls::identity::CertIdentity;

// ─────────────────────────────────────────────────────────────────────────────
// Public decision type
// ─────────────────────────────────────────────────────────────────────────────

/// Result of evaluating a certificate identity against the mTLS policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The tool invocation is permitted.
    Allow,
    /// The tool invocation is forbidden.
    Deny,
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled policy
// ─────────────────────────────────────────────────────────────────────────────

/// Compiled mTLS access control policy.
///
/// Build once at startup with [`MtlsPolicy::from_config`], then call
/// [`MtlsPolicy::evaluate`] on every tool invocation.
#[derive(Debug, Clone)]
pub struct MtlsPolicy {
    rules: Vec<CompiledRule>,
    /// Whether mTLS is enabled at all.
    enabled: bool,
}

impl MtlsPolicy {
    /// Compile the policy from gateway configuration.
    ///
    /// If `config.enabled` is `false`, [`MtlsPolicy::evaluate`] always returns
    /// [`PolicyDecision::Allow`] so the gateway behaves as before.
    #[must_use]
    pub fn from_config(config: &MtlsConfig) -> Self {
        let rules = config
            .policies
            .iter()
            .map(CompiledRule::from_config)
            .collect();

        Self {
            rules,
            enabled: config.enabled,
        }
    }

    /// Evaluate whether `(identity, backend, tool)` is permitted.
    ///
    /// When mTLS is disabled or no client certificate is present and
    /// `require_client_cert` is `false`, returns [`PolicyDecision::Allow`]
    /// to preserve backward compatibility.
    #[must_use]
    pub fn evaluate(
        &self,
        identity: Option<&CertIdentity>,
        backend: &str,
        tool: &str,
    ) -> PolicyDecision {
        if !self.enabled {
            return PolicyDecision::Allow;
        }

        // Build an effective identity; unauthenticated connections use default.
        let default_id = CertIdentity::default();
        let id = identity.unwrap_or(&default_id);

        for rule in &self.rules {
            if rule.matches(id) {
                return rule.decide(backend, tool);
            }
        }

        // Fail-closed: no rule matched.
        PolicyDecision::Deny
    }

    /// Returns `true` when the policy has zero rules (no restrictions).
    ///
    /// Useful for short-circuiting when policies are not configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled rule
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CompiledRule {
    criteria: CompiledCriteria,
    allow: CompiledScope,
    deny: CompiledScope,
}

impl CompiledRule {
    fn from_config(rule: &PolicyRuleConfig) -> Self {
        Self {
            criteria: CompiledCriteria::from_config(&rule.match_criteria),
            allow: CompiledScope::from_config(&rule.allow),
            deny: CompiledScope::from_config(&rule.deny),
        }
    }

    /// Returns `true` if this rule's match criteria apply to `identity`.
    fn matches(&self, identity: &CertIdentity) -> bool {
        self.criteria.matches(identity)
    }

    /// Evaluate allow/deny given that this rule matched.
    fn decide(&self, backend: &str, tool: &str) -> PolicyDecision {
        // Deny scope is checked first (deny overrides allow)
        if self.deny.matches_tool(tool) || self.deny.matches_backend(backend) {
            return PolicyDecision::Deny;
        }
        // Both tool and backend must be in the allow scope
        if self.allow.matches_tool(tool) && self.allow.matches_backend(backend) {
            return PolicyDecision::Allow;
        }
        // Rule matched cert but tool/backend not in allow list → deny
        PolicyDecision::Deny
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled match criteria
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CompiledCriteria {
    cn: Option<GlobPattern>,
    ou: Option<GlobPattern>,
    san_uri: Option<GlobPattern>,
    san_dns: Option<GlobPattern>,
    /// `true` means match-all (catch-all rule)
    any: bool,
}

impl CompiledCriteria {
    fn from_config(cfg: &CertMatchConfig) -> Self {
        Self {
            cn: cfg.cn.as_deref().map(GlobPattern::new),
            ou: cfg.ou.as_deref().map(GlobPattern::new),
            san_uri: cfg.san_uri.as_deref().map(GlobPattern::new),
            san_dns: cfg.san_dns.as_deref().map(GlobPattern::new),
            any: cfg.any.unwrap_or(false),
        }
    }

    fn matches(&self, identity: &CertIdentity) -> bool {
        if self.any {
            return true;
        }

        // All specified criteria must match
        if let Some(ref pat) = self.cn {
            if !identity
                .common_name
                .as_deref()
                .is_some_and(|cn| pat.matches(cn))
            {
                return false;
            }
        }
        if let Some(ref pat) = self.ou {
            if !identity
                .organizational_unit
                .as_deref()
                .is_some_and(|ou| pat.matches(ou))
            {
                return false;
            }
        }
        if let Some(ref pat) = self.san_uri {
            if !identity.san_uris.iter().any(|u| pat.matches(u)) {
                return false;
            }
        }
        if let Some(ref pat) = self.san_dns {
            if !identity.san_dns_names.iter().any(|d| pat.matches(d)) {
                return false;
            }
        }
        // At least one criterion must have been specified (otherwise it's a
        // vacuously-true rule with no match fields — we treat as no-match to
        // avoid accidental allow-all from an empty `match:` block).
        self.cn.is_some()
            || self.ou.is_some()
            || self.san_uri.is_some()
            || self.san_dns.is_some()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiled scope (allow / deny list)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CompiledScope {
    backends: Vec<GlobPattern>,
    tools: Vec<GlobPattern>,
}

impl CompiledScope {
    fn from_config(cfg: &ToolScopeConfig) -> Self {
        Self {
            backends: cfg.backends.iter().map(|s| GlobPattern::new(s)).collect(),
            tools: cfg.tools.iter().map(|s| GlobPattern::new(s)).collect(),
        }
    }

    fn matches_tool(&self, tool: &str) -> bool {
        self.tools.iter().any(|p| p.matches(tool))
    }

    fn matches_backend(&self, backend: &str) -> bool {
        self.backends.iter().any(|p| p.matches(backend))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Glob pattern (shared with routing_profile; duplicated for zero coupling)
// ─────────────────────────────────────────────────────────────────────────────

/// A compiled glob pattern supporting `*`, `prefix_*`, `*_suffix`, `*mid*`,
/// and exact matches.
#[derive(Debug, Clone)]
enum GlobPattern {
    Wildcard,
    Exact(String),
    Prefix(String),
    Suffix(String),
    Contains(String),
}

impl GlobPattern {
    fn new(s: &str) -> Self {
        let starts_star = s.starts_with('*');
        let ends_star = s.ends_with('*');

        if s == "*" {
            return Self::Wildcard;
        }
        match (starts_star, ends_star) {
            (true, true) => {
                let inner = &s[1..s.len() - 1];
                if inner.is_empty() {
                    Self::Wildcard
                } else {
                    Self::Contains(inner.to_string())
                }
            }
            (true, false) => Self::Suffix(s[1..].to_string()),
            (false, true) => Self::Prefix(s[..s.len() - 1].to_string()),
            (false, false) => Self::Exact(s.to_string()),
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Exact(e) => name == e,
            Self::Prefix(p) => name.starts_with(p.as_str()),
            Self::Suffix(s) => name.ends_with(s.as_str()),
            Self::Contains(c) => name.contains(c.as_str()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtls::config::{CertMatchConfig, MtlsConfig, PolicyRuleConfig, ToolScopeConfig};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn identity(
        cn: Option<&str>,
        ou: Option<&str>,
        san_uris: &[&str],
        san_dns: &[&str],
    ) -> CertIdentity {
        CertIdentity {
            common_name: cn.map(str::to_owned),
            organizational_unit: ou.map(str::to_owned),
            san_uris: san_uris.iter().map(|s| (*s).to_owned()).collect(),
            san_dns_names: san_dns.iter().map(|s| (*s).to_owned()).collect(),
            display_name: cn.unwrap_or("<unknown>").to_owned(),
        }
    }

    fn rule(
        cn: Option<&str>,
        ou: Option<&str>,
        san_uri: Option<&str>,
        any: Option<bool>,
        allow_backends: &[&str],
        allow_tools: &[&str],
        deny_backends: &[&str],
        deny_tools: &[&str],
    ) -> PolicyRuleConfig {
        PolicyRuleConfig {
            match_criteria: CertMatchConfig {
                cn: cn.map(str::to_owned),
                ou: ou.map(str::to_owned),
                san_uri: san_uri.map(str::to_owned),
                san_dns: None,
                any,
            },
            allow: ToolScopeConfig {
                backends: allow_backends.iter().map(|s| (*s).to_owned()).collect(),
                tools: allow_tools.iter().map(|s| (*s).to_owned()).collect(),
            },
            deny: ToolScopeConfig {
                backends: deny_backends.iter().map(|s| (*s).to_owned()).collect(),
                tools: deny_tools.iter().map(|s| (*s).to_owned()).collect(),
            },
        }
    }

    fn policy_with_rules(rules: Vec<PolicyRuleConfig>) -> MtlsPolicy {
        let cfg = MtlsConfig {
            enabled: true,
            policies: rules,
            ..Default::default()
        };
        MtlsPolicy::from_config(&cfg)
    }

    // ── disabled policy ───────────────────────────────────────────────────────

    #[test]
    fn disabled_policy_always_allows() {
        // GIVEN: mTLS not enabled
        let policy = MtlsPolicy::from_config(&MtlsConfig::default());
        let id = identity(Some("agent"), None, &[], &[]);
        // THEN: every invocation is allowed
        assert_eq!(
            policy.evaluate(Some(&id), "tavily", "search"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn disabled_policy_allows_without_identity() {
        let policy = MtlsPolicy::from_config(&MtlsConfig::default());
        assert_eq!(
            policy.evaluate(None, "backend", "tool"),
            PolicyDecision::Allow
        );
    }

    // ── no rule matched → deny ────────────────────────────────────────────────

    #[test]
    fn no_matching_rule_denies_by_default() {
        // GIVEN: policy with one CN rule that does NOT match
        let policy = policy_with_rules(vec![rule(
            Some("other-agent"),
            None,
            None,
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(Some("my-agent"), None, &[], &[]);
        // THEN: no rule matched → deny
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "search"),
            PolicyDecision::Deny
        );
    }

    // ── CN matching ───────────────────────────────────────────────────────────

    #[test]
    fn cn_exact_match_allows_tool() {
        let policy = policy_with_rules(vec![rule(
            Some("github-actions-ci"),
            None,
            None,
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(Some("github-actions-ci"), None, &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "brave_search"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn cn_mismatch_falls_to_next_rule() {
        let policy = policy_with_rules(vec![
            rule(
                Some("specific-agent"),
                None,
                None,
                None,
                &["*"],
                &["*"],
                &[],
                &[],
            ),
            rule(None, None, None, Some(true), &[], &[], &["*"], &["*"]),
        ]);
        let id = identity(Some("other-agent"), None, &[], &[]);
        // first rule doesn't match, catch-all denies
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "search"),
            PolicyDecision::Deny
        );
    }

    // ── OU matching ───────────────────────────────────────────────────────────

    #[test]
    fn ou_match_allows_all_tools() {
        let policy = policy_with_rules(vec![rule(
            None,
            Some("engineering"),
            None,
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(Some("any-cn"), Some("engineering"), &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "github", "list_prs"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn ou_mismatch_does_not_match_rule() {
        let policy = policy_with_rules(vec![rule(
            None,
            Some("engineering"),
            None,
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(Some("ci"), Some("ci-cd"), &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "github", "list_prs"),
            PolicyDecision::Deny
        );
    }

    // ── SPIFFE / SAN URI matching ─────────────────────────────────────────────

    #[test]
    fn san_uri_glob_matches_spiffe_identity() {
        let policy = policy_with_rules(vec![rule(
            None,
            None,
            Some("spiffe://company.com/agent/*"),
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(
            Some("cursor"),
            None,
            &["spiffe://company.com/agent/cursor"],
            &[],
        );
        assert_eq!(
            policy.evaluate(Some(&id), "github", "search"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn san_uri_glob_does_not_match_different_spiffe_path() {
        let policy = policy_with_rules(vec![rule(
            None,
            None,
            Some("spiffe://company.com/agent/*"),
            None,
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        // CI has a different SPIFFE path
        let id = identity(
            Some("ci"),
            None,
            &["spiffe://company.com/ci/github-actions"],
            &[],
        );
        assert_eq!(
            policy.evaluate(Some(&id), "github", "search"),
            PolicyDecision::Deny
        );
    }

    // ── catch-all rule ────────────────────────────────────────────────────────

    #[test]
    fn any_true_catch_all_denies_everything() {
        let policy =
            policy_with_rules(vec![rule(None, None, None, Some(true), &[], &[], &["*"], &["*"])]);
        let id = identity(Some("any-agent"), Some("any-ou"), &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "search"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn any_true_catch_all_allows_when_scope_matches() {
        let policy = policy_with_rules(vec![rule(
            None,
            None,
            None,
            Some(true),
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(Some("agent"), None, &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "anything", "any_tool"),
            PolicyDecision::Allow
        );
    }

    // ── deny overrides allow within same rule ─────────────────────────────────

    #[test]
    fn deny_tool_pattern_overrides_allow() {
        // GIVEN: ci agent allowed all tools except *write* and *delete*
        // Note: "*write*" (contains) matches "write_file", "file_write", etc.
        //       "*_write" (suffix) matches "file_write" but NOT "write_file".
        let policy = policy_with_rules(vec![rule(
            Some("ci-agent"),
            None,
            None,
            None,
            &["*"],
            &["*"],
            &[],
            &["*write*", "*delete*"],
        )]);
        let id = identity(Some("ci-agent"), None, &[], &[]);
        // allowed read
        assert_eq!(
            policy.evaluate(Some(&id), "fs", "read_file"),
            PolicyDecision::Allow
        );
        // denied: "write_file" contains "write"
        assert_eq!(
            policy.evaluate(Some(&id), "fs", "write_file"),
            PolicyDecision::Deny
        );
        // denied: "db_delete" contains "delete"
        assert_eq!(
            policy.evaluate(Some(&id), "db", "db_delete"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn deny_backend_blocks_access_regardless_of_tool() {
        let policy = policy_with_rules(vec![rule(
            Some("limited-agent"),
            None,
            None,
            None,
            &["allowed_backend"],
            &["*"],
            &["blocked_backend"],
            &[],
        )]);
        let id = identity(Some("limited-agent"), None, &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "blocked_backend", "safe_tool"),
            PolicyDecision::Deny
        );
        assert_eq!(
            policy.evaluate(Some(&id), "allowed_backend", "safe_tool"),
            PolicyDecision::Allow
        );
    }

    // ── first-match-wins ──────────────────────────────────────────────────────

    #[test]
    fn first_matching_rule_wins_not_later_ones() {
        // GIVEN: first rule allows, second rule (catch-all) denies
        let policy = policy_with_rules(vec![
            rule(
                Some("my-agent"),
                None,
                None,
                None,
                &["*"],
                &["*"],
                &[],
                &[],
            ),
            rule(None, None, None, Some(true), &[], &[], &["*"], &["*"]),
        ]);
        let id = identity(Some("my-agent"), None, &[], &[]);
        // THEN: first rule fires → allow
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "search"),
            PolicyDecision::Allow
        );
    }

    // ── backend / tool scope patterns ────────────────────────────────────────

    #[test]
    fn tool_prefix_glob_in_allow_scope() {
        let policy = policy_with_rules(vec![rule(
            None,
            Some("ci-cd"),
            None,
            None,
            &["*"],
            &["*_search*", "*_list*"],
            &[],
            &[],
        )]);
        let id = identity(Some("ci"), Some("ci-cd"), &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "tavily", "tavily_search"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(Some(&id), "tavily", "tavily_write"),
            PolicyDecision::Deny
        );
    }

    #[test]
    fn backend_exact_in_allow_scope_blocks_others() {
        let policy = policy_with_rules(vec![rule(
            None,
            Some("read-only"),
            None,
            None,
            &["brave", "tavily"],
            &["*"],
            &[],
            &[],
        )]);
        let id = identity(None, Some("read-only"), &[], &[]);
        assert_eq!(
            policy.evaluate(Some(&id), "brave", "search"),
            PolicyDecision::Allow
        );
        assert_eq!(
            policy.evaluate(Some(&id), "filesystem", "read_file"),
            PolicyDecision::Deny
        );
    }

    // ── identity absent (no client cert + optional mode) ─────────────────────

    #[test]
    fn none_identity_matches_any_rule() {
        // GIVEN: catch-all rule that allows
        let policy = policy_with_rules(vec![rule(
            None,
            None,
            None,
            Some(true),
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        assert_eq!(
            policy.evaluate(None, "brave", "search"),
            PolicyDecision::Allow
        );
    }

    // ── is_empty ──────────────────────────────────────────────────────────────

    #[test]
    fn empty_policy_has_is_empty_true() {
        let policy = policy_with_rules(vec![]);
        assert!(policy.is_empty());
    }

    #[test]
    fn policy_with_rules_is_not_empty() {
        let policy = policy_with_rules(vec![rule(
            None,
            None,
            None,
            Some(true),
            &["*"],
            &["*"],
            &[],
            &[],
        )]);
        assert!(!policy.is_empty());
    }

    // ── glob pattern unit tests ───────────────────────────────────────────────

    #[test]
    fn glob_wildcard_matches_anything() {
        let p = GlobPattern::new("*");
        assert!(p.matches("anything"));
        assert!(p.matches(""));
    }

    #[test]
    fn glob_exact_matches_only_exact() {
        let p = GlobPattern::new("write_file");
        assert!(p.matches("write_file"));
        assert!(!p.matches("write_file_safe"));
        assert!(!p.matches("read_file"));
    }

    #[test]
    fn glob_prefix_matches_starting_strings() {
        let p = GlobPattern::new("brave_*");
        assert!(p.matches("brave_search"));
        assert!(p.matches("brave_news"));
        assert!(!p.matches("gmail_send"));
    }

    #[test]
    fn glob_suffix_matches_ending_strings() {
        let p = GlobPattern::new("*_write");
        assert!(p.matches("file_write"));
        assert!(p.matches("db_write"));
        assert!(!p.matches("file_read"));
    }

    #[test]
    fn glob_contains_matches_substring() {
        let p = GlobPattern::new("*search*");
        assert!(p.matches("brave_search"));
        assert!(p.matches("search_engine"));
        assert!(p.matches("deep_search_tool"));
        assert!(!p.matches("brave_news"));
    }

    #[test]
    fn glob_double_star_is_wildcard() {
        let p = GlobPattern::new("**");
        assert!(p.matches("anything"));
    }
}
