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
        if let Some(ref pat) = self.cn
            && !identity
                .common_name
                .as_deref()
                .is_some_and(|cn| pat.matches(cn))
        {
            return false;
        }
        if let Some(ref pat) = self.ou
            && !identity
                .organizational_unit
                .as_deref()
                .is_some_and(|ou| pat.matches(ou))
        {
            return false;
        }
        if let Some(ref pat) = self.san_uri
            && !identity.san_uris.iter().any(|u| pat.matches(u))
        {
            return false;
        }
        if let Some(ref pat) = self.san_dns
            && !identity.san_dns_names.iter().any(|d| pat.matches(d))
        {
            return false;
        }
        // At least one criterion must have been specified (otherwise it's a
        // vacuously-true rule with no match fields — we treat as no-match to
        // avoid accidental allow-all from an empty `match:` block).
        self.cn.is_some() || self.ou.is_some() || self.san_uri.is_some() || self.san_dns.is_some()
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
mod tests;
