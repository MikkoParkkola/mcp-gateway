//! Agent scope format and matching.
//!
//! # Scope Format
//!
//! Scopes follow the pattern: `tools:<backend>:<name>:<action>`
//!
//! Examples:
//! - `tools:*`                    — full access to all tools on all backends
//! - `tools:backend:*`            — all tools on `backend`
//! - `tools:surreal:*`            — all tools on the `surreal` backend
//! - `tools:surreal:query:read`   — `query` tool on `surreal`, read action only
//! - `tools:surreal:query:*`      — `query` tool on `surreal`, any action
//!
//! # Actions
//!
//! `read`, `write`, `execute`, `*` (all).
//!
//! # Wildcard Rules
//!
//! - `tools:*` matches everything.
//! - `tools:<backend>:*` matches all tools on that backend.
//! - `tools:<backend>:<name>:*` matches any action on that tool.
//! - Missing segments act as wildcards from the right.

use serde::{Deserialize, Serialize};

/// Recognised action values in a scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Read-only operations.
    Read,
    /// Write / mutating operations.
    Write,
    /// Execution of commands or tools.
    Execute,
    /// Any action (`*`).
    Any,
}

impl Action {
    fn from_str(s: &str) -> Self {
        match s {
            "read" => Self::Read,
            "write" => Self::Write,
            "execute" => Self::Execute,
            _ => Self::Any, // "*" and anything else treated as wildcard
        }
    }

    /// Whether this action grants `required`.
    fn allows(&self, required: &Action) -> bool {
        matches!(self, Self::Any) || self == required
    }
}

/// A parsed agent scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// Backend name, or `*` for any.
    pub backend: String,
    /// Tool name, or `*` for any.
    pub tool: String,
    /// Permitted action.
    pub action: Action,
}

impl Scope {
    /// Parse a scope string.
    ///
    /// Returns `None` if the string does not start with `tools:`.
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("tools:")?;

        let mut parts = rest.splitn(3, ':');
        let backend = parts.next().unwrap_or("*").to_string();
        let tool = parts.next().unwrap_or("*").to_string();
        let action = Action::from_str(parts.next().unwrap_or("*"));

        Some(Self { backend, tool, action })
    }

    /// Test whether this scope grants access to `(backend, tool, action)`.
    pub fn grants(&self, backend: &str, tool: &str, action: &Action) -> bool {
        let backend_ok = self.backend == "*" || self.backend == backend;
        let tool_ok = self.tool == "*" || self.tool == tool;
        let action_ok = self.action.allows(action);
        backend_ok && tool_ok && action_ok
    }
}

/// Check whether `scopes` collectively grant `(backend, tool, action)`.
///
/// Returns `Ok(())` on success, `Err(reason)` on denial.
pub fn check_scopes(
    scopes: &[Scope],
    agent_id: &str,
    backend: &str,
    tool: &str,
    action: &Action,
) -> Result<(), String> {
    if scopes.iter().any(|s| s.grants(backend, tool, action)) {
        Ok(())
    } else {
        Err(format!(
            "Agent '{agent_id}' lacks scope for tool '{tool}' on backend '{backend}' (action: {action:?})"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Scope::parse ──────────────────────────────────────────────────────

    #[test]
    fn parse_full_scope() {
        let s = Scope::parse("tools:surreal:query:read").unwrap();
        assert_eq!(s.backend, "surreal");
        assert_eq!(s.tool, "query");
        assert_eq!(s.action, Action::Read);
    }

    #[test]
    fn parse_wildcard_everything() {
        let s = Scope::parse("tools:*").unwrap();
        assert_eq!(s.backend, "*");
        assert_eq!(s.tool, "*");
        assert_eq!(s.action, Action::Any);
    }

    #[test]
    fn parse_backend_wildcard() {
        let s = Scope::parse("tools:surreal:*").unwrap();
        assert_eq!(s.backend, "surreal");
        assert_eq!(s.tool, "*");
        assert_eq!(s.action, Action::Any);
    }

    #[test]
    fn parse_tool_wildcard_action() {
        let s = Scope::parse("tools:surreal:query:*").unwrap();
        assert_eq!(s.action, Action::Any);
    }

    #[test]
    fn parse_non_tools_prefix_returns_none() {
        assert!(Scope::parse("read:something").is_none());
        assert!(Scope::parse("").is_none());
    }

    // ── Scope::grants ─────────────────────────────────────────────────────

    #[test]
    fn full_wildcard_grants_everything() {
        let s = Scope::parse("tools:*").unwrap();
        assert!(s.grants("surreal", "query", &Action::Read));
        assert!(s.grants("fulcrum", "search", &Action::Execute));
    }

    #[test]
    fn backend_wildcard_grants_all_tools_on_backend() {
        let s = Scope::parse("tools:surreal:*").unwrap();
        assert!(s.grants("surreal", "query", &Action::Execute));
        assert!(!s.grants("brave", "search", &Action::Read));
    }

    #[test]
    fn exact_scope_grants_only_matching_combo() {
        let s = Scope::parse("tools:surreal:query:read").unwrap();
        assert!(s.grants("surreal", "query", &Action::Read));
        assert!(!s.grants("surreal", "query", &Action::Write));
        assert!(!s.grants("surreal", "create", &Action::Read));
        assert!(!s.grants("brave", "query", &Action::Read));
    }

    #[test]
    fn action_wildcard_grants_any_action() {
        let s = Scope::parse("tools:surreal:query:*").unwrap();
        assert!(s.grants("surreal", "query", &Action::Read));
        assert!(s.grants("surreal", "query", &Action::Write));
        assert!(s.grants("surreal", "query", &Action::Execute));
    }

    // ── check_scopes ──────────────────────────────────────────────────────

    #[test]
    fn check_scopes_allows_when_matching_scope_exists() {
        let scopes = vec![Scope::parse("tools:surreal:*").unwrap()];
        assert!(check_scopes(&scopes, "agent1", "surreal", "query", &Action::Read).is_ok());
    }

    #[test]
    fn check_scopes_denies_when_no_scope_matches() {
        let scopes = vec![Scope::parse("tools:surreal:query:read").unwrap()];
        let err = check_scopes(&scopes, "agent1", "brave", "search", &Action::Execute).unwrap_err();
        assert!(err.contains("agent1"));
        assert!(err.contains("brave"));
        assert!(err.contains("search"));
    }

    #[test]
    fn check_scopes_denies_empty_scope_list() {
        let err = check_scopes(&[], "agent1", "any", "tool", &Action::Read).unwrap_err();
        assert!(err.contains("agent1"));
    }

    #[test]
    fn action_from_str_unknown_becomes_any() {
        assert_eq!(Action::from_str("bogus"), Action::Any);
        assert_eq!(Action::from_str("*"), Action::Any);
    }
}
