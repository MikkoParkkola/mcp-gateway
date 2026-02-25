//! Routing profiles for session-scoped tool access control.
//!
//! A routing profile defines named allow/deny rules (both backend-level and
//! tool-level) that restrict which tools are visible and invocable within a
//! session.  The operator declares profiles in `config.yaml`; sessions bind
//! to one profile at a time via `gateway_set_profile` and can query the
//! current profile via `gateway_get_profile`.
//!
//! ## Glob pattern semantics
//!
//! Both tool and backend filter lists support a simple glob subset:
//! - `"brave_*"` — prefix match (anything starting with `brave_`)
//! - `"write_file"` — exact match
//!
//! Evaluation order (mirrors [`crate::security::policy`]):
//! 1. `allow_tools` / `allow_backends`: if **Some** and the tool/backend is
//!    **not** in the list → denied.
//! 2. `deny_tools` / `deny_backends`: if the tool/backend matches → denied.
//! 3. Otherwise → allowed.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ============================================================================
// Configuration types (deserialized from YAML)
// ============================================================================

/// Per-profile configuration declared in `config.yaml`.
///
/// All filter fields are optional; `None` means "no restriction" for that
/// dimension.
///
/// ```yaml
/// routing_profiles:
///   research:
///     allow_tools: ["brave_*", "wikipedia_*", "arxiv_*"]
///   coding:
///     deny_tools: ["gmail_*", "slack_*"]
///   dangerous:
///     # No restrictions — all tools available
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingProfileConfig {
    /// If `Some`, only backends whose names match are accessible.
    /// Supports glob prefix patterns (`"mybackend_*"`).
    #[serde(default)]
    pub allow_backends: Option<Vec<String>>,

    /// If `Some`, backends whose names match are blocked.
    /// Evaluated after `allow_backends`.
    #[serde(default)]
    pub deny_backends: Option<Vec<String>>,

    /// If `Some`, only tools whose names match are accessible.
    /// Supports glob prefix patterns (`"brave_*"`).
    #[serde(default)]
    pub allow_tools: Option<Vec<String>>,

    /// If `Some`, tools whose names match are blocked.
    /// Evaluated after `allow_tools`.
    #[serde(default)]
    pub deny_tools: Option<Vec<String>>,
}

// ============================================================================
// Compiled profile (efficient runtime evaluation)
// ============================================================================

/// A compiled routing profile ready for O(1) / O(k) lookup.
#[derive(Debug, Clone)]
pub struct RoutingProfile {
    /// Human-readable profile name (e.g. `"research"`).
    pub name: String,
    /// Compiled backend filter.
    backend_filter: PatternFilter,
    /// Compiled tool filter.
    tool_filter: PatternFilter,
}

impl RoutingProfile {
    /// Compile a named profile from its configuration.
    #[must_use]
    pub fn from_config(name: &str, config: &RoutingProfileConfig) -> Self {
        Self {
            name: name.to_string(),
            backend_filter: PatternFilter::new(
                config.allow_backends.as_deref(),
                config.deny_backends.as_deref(),
            ),
            tool_filter: PatternFilter::new(
                config.allow_tools.as_deref(),
                config.deny_tools.as_deref(),
            ),
        }
    }

    /// A permissive profile that allows every backend and tool.
    ///
    /// Used as the default when no profile is configured.
    #[must_use]
    pub fn allow_all(name: &str) -> Self {
        Self {
            name: name.to_string(),
            backend_filter: PatternFilter::allow_all(),
            tool_filter: PatternFilter::allow_all(),
        }
    }

    /// Check whether `(backend, tool)` is accessible under this profile.
    ///
    /// Returns `Ok(())` when allowed, `Err(message)` when denied.
    ///
    /// # Errors
    ///
    /// Returns `Err(String)` with a human-readable message when the backend or
    /// tool is blocked by this profile's allow/deny rules.
    pub fn check(&self, backend: &str, tool: &str) -> Result<(), String> {
        if !self.backend_filter.is_allowed(backend) {
            return Err(format!(
                "Backend '{backend}' is not available in the '{}' routing profile",
                self.name
            ));
        }
        if !self.tool_filter.is_allowed(tool) {
            return Err(format!(
                "Tool '{tool}' is not available in the '{}' routing profile",
                self.name
            ));
        }
        Ok(())
    }

    /// Check whether `backend` passes the backend-level filter alone.
    ///
    /// Useful for list/search operations that want to skip entire backends
    /// before iterating their tools.
    #[must_use]
    pub fn backend_allowed(&self, backend: &str) -> bool {
        self.backend_filter.is_allowed(backend)
    }

    /// Check whether `tool` passes the tool-level filter alone.
    #[must_use]
    pub fn tool_allowed(&self, tool: &str) -> bool {
        self.tool_filter.is_allowed(tool)
    }

    /// Human-readable summary of what this profile allows/denies.
    #[must_use]
    pub fn describe(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "backend_filter": self.backend_filter.describe(),
            "tool_filter": self.tool_filter.describe(),
        })
    }
}

// ============================================================================
// Pattern filter (allow/deny list with glob prefix support)
// ============================================================================

/// Compiled allow + deny pattern lists for a single dimension (tools or backends).
#[derive(Debug, Clone)]
struct PatternFilter {
    /// `None` = no allowlist (everything passes the allow stage).
    /// `Some(patterns)` = only items matching at least one pattern pass.
    allow: Option<Vec<Pattern>>,
    /// `None` = no denylist.
    /// `Some(patterns)` = items matching at least one pattern are rejected.
    deny: Option<Vec<Pattern>>,
}

impl PatternFilter {
    /// Build a filter from raw pattern strings.
    fn new(allow: Option<&[String]>, deny: Option<&[String]>) -> Self {
        Self {
            allow: allow.map(compile_patterns),
            deny: deny.map(compile_patterns),
        }
    }

    /// A filter that allows everything (no restrictions).
    fn allow_all() -> Self {
        Self {
            allow: None,
            deny: None,
        }
    }

    /// Return `true` if `name` passes both the allow and deny stages.
    fn is_allowed(&self, name: &str) -> bool {
        // Allow stage: must match at least one allowlist pattern (if list exists).
        if let Some(ref allow_patterns) = self.allow {
            if !allow_patterns.iter().any(|p| p.matches(name)) {
                return false;
            }
        }
        // Deny stage: must not match any denylist pattern.
        if let Some(ref deny_patterns) = self.deny {
            if deny_patterns.iter().any(|p| p.matches(name)) {
                return false;
            }
        }
        true
    }

    /// Human-readable description of this filter.
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({
            "allow": self.allow.as_ref().map(|ps| ps.iter().map(Pattern::raw).collect::<Vec<_>>()),
            "deny":  self.deny.as_ref().map(|ps| ps.iter().map(Pattern::raw).collect::<Vec<_>>()),
        })
    }
}

// ============================================================================
// Pattern (glob prefix or exact)
// ============================================================================

#[derive(Debug, Clone)]
enum Pattern {
    /// Exact name match.
    Exact(String),
    /// Prefix match — everything starting with this string is accepted.
    Prefix(String),
}

impl Pattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
        }
    }

    fn raw(&self) -> String {
        match self {
            Self::Exact(s) => s.clone(),
            Self::Prefix(s) => format!("{s}*"),
        }
    }
}

/// Compile a slice of raw pattern strings into [`Pattern`] values.
fn compile_patterns(raw: &[String]) -> Vec<Pattern> {
    raw.iter()
        .map(|s| {
            if let Some(prefix) = s.strip_suffix('*') {
                Pattern::Prefix(prefix.to_string())
            } else {
                Pattern::Exact(s.clone())
            }
        })
        .collect()
}

// ============================================================================
// Profile registry (immutable, built once at startup)
// ============================================================================

/// Immutable registry of all named routing profiles, built once at startup.
///
/// Provides O(1) lookup by name and a fallback allow-all profile.
#[derive(Debug)]
pub struct ProfileRegistry {
    profiles: HashMap<String, RoutingProfile>,
    default_profile: String,
}

impl ProfileRegistry {
    /// Build the registry from the configuration map.
    ///
    /// `default_profile` is the profile name used for new sessions. If the
    /// name does not correspond to a configured profile, a permissive
    /// allow-all profile is created for that name.
    #[must_use]
    pub fn from_config(
        configs: &HashMap<String, RoutingProfileConfig>,
        default_profile: &str,
    ) -> Self {
        let profiles: HashMap<String, RoutingProfile> = configs
            .iter()
            .map(|(name, cfg)| {
                (name.clone(), RoutingProfile::from_config(name, cfg))
            })
            .collect();

        Self {
            profiles,
            default_profile: default_profile.to_string(),
        }
    }

    /// Return the default profile name.
    #[must_use]
    pub fn default_name(&self) -> &str {
        &self.default_profile
    }

    /// Look up a profile by name.
    ///
    /// Returns the allow-all profile named `name` when the name is unknown.
    #[must_use]
    pub fn get(&self, name: &str) -> RoutingProfile {
        self.profiles
            .get(name)
            .cloned()
            .unwrap_or_else(|| RoutingProfile::allow_all(name))
    }

    /// Return `true` if a profile with this name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.profiles.contains_key(name)
    }

    /// Return the names of all configured profiles.
    #[must_use]
    pub fn profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self {
            profiles: HashMap::new(),
            default_profile: "default".to_string(),
        }
    }
}

// ============================================================================
// Per-session profile store
// ============================================================================

/// Thread-safe store that maps session IDs to their active profile name.
///
/// New sessions automatically receive the registry's default profile.
#[derive(Debug, Default)]
pub struct SessionProfileStore {
    /// `session_id` → `profile_name`
    sessions: RwLock<HashMap<String, String>>,
}

impl SessionProfileStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the active profile name for a session.
    ///
    /// Returns `default_name` when the session has no explicit assignment.
    #[must_use]
    pub fn get_profile_name(&self, session_id: &str, default_name: &str) -> String {
        self.sessions
            .read()
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| default_name.to_string())
    }

    /// Assign a profile to a session.
    pub fn set_profile(&self, session_id: &str, profile_name: &str) {
        self.sessions
            .write()
            .insert(session_id.to_string(), profile_name.to_string());
    }

    /// Remove a session (called on session teardown).
    pub fn remove_session(&self, session_id: &str) {
        self.sessions.write().remove(session_id);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────

    fn profile_from(
        allow_tools: Option<&[&str]>,
        deny_tools: Option<&[&str]>,
        allow_backends: Option<&[&str]>,
        deny_backends: Option<&[&str]>,
    ) -> RoutingProfile {
        let cfg = RoutingProfileConfig {
            allow_tools: allow_tools
                .map(|s| s.iter().map(|x| (*x).to_string()).collect()),
            deny_tools: deny_tools
                .map(|s| s.iter().map(|x| (*x).to_string()).collect()),
            allow_backends: allow_backends
                .map(|s| s.iter().map(|x| (*x).to_string()).collect()),
            deny_backends: deny_backends
                .map(|s| s.iter().map(|x| (*x).to_string()).collect()),
        };
        RoutingProfile::from_config("test", &cfg)
    }

    // ── allow_all profile ────────────────────────────────────────────────

    #[test]
    fn allow_all_profile_permits_any_tool() {
        // GIVEN: a fully permissive profile
        let profile = RoutingProfile::allow_all("open");
        // WHEN / THEN: any (backend, tool) pair is allowed
        assert!(profile.check("brave", "brave_search").is_ok());
        assert!(profile.check("filesystem", "write_file").is_ok());
    }

    // ── allow_tools list ─────────────────────────────────────────────────

    #[test]
    fn allow_tools_exact_permits_listed_tool() {
        // GIVEN: research profile that only allows "brave_search"
        let p = profile_from(Some(&["brave_search"]), None, None, None);
        // WHEN / THEN
        assert!(p.check("brave", "brave_search").is_ok());
    }

    #[test]
    fn allow_tools_exact_blocks_unlisted_tool() {
        let p = profile_from(Some(&["brave_search"]), None, None, None);
        assert!(p.check("brave", "brave_suggest").is_err());
    }

    #[test]
    fn allow_tools_glob_prefix_permits_matching_tools() {
        // GIVEN: allow_tools: ["brave_*"]
        let p = profile_from(Some(&["brave_*"]), None, None, None);
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("b", "brave_news").is_ok());
    }

    #[test]
    fn allow_tools_glob_prefix_blocks_non_matching_tools() {
        let p = profile_from(Some(&["brave_*"]), None, None, None);
        assert!(p.check("b", "gmail_send").is_err());
    }

    // ── deny_tools list ──────────────────────────────────────────────────

    #[test]
    fn deny_tools_exact_blocks_listed_tool() {
        let p = profile_from(None, Some(&["gmail_send"]), None, None);
        assert!(p.check("gmail", "gmail_send").is_err());
    }

    #[test]
    fn deny_tools_exact_permits_other_tools() {
        let p = profile_from(None, Some(&["gmail_send"]), None, None);
        assert!(p.check("brave", "brave_search").is_ok());
    }

    #[test]
    fn deny_tools_glob_prefix_blocks_matching_tools() {
        // coding profile: deny_tools: ["gmail_*", "slack_*"]
        let p = profile_from(None, Some(&["gmail_*", "slack_*"]), None, None);
        assert!(p.check("g", "gmail_send").is_err());
        assert!(p.check("s", "slack_post").is_err());
        assert!(p.check("brave", "brave_search").is_ok());
    }

    // ── allow + deny interaction ─────────────────────────────────────────

    #[test]
    fn deny_overrides_allow_when_both_match() {
        // allow_tools: ["brave_*"], deny_tools: ["brave_news"]
        // brave_news is in both → should be denied (deny wins)
        let p = profile_from(
            Some(&["brave_*"]),
            Some(&["brave_news"]),
            None,
            None,
        );
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("b", "brave_news").is_err());
    }

    // ── backend filter ───────────────────────────────────────────────────

    #[test]
    fn allow_backends_blocks_unlisted_backend() {
        let p = profile_from(None, None, Some(&["brave", "arxiv"]), None);
        assert!(p.check("brave", "brave_search").is_ok());
        assert!(p.check("gmail", "gmail_send").is_err());
    }

    #[test]
    fn deny_backends_glob_blocks_matching_backend() {
        let p = profile_from(None, None, None, Some(&["internal_*"]));
        assert!(p.check("internal_db", "query").is_err());
        assert!(p.check("brave", "brave_search").is_ok());
    }

    // ── error messages ───────────────────────────────────────────────────

    #[test]
    fn error_message_contains_profile_name_for_denied_tool() {
        let cfg = RoutingProfileConfig {
            allow_tools: Some(vec!["brave_search".to_string()]),
            ..Default::default()
        };
        let p = RoutingProfile::from_config("research", &cfg);
        let err = p.check("brave", "gmail_send").unwrap_err();
        assert!(err.contains("research"), "error should mention profile name");
        assert!(err.contains("gmail_send"), "error should mention tool name");
    }

    #[test]
    fn error_message_contains_profile_name_for_denied_backend() {
        let cfg = RoutingProfileConfig {
            deny_backends: Some(vec!["internal_*".to_string()]),
            ..Default::default()
        };
        let p = RoutingProfile::from_config("safe", &cfg);
        let err = p.check("internal_db", "query").unwrap_err();
        assert!(err.contains("safe"));
        assert!(err.contains("internal_db"));
    }

    // ── backend_allowed / tool_allowed helpers ───────────────────────────

    #[test]
    fn backend_allowed_matches_profile_backend_filter() {
        let p = profile_from(None, None, Some(&["brave"]), None);
        assert!(p.backend_allowed("brave"));
        assert!(!p.backend_allowed("gmail"));
    }

    #[test]
    fn tool_allowed_matches_profile_tool_filter() {
        let p = profile_from(Some(&["brave_*"]), None, None, None);
        assert!(p.tool_allowed("brave_search"));
        assert!(!p.tool_allowed("gmail_send"));
    }

    // ── ProfileRegistry ──────────────────────────────────────────────────

    #[test]
    fn registry_returns_allow_all_for_unknown_profile() {
        let registry = ProfileRegistry::default();
        let p = registry.get("nonexistent");
        assert!(p.check("anything", "any_tool").is_ok());
    }

    #[test]
    fn registry_returns_configured_profile_by_name() {
        let mut configs = HashMap::new();
        configs.insert(
            "research".to_string(),
            RoutingProfileConfig {
                allow_tools: Some(vec!["brave_*".to_string()]),
                ..Default::default()
            },
        );
        let registry = ProfileRegistry::from_config(&configs, "research");
        let p = registry.get("research");
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("g", "gmail_send").is_err());
    }

    #[test]
    fn registry_contains_returns_true_for_known_profile() {
        let mut configs = HashMap::new();
        configs.insert("coding".to_string(), RoutingProfileConfig::default());
        let registry = ProfileRegistry::from_config(&configs, "coding");
        assert!(registry.contains("coding"));
        assert!(!registry.contains("research"));
    }

    #[test]
    fn registry_default_name_matches_configured_default() {
        let registry = ProfileRegistry::from_config(&HashMap::new(), "coding");
        assert_eq!(registry.default_name(), "coding");
    }

    // ── SessionProfileStore ──────────────────────────────────────────────

    #[test]
    fn session_store_returns_default_for_new_session() {
        let store = SessionProfileStore::new();
        assert_eq!(store.get_profile_name("s1", "research"), "research");
    }

    #[test]
    fn session_store_returns_assigned_profile_after_set() {
        let store = SessionProfileStore::new();
        store.set_profile("s1", "coding");
        assert_eq!(store.get_profile_name("s1", "research"), "coding");
    }

    #[test]
    fn session_store_remove_reverts_to_default() {
        let store = SessionProfileStore::new();
        store.set_profile("s1", "coding");
        store.remove_session("s1");
        assert_eq!(store.get_profile_name("s1", "research"), "research");
    }

    #[test]
    fn session_store_isolates_different_sessions() {
        let store = SessionProfileStore::new();
        store.set_profile("s1", "research");
        store.set_profile("s2", "coding");
        assert_eq!(store.get_profile_name("s1", "default"), "research");
        assert_eq!(store.get_profile_name("s2", "default"), "coding");
    }
}
