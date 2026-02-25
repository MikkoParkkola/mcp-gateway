//! Routing profiles (Toolshed) for session-scoped tool access control.
//!
//! A routing profile defines named allow/deny rules (both backend-level and
//! tool-level) that restrict which tools are visible and invocable within a
//! session.  The operator declares profiles in `config.yaml`; sessions bind
//! to one profile at a time via `gateway_set_profile` and can query the
//! current profile via `gateway_get_profile` or list all profiles via
//! `gateway_list_profiles`.
//!
//! ## Profile selection
//!
//! A profile can be selected in three ways (precedence: header > params > default):
//! 1. **HTTP header**: `X-MCP-Profile: coding` on the initialize request.
//! 2. **Initialize params**: `{"profile": "coding"}` in the JSON-RPC body.
//! 3. **Meta-tool**: `gateway_set_profile({"profile": "coding"})` mid-session.
//!
//! ## Glob pattern semantics
//!
//! Both tool and backend filter lists support four glob forms:
//! - `"brave_*"` — prefix match (anything starting with `brave_`)
//! - `"*_write"` — suffix match (anything ending with `_write`)
//! - `"*search*"` — contains match (anything containing `search`)
//! - `"*"` — wildcard (matches everything)
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
/// Glob patterns support four forms:
/// - `"brave_*"` — prefix match (anything starting with `brave_`)
/// - `"*_write"` — suffix match (anything ending with `_write`)
/// - `"*search*"` — contains match (anything containing `search`)
/// - `"write_file"` — exact match
///
/// ```yaml
/// routing_profiles:
///   research:
///     description: "Research tasks — web, papers, knowledge"
///     allow_tools: ["brave_*", "exa_*", "arxiv_*", "gateway_*"]
///   coding:
///     description: "Coding tasks"
///     allow_tools: ["file_*", "git_*", "lint_*", "gateway_*"]
///   communication:
///     description: "Communication tasks"
///     allow_tools: ["gmail_*", "linear_*", "gateway_*"]
///   full:
///     description: "All tools (default)"
///     # No restrictions
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingProfileConfig {
    /// Human-readable description of this profile's purpose.
    #[serde(default)]
    pub description: String,

    /// If `Some`, only backends whose names match are accessible.
    /// Supports glob patterns (`"mybackend_*"`, `"*internal*"`).
    #[serde(default)]
    pub allow_backends: Option<Vec<String>>,

    /// If `Some`, backends whose names match are blocked.
    /// Evaluated after `allow_backends`.
    #[serde(default)]
    pub deny_backends: Option<Vec<String>>,

    /// If `Some`, only tools whose names match are accessible.
    /// Supports glob patterns (`"brave_*"`, `"*search*"`).
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
    /// Human-readable description of this profile's purpose.
    pub description: String,
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
            description: config.description.clone(),
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
            description: "All tools (unrestricted)".to_string(),
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
            "description": self.description,
            "backend_filter": self.backend_filter.describe(),
            "tool_filter": self.tool_filter.describe(),
        })
    }
}

// ============================================================================
// Pattern filter (allow/deny list with glob support)
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
// Pattern (wildcard, prefix, suffix, contains, or exact)
// ============================================================================

/// A compiled glob pattern for matching tool or backend names.
///
/// Supports five forms:
/// - `Wildcard` — matches everything (from `"*"`)
/// - `Exact("write_file")` — `name == "write_file"`
/// - `Prefix("brave_")` — `name.starts_with("brave_")` (from `"brave_*"`)
/// - `Suffix("_write")` — `name.ends_with("_write")` (from `"*_write"`)
/// - `Contains("search")` — `name.contains("search")` (from `"*search*"`)
#[derive(Debug, Clone)]
enum Pattern {
    /// Matches everything.
    Wildcard,
    /// Exact name match.
    Exact(String),
    /// Prefix match — everything starting with this string.
    Prefix(String),
    /// Suffix match — everything ending with this string.
    Suffix(String),
    /// Contains match — everything containing this substring.
    Contains(String),
}

impl Pattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
            Self::Suffix(suffix) => name.ends_with(suffix.as_str()),
            Self::Contains(substr) => name.contains(substr.as_str()),
        }
    }

    fn raw(&self) -> String {
        match self {
            Self::Wildcard => "*".to_string(),
            Self::Exact(s) => s.clone(),
            Self::Prefix(s) => format!("{s}*"),
            Self::Suffix(s) => format!("*{s}"),
            Self::Contains(s) => format!("*{s}*"),
        }
    }
}

/// Compile a slice of raw pattern strings into [`Pattern`] values.
fn compile_patterns(raw: &[String]) -> Vec<Pattern> {
    raw.iter().map(|s| compile_pattern(s)).collect()
}

/// Compile a single raw pattern string into a [`Pattern`].
///
/// Pattern forms:
/// - `"*"` → `Wildcard`
/// - `"brave_*"` → `Prefix("brave_")`
/// - `"*_write"` → `Suffix("_write")`
/// - `"*search*"` → `Contains("search")`
/// - `"write_file"` → `Exact("write_file")`
pub(crate) fn compile_pattern(s: &str) -> Pattern {
    match (s.starts_with('*'), s.ends_with('*')) {
        // Pure wildcard
        (_, _) if s == "*" => Pattern::Wildcard,
        // Contains: starts and ends with '*', interior non-empty
        (true, true) => {
            let inner = s[1..s.len() - 1].to_string();
            if inner.is_empty() {
                Pattern::Wildcard
            } else {
                Pattern::Contains(inner)
            }
        }
        // Suffix: starts with '*' only
        (true, false) => Pattern::Suffix(s[1..].to_string()),
        // Prefix: ends with '*' only
        (false, true) => Pattern::Prefix(s[..s.len() - 1].to_string()),
        // Exact
        (false, false) => Pattern::Exact(s.to_string()),
    }
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

    /// Return the names of all configured profiles, sorted alphabetically.
    #[must_use]
    pub fn profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Return a list of all profiles with their names and descriptions, sorted by name.
    #[must_use]
    pub fn profile_summaries(&self) -> Vec<serde_json::Value> {
        let mut summaries: Vec<_> = self
            .profiles
            .values()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                })
            })
            .collect();
        // Sort by name for deterministic output
        summaries.sort_by(|a, b| {
            a["name"]
                .as_str()
                .unwrap_or("")
                .cmp(b["name"].as_str().unwrap_or(""))
        });
        summaries
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
            description: String::new(),
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

    // ── description field ────────────────────────────────────────────────

    #[test]
    fn profile_description_is_propagated_from_config() {
        // GIVEN: a profile config with a description
        let cfg = RoutingProfileConfig {
            description: "Research tasks".to_string(),
            ..Default::default()
        };
        // WHEN: compiled
        let p = RoutingProfile::from_config("research", &cfg);
        // THEN: description is preserved
        assert_eq!(p.description, "Research tasks");
    }

    #[test]
    fn allow_all_profile_has_default_description() {
        // GIVEN: allow_all profile
        let p = RoutingProfile::allow_all("full");
        // THEN: description is non-empty
        assert!(!p.description.is_empty());
    }

    #[test]
    fn describe_includes_name_and_description() {
        // GIVEN: a named profile with a description
        let cfg = RoutingProfileConfig {
            description: "Coding assistant".to_string(),
            ..Default::default()
        };
        let p = RoutingProfile::from_config("coding", &cfg);
        // WHEN: described
        let desc = p.describe();
        // THEN: both name and description appear
        assert_eq!(desc["name"], "coding");
        assert_eq!(desc["description"], "Coding assistant");
    }

    // ── contains-glob patterns ───────────────────────────────────────────

    #[test]
    fn contains_glob_matches_substring_anywhere_in_name() {
        // GIVEN: allow_tools: ["*search*"]
        let p = profile_from(Some(&["*search*"]), None, None, None);
        // WHEN / THEN: any tool with "search" in the name is allowed
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("b", "search_web").is_ok());
        assert!(p.check("b", "advanced_search_engine").is_ok());
    }

    #[test]
    fn contains_glob_blocks_tools_without_substring() {
        // GIVEN: allow_tools: ["*search*"]
        let p = profile_from(Some(&["*search*"]), None, None, None);
        // WHEN / THEN: tools without "search" are blocked
        assert!(p.check("b", "brave_news").is_err());
        assert!(p.check("b", "gmail_send").is_err());
    }

    #[test]
    fn suffix_glob_matches_tools_ending_with_pattern() {
        // GIVEN: allow_tools: ["*_write"]
        let p = profile_from(Some(&["*_write"]), None, None, None);
        // WHEN / THEN: tools ending with "_write" are allowed
        assert!(p.check("b", "file_write").is_ok());
        assert!(p.check("b", "memory_write").is_ok());
    }

    #[test]
    fn suffix_glob_blocks_non_suffix_matching_tools() {
        // GIVEN: allow_tools: ["*_write"]
        let p = profile_from(Some(&["*_write"]), None, None, None);
        // WHEN / THEN: tools not ending with "_write" are blocked
        assert!(p.check("b", "file_read").is_err());
        assert!(p.check("b", "write_file").is_err());
    }

    #[test]
    fn wildcard_alone_allows_everything() {
        // GIVEN: allow_tools: ["*"]
        let p = profile_from(Some(&["*"]), None, None, None);
        // WHEN / THEN: any tool passes
        assert!(p.check("b", "anything").is_ok());
        assert!(p.check("b", "brave_search").is_ok());
    }

    #[test]
    fn compile_pattern_wildcard_only() {
        // GIVEN / WHEN
        let pat = compile_pattern("*");
        // THEN: any name matches
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn compile_pattern_prefix() {
        let pat = compile_pattern("brave_*");
        assert!(pat.matches("brave_search"));
        assert!(pat.matches("brave_news"));
        assert!(!pat.matches("exa_search"));
    }

    #[test]
    fn compile_pattern_suffix() {
        let pat = compile_pattern("*_search");
        assert!(pat.matches("brave_search"));
        assert!(pat.matches("exa_search"));
        assert!(!pat.matches("brave_news"));
    }

    #[test]
    fn compile_pattern_contains() {
        let pat = compile_pattern("*search*");
        assert!(pat.matches("brave_search"));
        assert!(pat.matches("search_web"));
        assert!(pat.matches("advanced_search_engine"));
        assert!(!pat.matches("brave_news"));
    }

    #[test]
    fn compile_pattern_exact() {
        let pat = compile_pattern("write_file");
        assert!(pat.matches("write_file"));
        assert!(!pat.matches("write_files"));
        assert!(!pat.matches("xwrite_file"));
    }

    #[test]
    fn pattern_raw_round_trips_correctly() {
        // GIVEN: patterns of each form
        let cases = [
            ("*", "*"),
            ("brave_*", "brave_*"),
            ("*_search", "*_search"),
            ("*search*", "*search*"),
            ("exact", "exact"),
        ];
        for (input, expected_raw) in cases {
            let pat = compile_pattern(input);
            assert_eq!(pat.raw(), expected_raw, "raw() mismatch for '{input}'");
        }
    }

    // ── ProfileRegistry::profile_summaries ───────────────────────────────

    #[test]
    fn profile_summaries_returns_sorted_profiles_with_descriptions() {
        // GIVEN: registry with two profiles
        let mut configs = HashMap::new();
        configs.insert(
            "research".to_string(),
            RoutingProfileConfig {
                description: "Research tasks".to_string(),
                ..Default::default()
            },
        );
        configs.insert(
            "coding".to_string(),
            RoutingProfileConfig {
                description: "Coding tasks".to_string(),
                ..Default::default()
            },
        );
        let registry = ProfileRegistry::from_config(&configs, "coding");
        // WHEN
        let summaries = registry.profile_summaries();
        // THEN: sorted alphabetically, descriptions present
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0]["name"], "coding");
        assert_eq!(summaries[0]["description"], "Coding tasks");
        assert_eq!(summaries[1]["name"], "research");
        assert_eq!(summaries[1]["description"], "Research tasks");
    }

    #[test]
    fn profile_summaries_empty_when_no_profiles_configured() {
        // GIVEN: empty registry
        let registry = ProfileRegistry::default();
        // WHEN / THEN: returns empty vec
        assert!(registry.profile_summaries().is_empty());
    }

    // ── toolshed-style include/exclude patterns from issue #83 ───────────

    #[test]
    fn coding_profile_includes_file_and_git_tools_excludes_communication() {
        // GIVEN: coding profile — allow file_*, git_*, lint_*, gateway_*
        let p = profile_from(
            Some(&["file_*", "git_*", "lint_*", "gateway_*"]),
            None,
            None,
            None,
        );
        // WHEN / THEN: file and git tools pass
        assert!(p.check("b", "file_read").is_ok());
        assert!(p.check("b", "file_write").is_ok());
        assert!(p.check("b", "git_commit").is_ok());
        assert!(p.check("b", "lint_check").is_ok());
        assert!(p.check("b", "gateway_invoke").is_ok());
        // AND: communication tools are blocked
        assert!(p.check("b", "gmail_send").is_err());
        assert!(p.check("b", "beeper_send").is_err());
    }

    #[test]
    fn research_profile_allows_search_tools_blocks_communication() {
        // GIVEN: research profile — allow brave_*, exa_*, gateway_*
        let p = profile_from(
            Some(&["brave_*", "exa_*", "tavily_*", "gateway_*"]),
            None,
            None,
            None,
        );
        // WHEN / THEN: search tools pass
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("b", "exa_search").is_ok());
        assert!(p.check("b", "tavily_search").is_ok());
        assert!(p.check("b", "gateway_list_tools").is_ok());
        // AND: non-search tools are blocked
        assert!(p.check("b", "gmail_send").is_err());
        assert!(p.check("b", "linear_create_issue").is_err());
    }

    #[test]
    fn full_profile_uses_wildcard_to_allow_all_tools() {
        // GIVEN: full profile — include: ["*"]
        let p = profile_from(Some(&["*"]), None, None, None);
        // WHEN / THEN: any tool passes
        assert!(p.check("b", "brave_search").is_ok());
        assert!(p.check("b", "gmail_send").is_ok());
        assert!(p.check("b", "anything_at_all").is_ok());
    }

    #[test]
    fn meta_tools_always_included_when_gateway_prefix_in_allow_list() {
        // GIVEN: profile with gateway_* in allow list
        let p = profile_from(Some(&["brave_*", "gateway_*"]), None, None, None);
        // WHEN / THEN: meta-tools pass
        assert!(p.check("b", "gateway_invoke").is_ok());
        assert!(p.check("b", "gateway_list_tools").is_ok());
        assert!(p.check("b", "gateway_set_profile").is_ok());
        // AND: non-gateway, non-brave blocked
        assert!(p.check("b", "gmail_send").is_err());
    }
}
