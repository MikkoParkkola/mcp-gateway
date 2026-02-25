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
//! Both tool and backend filter lists support a glob subset:
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
/// ```yaml
/// routing_profiles:
///   research:
///     description: "Web research — brave, arxiv, wikipedia only"
///     allow_tools: ["brave_*", "wikipedia_*", "arxiv_*"]
///   coding:
///     description: "Software development — no social or email tools"
///     deny_tools: ["gmail_*", "slack_*"]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingProfileConfig {
    /// Human-readable description shown by `gateway_list_profiles`.
    #[serde(default)]
    pub description: String,

    /// If `Some`, only backends whose names match are accessible.
    /// Supports glob patterns (`"mybackend_*"`, `"*_internal"`, `"*search*"`).
    #[serde(default)]
    pub allow_backends: Option<Vec<String>>,

    /// If `Some`, backends whose names match are blocked.
    /// Evaluated after `allow_backends`.
    #[serde(default)]
    pub deny_backends: Option<Vec<String>>,

    /// If `Some`, only tools whose names match are accessible.
    /// Supports glob patterns (`"brave_*"`, `"*_read"`, `"*search*"`).
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
    /// Human-readable description (e.g. `"Web research tools only"`).
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
// Pattern filter (allow/deny list with full glob support)
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
// Pattern (full glob subset: exact, prefix, suffix, contains, wildcard)
// ============================================================================

#[derive(Debug, Clone)]
enum Pattern {
    /// Matches any string — compiled from `"*"`.
    Wildcard,
    /// Exact name match — compiled from `"exact_name"`.
    Exact(String),
    /// Prefix match — compiled from `"prefix_*"`.
    Prefix(String),
    /// Suffix match — compiled from `"*_suffix"`.
    Suffix(String),
    /// Substring match — compiled from `"*substring*"`.
    Contains(String),
}

impl Pattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Exact(exact) => name == exact,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
            Self::Suffix(suffix) => name.ends_with(suffix.as_str()),
            Self::Contains(inner) => name.contains(inner.as_str()),
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

/// Compile a raw glob string into a [`Pattern`].
///
/// Handles five forms:
/// - `"*"` → `Wildcard`
/// - `"prefix_*"` → `Prefix("prefix_")`
/// - `"*_suffix"` → `Suffix("_suffix")`
/// - `"*contains*"` → `Contains("contains")`
/// - `"exact"` → `Exact("exact")`
fn compile_pattern(s: &str) -> Pattern {
    let starts_star = s.starts_with('*');
    let ends_star = s.ends_with('*');

    match (starts_star, ends_star) {
        _ if s == "*" => Pattern::Wildcard,
        (true, true) => {
            // Strip leading and trailing '*'
            let inner = &s[1..s.len() - 1];
            if inner.is_empty() {
                Pattern::Wildcard
            } else {
                Pattern::Contains(inner.to_string())
            }
        }
        (true, false) => Pattern::Suffix(s[1..].to_string()),
        (false, true) => Pattern::Prefix(s[..s.len() - 1].to_string()),
        (false, false) => Pattern::Exact(s.to_string()),
    }
}

/// Compile a slice of raw pattern strings into [`Pattern`] values.
fn compile_patterns(raw: &[String]) -> Vec<Pattern> {
    raw.iter().map(|s| compile_pattern(s)).collect()
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

    /// Return a JSON summary of every configured profile, sorted alphabetically.
    ///
    /// Each entry contains `"name"` and `"description"` fields.
    #[must_use]
    pub fn profile_summaries(&self) -> Vec<serde_json::Value> {
        let mut summaries: Vec<serde_json::Value> = self
            .profiles
            .values()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "description": p.description,
                })
            })
            .collect();
        summaries.sort_by(|a, b| {
            let na = a["name"].as_str().unwrap_or("");
            let nb = b["name"].as_str().unwrap_or("");
            na.cmp(nb)
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

    #[test]
    fn allow_all_profile_has_unrestricted_description() {
        // GIVEN: a permissive profile
        let profile = RoutingProfile::allow_all("open");
        // THEN: description communicates lack of restrictions
        assert!(!profile.description.is_empty());
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

    // ── compile_pattern: glob variant coverage ───────────────────────────

    #[test]
    fn compile_pattern_bare_star_is_wildcard() {
        // GIVEN: pattern "*"
        let pat = compile_pattern("*");
        // THEN: matches anything
        assert!(pat.matches("anything"));
        assert!(pat.matches(""));
    }

    #[test]
    fn compile_pattern_prefix_star_is_suffix_match() {
        // GIVEN: pattern "*_write" — leading star, no trailing star
        let pat = compile_pattern("*_write");
        // THEN: matches anything ending in "_write"
        assert!(pat.matches("file_write"));
        assert!(pat.matches("db_write"));
        assert!(!pat.matches("file_read"));
    }

    #[test]
    fn compile_pattern_trailing_star_is_prefix_match() {
        // GIVEN: pattern "brave_*" — trailing star, no leading star
        let pat = compile_pattern("brave_*");
        // THEN: matches anything starting with "brave_"
        assert!(pat.matches("brave_search"));
        assert!(pat.matches("brave_news"));
        assert!(!pat.matches("gmail_send"));
    }

    #[test]
    fn compile_pattern_both_stars_is_contains_match() {
        // GIVEN: pattern "*search*"
        let pat = compile_pattern("*search*");
        // THEN: matches anything containing "search"
        assert!(pat.matches("brave_search"));
        assert!(pat.matches("search_engine"));
        assert!(pat.matches("deep_search_tool"));
        assert!(!pat.matches("brave_news"));
    }

    #[test]
    fn compile_pattern_no_stars_is_exact_match() {
        // GIVEN: pattern "write_file"
        let pat = compile_pattern("write_file");
        // THEN: only exact name matches
        assert!(pat.matches("write_file"));
        assert!(!pat.matches("write_file_safe"));
        assert!(!pat.matches("read_file"));
    }

    #[test]
    fn compile_pattern_double_star_empty_inner_is_wildcard() {
        // GIVEN: pattern "**" — both stars, empty inner
        let pat = compile_pattern("**");
        // THEN: treated as wildcard
        assert!(pat.matches("anything"));
    }

    #[test]
    fn pattern_raw_roundtrips_correctly() {
        // GIVEN: various patterns
        // THEN: raw() produces the original string form
        assert_eq!(compile_pattern("*").raw(), "*");
        assert_eq!(compile_pattern("brave_*").raw(), "brave_*");
        assert_eq!(compile_pattern("*_write").raw(), "*_write");
        assert_eq!(compile_pattern("*search*").raw(), "*search*");
        assert_eq!(compile_pattern("exact").raw(), "exact");
    }

    // ── suffix and contains in filter lists ──────────────────────────────

    #[test]
    fn allow_tools_suffix_glob_filters_correctly() {
        // GIVEN: allow_tools: ["*_read"] — only read tools allowed
        let p = profile_from(Some(&["*_read"]), None, None, None);
        // THEN: read tools pass, write tools are blocked
        assert!(p.tool_allowed("file_read"));
        assert!(p.tool_allowed("db_read"));
        assert!(!p.tool_allowed("file_write"));
        assert!(!p.tool_allowed("db_delete"));
    }

    #[test]
    fn allow_tools_contains_glob_filters_correctly() {
        // GIVEN: allow_tools: ["*search*"]
        let p = profile_from(Some(&["*search*"]), None, None, None);
        // THEN: any tool containing "search" passes
        assert!(p.tool_allowed("brave_search"));
        assert!(p.tool_allowed("search_engine"));
        assert!(p.tool_allowed("deep_search_tool"));
        assert!(!p.tool_allowed("brave_news"));
    }

    #[test]
    fn deny_tools_suffix_glob_blocks_correctly() {
        // GIVEN: deny_tools: ["*_delete"] — no delete tools
        let p = profile_from(None, Some(&["*_delete"]), None, None);
        // THEN: delete tools blocked, everything else passes
        assert!(!p.tool_allowed("db_delete"));
        assert!(!p.tool_allowed("file_delete"));
        assert!(p.tool_allowed("db_read"));
        assert!(p.tool_allowed("file_write"));
    }

    #[test]
    fn wildcard_in_allow_list_permits_all_tools() {
        // GIVEN: allow_tools: ["*"] — wildcard
        let p = profile_from(Some(&["*"]), None, None, None);
        // THEN: anything passes the allow stage
        assert!(p.tool_allowed("brave_search"));
        assert!(p.tool_allowed("gmail_send"));
    }

    // ── description field ────────────────────────────────────────────────

    #[test]
    fn description_is_preserved_from_config() {
        // GIVEN: a config with description
        let cfg = RoutingProfileConfig {
            description: "Research tools only".to_string(),
            allow_tools: Some(vec!["brave_*".to_string()]),
            ..Default::default()
        };
        // WHEN: compiling the profile
        let profile = RoutingProfile::from_config("research", &cfg);
        // THEN: description is preserved
        assert_eq!(profile.description, "Research tools only");
    }

    #[test]
    fn describe_includes_description_field() {
        // GIVEN: a profile with description
        let cfg = RoutingProfileConfig {
            description: "Only brave tools".to_string(),
            allow_tools: Some(vec!["brave_*".to_string()]),
            ..Default::default()
        };
        let profile = RoutingProfile::from_config("research", &cfg);
        // WHEN: calling describe()
        let desc = profile.describe();
        // THEN: description appears in the JSON
        assert_eq!(desc["description"], "Only brave tools");
        assert_eq!(desc["name"], "research");
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

    #[test]
    fn profile_summaries_returns_sorted_name_description_pairs() {
        // GIVEN: registry with three profiles
        let mut configs = HashMap::new();
        configs.insert(
            "research".to_string(),
            RoutingProfileConfig {
                description: "Web research".to_string(),
                ..Default::default()
            },
        );
        configs.insert(
            "coding".to_string(),
            RoutingProfileConfig {
                description: "Software dev".to_string(),
                ..Default::default()
            },
        );
        configs.insert(
            "admin".to_string(),
            RoutingProfileConfig {
                description: "Admin tools".to_string(),
                ..Default::default()
            },
        );
        let registry = ProfileRegistry::from_config(&configs, "coding");
        // WHEN: requesting summaries
        let summaries = registry.profile_summaries();
        // THEN: sorted alphabetically by name
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0]["name"], "admin");
        assert_eq!(summaries[0]["description"], "Admin tools");
        assert_eq!(summaries[1]["name"], "coding");
        assert_eq!(summaries[2]["name"], "research");
    }

    #[test]
    fn profile_summaries_empty_when_no_profiles_configured() {
        // GIVEN: empty registry
        let registry = ProfileRegistry::default();
        // THEN: summaries is empty
        assert!(registry.profile_summaries().is_empty());
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
