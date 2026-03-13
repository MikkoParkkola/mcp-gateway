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
        allow_tools: allow_tools.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
        deny_tools: deny_tools.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
        allow_backends: allow_backends.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
        deny_backends: deny_backends.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
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
    let p = profile_from(Some(&["brave_*"]), Some(&["brave_news"]), None, None);
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
    assert!(
        err.contains("research"),
        "error should mention profile name"
    );
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
