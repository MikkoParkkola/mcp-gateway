// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tests for the curated server registry.

use super::*;

#[test]
fn all_returns_non_empty_slice() {
    // GIVEN: the static registry
    // WHEN: all() is called
    // THEN: the result contains at least 20 entries
    assert!(
        all().len() >= 20,
        "Expected at least 20 entries, got {}",
        all().len()
    );
}

#[test]
fn lookup_known_name_returns_entry() {
    // GIVEN: a server known to be in the registry
    // WHEN: looking up by exact name
    // THEN: the correct entry is returned
    let entry = lookup("tavily").expect("tavily must be in registry");
    assert_eq!(entry.name, "tavily");
    assert_eq!(entry.category, "search");
    assert!(entry.required_env.contains(&"TAVILY_API_KEY"));
}

#[test]
fn lookup_is_case_insensitive() {
    // GIVEN: the registry has "github"
    // WHEN: looking up with uppercase letters
    // THEN: the entry is still found
    assert!(lookup("GitHub").is_some());
    assert!(lookup("GITHUB").is_some());
}

#[test]
fn lookup_unknown_name_returns_none() {
    // GIVEN: a name that does not exist in the registry
    // WHEN: looking it up
    // THEN: None is returned
    assert!(lookup("definitely-not-a-real-mcp-server").is_none());
}

#[test]
fn search_by_category_returns_matching_entries() {
    // GIVEN: the registry contains multiple "database" category entries
    // WHEN: searching for "database"
    // THEN: all entries with category == "database" are included in the results
    //       (search also matches on name/description so results may include more)
    let results = search("database");
    assert!(
        results.len() >= 2,
        "Expected at least 2 entries matching 'database', got {}",
        results.len()
    );
    // All dedicated database-category servers must be present.
    let database_entries: Vec<_> = all().iter().filter(|e| e.category == "database").collect();
    for db_entry in database_entries {
        assert!(
            results.iter().any(|r| r.name == db_entry.name),
            "database-category entry '{}' missing from search results",
            db_entry.name
        );
    }
}

#[test]
fn search_by_description_term_returns_matching_entries() {
    // GIVEN: entries with "memory" in their descriptions
    // WHEN: searching "memory"
    // THEN: at least the memory server is returned
    let results = search("memory");
    assert!(
        results.iter().any(|e| e.name == "memory"),
        "expected 'memory' entry in search results"
    );
}

#[test]
fn search_empty_query_returns_all() {
    // GIVEN: an empty query matches every entry
    // WHEN: searching ""
    // THEN: all entries are returned
    assert_eq!(search("").len(), all().len());
}

#[test]
fn context7_has_http_transport() {
    // GIVEN: context7 is an HTTP-only server
    // WHEN: looking it up
    // THEN: its transport is Http with a non-empty default URL
    let entry = lookup("context7").expect("context7 must be in registry");
    match entry.transport {
        Transport::Http { default_url, .. } => assert!(!default_url.is_empty()),
        Transport::Stdio => panic!("expected Http transport for context7"),
    }
}

#[test]
fn all_stdio_entries_have_non_empty_command() {
    // GIVEN: every stdio entry must have a launchable command
    // WHEN: iterating all entries
    // THEN: none have an empty command string
    for entry in all() {
        if let Transport::Stdio = entry.transport {
            assert!(
                !entry.command.is_empty(),
                "{} has Stdio transport but empty command",
                entry.name
            );
        }
    }
}

#[test]
fn registry_names_are_unique() {
    // GIVEN: names must be unique for lookup to be unambiguous
    let mut seen = std::collections::HashSet::new();
    for entry in all() {
        assert!(
            seen.insert(entry.name),
            "duplicate name in registry: {}",
            entry.name
        );
    }
}

// ── MIK-7787: login, reach and setup ────────────────────────────────────────

fn names(filter: impl Fn(&RegistryEntry) -> bool) -> Vec<&'static str> {
    let mut names: Vec<_> = all().iter().filter(|e| filter(e)).map(|e| e.name).collect();
    names.sort_unstable();
    names
}

/// `${NAME}` references in a header template.
fn template_vars(value: &str) -> Vec<&str> {
    value
        .split("${")
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name))
        .collect()
}

#[test]
fn each_login_kind_matches_its_transport_and_variables() {
    for e in all() {
        let http = matches!(e.transport, Transport::Http { .. });
        match e.auth {
            Auth::None => assert!(
                e.required_env.is_empty(),
                "{}: no login, no required env",
                e.name
            ),
            Auth::EnvVars => assert!(
                !http && !e.required_env.is_empty(),
                "{}: EnvVars is a stdio server with required env",
                e.name
            ),
            Auth::OAuth => assert!(
                http && e.required_env.is_empty(),
                "{}: OAuth is a hosted server and needs no env",
                e.name
            ),
            Auth::Header { value, .. } => {
                assert!(http, "{}: a header goes on an http backend", e.name);
                let mut vars = template_vars(value);
                vars.sort_unstable();
                let mut required = e.required_env.to_vec();
                required.sort_unstable();
                assert_eq!(
                    vars, required,
                    "{}: header variables are the required env",
                    e.name
                );
            }
        }
    }
}

#[test]
fn the_init_starter_set_is_exactly_the_no_login_ready_servers() {
    // Lead decision 2026-10-02. semgrep is out: warm start would download its
    // engine at gateway start (src/gateway/server/warmstart.rs).
    assert_eq!(
        names(RegistryEntry::default_enabled),
        ["context7", "memory", "sequential-thinking", "time"]
    );
}

#[test]
fn every_server_that_can_reach_any_address_is_classified_on_purpose() {
    assert_eq!(
        names(|e| matches!(e.reach, Reach::Arbitrary { .. })),
        ["chrome-devtools", "fetch", "git", "playwright"]
    );
    assert!(
        all()
            .iter()
            .all(|e| e.reach_allows_on() == matches!(e.reach, Reach::Bounded))
    );
}

#[test]
fn only_asana_speaks_the_legacy_sse_handshake() {
    assert_eq!(
        names(|e| matches!(
            e.transport,
            Transport::Http {
                flavor: HttpFlavor::Sse,
                ..
            }
        )),
        ["asana"]
    );
}

/// chrome-devtools-mcp drives a local Chrome; the entry says so before the
/// user adds it, instead of the first tool call failing.
#[test]
fn chrome_devtools_names_its_chrome_prerequisite() {
    let entry = lookup("chrome-devtools").expect("chrome-devtools is listed");
    assert!(
        matches!(entry.setup, Setup::NeedsService { hint } if hint.contains("Chrome")),
        "{:?}",
        entry.setup
    );
}
