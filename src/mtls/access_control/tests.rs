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
