// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8298: a pattern its section cannot match is refused at load.
//!
//! Tool sections match an exact name or a trailing `prefix*`; backend
//! sections and agent scope segments match an exact name or `*` alone. Any
//! other `*` used to load as a literal and match nothing (an inert deny, or an
//! allow that grants nothing). Each row loads a written YAML file through
//! `Config::load`, the path start-up and hot reload share.

use super::*;
use crate::gateway::oauth::{Action, Scope, check_scopes};

const KEY: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn load(yaml: &str) -> Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, yaml).expect("write config");
    Config::load(Some(&path))
}

/// The load is refused, and the one-line error names `key` and the pattern.
fn assert_refused(yaml: &str, key: &str, pattern: &str) {
    let err = match load(yaml) {
        Ok(_) => panic!("{key} = {pattern:?} loaded; it must be refused"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains(key), "error does not name {key}: {err}");
    assert!(
        err.contains(&format!("{pattern:?}")),
        "error does not quote {pattern:?}: {err}"
    );
    assert!(err.contains("matches no"), "error does not say why: {err}");
    assert!(!err.contains('\n'), "error is not one line: {err}");
}

fn tool_policy(list: &str, pattern: &str, enabled: bool) -> String {
    format!("security:\n  tool_policy:\n    enabled: {enabled}\n    {list}: [{pattern:?}]\n")
}

fn api_key(field: &str, pattern: &str) -> String {
    let backends = if field == "backends" {
        format!("[{pattern:?}]")
    } else {
        "[\"*\"]".into()
    };
    let extra = if field == "backends" {
        String::new()
    } else {
        format!("\n      {field}: [{pattern:?}]")
    };
    format!(
        "auth:\n  enabled: false\n  api_keys:\n    - name: ci\n      key_sha256: {KEY:?}\n      backends: {backends}{extra}\n"
    )
}

fn key_server(field: &str, pattern: &str) -> String {
    let (backends, tools) = if field == "backends" {
        (format!("[{pattern:?}]"), "[\"*\"]".to_string())
    } else {
        ("[\"*\"]".to_string(), format!("[{pattern:?}]"))
    };
    format!(
        "key_server:\n  enabled: false\n  policies:\n    - match:\n        issuer: https://issuer.example\n      scopes:\n        backends: {backends}\n        tools: {tools}\n"
    )
}

fn agent(scope: &str) -> String {
    format!(
        "agent_auth:\n  enabled: false\n  agents:\n    - client_id: ci\n      name: ci\n      scopes: [{scope:?}]\n"
    )
}

/// Tool-section patterns with a `*` before their last character.
const INNER: &[&str] = &["*_delete", "a*b", "*search*", "**"];

// ── LOAD.1: refused, per section, whatever `enabled` says ──────────────────

#[test]
fn tool_policy_deny_with_an_inner_star_is_refused() {
    for p in INNER {
        assert_refused(
            &tool_policy("deny", p, true),
            "security.tool_policy.deny[0]",
            p,
        );
    }
}

#[test]
fn tool_policy_allow_with_an_inner_star_is_refused() {
    for p in INNER {
        assert_refused(
            &tool_policy("allow", p, true),
            "security.tool_policy.allow[0]",
            p,
        );
    }
}

#[test]
fn a_disabled_tool_policy_is_still_checked() {
    assert_refused(
        &tool_policy("deny", "*_delete", false),
        "security.tool_policy.deny[0]",
        "*_delete",
    );
}

#[test]
fn api_key_tool_lists_with_an_inner_star_are_refused() {
    for field in ["denied_tools", "allowed_tools"] {
        for p in INNER {
            assert_refused(
                &api_key(field, p),
                &format!("auth.api_keys[0].{field}[0]"),
                p,
            );
        }
    }
}

#[test]
fn key_server_scope_tools_with_an_inner_star_are_refused_while_disabled() {
    for p in INNER {
        assert_refused(
            &key_server("tools", p),
            "key_server.policies[0].scopes.tools[0]",
            p,
        );
    }
}

#[test]
fn backend_lists_take_an_exact_name_or_a_lone_star() {
    for p in ["gh*", "a*b", "*gh", "**"] {
        assert_refused(&api_key("backends", p), "auth.api_keys[0].backends[0]", p);
        assert_refused(
            &key_server("backends", p),
            "key_server.policies[0].scopes.backends[0]",
            p,
        );
    }
}

#[test]
fn agent_scope_segments_take_an_exact_name_or_a_lone_star() {
    for scope in [
        "tools:gh*:search",
        "tools:gh:a*b",
        "tools:*gh",
        "tools:gh:*x:read",
    ] {
        assert_refused(&agent(scope), "agent_auth.agents[0].scopes[0]", scope);
    }
}

#[test]
fn a_backend_name_holding_a_star_is_refused() {
    let err = load("backends:\n  \"my*be\":\n    command: echo\n")
        .expect_err("a backend named my*be loaded; it must be refused")
        .to_string();
    assert!(err.contains("my*be"), "{err}");
    assert!(err.contains('*'), "{err}");
}

#[test]
fn an_agent_scope_action_must_be_a_known_action() {
    for scope in ["tools:gh:search:reed", "tools:gh:search:read*"] {
        let Err(err) = load(&agent(scope)) else {
            panic!("{scope:?} loaded; it must be refused");
        };
        let err = err.to_string();
        assert!(err.contains("agent_auth.agents[0].scopes[0]"), "{err}");
        assert!(err.contains(&format!("{scope:?}")), "{err}");
        assert!(err.contains("not an action"), "{err}");
        assert!(!err.contains('\n'), "{err}");
    }
}

#[test]
fn an_agent_scope_without_the_tools_prefix_is_refused() {
    let err = load(&agent("surreal:*"))
        .expect_err("'surreal:*' loaded; it grants nothing and must be refused")
        .to_string();
    assert!(err.contains("agent_auth.agents[0].scopes[0]"), "{err}");
    assert!(err.contains("\"surreal:*\""), "{err}");
    assert!(err.contains("tools:"), "{err}");
}

#[test]
fn a_capability_backend_name_holding_a_star_is_refused() {
    let err = load("capabilities:\n  name: \"my*caps\"\n")
        .expect_err("capabilities.name my*caps loaded; it must be refused")
        .to_string();
    assert!(err.contains("capabilities.name"), "{err}");
    assert!(err.contains("my*caps"), "{err}");
}

// ── LOAD.2: what matched before loads and decides the same ─────────────────

#[test]
fn exact_names_and_trailing_prefixes_still_load_and_decide_the_same() {
    let yaml = format!(
        "security:\n  tool_policy:\n    enabled: true\n    use_default_deny: false\n    deny: [\"fs_*\", \"drop_table\"]\n    allow: [\"fs_read\"]\n\
         auth:\n  enabled: false\n  api_keys:\n    - name: ci\n      key_sha256: {KEY:?}\n      backends: [\"gh\", \"*\"]\n      allowed_tools: [\"search_*\", \"gh:issue_list\"]\n      denied_tools: [\"search_admin\"]\n\
         key_server:\n  enabled: false\n  policies:\n    - match:\n        issuer: https://issuer.example\n      scopes:\n        backends: [\"gh\"]\n        tools: [\"brave_*\", \"*\"]\n\
         agent_auth:\n  enabled: false\n  agents:\n    - client_id: ci\n      name: ci\n      scopes: [\"tools:gh:*\", \"tools:*:search:read\", \"tools:gh:*:read\", \"tools:gh:search:read\"]\n"
    );
    let config = load(&yaml).expect("a config of exact names and trailing prefixes loads");

    let policy = crate::security::ToolPolicy::from_config(&config.security.tool_policy);
    assert!(
        policy.check("s", "fs_write").is_err(),
        "fs_* denies fs_write"
    );
    assert!(policy.check("s", "drop_table").is_err(), "exact deny");
    assert!(
        policy.check("s", "fs_read").is_ok(),
        "allow takes precedence"
    );
    assert!(
        policy.check("s", "search").is_ok(),
        "unlisted falls to default allow"
    );

    let key = &config.auth.api_keys[0];
    let client = crate::gateway::auth::AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: key.name.clone(),
        rate_limit: 0,
        backends: key.backends.clone(),
        allowed_tools: key.allowed_tools.clone(),
        denied_tools: key.denied_tools.clone(),
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    assert!(
        client.check_tool_scope("x", "search_web").is_ok(),
        "prefix allow"
    );
    assert!(
        client.check_tool_scope("gh", "issue_list").is_ok(),
        "qualified exact allow"
    );
    assert!(
        client.check_tool_scope("x", "search_admin").is_err(),
        "exact deny"
    );
    assert!(
        client.check_tool_scope("x", "write").is_err(),
        "outside the allowlist"
    );
    assert!(client.can_access_backend("gh") && client.can_access_backend("other"));

    let scopes: Vec<Scope> = config.agent_auth.agents[0]
        .scopes
        .iter()
        .filter_map(|s| Scope::parse(s))
        .collect();
    let grants = |b: &str, t: &str, a: Action| check_scopes(&scopes, "ci", b, t, &a).is_ok();
    assert!(
        grants("gh", "anything", Action::Write),
        "tools:gh:* grants every tool and action on gh"
    );
    assert!(
        grants("other", "search", Action::Read),
        "tools:*:search:read"
    );
    assert!(!grants("other", "search", Action::Write), "read only");
    assert!(!grants("other", "list", Action::Read), "search only off gh");
}

/// Each narrow grant decides alone, with no broader sibling beside it.
#[test]
fn narrow_grants_decide_on_their_own() {
    let yaml = format!(
        "auth:\n  enabled: false\n  api_keys:\n    - name: ci\n      key_sha256: {KEY:?}\n      backends: [\"gh\"]\n\
         agent_auth:\n  enabled: false\n  agents:\n    - client_id: ci\n      name: ci\n      scopes: [\"tools:gh:*:read\"]\n"
    );
    let config = load(&yaml).expect("exact backends and a lone-star scope load");
    let key = &config.auth.api_keys[0];
    let client = crate::gateway::auth::AuthenticatedClient {
        quota_principal: None,
        principal: String::new(),
        name: key.name.clone(),
        rate_limit: 0,
        backends: key.backends.clone(),
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    };
    assert!(client.can_access_backend("gh"), "the exact backend");
    assert!(
        !client.can_access_backend("other"),
        "only the exact backend"
    );

    let scopes: Vec<Scope> = config.agent_auth.agents[0]
        .scopes
        .iter()
        .filter_map(|s| Scope::parse(s))
        .collect();
    let grants = |b: &str, t: &str, a: Action| check_scopes(&scopes, "ci", b, t, &a).is_ok();
    assert!(
        grants("gh", "any_tool", Action::Read),
        "tools:gh:*:read reads any tool on gh"
    );
    assert!(!grants("gh", "any_tool", Action::Write), "and only reads");
    assert!(!grants("other", "any_tool", Action::Read), "and only on gh");
}

fn refusal(yaml: &str) -> String {
    match load(yaml) {
        Ok(_) => panic!("loaded; it must be refused"),
        Err(e) => e.to_string(),
    }
}

/// A broader `prefix*` only denies more, so a deny hint offers it first; on an
/// allow list it would grant more, so the hint leads with the exact names.
#[test]
fn deny_hints_offer_the_prefix_first_and_allow_hints_the_exact_names() {
    let deny = refusal(&tool_policy("deny", "a*b", true));
    let (use_prefix, exact) = (
        deny.find("Use \"a*\""),
        deny.find("list the exact tool names"),
    );
    assert!(
        matches!((use_prefix, exact), (Some(p), Some(e)) if p < e),
        "{deny}"
    );

    let allow = refusal(&tool_policy("allow", "a*b", true));
    let (exact, prefix) = (
        allow.find("List the exact tool names"),
        allow.find("\"a*\""),
    );
    assert!(
        matches!((exact, prefix), (Some(e), Some(p)) if e < p),
        "{allow}"
    );
    assert!(allow.contains("may be allowed (broader)"), "{allow}");
}

#[test]
fn the_key_server_backend_refusal_says_why_it_depends_on_the_client() {
    let err = refusal(&key_server("backends", "gh*"));
    assert!(
        err.contains("a client that does not name it in its request"),
        "{err}"
    );
    assert!(err.contains("List the exact backend names"), "{err}");
}

#[test]
fn an_agent_segment_refusal_names_the_segment_and_its_fix() {
    let err = refusal(&agent("tools:gh*:search"));
    assert!(err.contains("the backend segment \"gh*\""), "{err}");
    assert!(
        err.contains("Write one backend name there, or '*'"),
        "{err}"
    );
}
