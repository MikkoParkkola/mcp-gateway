// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The Policies read model: the tool policy with each deny entry's coverage
//! by the allow entries, and the finding rules with editability, shadowing
//! and where a scoped rule applies differently.

use std::sync::Arc;

use axum::body::to_bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::guard::Guard;
use super::policies::{read_model, read_policies};
use crate::config::Config;
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::gateway::routes;
use crate::security::policy::{PolicyAction, ToolPolicyConfig};

/// A config whose tool policy has `allow` and `deny`.
fn tool_policy(allow: &[&str], deny: &[&str]) -> Config {
    let mut config = Config::default();
    config.security.tool_policy = ToolPolicyConfig {
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        deny: deny.iter().map(|s| (*s).to_owned()).collect(),
        ..ToolPolicyConfig::default()
    };
    config
}

/// The read model's deny entry at `path`.
fn deny_at<'a>(model: &'a Value, path: &str) -> &'a Value {
    model["tool_policy"]["deny"]
        .as_array()
        .and_then(|d| d.iter().find(|e| e["path"] == path))
        .unwrap_or_else(|| panic!("no deny entry at {path}: {model}"))
}

fn client(admin: bool) -> AuthenticatedClient {
    AuthenticatedClient {
        name: "policies-route".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        principal: crate::gateway::auth::principal_of("policies-route-secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: crate::security::audit::CredentialKind::ApiKey,
    }
}

async fn get(state: &Arc<AppState>, caller: Option<AuthenticatedClient>) -> (StatusCode, Value) {
    let guard = Guard::for_route(routes::UI_POLICIES, &Method::GET, caller);
    let response = read_policies(State(Arc::clone(state)), guard).await;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn state() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    crate::gateway::router::tests::audience_state(
        &crate::config::AuthConfig::default(),
        (None, None),
        |meta| meta,
    )
    .await
}

/// R0: an admin is served; a non-admin and an anonymous caller are refused.
#[tokio::test]
async fn r0_only_an_admin_reads_the_policies() {
    let (state, _dir) = state().await;
    let (ok, body) = get(&state, Some(client(true))).await;
    assert_eq!(ok, StatusCode::OK, "{body}");
    assert!(body["tool_policy"].is_object() && body["finding_rules"].is_array());
    let (refused, _) = get(&state, Some(client(false))).await;
    assert_eq!(
        refused,
        super::errors::admin_auth_required().0,
        "a non-admin"
    );
    let (anonymous, _) = get(&state, None).await;
    assert_ne!(anonymous, StatusCode::OK, "an anonymous caller");
}

/// N1: the endpoint reads the published generation, so a reload shows.
#[tokio::test]
async fn n1_a_reload_shows_in_the_read_model() {
    let (state, _dir) = state().await;
    let mut config = (*state.live_config.get()).clone();
    config.security.tool_policy.deny = vec!["reloaded_*".to_owned()];
    state.live_config.set(config);
    let (_, body) = get(&state, Some(client(true))).await;
    assert_eq!(
        body["tool_policy"]["deny"][0]["entry"], "reloaded_*",
        "{body}"
    );
}

/// The built-in default denies, in source order (`policy.rs`).
const DEFAULT_DENIES: [&str; 15] = [
    "write_file",
    "delete_file",
    "move_file",
    "create_directory",
    "run_command",
    "execute_command",
    "shell_exec",
    "run_script",
    "eval",
    "drop_table",
    "drop_database",
    "truncate_table",
    "kill_process",
    "shutdown",
    "reboot",
];

/// R1a: the switches, the 15 default denies by name and order with their
/// path, and each configured entry with its own path.
#[test]
fn r1a_the_tool_policy_and_its_paths() {
    let mut config = tool_policy(&["srv:read"], &["delete_*", "srv:run"]);
    config.security.tool_policy.default_action = PolicyAction::Deny;
    let model = read_model(&config);
    let policy = &model["tool_policy"];
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["default_action"], "deny");
    assert_eq!(policy["use_default_deny"], true);
    let names: Vec<&str> = policy["default_denies"]
        .as_array()
        .expect("default denies")
        .iter()
        .map(|d| {
            assert_eq!(d["path"], "security.tool_policy.use_default_deny");
            assert_eq!(d["active"], true);
            d["name"].as_str().expect("a name")
        })
        .collect();
    assert_eq!(names, DEFAULT_DENIES);
    assert_eq!(
        policy["allow"],
        json!([{ "entry": "srv:read", "path": "security.tool_policy.allow[0]" }])
    );
    assert_eq!(policy["deny"][0]["entry"], "delete_*");
    assert_eq!(policy["deny"][0]["path"], "security.tool_policy.deny[0]");
    assert_eq!(policy["deny"][1]["path"], "security.tool_policy.deny[1]");
}

/// R1b: deny `delete_*` is partly overridden by allow `srv:delete_draft`
/// and by allow `other:x` (they meet at server `delete_srv`, tool `other:x`),
/// and fully overridden by allow `delete_*`.
#[test]
fn r1b_coverage_of_a_prefix_deny() {
    let config = tool_policy(&["srv:delete_draft", "delete_*", "other:x"], &["delete_*"]);
    let model = read_model(&config);
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["overridden_by"],
        json!(["security.tool_policy.allow[1]"])
    );
    assert_eq!(
        deny["partly_overridden_by"],
        json!([
            "security.tool_policy.allow[0]",
            "security.tool_policy.allow[2]"
        ])
    );
}

/// R1c: the spellings, as the real matcher reads them.
#[test]
fn r1c_coverage_across_spellings() {
    // deny `srv:run`: allow `run` misses (other, srv:run): partly; allow
    // `srv:*` covers both of its pairs: fully.
    let model = read_model(&tool_policy(&["run", "srv:*"], &["srv:run"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["overridden_by"],
        json!(["security.tool_policy.allow[1]"])
    );
    assert_eq!(
        deny["partly_overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
    // deny `run`: allow `srv:run` covers one server's copy only.
    let model = read_model(&tool_policy(&["srv:run"], &["run"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["partly_overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
    assert_eq!(deny["overridden_by"], json!([]));
    // deny `srv:*`: allow `srv:read` covers part of it.
    let model = read_model(&tool_policy(&["srv:read"], &["srv:*"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["partly_overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
    // a default deny overridden by allow `eval`.
    let model = read_model(&tool_policy(&["eval"], &[]));
    let eval = model["tool_policy"]["default_denies"]
        .as_array()
        .and_then(|d| d.iter().find(|e| e["name"] == "eval"))
        .expect("eval listed");
    assert_eq!(
        eval["overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
}

/// R1d: computed from the config lists, not the compiled policy: two
/// identical deny entries are both listed, each with its own path.
#[test]
fn r1d_identical_entries_keep_their_own_paths() {
    let model = read_model(&tool_policy(&[], &["delete_*", "delete_*"]));
    let deny = model["tool_policy"]["deny"].as_array().expect("deny");
    assert_eq!(deny.len(), 2);
    assert_eq!(deny[1]["path"], "security.tool_policy.deny[1]");
}

/// Names the oracle tries: prefixes and splits of the entries' literals,
/// colon-bearing names, and fresh names sharing nothing.
const SERVERS: [&str; 9] = [
    "srv",
    "other",
    "delete_srv",
    "a",
    "ab",
    "abx",
    "a:b",
    "srv:x",
    "zz",
];
const TOOLS: [&str; 14] = [
    "run",
    "srv:run",
    "read",
    "srv:read",
    "delete_draft",
    "delete_x",
    "other:x",
    "x",
    "bx",
    "a:bx",
    "a:b:c",
    "eval",
    "b",
    "zz",
];

/// Whether a policy made of the single entry `entry` matches (server, tool),
/// read through the real matcher.
fn matches(entry: &str, server: &str, tool: &str) -> bool {
    let policy = crate::security::policy::ToolPolicy::from_config(&ToolPolicyConfig {
        deny: vec![entry.to_owned()],
        use_default_deny: false,
        ..ToolPolicyConfig::default()
    });
    policy.check(server, tool).is_err()
}

/// R1e: every (deny, allow) pair from a set of entry shapes agrees with a
/// brute force over the oracle's names, judged by the real matcher.
#[test]
fn r1e_coverage_agrees_with_the_real_matcher() {
    let entries = [
        "run",
        "srv:run",
        "srv:*",
        "delete_*",
        "srv:delete_draft",
        "other:x",
        "ab*",
        "a:b*",
        "a:b:c",
        "eval",
        "*",
        "b*",
    ];
    for deny in entries {
        for allow in entries {
            let model = read_model(&tool_policy(&[allow], &[deny]));
            let row = deny_at(&model, "security.tool_policy.deny[0]");
            let full = row["overridden_by"].as_array().expect("full").len() == 1;
            let part = row["partly_overridden_by"].as_array().expect("part").len() == 1;
            let (mut both, mut deny_only) = (false, false);
            // Every name in both roles: a server named like a tool prefix
            // (server `b`, tool `run`: `b:run` starts with `b`) is a pair too.
            // The fixed names, both entries' literals, their parts either
            // side of every `:`, and each of those with a character added.
            let mut names: Vec<String> = SERVERS
                .iter()
                .chain(TOOLS.iter())
                .map(|n| (*n).to_owned())
                .collect();
            for entry in [deny, allow] {
                let literal = entry.strip_suffix('*').unwrap_or(entry);
                names.push(literal.to_owned());
                for (i, _) in literal.match_indices(':') {
                    names.push(literal[..i].to_owned());
                    names.push(literal[i + 1..].to_owned());
                }
            }
            let suffixed: Vec<String> = names.iter().map(|n| format!("{n}q")).collect();
            names.extend(suffixed);
            for s in &names {
                for t in &names {
                    let (s, t) = (s.as_str(), t.as_str());
                    if matches(deny, s, t) {
                        if matches(allow, s, t) {
                            both = true;
                        } else {
                            deny_only = true;
                        }
                    }
                }
            }
            // The brute force can only find a witness the model's own
            // witnesses must also find; the reverse (a model witness the
            // brute force lacks) is the coverage the oracle checks loosely.
            if deny_only {
                assert!(!full, "deny {deny} allow {allow}: an uncovered pair exists");
            }
            if both {
                assert!(full || part, "deny {deny} allow {allow}: they meet");
            } else {
                assert!(!full && !part, "deny {deny} allow {allow}: they never meet");
            }
        }
    }
}

/// R1f: the real policy agrees: a deny fully overridden by an allow lets
/// every one of the deny's oracle pairs through; partly, some.
#[test]
fn r1f_a_full_override_lets_every_denied_pair_through() {
    for (deny, allow) in [
        ("delete_*", "delete_*"),
        ("srv:run", "srv:*"),
        ("eval", "eval"),
    ] {
        let model = read_model(&tool_policy(&[allow], &[deny]));
        assert_eq!(
            deny_at(&model, "security.tool_policy.deny[0]")["overridden_by"],
            json!(["security.tool_policy.allow[0]"]),
            "{deny} {allow}"
        );
        let policy = crate::security::policy::ToolPolicy::from_config(&ToolPolicyConfig {
            allow: vec![allow.to_owned()],
            deny: vec![deny.to_owned()],
            use_default_deny: false,
            ..ToolPolicyConfig::default()
        });
        for s in SERVERS {
            for t in TOOLS {
                if matches(deny, s, t) {
                    assert!(
                        policy.check(s, t).is_ok(),
                        "{deny} {allow}: ({s}, {t}) refused"
                    );
                }
            }
        }
    }
}

/// R1g: with `use_default_deny: false` the default denies are listed as
/// inactive with no coverage; with the policy off, everything is still
/// listed and `enabled` says so.
#[test]
fn r1g_inactive_default_denies_and_a_disabled_policy() {
    let mut config = tool_policy(&["eval"], &["delete_*"]);
    config.security.tool_policy.use_default_deny = false;
    let model = read_model(&config);
    for d in model["tool_policy"]["default_denies"]
        .as_array()
        .expect("listed")
    {
        assert_eq!(d["active"], false, "{d}");
        assert_eq!(d["overridden_by"], json!([]), "{d}");
        assert_eq!(d["partly_overridden_by"], json!([]), "{d}");
    }
    config.security.tool_policy.enabled = false;
    let model = read_model(&config);
    assert_eq!(model["tool_policy"]["enabled"], false);
    assert_eq!(model["tool_policy"]["deny"][0]["entry"], "delete_*");
}

/// R1i: colon-bearing names: deny `ab*` is partly overridden by allow
/// `a:b*` (they meet at server `abx`, tool `a:bx`).
#[test]
fn r1i_colon_bearing_names() {
    assert!(matches("ab*", "abx", "a:bx") && matches("a:b*", "abx", "a:bx"));
    assert!(matches("ab*", "ab", "x") && !matches("a:b*", "ab", "x"));
    let model = read_model(&tool_policy(&["a:b*"], &["ab*"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["partly_overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
}

/// R1j: allow `*` fully overrides every deny; deny `*` is partly overridden
/// by any narrower allow.
#[test]
fn r1j_the_star_entries() {
    let model = read_model(&tool_policy(&["*"], &["delete_*"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
    let model = read_model(&tool_policy(&["srv:read"], &["*"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["partly_overridden_by"],
        json!(["security.tool_policy.allow[0]"])
    );
}

/// R1k: two identical allows both appear, each with its own path.
#[test]
fn r1k_identical_allows_are_both_named() {
    let model = read_model(&tool_policy(&["delete_*", "delete_*"], &["delete_*"]));
    let deny = deny_at(&model, "security.tool_policy.deny[0]");
    assert_eq!(
        deny["overridden_by"],
        json!([
            "security.tool_policy.allow[0]",
            "security.tool_policy.allow[1]"
        ])
    );
}

/// E0: a config with no tool policy entries and no rules answers with the
/// defaults and empty lists.
#[test]
fn e0_an_empty_config_answers_with_the_defaults() {
    let model = read_model(&Config::default());
    assert_eq!(model["tool_policy"]["enabled"], true);
    assert_eq!(model["tool_policy"]["allow"], json!([]));
    assert_eq!(model["tool_policy"]["deny"], json!([]));
    #[cfg(feature = "firewall")]
    assert_eq!(
        model["finding_rules"],
        json!([]),
        "built, no rule configured"
    );
}

/// A build without the firewall answers `finding_rules: null`, told apart
/// from a built firewall with no rule (`[]`, E0).
#[cfg(not(feature = "firewall"))]
#[test]
fn e1_a_build_without_the_firewall_has_no_finding_rules_section() {
    let model = read_model(&Config::default());
    assert_eq!(model["finding_rules"], Value::Null);
    assert!(
        model["tool_policy"].is_object(),
        "the tool policy is still read"
    );
}
