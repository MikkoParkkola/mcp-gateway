// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A generation compiles its rules with ids under the running record key:
//! the same rule keeps its id across a reload and a restart.

use std::sync::Arc;

use super::Generation;
use crate::config::Config;
use crate::gateway::auth::ResolvedAuthConfig;
use crate::gateway::record_principal::{TEST_RECORD_KEY, test_record_key};
use crate::security::rule_id::RuleId;

const OTHER_KEY: &str = "another-record-key-not-a-secret-fedcba9876543210";

fn config(deny: &[&str]) -> Config {
    let mut c = Config::default();
    c.security.tool_policy.enabled = true;
    c.security.tool_policy.use_default_deny = false;
    c.security.tool_policy.deny = deny.iter().map(|s| (*s).to_string()).collect();
    c
}

fn startup(c: Config, record_key: &str) -> Generation {
    let auth = Arc::new(ResolvedAuthConfig::from_config(&c.auth, record_key));
    Generation::prepare_startup(c, auth)
}

fn deny_id(pattern: &str) -> RuleId {
    let bytes = serde_json::to_vec(&("deny", pattern)).expect("serialises");
    RuleId::of("tool_policy", &test_record_key().rule_id_key(), &bytes)
}

/// The id that refused `tool` under `g`.
fn refused_by(g: &Generation, tool: &str) -> Option<RuleId> {
    g.tool_policy()
        .check_explained("s", tool)
        .expect_err("refused")
        .1
        .cloned()
}

#[test]
fn the_startup_generation_records_rule_ids() {
    let g = startup(config(&["x"]), TEST_RECORD_KEY);
    assert_eq!(refused_by(&g, "x"), Some(deny_id("x")));
}

#[test]
fn an_unchanged_rule_keeps_its_id_across_a_reload() {
    let first = startup(config(&["x", "z"]), TEST_RECORD_KEY);
    // An unrelated entry inserted before it, and the untouched ones reordered.
    let next = Generation::following(config(&["y", "z", "x"]), Arc::clone(first.auth()), &first);
    assert_eq!(refused_by(&next, "x"), Some(deny_id("x")));
    assert_eq!(refused_by(&next, "z"), Some(deny_id("z")));
}

#[test]
fn a_reconstructed_startup_with_the_same_key_gives_the_same_ids() {
    let a = startup(config(&["x"]), TEST_RECORD_KEY);
    let b = startup(config(&["x"]), TEST_RECORD_KEY);
    assert_eq!(refused_by(&a, "x"), refused_by(&b, "x"));
    assert_eq!(refused_by(&a, "x"), Some(deny_id("x")));
}

#[test]
fn a_new_record_key_changes_every_id() {
    let g = startup(config(&["x"]), OTHER_KEY);
    let named = refused_by(&g, "x").expect("named");
    assert_ne!(named, deny_id("x"));
    assert!(named.as_str().starts_with("tool_policy:"));
}

#[test]
fn a_reload_keeps_the_running_record_key() {
    let first = startup(config(&["x"]), TEST_RECORD_KEY);
    let running = config(&["x"]);
    let mut candidate = config(&["x"]);
    candidate.security.record_principal_key =
        Some(serde_json::from_value(serde_json::json!(OTHER_KEY)).expect("a key reference"));
    let next = Generation::prepare(
        candidate,
        &crate::config::EnvOverlay::none(),
        (&running, &first),
    )
    .expect("prepares");
    assert_eq!(refused_by(&next, "x"), Some(deny_id("x")));
}
