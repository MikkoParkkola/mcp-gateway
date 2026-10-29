// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A firewall rule's `match` glob that does not parse.
//!
//! It used to be replaced by `*` without a word, so a typo in an `allow` rule
//! allowed every tool: the firewall failed open on a spelling mistake.

use super::*;
use serde_json::json;

/// An unclosed `[` is not a glob the `glob` crate accepts.
const BAD_GLOB: &str = "exec_[";

fn allow_rule(tool_match: &str) -> FirewallRule {
    FirewallRule {
        tool_match: tool_match.to_string(),
        action: FirewallAction::Allow,
        reason: None,
        scan: vec![],
        servers: None,
        keys: None,
        except: None,
    }
}

/// The load refuses the rule and names where it is, never the pattern
/// itself: a rule's text is the operator's to read in their own file.
#[test]
fn an_invalid_rule_glob_is_refused_at_load_naming_its_path() {
    let cfg = FirewallConfig {
        rules: vec![allow_rule("read_*"), allow_rule(BAD_GLOB)],
        ..FirewallConfig::default()
    };
    let err = cfg.validate().expect_err("an invalid glob must not load");
    assert!(
        err.contains("security.firewall.rules[1].match"),
        "the error names the rule's path: {err}"
    );
    assert!(
        !err.contains(BAD_GLOB),
        "the error echoes the pattern: {err}"
    );
}

/// A disabled firewall runs no rules, so its rules cannot fail open and
/// load as before.
#[test]
fn a_disabled_firewall_still_loads_an_invalid_rule_glob() {
    let cfg = FirewallConfig {
        enabled: false,
        rules: vec![allow_rule(BAD_GLOB)],
        ..FirewallConfig::default()
    };
    assert!(cfg.validate().is_ok());
}

/// Even when the load is skipped, an `allow` rule with a broken glob must
/// not allow a tool it was never meant to name.
#[test]
fn an_invalid_allow_glob_does_not_allow_an_unrelated_tool() {
    let cfg = FirewallConfig {
        rules: vec![allow_rule(BAD_GLOB)],
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, None);
    let args = json!({ "cmd": "; rm -rf /" });
    let verdict = fw.check_request("s1", "srv", "shell_run", &args, "caller", "s1");
    assert!(
        !verdict.allowed,
        "a broken allow glob let a shell injection through: {verdict:?}"
    );
}

/// A `block` rule with a broken glob is refused the same way: its fallback
/// would block every tool, so the load refusal names the broken key.
#[test]
fn an_invalid_block_glob_is_refused_at_load() {
    let cfg = FirewallConfig {
        rules: vec![FirewallRule {
            action: FirewallAction::Block,
            ..allow_rule(BAD_GLOB)
        }],
        ..FirewallConfig::default()
    };
    let err = cfg.validate().expect_err("an invalid glob must not load");
    assert!(err.contains("security.firewall.rules[0].match"), "{err}");
}

/// Through `Config::load`, the path start-up and hot reload share.
#[test]
fn gateway_yaml_with_an_invalid_rule_glob_does_not_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let yaml = format!(
        "security:\n  firewall:\n    enabled: true\n    rules:\n      - match: \"{BAD_GLOB}\"\n        action: allow\n"
    );
    crate::gateway::test_helpers::write_owner_only(&path, yaml).expect("write config");
    let err = crate::config::Config::load(Some(&path))
        .expect_err("an invalid glob must not load")
        .to_string();
    assert!(err.contains("security.firewall.rules[0].match"), "{err}");
}

/// A rule whose glob does not parse, reaching the firewall without the load,
/// fails closed: it blocks on every tool, whatever its action. Matching no
/// tool would leave a `block` rule blocking nothing.
#[test]
fn an_invalid_glob_compiles_to_a_block_on_every_tool() {
    for action in [
        FirewallAction::Allow,
        FirewallAction::Warn,
        FirewallAction::Block,
    ] {
        let rule = compile_rule(&FirewallRule {
            action,
            ..allow_rule("exec_*[")
        });
        assert_eq!(rule.action, FirewallAction::Block, "{action:?}");
        for tool in ["exec_*[", "exec_run", "exec_", "anything"] {
            assert!(rule_matches(&rule, tool), "{action:?} missed {tool}");
        }
    }
}

/// A broken `block` glob ahead of an `allow` still blocks the call.
#[test]
fn an_invalid_block_glob_still_blocks_without_the_load() {
    let cfg = FirewallConfig {
        rules: vec![
            FirewallRule {
                action: FirewallAction::Block,
                ..allow_rule(BAD_GLOB)
            },
            allow_rule("*"),
        ],
        ..FirewallConfig::default()
    };
    let fw = Firewall::from_config(cfg, None);
    let args = json!({ "cmd": "; rm -rf /" });
    let verdict = fw.check_request("s1", "srv", "shell_run", &args, "caller", "s1");
    assert!(
        !verdict.allowed,
        "a broken block glob let it through: {verdict:?}"
    );
}
