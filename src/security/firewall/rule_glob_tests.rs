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
