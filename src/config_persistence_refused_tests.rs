// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A write cannot add a firewall rule the firewall-on load refuses, whatever
//! `enabled` says: the rules apply on the next reload. A write that carries
//! such a rule over unchanged keeps it, and the text writers that carry a
//! whole file through (`init`, `upgrade`) keep it byte for byte and warn.

use std::path::PathBuf;

use super::{CommentLoss, edit_config, edit_config_text};
use crate::config::Config;
use crate::security::firewall::FirewallRule;

const DORMANT: &str = "{match: \"*\", action: warn, except: [{}]}";

fn config_file(rules: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let rules = rules
        .iter()
        .map(|r| format!("      - {r}\n"))
        .collect::<Vec<_>>()
        .concat();
    let text = format!(
        "server:\n  port: 39990\nsecurity:\n  firewall:\n    enabled: false\n    rules:\n{rules}"
    );
    crate::gateway::test_helpers::write_owner_only(&path, text).expect("write");
    (dir, path)
}

fn rule(yaml: &str) -> FirewallRule {
    crate::yaml::from_str(yaml).expect("the rule parses")
}

fn rules(path: &std::path::Path) -> Vec<FirewallRule> {
    Config::load_literal_with_text(path)
        .expect("loads")
        .0
        .security
        .firewall
        .rules
}

/// W1: a write adding an exception that sets no field is refused with the
/// firewall off in the file, naming the rule; the file is unchanged.
#[test]
fn a_write_adding_a_refused_rule_is_refused_with_the_firewall_off() {
    let (_dir, path) = config_file(&["{match: \"ok\", action: warn}"]);
    let before = std::fs::read(&path).expect("read");
    let refused = edit_config(&path, CommentLoss::Rewrite, |config| {
        config.security.firewall.rules.push(rule(DORMANT));
        Ok(())
    })
    .expect_err("an added refused rule is refused");
    assert!(
        refused.contains("security.firewall.rules[1].except[0] sets no field"),
        "{refused}"
    );
    assert!(refused.contains("fix or remove the rule"), "{refused}");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "nothing written"
    );
}

/// W2: a write that changes another key carries a refused rule already in
/// the file over unchanged.
#[test]
fn a_write_elsewhere_carries_a_refused_rule_over_unchanged() {
    let (_dir, path) = config_file(&[DORMANT]);
    edit_config(&path, CommentLoss::Rewrite, |config| {
        config.server.port = 39991;
        Ok(())
    })
    .expect("a carried rule does not stop the write");
    assert_eq!(rules(&path), vec![rule(DORMANT)]);
    assert_eq!(
        Config::load_literal_with_text(&path)
            .expect("loads")
            .0
            .server
            .port,
        39991
    );
}

/// W3: each refused rule in the file carries one copy: a write duplicating
/// it adds the second, which is refused; a write changing it is refused.
#[test]
fn a_second_copy_or_a_changed_refused_rule_is_added_and_refused() {
    let (_dir, path) = config_file(&[DORMANT]);
    let refused = edit_config(&path, CommentLoss::Rewrite, |config| {
        config.security.firewall.rules.push(rule(DORMANT));
        Ok(())
    })
    .expect_err("a second copy is added");
    assert!(
        refused.contains("security.firewall.rules[1].except[0] sets no field"),
        "{refused}"
    );
    let changed = edit_config(&path, CommentLoss::Rewrite, |config| {
        config.security.firewall.rules[0].action = crate::security::firewall::FirewallAction::Block;
        Ok(())
    })
    .expect_err("a changed refused rule is added");
    assert!(
        changed.contains("security.firewall.rules[0].except[0] sets no field"),
        "{changed}"
    );
    assert_eq!(rules(&path), vec![rule(DORMANT)], "the file is unchanged");
}

/// W4: `upgrade`'s text rewrite carries the file through: the refused rule
/// stays byte for byte, the write succeeds, and one warning names it.
#[test]
fn a_text_rewrite_keeps_a_refused_rule_and_warns_once() {
    let reason = format!("w4-{}", std::process::id());
    let dormant = format!("{{match: \"*\", action: warn, reason: {reason}, except: [{{}}]}}");
    let (_dir, path) = config_file(&[&dormant]);
    let ((), warnings) = crate::test_log_capture::capture_warnings(|| {
        edit_config_text(&path, |current| {
            Ok(current.map(|text| text.replace("port: 39990", "port: 39992")))
        })
        .expect("a carry-through write succeeds");
    });
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(
        text.contains(&format!("      - {dormant}\n")),
        "the rule is byte for byte: {text}"
    );
    assert!(text.contains("port: 39992"), "{text}");
    assert_eq!(
        warnings
            .matches("security.firewall.rules[0].except[0] sets no field")
            .count(),
        1,
        "{warnings}"
    );
}
