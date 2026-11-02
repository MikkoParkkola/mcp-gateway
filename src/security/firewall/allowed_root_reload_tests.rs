// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Folder rules reload with every other rule. A reload publishes a generation
//! whose firewall policy is `FirewallPolicy::compile` of its config, and both
//! firewall entry points judge a call under the policy they are handed, never
//! the one the firewall was built with. So a reload that adds an
//! `allowed_roots` rule applies on the next call, and one that removes it
//! stops applying.

use serde_json::json;

use super::super::*;
use super::tree::{Fx, Seen, root_rule, seen, target};
use crate::security::firewall::{FirewallConfig, FirewallPolicy, FirewallRule, ScanSubject};

/// The policy a reload to `rules` publishes.
fn reloaded(rules: Vec<FirewallRule>) -> FirewallPolicy {
    FirewallPolicy::compile(&FirewallConfig {
        rules,
        ..FirewallConfig::default()
    })
}

/// A read of a file outside `safe/`, judged under `policy` at admission and
/// at the dispatch rescan; both entry points must agree.
fn judged(fx: &Fx, policy: &FirewallPolicy) -> Seen {
    let sender = fx.sender();
    let args = json!({"path": fx.path("outside/f")});
    let admitted = fx.fw.check_request_keyed(
        policy,
        "s1",
        target("read_file"),
        &args,
        "caller",
        "id-1",
        sender.as_deref(),
    );
    let rescanned = fx.fw.rescan(
        policy,
        target("read_file"),
        &args,
        ScanSubject::Arguments,
        sender.as_deref(),
    );
    let (a, r) = (seen(&admitted), seen(&rescanned));
    assert_eq!(a, r, "admission and rescan disagree");
    a
}

#[test]
fn a_reload_that_adds_a_folder_rule_applies_on_the_next_call() {
    let fx = Fx::with_rules(|_| Vec::new());
    assert_eq!(
        judged(&fx, fx.fw.startup_policy()),
        Seen::Allowed,
        "control: the firewall was built with no folder rule"
    );
    let rule = root_rule(
        "read_file",
        &[fx.path("safe")],
        &["path"],
        FirewallAction::Block,
    );
    assert_eq!(
        judged(&fx, &reloaded(vec![rule])),
        Seen::Outside(FirewallAction::Block),
        "the reloaded folder rule did not apply"
    );
}

#[test]
fn a_reload_that_removes_a_folder_rule_stops_applying() {
    let fx = Fx::new(&["path"], FirewallAction::Block);
    assert_eq!(
        judged(&fx, fx.fw.startup_policy()),
        Seen::Outside(FirewallAction::Block),
        "control: the firewall was built with the folder rule"
    );
    assert_eq!(
        judged(&fx, &reloaded(Vec::new())),
        Seen::Allowed,
        "a folder rule a reload removed still applied"
    );
}
