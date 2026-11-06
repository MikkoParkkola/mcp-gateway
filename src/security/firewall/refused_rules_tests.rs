// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rules the firewall-on load refuses: one definition, read by the load, the
//! compiler and the warning a firewall-off load gives.

use super::{RuleKeys, first_refusal};
use crate::config::Config;
use crate::security::firewall::FirewallRule;
use crate::security::firewall::verdict::refused_shape;

fn rule(yaml: &str) -> FirewallRule {
    crate::yaml::from_str(yaml).expect("the rule parses")
}

/// Each shape the load refuses, the message it gives, and whether it
/// compiles fail-closed (`refused_shape`). Messages are the base's, verbatim.
#[test]
fn every_refused_shape_has_one_message_and_one_compiled_form() {
    let configured = RuleKeys::Configured(vec!["k"]);
    let cases: &[(&str, &str, bool)] = &[
        (
            "{match: \"t[\", action: block}",
            "security.firewall.rules[3].match is not a valid glob",
            true,
        ),
        (
            "{match: \"*\", action: block, servers: []}",
            "security.firewall.rules[3].servers must not be empty; leave it out to apply to all",
            true,
        ),
        (
            "{match: \"*\", action: block, keys: []}",
            "security.firewall.rules[3].keys must not be empty; leave it out to apply to all",
            true,
        ),
        (
            "{match: \"*\", action: block, except: []}",
            "security.firewall.rules[3].except must not be empty; leave it out to apply to all",
            true,
        ),
        (
            "{match: \"*\", action: block, servers: [\"s[\"]}",
            "security.firewall.rules[3].servers[0] is not a valid glob",
            true,
        ),
        (
            "{match: \"*\", action: block, except: [{}]}",
            "security.firewall.rules[3].except[0] sets no field",
            true,
        ),
        (
            "{match: \"*\", action: block, except: [{tool: \"t[\"}]}",
            "security.firewall.rules[3].except[0].tool is not a valid glob",
            true,
        ),
        (
            "{match: \"*\", action: block, keys: [nobody]}",
            "security.firewall.rules[3].keys[0] names no configured API key",
            false,
        ),
        (
            "{match: \"*\", action: block, except: [{key: nobody}]}",
            "security.firewall.rules[3].except[0].key names no configured API key",
            false,
        ),
    ];
    for (yaml, message, block_all) in cases {
        let r = rule(yaml);
        assert_eq!(
            first_refusal(3, &r, &configured).as_deref(),
            Some(*message),
            "{yaml}"
        );
        assert_eq!(refused_shape(&r), *block_all, "{yaml}");
    }
    assert_eq!(
        first_refusal(
            3,
            &rule("{match: \"*\", action: block, keys: [k]}"),
            &configured
        ),
        None
    );
}

/// With authentication off, any key reference is refused, with the base's
/// message.
#[test]
fn a_key_reference_needs_api_key_authentication() {
    let r = rule("{match: \"*\", action: block, keys: [k]}");
    assert_eq!(
        first_refusal(0, &r, &RuleKeys::AuthOff).as_deref(),
        Some(
            "security.firewall.rules[0].keys[0] needs API-key authentication (auth.enabled with auth.api_keys)"
        )
    );
}

/// Two problems in one rule: the message is the first in the load's order
/// (keys first), and the compiled form follows the glob and scope checks.
#[test]
fn two_problems_report_the_first_and_compile_by_the_scope() {
    let keys = RuleKeys::Configured(vec!["k"]);
    let both = rule("{match: \"*\", action: block, keys: [nobody], except: []}");
    assert_eq!(
        first_refusal(0, &both, &keys).as_deref(),
        Some("security.firewall.rules[0].keys[0] names no configured API key")
    );
    assert!(
        refused_shape(&both),
        "the empty except still compiles fail-closed"
    );
    let folder = rule(
        "{match: \"*\", action: allow, keys: [nobody], allowed_roots: [\"/srv\"], path_args: [\"path\"]}",
    );
    assert!(
        first_refusal(0, &folder, &keys).is_some_and(|m| m.contains("names no configured API key"))
    );
    assert!(
        !refused_shape(&folder),
        "a folder or key problem compiles as written"
    );
    // A folder problem alone reaches the folder check, last in the order.
    let roots_only = rule("{match: \"*\", action: block, allowed_roots: [\"/srv\"]}");
    assert_eq!(
        first_refusal(0, &roots_only, &keys).as_deref(),
        Some("security.firewall.rules[0].path_args is required with allowed_roots")
    );
    assert!(
        !refused_shape(&roots_only),
        "a folder problem compiles as written"
    );
}

/// A load with the firewall off takes a refused rule and warns once, naming
/// it; a second load of the same file stays quiet; a valid rule never warns.
#[test]
fn a_firewall_off_load_takes_a_refused_rule_and_warns_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let reason = format!("row-{}", std::process::id());
    crate::gateway::test_helpers::write_owner_only(
        &path,
        format!(
            "security:\n  firewall:\n    enabled: false\n    rules:\n      - {{match: \"*\", action: warn, reason: {reason}, except: [{{}}]}}\n      - {{match: \"ok\", action: warn}}\n"
        ),
    )
    .expect("write config");
    let (loads, warnings) = crate::test_log_capture::capture_warnings(|| {
        (
            Config::load(Some(&path)).is_ok(),
            Config::load(Some(&path)).is_ok(),
        )
    });
    assert_eq!(loads, (true, true), "a firewall-off load takes the rule");
    assert_eq!(
        warnings
            .matches("security.firewall.rules[0].except[0] sets no field")
            .count(),
        1,
        "one warning for two loads: {warnings}"
    );
    assert!(
        warnings.contains("turning the firewall on is refused"),
        "{warnings}"
    );
    assert!(
        !warnings.contains("security.firewall.rules[1]"),
        "the valid rule is quiet: {warnings}"
    );
}
