// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A reload cannot put a firewall rule the load refuses into the running
//! firewall. `security.firewall.enabled` and `auth.enabled` change only on a
//! restart, so a reload's new rules join the firewall that is running, with
//! the authentication that is running: the reload is judged against both.

use std::sync::Arc;

use super::{LiveConfig, load_config_patch};
use crate::config::{Config, LiveEnv};
use crate::gateway::test_helpers::write_owner_only;

/// A started gateway from `startup`, and a reload of `reload` against it.
fn reload_after(startup: &str, reload: &str) -> (Result<(), String>, Arc<LiveConfig>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, startup).expect("write config");
    let started = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(started.config.clone()));
    let env = LiveEnv::new(started.overlay, started.env_paths);
    write_owner_only(&path, reload).expect("rewrite config");
    let outcome = load_config_patch(&path, &live, &env).map(|_| ());
    (outcome, live)
}

fn firewall(enabled: bool, rule: &str) -> String {
    format!("security:\n  firewall:\n    enabled: {enabled}\n    rules:\n      - {rule}\n")
}

const VALID: &str = "{match: \"foo\", scan: [credentials], action: warn}";

/// Lead row: with the firewall running, a reload whose file says it is off
/// and carries an exception setting no field is refused, naming the rule,
/// and the running rules stay.
#[test]
fn a_reload_saying_off_cannot_add_a_refused_shape_while_the_firewall_runs() {
    let (outcome, live) = reload_after(
        &firewall(true, VALID),
        &firewall(
            false,
            "{match: \"foo\", scan: [credentials], action: warn, except: [{}]}",
        ),
    );
    let refused = outcome.expect_err("refused while the firewall runs");
    assert!(
        refused.contains("security.firewall.rules[0].except[0] sets no field"),
        "{refused}"
    );
    assert!(
        refused.contains("security.firewall.enabled"),
        "the remedy names the switch: {refused}"
    );
    assert!(
        live.get().security.firewall.rules[0].except.is_none(),
        "the running rules stay"
    );
}

/// Lead row: with auth off and the firewall running, a reload that turns
/// auth on and adds a rule scoped to an API key is refused: until a restart
/// no caller carries a key, so the rule would apply to no one.
#[test]
fn a_reload_turning_auth_on_cannot_add_a_keyed_rule_while_auth_is_off() {
    let digest = "0".repeat(64);
    let keyed = format!(
        "auth:\n  enabled: true\n  api_keys:\n    - name: k\n      key_sha256: \"sha256:{digest}\"\n{}",
        firewall(
            true,
            "{match: \"*\", scan: [credentials], action: block, keys: [k]}"
        )
    );
    let (outcome, live) = reload_after(&firewall(true, VALID), &keyed);
    let refused = outcome.expect_err("refused while the running process has auth off");
    assert!(
        refused.contains("security.firewall.rules[0].keys[0]"),
        "{refused}"
    );
    assert!(
        refused.contains("restart"),
        "the remedy names the restart: {refused}"
    );
    assert!(
        live.get().security.firewall.rules[0].keys.is_none(),
        "the running rules stay"
    );
}
