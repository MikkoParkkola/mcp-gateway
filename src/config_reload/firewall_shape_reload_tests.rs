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

const KEY_K: &str = "auth:\n  enabled: true\n  api_keys:\n    - name: k\n      key_sha256: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"\n";

/// A started gateway from `startup`: its file, live config and env.
fn started(
    startup: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<LiveConfig>,
    LiveEnv,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, startup).expect("write config");
    let started = Config::load_evaluated(Some(&path)).expect("startup loads");
    let live = Arc::new(LiveConfig::new(started.config.clone()));
    let env = LiveEnv::new(started.overlay, started.env_paths);
    (dir, path, live, env)
}

/// An earlier reload published `auth.enabled: true` with a key; the process
/// still runs without API-key authentication, so a later reload adding a
/// rule scoped to that key is refused: the check reads what runs, not what
/// was published.
#[test]
fn a_published_auth_switch_does_not_let_a_keyed_rule_in_before_a_restart() {
    let (_dir, path, live, env) = started(&firewall(true, VALID));
    write_owner_only(&path, format!("{KEY_K}{}", firewall(true, VALID))).expect("write");
    let first = load_config_patch(&path, &live, &env).expect("a reload turning auth on is taken");
    live.set(first.config);
    assert!(
        live.get().auth.enabled,
        "the published config says auth is on"
    );
    write_owner_only(
        &path,
        format!(
            "{KEY_K}{}",
            firewall(
                true,
                "{match: \"*\", scan: [credentials], action: block, keys: [k]}"
            )
        ),
    )
    .expect("write");
    let refused = load_config_patch(&path, &live, &env)
        .map(|_| ())
        .expect_err("still refused before a restart");
    assert!(
        refused.contains("security.firewall.rules[0].keys[0]"),
        "{refused}"
    );
    assert!(
        refused.contains("restart the gateway so auth.enabled"),
        "{refused}"
    );
}

/// An exception's `key` is a key reference too: with API-key authentication
/// running, one naming no configured key is refused, naming the exception.
#[test]
fn an_exception_naming_no_configured_key_is_refused_while_the_firewall_runs() {
    let startup = format!("{KEY_K}{}", firewall(true, VALID));
    let reload = format!(
        "{KEY_K}{}",
        firewall(
            false,
            "{match: \"*\", scan: [credentials], action: block, except: [{key: nobody}]}"
        )
    );
    let (outcome, _live) = reload_after(&startup, &reload);
    let refused = outcome.expect_err("refused while the firewall runs");
    assert!(
        refused.contains("security.firewall.rules[0].except[0].key names no configured API key"),
        "{refused}"
    );
    assert!(
        refused.contains("security.firewall.enabled: false"),
        "{refused}"
    );
}

/// PUBSHAPE.5 guard: with the firewall off, a reload or a start that turns
/// it on with a refused rule present is refused by the load, naming the rule.
#[test]
fn turning_the_firewall_on_with_a_refused_rule_is_refused() {
    let dormant = "{match: \"*\", scan: [credentials], action: warn, except: [{}]}";
    let (outcome, _live) = reload_after(&firewall(false, dormant), &firewall(true, dormant));
    let refused = outcome.expect_err("a reload switching it on is refused");
    assert!(
        refused.contains("security.firewall.rules[0].except[0] sets no field"),
        "{refused}"
    );
    let (_dir, path, _live, _env) = started(&firewall(false, VALID));
    write_owner_only(&path, firewall(true, dormant)).expect("write");
    let start = Config::load(Some(&path)).expect_err("a start with it on is refused");
    assert!(
        format!("{start:#}").contains("security.firewall.rules[0].except[0] sets no field"),
        "{start:#}"
    );
}

/// A file edited by hand to hold a refused rule while the firewall runs: a
/// UI write and a whole-config write that carry it are refused before
/// writing, since the reload after them would refuse it; the file stays.
#[tokio::test]
async fn a_write_carrying_a_refused_rule_is_refused_while_the_firewall_runs() {
    let (_dir, path, live, _env) = started(&firewall(true, VALID));
    let ctx = super::ReloadContext::new(
        path.clone(),
        Arc::clone(&live),
        Arc::new(crate::backend::BackendRegistry::new()),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    write_owner_only(
        &path,
        firewall(
            false,
            "{match: \"*\", scan: [credentials], action: warn, except: [{}]}",
        ),
    )
    .expect("hand edit");
    let before = std::fs::read(&path).expect("read");

    let mutated = ctx
        .mutate_and_reload_outcome(&path, |config: &mut Config| {
            config.server.port = 39993;
            Ok::<(), ()>(())
        })
        .await;
    let Err(refused) = mutated else {
        panic!("the UI write is refused");
    };
    assert!(
        refused.to_string().contains("except[0] sets no field"),
        "{refused}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "the UI write wrote nothing"
    );

    let mut whole = Config::load_literal_with_text(&path).expect("loads").0;
    whole.server.port = 39994;
    let refused = ctx
        .write_and_reload_outcome(&path, &whole)
        .await
        .expect_err("the whole-config write is refused");
    assert!(
        refused.to_string().contains("except[0] sets no field"),
        "{refused}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "the whole write wrote nothing"
    );
}

const OFF_VALID: &str = "security:\n  firewall:\n    enabled: false\n    rules:\n      - {match: \"foo\", scan: [credentials], action: warn}\n";
const OFF_DORMANT: &str = "security:\n  firewall:\n    enabled: false\n    rules:\n      - {match: \"foo\", scan: [credentials], action: warn, except: [{}]}\n";
const OFF_DORMANT_PORT: &str = "server:\n  port: 39995\nsecurity:\n  firewall:\n    enabled: false\n    rules:\n      - {match: \"foo\", scan: [credentials], action: warn, except: [{}]}\n";

/// A replace of `start` after a hand edit to `edited` (never reloaded), with
/// `OFF_DORMANT_PORT`.
async fn replace_after_edit(start: &str, edited: &str) -> (Result<(), String>, String) {
    use super::reload_context::replace::{Expected, Replaced, replace_detached};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, start).expect("write");
    let ctx = super::replace_test_support::context(&path);
    write_owner_only(&path, edited).expect("hand edit");
    let outcome = replace_detached(
        ctx,
        super::replace_test_support::to(Expected::Any, OFF_DORMANT_PORT, Replaced::Discard),
        super::replace_test_support::WAIT,
    )
    .await
    .map(|_| ())
    .map_err(|e| format!("{e:?}"));
    (outcome, std::fs::read_to_string(&path).expect("read"))
}

/// A replace judges which refused rules it carries against the bytes it
/// replaces, not the published config: a rule hand-edited in and never
/// reloaded is carried by a replace that keeps it.
#[tokio::test]
async fn a_replace_carries_a_refused_rule_the_replaced_bytes_hold() {
    let (outcome, after) = replace_after_edit(OFF_VALID, OFF_DORMANT).await;
    outcome.expect("the refused rule on disk is carried");
    assert_eq!(after, OFF_DORMANT_PORT);
}

/// The other side: a refused rule the published config holds but the bytes
/// on disk no longer do is not carried; a replace putting it back adds it.
#[tokio::test]
async fn a_replace_cannot_restore_a_refused_rule_dropped_on_disk() {
    let (outcome, after) = replace_after_edit(OFF_DORMANT, OFF_VALID).await;
    let refused = outcome.expect_err("the rule is added again");
    assert!(refused.contains("except[0] sets no field"), "{refused}");
    assert_eq!(after, OFF_VALID, "nothing written");
}

/// A gateway started with authentication on and only a bearer token can
/// reload its first API key, live; a rule naming that key in the same reload
/// is taken: whether authentication is on is the running process's, the
/// keys are the reload's.
#[test]
fn a_running_authenticated_gateway_takes_its_first_key_and_a_rule_naming_it() {
    let bearer =
        "auth:\n  enabled: true\n  bearer_token: \"zq-bearer-for-the-first-key-row-000000\"\n";
    let startup = format!("{bearer}{}", firewall(true, VALID));
    let reload = format!(
        "{bearer}  api_keys:\n    - name: k\n      key_sha256: \"sha256:{}\"\n{}",
        "1".repeat(64),
        firewall(
            true,
            "{match: \"*\", scan: [credentials], action: block, keys: [k]}"
        )
    );
    let (outcome, _live) = reload_after(&startup, &reload);
    outcome.expect("the first key and its rule reload together");
}

/// The fail-open stays closed: with authentication running and no API key,
/// a reload adding a rule scoped to a key it does not configure is refused,
/// naming the rule; the rule would apply to no caller.
#[test]
fn a_running_authenticated_gateway_refuses_a_keyed_rule_with_no_key() {
    let bearer =
        "auth:\n  enabled: true\n  bearer_token: \"zq-bearer-for-the-first-key-row-000000\"\n";
    let startup = format!("{bearer}{}", firewall(true, VALID));
    let reload = format!(
        "{bearer}{}",
        firewall(
            true,
            "{match: \"*\", scan: [credentials], action: block, keys: [k]}"
        )
    );
    let (outcome, live) = reload_after(&startup, &reload);
    let refused = outcome.expect_err("a key reference with no key is refused");
    assert!(
        refused.contains("security.firewall.rules[0].keys[0] needs API-key authentication"),
        "{refused}"
    );
    assert!(
        live.get().security.firewall.rules[0].keys.is_none(),
        "the running rules stay"
    );
}
