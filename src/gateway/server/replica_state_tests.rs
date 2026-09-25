// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.REPLICA.1 — state held in one process's memory refuses more than one
//! declared replica.
//!
//! Three holders, three reasons: key-server tokens (`InMemoryTokenStore`),
//! managed accounts (`single_process` custody) and task records (the per-pod
//! task store, reachable only on the modern protocol). Each test asserts its own
//! reason AND the absence of the other two, so dropping one disjunct reddens
//! exactly one test.

use super::support::replica_state_refusal;
use crate::config::Config;
use crate::config_reload::LiveConfig;

const KEY_SERVER: &str = "InMemoryTokenStore";
const ACCOUNTS: &str = "single_process";
const TASKS: &str = "task store";

/// A structurally valid, enabled `accounts` block. Nothing here resolves it:
/// the refusal reads `enabled`, never the keys.
const ACCOUNTS_BLOCK: &str = "schema_version: accounts.v1
enabled: true
deployment: single_process
instance_id: replica-test
store_dir: /nonexistent/records
authority_dir: /nonexistent/authority
current_key_id: current
keys:
  current: env:REPLICA_TEST_KEY
";

fn config(replicas: u32, key_server: bool, accounts: bool, modern: bool) -> Config {
    let mut c = Config::default();
    c.server.replicas = replicas;
    c.server.modern_protocol = modern;
    c.key_server.enabled = key_server;
    if accounts {
        c.accounts = Some(serde_yaml::from_str(ACCOUNTS_BLOCK).expect("accounts fixture"));
    }
    c
}

fn refused(c: &Config) -> String {
    replica_state_refusal(c).expect("this configuration must be refused")
}

#[test]
fn key_server_with_two_replicas_refused() {
    let reason = refused(&config(2, true, false, false));
    assert!(reason.contains(KEY_SERVER), "{reason}");
    assert!(reason.contains("replicas: 1"), "{reason}");
    assert!(!reason.contains(ACCOUNTS), "{reason}");
    assert!(!reason.contains(TASKS), "{reason}");
}

#[test]
fn accounts_with_two_replicas_refused() {
    let reason = refused(&config(2, false, true, false));
    assert!(reason.contains(ACCOUNTS), "{reason}");
    assert!(reason.contains("replicas: 1"), "{reason}");
    assert!(!reason.contains(KEY_SERVER), "{reason}");
    assert!(!reason.contains(TASKS), "{reason}");
}

/// F7: the task surface is on whenever the modern protocol is, which is the
/// 4.0.0 default, so a stock config declaring two replicas is refused.
#[test]
fn tasks_with_two_replicas_refused() {
    let reason = refused(&config(
        2,
        false,
        false,
        Config::default().server.modern_protocol,
    ));
    assert!(reason.contains(TASKS), "{reason}");
    assert!(reason.contains("modern_protocol: false"), "{reason}");
    assert!(!reason.contains(KEY_SERVER), "{reason}");
    assert!(!reason.contains(ACCOUNTS), "{reason}");
}

#[test]
fn every_applying_reason_is_reported() {
    let reason = refused(&config(2, true, true, true));
    for expected in [KEY_SERVER, ACCOUNTS, TASKS] {
        assert!(reason.contains(expected), "missing {expected}: {reason}");
    }
}

/// Positive control: one replica holds every feature.
#[test]
fn one_replica_with_key_server_allowed() {
    assert_eq!(replica_state_refusal(&config(1, true, true, true)), None);
}

/// Positive control: many replicas with no per-process state.
#[test]
fn many_replicas_without_state_allowed() {
    assert_eq!(replica_state_refusal(&config(5, false, false, false)), None);
}

/// Positive control: an `accounts` block that is present but disabled holds
/// no custody.
#[test]
fn disabled_accounts_with_two_replicas_allowed() {
    let mut c = config(2, false, true, false);
    if let Some(accounts) = c.accounts.as_mut() {
        accounts.enabled = false;
    }
    assert_eq!(replica_state_refusal(&c), None);
}

#[test]
fn default_replicas_is_one() {
    assert_eq!(Config::default().server.replicas, 1);
    assert_eq!(replica_state_refusal(&Config::default()), None);
}

/// A reload cannot switch any of the three on under a running process: each
/// lives in a restart-scoped section, so the edit is reported as pending and
/// the startup check sees it on the next start.
#[test]
fn reload_cannot_enable_key_server_live() {
    let running = config(2, false, false, false);
    for (section, wanted) in [
        ("key_server", config(2, true, false, false)),
        ("accounts", config(2, false, true, false)),
        ("server", config(2, false, false, true)),
    ] {
        let live = LiveConfig::new(running.clone());
        live.set(wanted);
        let pending = live.pending_restart_fields();
        assert!(
            pending.contains(&section),
            "enabling {section} must wait for a restart: {pending:?}"
        );
    }
}
