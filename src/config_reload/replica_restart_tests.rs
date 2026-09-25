// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.REPLICA.1: a restart-only edit that the replica check will refuse
//! is named in the reload outcome, as the network-bind refusal already is.

use super::{LiveConfig, ReloadOutcome, with_pending_restart};
use crate::config::Config;

fn outcome() -> ReloadOutcome {
    ReloadOutcome {
        changes: "server.replicas".to_string(),
        restart_required: false,
        restart_reason: None,
        pending_restart_fields: Vec::new(),
    }
}

#[test]
fn a_restart_into_a_replica_refusal_is_named_in_the_outcome() {
    let running = Config::default();
    let mut wanted = Config::default();
    wanted.server.replicas = 2;
    wanted.key_server.enabled = true;
    let live = LiveConfig::new(running);
    live.set(wanted);
    let warned = with_pending_restart(outcome(), &live, Vec::new());
    assert!(warned.restart_required, "{}", warned.changes);
    assert!(
        warned.changes.contains("a restart would not start")
            && warned.changes.contains("InMemoryTokenStore"),
        "the restart advice must name the replica refusal: {}",
        warned.changes
    );
}

/// Positive control: the same edit at one replica restarts cleanly and warns
/// nothing.
#[test]
fn a_restart_at_one_replica_is_not_warned() {
    let mut wanted = Config::default();
    wanted.key_server.enabled = true;
    let live = LiveConfig::new(Config::default());
    live.set(wanted);
    let quiet = with_pending_restart(outcome(), &live, Vec::new());
    assert!(quiet.restart_required, "{}", quiet.changes);
    assert!(
        !quiet.changes.contains("would not start"),
        "{}",
        quiet.changes
    );
}
