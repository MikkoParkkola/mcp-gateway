// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A server whose runtime plan needs a confirmation never starts, because a
//! live start refuses such a plan and nothing can grant one. Its state says
//! so: Refused, naming the settings in plain words, with no retry promised.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::tests::fresh;
use super::{ServerState, StateInputs, StateView, decide};
use crate::failsafe::CircuitState;
use crate::runtime::RuntimeDenyReason;

/// A fixed instant, so no answer depends on the clock.
fn at() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(2_000_000_000)
}

/// The fixture backend, holding the given confirmation ids.
fn held(ids: &[&str]) -> StateInputs {
    StateInputs {
        confirmations: ids.iter().map(|id| (*id).to_owned()).collect(),
        ..fresh()
    }
}

/// The answer a held server must give, with `settings` as the reason names them.
fn refused(settings: &str) -> StateView {
    StateView {
        state: ServerState::Refused,
        reason: format!(
            "Its runtime settings ask for {settings}; it will not start until those settings change."
        ),
        next_retry_at: None,
    }
}

#[test]
fn each_confirmation_is_named_in_plain_words() {
    for (id, words) in [
        ("filesystem.host_mount", "a host mount"),
        ("network.full_egress", "full network access"),
        ("runtime.privileged", "privileged mode"),
        ("environment.guarded_names", "guarded environment names"),
    ] {
        assert_eq!(decide(&held(&[id]), at()), refused(words), "{id}");
    }
}

#[test]
fn two_confirmations_are_both_named() {
    // Not in sorted order, so a sort in place of first-seen order fails here.
    let inputs = held(&["network.full_egress", "filesystem.host_mount"]);
    assert_eq!(
        decide(&inputs, at()),
        refused("full network access and a host mount")
    );
}

/// Three or more settings: commas, then "and" before the last, in the order
/// first seen, with a later repeat dropped wherever it falls.
#[test]
fn several_confirmations_keep_first_seen_order_and_drop_a_later_repeat() {
    let inputs = held(&[
        "runtime.privileged",
        "environment.guarded_names",
        "runtime.privileged",
        "filesystem.host_mount",
    ]);
    assert_eq!(
        decide(&inputs, at()),
        refused("privileged mode, guarded environment names and a host mount")
    );
}

#[test]
fn a_repeated_confirmation_is_named_once() {
    let inputs = held(&["filesystem.host_mount", "filesystem.host_mount"]);
    assert_eq!(decide(&inputs, at()), refused("a host mount"));
}

#[test]
fn a_confirmation_outside_the_known_four_is_shown_as_its_id() {
    let inputs = held(&["runtime.other_gate"]);
    assert_eq!(decide(&inputs, at()), refused("runtime.other_gate"));
}

#[test]
fn the_held_reason_wins_over_a_failed_start() {
    let inputs = StateInputs {
        start_failed: true,
        ..held(&["network.full_egress"])
    };
    assert_eq!(decide(&inputs, at()), refused("full network access"));
}

#[test]
fn the_held_reason_wins_over_a_sign_in_wait() {
    let inputs = StateInputs {
        auth_wait: true,
        ..held(&["runtime.privileged"])
    };
    assert_eq!(decide(&inputs, at()), refused("privileged mode"));
}

/// Every branch below the held check that would promise a retry: an open
/// breaker, a half-open one, and an unhealthy server that is still running.
#[test]
fn the_held_reason_wins_over_every_retrying_signal() {
    let signals = [
        StateInputs {
            breaker: CircuitState::Open,
            retry_after: Duration::from_secs(30),
            healthy: false,
            consecutive_failures: 4,
            ..held(&["network.full_egress"])
        },
        StateInputs {
            breaker: CircuitState::HalfOpen,
            ..held(&["network.full_egress"])
        },
        StateInputs {
            healthy: false,
            running: true,
            consecutive_failures: 2,
            ..held(&["network.full_egress"])
        },
    ];
    for inputs in signals {
        assert_eq!(decide(&inputs, at()), refused("full network access"));
    }
}

/// Already true before the change; kept so the held check stays below it.
#[test]
fn a_policy_denial_still_wins_over_a_confirmation() {
    let inputs = StateInputs {
        denied: true,
        denial_reasons: vec![RuntimeDenyReason::ForbiddenMount],
        ..held(&["filesystem.host_mount"])
    };
    let view = decide(&inputs, at());
    assert_eq!(view.state, ServerState::Refused);
    assert!(
        view.reason.starts_with("Refused by the runtime policy"),
        "{}",
        view.reason
    );
}

/// Already true before the change; kept so nothing else moves.
#[test]
fn no_confirmation_leaves_the_answer_as_it_was() {
    assert_eq!(decide(&held(&[]), at()).state, ServerState::Dormant);
}

/// The ids reach the state through a real backend built from a planned
/// profile, not only through hand-made inputs.
#[cfg(feature = "webui")]
#[tokio::test]
async fn a_backend_whose_plan_needs_full_network_reads_refused() {
    use crate::backend::Backend;
    use crate::config::{BackendConfig, FailsafeConfig};
    use crate::runtime::{
        RuntimeAvailability, RuntimeIntent, RuntimeNetworkEgress, RuntimePlanner,
    };

    let mut intent = RuntimeIntent::named("held");
    intent.image = Some("ghcr.io/example/held:1".to_owned());
    intent.requested_egress = RuntimeNetworkEgress::Full;
    let plan = RuntimePlanner::new(RuntimeAvailability::with_docker()).plan(&intent);
    let ids: Vec<&str> = plan.confirmations.iter().map(|c| c.id.as_str()).collect();
    assert!(
        ids == ["network.full_egress"] && !plan.is_denied(),
        "premise: {plan:?}"
    );
    let backend = Backend::new_with_runtime_plan(
        "held",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
        Some(plan),
    );
    assert_eq!(backend.server_state(at()), refused("full network access"));
}
