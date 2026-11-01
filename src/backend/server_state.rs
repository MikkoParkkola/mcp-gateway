// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The one-word state an operator reads for a backend, why it is in it, and
//! when it retries on its own.
//!
//! Decided from counts and flags the gateway owns. No error text from a
//! backend reaches `reason`: an upstream error can quote a URL or a token.

use std::time::{Duration, SystemTime};

use serde::Serialize;

use crate::failsafe::CircuitState;
use crate::runtime::RuntimeDenyReason;

/// What the operator sees for one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Connected and answering.
    Running,
    /// Running and answering, but its recent calls are far slower than its
    /// own usual: the recent p95 is over three times its baseline.
    Slow,
    /// The breaker is open: calls are held back and it retries by itself.
    Paused,
    /// Not running, and nothing is wrong: stopped while idle, or not started yet.
    Dormant,
    /// Failing while calls still go through, or its connection dropped.
    Unhealthy,
    /// The runtime policy refuses every start.
    Refused,
    /// Waiting on a person to sign in.
    NeedsSignIn,
    /// Found on this machine but not behind the gateway. Rows come from the
    /// discovery route; this read model never produces it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the value is part of the state vocabulary now; the discovery route constructs it"
        )
    )]
    Unmanaged,
}

/// The signals [`decide`] reads. Flags and counts only.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one independent fact read once from the slot; no two encode a state"
)]
#[derive(Debug, Clone)]
pub(crate) struct StateInputs {
    /// The runtime plan is denied; `denial_reasons` says why.
    pub denied: bool,
    pub denial_reasons: Vec<RuntimeDenyReason>,
    /// The last dispatch or fill on the shared slot waited on a sign-in, and
    /// nothing has succeeded since.
    pub auth_wait: bool,
    pub breaker: CircuitState,
    /// Time until the open breaker admits a probe.
    pub retry_after: Duration,
    pub healthy: bool,
    pub consecutive_failures: u64,
    pub running: bool,
    /// Stopped by the idle reaper.
    pub reaped: bool,
    /// The shared slot has been connected at least once.
    pub ever_started: bool,
    /// The last start failed (not on a sign-in), and none has succeeded since.
    pub start_failed: bool,
    /// Its recent p95 and its usual (baseline) p95 in ms, when the recent
    /// one is far over the usual; `None` while the baseline is still warming.
    pub slow: Option<crate::failsafe::Slow>,
}

/// [`decide`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateView {
    pub state: ServerState,
    pub reason: String,
    pub next_retry_at: Option<SystemTime>,
}

/// First match wins, worst first, so a real failure is never shown as a
/// gentler state.
pub(crate) fn decide(inputs: &StateInputs, now: SystemTime) -> StateView {
    let view = |state, reason: String, next_retry_at| StateView {
        state,
        reason,
        next_retry_at,
    };
    if inputs.denied {
        let codes: Vec<String> = inputs
            .denial_reasons
            .iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        return view(
            ServerState::Refused,
            format!("Refused by the runtime policy: {}.", codes.join(", ")),
            None,
        );
    }
    if inputs.auth_wait {
        return view(
            ServerState::NeedsSignIn,
            "Waiting for someone to sign in to this server.".to_owned(),
            None,
        );
    }
    match inputs.breaker {
        CircuitState::Open => {
            return view(
                ServerState::Paused,
                format!(
                    "{} failures in a row; calls are held back and it retries on its own.",
                    inputs.consecutive_failures
                ),
                Some(now + inputs.retry_after),
            );
        }
        CircuitState::HalfOpen => {
            return view(
                ServerState::Paused,
                "Trying again now after failing.".to_owned(),
                Some(now),
            );
        }
        CircuitState::Closed => {}
    }
    if !inputs.healthy {
        let reason = if inputs.running {
            format!(
                "{} recent failures; calls still go through.",
                inputs.consecutive_failures
            )
        } else {
            format!(
                "{} recent failures; the next call tries to start it again.",
                inputs.consecutive_failures
            )
        };
        return view(ServerState::Unhealthy, reason, None);
    }
    // A connected transport serves even when a rebuild beside it failed:
    // the failed start only matters once nothing is connected.
    if inputs.running {
        if let Some(slow) = inputs.slow {
            return view(
                ServerState::Slow,
                format!(
                    "Answering, but the p95 of its last 100 answered calls is {} ms, over three times its usual {} ms.",
                    slow.recent_ms, slow.usual_ms
                ),
                None,
            );
        }
        return view(ServerState::Running, "Running.".to_owned(), None);
    }
    if inputs.start_failed {
        return view(
            ServerState::Unhealthy,
            "Its last start failed; the next call tries again.".to_owned(),
            None,
        );
    }
    if inputs.reaped {
        return view(
            ServerState::Dormant,
            "Stopped while idle; it starts on the next call.".to_owned(),
            None,
        );
    }
    if inputs.ever_started {
        return view(
            ServerState::Unhealthy,
            "Its connection dropped; it restarts on the next call.".to_owned(),
            None,
        );
    }
    view(
        ServerState::Dormant,
        "Not started yet; it starts on the first call.".to_owned(),
        None,
    )
}

#[cfg(test)]
#[path = "server_state_tests.rs"]
mod tests;
