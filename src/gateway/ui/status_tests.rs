// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The status row's wire values, beside the private type that serializes them.

use super::ServerStatus;

/// Every server `state` word the web shell's glossary keys on, as the status
/// row type serializes it (the struct `GET /ui/api/status` returns per server).
#[test]
fn every_server_state_serializes_to_the_word_the_shell_reads() {
    use crate::backend::server_state::ServerState;
    let row = |state| ServerStatus {
        name: "x".to_owned(),
        running: false,
        transport: "http".to_owned(),
        tools_cached: 0,
        request_count: 0,
        calls_24h: None,
        calls_prev_24h: None,
        circuit_state: "closed".to_owned(),
        circuit_trips: 0,
        current_failures: 0,
        healthy: true,
        success_count: 0,
        failure_count: 0,
        latency_p50_ms: None,
        latency_p95_ms: None,
        latency_p99_ms: None,
        state,
        reason: String::new(),
        next_retry_at: None,
        cleartext_credentials_accepted: false,
    };
    for (state, word) in [
        (ServerState::Running, "running"),
        (ServerState::Slow, "slow"),
        (ServerState::Paused, "paused"),
        (ServerState::Dormant, "dormant"),
        (ServerState::Unhealthy, "unhealthy"),
        (ServerState::Refused, "refused"),
        (ServerState::NeedsSignIn, "needs_sign_in"),
        (ServerState::Unmanaged, "unmanaged"),
    ] {
        let wire = serde_json::to_value(row(state)).expect("serializes");
        assert_eq!(wire["state"], word, "{wire}");
    }
}
