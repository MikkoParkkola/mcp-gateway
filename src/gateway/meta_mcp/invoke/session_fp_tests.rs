// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F9-T7c: the projection A/B event keys on the session's fingerprint.

use serde_json::json;

use crate::gateway::session_id::log_capture::{assert_fingerprinted, capture_debug};

#[test]
fn the_projection_event_logs_the_session_by_fingerprint() {
    let id = "gw-ab000000-projected-session";
    let (captured, guard) = capture_debug();
    super::emit_projection_ab_event(
        Some(id),
        "srv",
        "tool",
        crate::projection::AbRecord {
            arm: "treatment",
            projected: true,
        },
        &json!({}),
    );
    drop(guard);
    assert_fingerprinted(&captured.text(), "projection A/B invocation", id);
}
