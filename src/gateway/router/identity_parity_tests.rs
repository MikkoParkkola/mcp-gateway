// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7512 route-parity row for provable agent identity.
//!
//! Its own file because `router/tests.rs` is already over the 800-line
//! ceiling and the gate ratchets: a file that big may shrink, never grow.
//! The shared fixtures stay in `tests.rs`, where the rows that also use
//! them live.

use axum::http::StatusCode;
use tower::ServiceExt;

use super::create_router;
use super::tests::{direct_route_call, direct_route_state_with_identity};

#[tokio::test]
async fn direct_route_refuses_a_declared_label_that_names_an_allowlisted_agent() {
    // Anchor: funded change 3. `known_agents` admits proven principals only, so
    // a caller that merely sets the header cannot satisfy it — on this route as
    // much as on /mcp. Before the split this request was admitted with 200.
    let (state, _store) = direct_route_state_with_identity(crate::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        known_agents: vec![crate::security::KnownAgent {
            source: crate::security::AgentSourceKey::Mtls,
            id: "known-agent".to_string(),
        }],
        ..Default::default()
    })
    .await;
    let response = create_router(state)
        .oneshot(direct_route_call(Some("known-agent")))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a self-declared label satisfied the allowlist on the direct route"
    );
}
