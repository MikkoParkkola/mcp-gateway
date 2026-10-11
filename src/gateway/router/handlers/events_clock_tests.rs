// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T8: a dashboard-session subscription on a clock
//! before 1970 has no lease end to store, so the call is refused. The handler
//! turns this `Err` into a `-32603` answer before a subscription row exists.

use super::*;
use crate::gateway::auth::AuthenticatedClient;

fn dashboard_client() -> AuthenticatedClient {
    AuthenticatedClient {
        name: "alice".to_owned(),
        rate_limit: 0,
        backends: vec!["*".to_owned()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        principal: crate::gateway::auth::principal_of("secret"),
        quota_principal: None,
        authenticated: true,
        credential_kind: CredentialKind::DashboardSession,
    }
}

/// MIK-8202 RECORDER (lease stamp) rule, P2 row 9. Mutant: lease at
/// 1970 plus the idle timeout (the credential is built).
#[tokio::test]
async fn t8_a_dashboard_subscription_on_an_unreadable_clock_is_refused_with_the_clock_error() {
    // GIVEN: a gateway and a dashboard session presenting a digest
    let (state, _dir) = crate::gateway::router::tests::test_router_app_state().await;
    let presented = Presented {
        facts: None,
        identity: None,
        session_sha256: Some("session-digest".to_owned()),
        bearer_sha256: None,
    };
    let caller = dashboard_client();
    // WHEN: the credential is taken on a clock before 1970
    let _clock = crate::clock::test_clock::before_epoch();
    let credential = presented.credential(Some(&caller), &state);
    // THEN: refused for the clock, so no lease and no row follow
    let why = credential
        .map(|c| c.expires_at)
        .expect_err("no lease end can be computed");
    assert!(why.to_lowercase().contains("clock"), "{why}");
}
