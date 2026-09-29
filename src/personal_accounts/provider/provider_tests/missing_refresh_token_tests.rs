// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2255: a grant with no refresh token can never be refreshed. Reporting that
//! as `Unavailable` (transient) left the account Connected and failing forever;
//! it is `InvalidGrant`, which the service turns into reconnect-required.

use super::*;

#[tokio::test]
async fn a_grant_without_a_refresh_token_is_an_invalid_grant_with_no_token_call() {
    let (trace, provider) = google_rig(token_ok(""), true, NOW).await;
    let mut current = grant();
    current.refresh_token = None;

    let outcome = provider
        .refresh(&account("workspace", GOOGLE_ISSUER, RESOURCE), &current)
        .await;

    assert_eq!(outcome.err(), Some(ProviderRefreshError::InvalidGrant));
    assert!(
        trace.token_calls().is_empty(),
        "there is nothing to send, so the token endpoint is never called"
    );
}
