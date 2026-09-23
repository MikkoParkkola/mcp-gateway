// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Revoke refusals and the operator-visible logs of a partial revoke:
//! a store that cannot tombstone, descriptors that cannot compile, a skipped
//! eviction and a failed provider revocation.

use super::*;
use crate::personal_accounts::AccountHandles;
use crate::personal_accounts::revoke_fixture::StoreDown;

/// Log lines carrying `marker`, captured while `run` executes.
async fn logged(marker: &str, run: impl std::future::Future<Output = ()>) -> Vec<String> {
    let (captured, guard) = super::super::start_route::capture();
    run.await;
    drop(guard);
    let text = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    text.lines()
        .filter(|line| line.contains(marker))
        .map(str::to_owned)
        .collect()
}

/// No subject, full digest or token in any of `lines`.
fn assert_redacted(lines: &[String]) {
    let digest = key("alice").digest().unwrap();
    for line in lines {
        for secret in [digest.as_str(), "alice", A_REFRESH, A_ACCESS] {
            assert!(!line.contains(secret), "{secret} leaked: {line}");
        }
    }
}

/// A store error during the tombstone is 503 `storage_unavailable`, before
/// any audit row or provider call.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_store_error_is_503_with_no_audit_and_no_provider_call() {
    // GIVEN: the router's revocation half cannot tombstone
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    let down = Arc::new(StoreDown::default());
    let handles = AccountHandles {
        revocation: Arc::clone(&down) as Arc<dyn crate::personal_accounts::AccountRevocation>,
        journeys: gw.fixture.handles().journeys,
    };
    let router = create_router_with_accounts(Arc::clone(&gw.state), None, Some(handles));
    let gw = Gateway { router, ..gw };
    // WHEN
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "storage_unavailable");
    assert_eq!(down.provider_calls(), 0, "no provider call");
    let audit = std::fs::read_to_string(gw.dir.path().join("audit.ndjson")).unwrap_or_default();
    assert!(!audit.contains("account_revoke"), "no audit row: {audit}");
}

/// A descriptor set that no longer compiles is a server-side 503, not the
/// caller's 404, and nothing is revoked.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_uncompilable_descriptors_are_503_not_404() {
    // GIVEN: a reload drops the managed descriptor's issuer
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    let mut config = (*gw.state.live_config.get()).clone();
    let descriptors = config.accounts.as_mut().unwrap().descriptors.as_mut();
    descriptors.unwrap().get_mut(ACCOUNT).unwrap().issuer = None;
    gw.state.live_config.set(config);
    // WHEN
    let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
    // THEN
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], "storage_unavailable");
    assert_eq!(gw.fixture.state(&key("alice")).await, "connected");
    assert!(gw.fixture.received().is_empty());
}

/// A bound backend the registry does not hold is a skipped eviction, logged
/// under an 8-character digest prefix and nothing that names the principal.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_logs_a_skipped_eviction_under_the_digest_prefix_only() {
    // GIVEN: the bound backend is not registered
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    assert!(gw.state.backends.get(BOUND_BACKEND).is_none(), "premise");
    // WHEN
    let lines = logged("revoke evicted no sessions", async {
        assert_eq!(delete(&gw, Some("alice"), ACCOUNT).await.0, StatusCode::OK);
    })
    .await;
    // THEN
    let digest = key("alice").digest().unwrap();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(&digest[..8]) && lines[0].contains(BOUND_BACKEND));
    assert_redacted(&lines);
}

/// A 200 that reports `provider_revocation: failed` leaves a warning; the
/// grant may still be live upstream.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_route_logs_a_failed_provider_revocation_without_tokens() {
    // GIVEN
    let gw = gateway(true, &[(key("alice"), grant("alice"), Seed::Connected)]).await;
    gw.fixture.answer(503);
    // WHEN
    let lines = logged("provider revocation failed", async {
        let (status, body) = delete(&gw, Some("alice"), ACCOUNT).await;
        assert_eq!((status, body), (StatusCode::OK, revoked_body("failed")));
    })
    .await;
    // THEN
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_redacted(&lines);
}
