// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A11 on the REST route: an upstream 401 against a managed account forces one
//! refresh, then asks the user to reconnect (tier3 design §A11, amendment rev 4).
//!
//! These cells drive `CapabilityBackend::call_tool_with_context` (the gap-A
//! site) through the fixture's `call`, because only that context opens the
//! loopback capture endpoint. The meta route's Err arm, which turns these marks
//! into an offer or a recovery hint, is shared by every backend kind and is
//! pinned by the MCP-route cells and the mapping unit (T14).
//!
//! Every cell counts provider round trips through the REAL custody and requests
//! at the REAL capture endpoint, so a refresh or a retry is observed, never
//! inferred.

use std::sync::Arc;

use crate::personal_accounts::AccountCustody;
use crate::personal_accounts::refusal::{AccountState, marked, upstream_rejection};

use super::super::account_resolver_fixture::{
    ALICE_WORK_TOKEN, Custody, ProviderStep, ROTATED_TOKEN, WORK, account_key, custody_with_steps,
    grant,
};
use super::super::account_rest_fixture::{
    Captured, backend_with, call, capability, capture_endpoint_answering, installed_gateway,
    managed,
};

/// Never expires, so only a 401 can make custody refresh.
const FRESH: u64 = u64::MAX;
const FORCED_TOKEN: &str = "synthetic-alice-work-forced-a11-8d31";

/// One managed account, one capability pointed at a capture endpoint that
/// answers `statuses` first, and a provider that answers `steps` first.
async fn managed_capability(
    statuses: &[u16],
    steps: &[ProviderStep],
    multi_user: bool,
) -> (
    Arc<crate::capability::CapabilityBackend>,
    Custody,
    Arc<Captured>,
) {
    let custody = custody_with_steps(
        &[(account_key("alice", WORK), grant(ALICE_WORK_TOKEN, FRESH))],
        ROTATED_TOKEN,
        steps,
    );
    let installed: Arc<dyn AccountCustody> = custody.installed();
    let (_meta, registry) = installed_gateway(&[(WORK, managed(WORK))], &installed);
    let (port, captured) = capture_endpoint_answering(statuses).await;
    let backend = backend_with(
        &registry,
        capability(
            &format!("http://127.0.0.1:{port}"),
            "oauth:google",
            Some(WORK),
        ),
    )
    .expect("the capability must register");
    backend.set_multi_user(multi_user);
    (backend, custody, captured)
}

#[track_caller]
fn assert_reconnect(error: &crate::Error, what: &str) {
    let refusal =
        marked(error).unwrap_or_else(|| panic!("{what}: not a reconnect refusal: {error}"));
    assert_eq!(refusal.state, AccountState::ReconnectRequired, "{what}");
}

#[track_caller]
fn assert_rejected(error: &crate::Error, code: &str, retry: bool, what: &str) {
    let rejection = upstream_rejection(error)
        .unwrap_or_else(|| panic!("{what}: not an upstream rejection: {error}"));
    assert_eq!(
        (rejection.error_code, rejection.retry),
        (code, retry),
        "{what}"
    );
}

/// T1: a revoked upstream grant becomes a reconnect refusal on the first 401,
/// and the account is fenced, so the next call is refused before the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_401_with_revoked_grant_returns_reconnect_offer() {
    let (backend, custody, captured) =
        managed_capability(&[401], &[ProviderStep::InvalidGrant], true).await;

    let first = call(&backend, Some("alice"))
        .await
        .expect_err("a 401 on a revoked grant must refuse, not return a tool result");
    assert_reconnect(&first, "first call");
    assert_eq!(custody.refreshes(), 1, "exactly one forced refresh");

    // The next call is refused BEFORE the wire by the account resolve. That
    // refusal is unmarked on purpose at the capability backend (the meta route
    // attaches the offer, `credentials.rs` "No offer is made here").
    let second = call(&backend, Some("alice"))
        .await
        .expect_err("a fenced account must refuse");
    assert!(
        second.to_string().contains("account must reconnect"),
        "after the fence: {second}"
    );
    assert!(
        marked(&second).is_none(),
        "the capability backend strips the mark; the meta route attaches the offer: {second}"
    );
    assert_eq!(
        captured.count(),
        1,
        "the fenced account never reaches the wire again"
    );
    assert_eq!(custody.refreshes(), 1);
}

/// T15: the same on a single-user gateway, where the credential is prepared
/// inside the executor today and dropped before the 401 is seen.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_user_upstream_401_still_reaches_the_forced_refresh() {
    let (backend, custody, _captured) =
        managed_capability(&[401], &[ProviderStep::InvalidGrant], false).await;

    let error = call(&backend, Some("alice"))
        .await
        .expect_err("a 401 on a revoked grant must refuse on a single-user gateway too");
    assert_reconnect(&error, "single-user");
    assert_eq!(custody.refreshes(), 1);
}

/// T2: a live grant rotates; the caller is told to retry, and the retry
/// presents the rotated token.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_401_with_live_grant_refreshes_and_says_retry() {
    let (backend, custody, captured) =
        managed_capability(&[401], &[ProviderStep::Rotate(FORCED_TOKEN)], true).await;

    let first = call(&backend, Some("alice"))
        .await
        .expect_err("the 401 is reported");
    assert_rejected(&first, "UPSTREAM_AUTH_REJECTED", true, "after a rotation");
    assert_eq!(custody.refreshes(), 1);

    call(&backend, Some("alice"))
        .await
        .expect("the retry presents the rotated token and succeeds");
    let seen = captured.authorizations();
    assert_eq!(seen.len(), 2);
    assert_eq!(
        seen[0].as_deref(),
        Some(format!("Bearer {ALICE_WORK_TOKEN}").as_str())
    );
    assert_eq!(
        seen[1].as_deref(),
        Some(format!("Bearer {FORCED_TOKEN}").as_str())
    );
}

/// T3: a backend that refuses every token costs one provider round trip per
/// token revision, and says so instead of asking for endless retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_401_costs_one_forced_refresh() {
    let (backend, custody, captured) = managed_capability(
        &[401, 401, 401, 401, 401],
        &[ProviderStep::Rotate(FORCED_TOKEN)],
        true,
    )
    .await;

    let first = call(&backend, Some("alice")).await.expect_err("401");
    assert_rejected(&first, "UPSTREAM_AUTH_REJECTED", true, "call 1");
    for n in 2..=5 {
        let again = call(&backend, Some("alice")).await.expect_err("401");
        assert_rejected(
            &again,
            "UPSTREAM_AUTH_REJECTED_PERSISTENT",
            false,
            &format!("call {n}"),
        );
    }
    assert_eq!(
        custody.refreshes(),
        1,
        "one forced refresh per token revision"
    );
    assert_eq!(captured.count(), 5, "no call is retried automatically");
}

/// T5 (positive control): other statuses keep today's error and never refresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_401_status_is_unchanged() {
    let (backend, custody, captured) = managed_capability(&[500, 403], &[], true).await;

    for status in [500, 403] {
        let error = call(&backend, Some("alice"))
            .await
            .expect_err("an error status fails");
        assert!(
            marked(&error).is_none() && upstream_rejection(&error).is_none(),
            "{status} must keep today's backend error: {error}"
        );
    }
    assert_eq!(custody.refreshes(), 0);
    assert_eq!(captured.count(), 2, "one request per status, none retried");
}

/// T6 (positive control): a 200 whose body says "401" is a success. The body
/// never decides custody.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn body_text_401_in_200_is_not_detected() {
    let (backend, custody, _captured) = managed_capability(&[200], &[], true).await;

    call(&backend, Some("alice"))
        .await
        .expect("a 200 passes through whatever its body says");
    assert_eq!(custody.refreshes(), 0);
}

#[path = "upstream_401_mcp_tests.rs"]
mod mcp_route;

#[path = "upstream_401_direct_tests.rs"]
mod direct_route;

#[path = "upstream_401_offer_tests.rs"]
mod offer_route;
