// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 C0c: closing a CF stream cancels an in-flight JWKS check.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::gateway::streaming::told::custody_tests::CustodyFixture;
use crate::key_server::oidc_test_harness::{Harness, ISS_A, config_yaml};

/// Two live subjects must keep independent grace histories: each counts
/// only its own transient failures, and a good verification resets only
/// the subject it verified. The disconnect premise is proven on the raw
/// verifier first and mutates neither subject's grace.
pub(in crate::gateway::streaming) async fn grace_history_challenge(
    first: &ViewSubject,
    second: &ViewSubject,
    good: &OidcVerifier,
) {
    let disconnect_jwks = DisconnectJwks::start().await;
    let bad = disconnecting_verifier(&disconnect_jwks);
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let good_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(good),
    };
    let bad_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&bad),
    };
    assert_disconnect_premise(&disconnect_jwks, &bad, first).await;
    std::assert_eq!(
        first.verify_held_cf(&good_ctx).await,
        Ok(()),
        "VOID: a good verification must reset the first subject"
    );
    std::assert_eq!(
        second.verify_held_cf(&good_ctx).await,
        Ok(()),
        "VOID: a good verification must reset the second subject"
    );
    std::assert_eq!(
        first.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "the first subject's first transient must stay within its own grace"
    );
    std::assert_eq!(
        first.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "the first subject's second transient must stay within its own grace"
    );
    std::assert_eq!(
        second.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "the second subject's first transient must not spend the first subject's grace"
    );
    std::assert_eq!(
        first.verify_held_cf(&bad_ctx).await,
        Err(DeadReason::Cf),
        "the first subject's third transient must fail closed on its own count"
    );
    std::assert_eq!(
        second.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "the second subject's second transient must stay within its own grace"
    );
    std::assert_eq!(
        first.verify_held_cf(&good_ctx).await,
        Ok(()),
        "a good verification must restore the first subject before close"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn closing_a_cf_stream_cancels_an_inflight_jwks_verification() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let good = good_verifier(&harness);
    let token = harness.mint(ISS_A, "alice", &json!({"jti": "custody-inflight"}));
    let subject = admitted_subject(&good, token).await;
    let (fixture, view) = CustodyFixture::attach(subject, good).await;
    let fixture = Arc::new(fixture);
    let mut body = fixture.body(view);
    body.expect_connected().await;
    let mut gated = GatedDisconnectJwks::start().await;
    fixture.set_verifier(gated_verifier(&gated));
    fixture.set_digest("s1", "x2");
    let broadcast_fixture = Arc::clone(&fixture);
    let mut broadcast = tokio::spawn(async move { broadcast_fixture.broadcast().await });
    let release = match tokio::time::timeout(Duration::from_secs(5), gated.await_arrival()).await {
        Ok(release) => release,
        Err(elapsed) => {
            broadcast.abort();
            let _ = broadcast.await;
            panic!(
                "VOID: gated JWKS arrival did not occur within 5s on current \
                     production (missing arrival, never RED): {elapsed}"
            )
        }
    };
    let completed_at_close = fixture.completed_verifications();
    drop(body);
    let reached = match tokio::time::timeout(Duration::from_secs(5), &mut broadcast).await {
        Ok(Ok(reached)) => reached,
        Ok(Err(error)) => panic!("VOID: judged broadcast task failed: {error}"),
        Err(elapsed) => {
            broadcast.abort();
            let _ = broadcast.await;
            panic!(
                "RED: an in-flight JWKS verification kept running after its stream \
                 closed; it must end with the stream: {elapsed}"
            )
        }
    };
    std::assert_eq!(
        fixture.completed_verifications(),
        completed_at_close,
        "no verification may complete for a stream already closed"
    );
    std::assert_eq!(
        reached,
        0,
        "closing a CF stream must cancel its in-flight verification: no copy \
         may be reached after close"
    );
    std::assert!(
        fixture.primary().all_owners_dead(),
        "closing a CF stream must drop every raw subject owner"
    );
    drop(release);
    drop(gated);
}
