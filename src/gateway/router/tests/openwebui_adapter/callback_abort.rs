// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Post-exchange aborts (design §6.2 steps 9-11, §6.3; rows T-C05a, T-C05c,
//! T-ABORT, T-R2-1, T-R2-2): nothing is committed, and the fresh tokens are
//! revoked at the provider exactly once through `abort_after_exchange`.

use std::time::Duration;

use super::*;

fn refresh(n: u32) -> String {
    format!("fresh-refresh-{n}-5c1d")
}

/// How many times the fake `/revoke` received `token`.
fn revoked(gw: &Gateway, token: &str) -> usize {
    gw.fixture
        .received()
        .iter()
        .filter(|(sent, _)| sent == token)
        .count()
}

async fn api_delete(gw: &Gateway, subject: &str, account: &str) -> (StatusCode, Value) {
    let request = Request::delete(format!("/accounts/v1/connections/{account}"))
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(subject))
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(gw, request).await;
    (status, serde_json::from_str(&body).unwrap())
}

/// A grant response that fails validation, with its own tokens.
fn scripted(scope: &str, token_type: &str, with_refresh: bool) -> Value {
    let mut body = json!({"access_token": "scripted-access-3e8b", "token_type": token_type,
                          "expires_in": 3600, "scope": scope});
    if with_refresh {
        body["refresh_token"] = json!("scripted-refresh-6f0a");
    }
    body
}

/// T-C05a: a revoke lands while the user is at the provider. The callback's
/// commit is fenced, the account stays revoked, and the fresh refresh token
/// is revoked once.
#[tokio::test(flavor = "multi_thread")]
async fn t_c05a_callback_after_revoke_is_fenced_and_revokes_fresh_tokens() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let first = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &first).await, "connected");
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_eq!(api_delete(&gw, ALICE, WORK).await.0, StatusCode::OK);
    // WHEN
    let outcome = complete(&gw, &flow).await;
    // THEN
    assert_outcome(&outcome, "superseded_grant; provider_revoked");
    let status = journey_status(&gw, ALICE, &flow.id).await;
    assert_eq!(status["status"], "failed");
    assert_eq!(status["reason"], "superseded_grant");
    assert_eq!(
        gw.fixture.exchanges().len(),
        2,
        "the fence acts after the exchange"
    );
    assert_eq!(revoked(&gw, &refresh(2)), 1);
    assert_eq!(gw.fixture.state(&key_of(&gw, ALICE, WORK)).await, "revoked");
}

/// T-C05c, T-ABORT (validation arms): a narrower scope, a non-Bearer token
/// and a missing refresh token under `access_type=offline` each commit
/// nothing and revoke the fresh token once.
#[tokio::test(flavor = "multi_thread")]
async fn t_c05c_invalid_grants_are_refused_and_revoked() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let cases = [
        (
            scripted("other.scope", "Bearer", true),
            "scope_missing",
            "scripted-refresh-6f0a",
            1,
        ),
        (
            scripted("fixture.read", "mac", true),
            "unexpected_token_form",
            "scripted-refresh-6f0a",
            2,
        ),
        (
            scripted("fixture.read", "Bearer", false),
            "no_refresh_token",
            "scripted-access-3e8b",
            1,
        ),
    ];
    // The two refresh-token cases share one token, so its count accumulates.
    for (response, reason, token, count) in cases {
        let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
        gw.fixture.token.queue(200, response);
        // WHEN
        let outcome = complete(&gw, &flow).await;
        // THEN
        assert_outcome(&outcome, &format!("{reason}; provider_revoked"));
        let status = journey_status(&gw, ALICE, &flow.id).await;
        assert_eq!(status["status"], "failed");
        assert_eq!(status["reason"], reason);
        assert_eq!(revoked(&gw, token), count, "{reason}");
        assert_eq!(gw.fixture.state(&key_of(&gw, ALICE, WORK)).await, "absent");
    }
    assert_eq!(gw.fixture.exchanges().len(), 3);
}

/// T-ABORT (store and audit arms, revocation outcomes): a failed pre-commit
/// audit write and a failed commit abort like any other; a 503 at `/revoke`
/// is reported as failed.
#[tokio::test(flavor = "multi_thread")]
async fn t_abort_audit_and_storage_failures_revoke_and_report_the_outcome() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let audit = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let storage = begin(&gw, ALICE, ALICE_TOKEN, HOME).await;
    let refused = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    // WHEN
    let log = gw.state.transparency_log.as_ref().unwrap();
    log.fail_next_append_for_test();
    let audit_out = complete(&gw, &audit).await;
    gw.fixture.fail_next_commit();
    let storage_out = complete(&gw, &storage).await;
    gw.fixture.answer(503);
    gw.fixture
        .token
        .queue(200, scripted("other.scope", "Bearer", true));
    let refused_out = complete(&gw, &refused).await;
    // THEN
    assert_outcome(&audit_out, "audit_unavailable; provider_revoked");
    assert_outcome(&storage_out, "storage_unavailable; provider_revoked");
    assert_outcome(&refused_out, "scope_missing; provider_revoke_failed");
    assert_eq!(revoked(&gw, "scripted-refresh-6f0a"), 1);
    assert_eq!(gw.fixture.state(&key_of(&gw, BOB, WORK)).await, "absent");
    for (subject, account, n) in [(ALICE, WORK, 1), (ALICE, HOME, 2)] {
        assert_eq!(revoked(&gw, &refresh(n)), 1, "{subject}/{account}");
        assert_eq!(
            gw.fixture.state(&key_of(&gw, subject, account)).await,
            "absent"
        );
    }
    let status = journey_status(&gw, ALICE, &storage.id).await;
    assert_eq!(status["status"], "failed");
    assert_eq!(status["reason"], "storage_unavailable");
}

/// T-ABORT (no revocation endpoint configured): the abort still happens, and
/// the page says the provider could not be told.
#[tokio::test(flavor = "multi_thread")]
async fn t_abort_without_a_revocation_endpoint_reports_unsupported() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Absent).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    gw.fixture
        .token
        .queue(200, scripted("other.scope", "Bearer", true));
    // WHEN
    let outcome = complete(&gw, &flow).await;
    // THEN
    assert_outcome(&outcome, "scope_missing; provider_revoke_unsupported");
    assert!(gw.fixture.received().is_empty());
}

/// T-R2-1: the grant is published and the later `journeys.json` write fails.
/// The page still reports the connection and every principal keeps using the
/// authority. The next journey read heals from the renamed file (§5.2).
#[tokio::test(flavor = "multi_thread")]
async fn t_r2_1_journeys_write_failure_after_commit_does_not_poison_the_authority() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let bob = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &bob).await, "connected");
    let alice = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    gw.fixture.fail_journeys_write_after_exchange();
    // WHEN
    let outcome = complete(&gw, &alice).await;
    // THEN
    assert_outcome(&outcome, "connected; status unavailable");
    let alice_token = gw.fixture.access_token(&key_of(&gw, ALICE, WORK)).await;
    assert_eq!(alice_token.as_deref(), Some("fresh-access-2-9e4a"));
    let bob_key = key_of(&gw, BOB, WORK);
    assert_eq!(
        gw.fixture.access_token(&bob_key).await.as_deref(),
        Some("fresh-access-1-9e4a")
    );
    gw.fixture.advance(3601);
    assert!(
        gw.fixture.refreshed_token(&bob_key).await.is_some(),
        "B refreshes"
    );
    let status = journey_status(&gw, ALICE, &alice.id).await;
    assert_eq!(status["status"], "connected", "{status}");
    assert!(
        gw.fixture.received().is_empty(),
        "a durable grant is never revoked"
    );
}

/// Holds A's callback at `/token`, runs `during`, then releases it.
async fn held_callback(
    gw: &Gateway,
    flow: &Flow,
    during: impl std::future::Future<Output = ()>,
) -> (StatusCode, String) {
    let hold = gw.fixture.token.hold();
    let request = callback_request(&code_query(flow), &[&flow.cookie]);
    let pending = tokio::spawn(gw.router.clone().oneshot(request));
    tokio::time::timeout(Duration::from_secs(5), hold.entered.notified())
        .await
        .expect("callback reached /token");
    during.await;
    hold.release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("held callback finished")
        .unwrap()
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// T-R2-2: a journey swept (a) or superseded (b) during the exchange window
/// is never resurrected; the fresh tokens are revoked.
#[tokio::test(flavor = "multi_thread")]
async fn t_r2_2_journey_gone_during_exchange_commits_nothing() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let swept = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let superseded = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    // WHEN: (b) first, since (a)'s clock jump would also expire (b)
    let (b_status, b_body) = held_callback(&gw, &superseded, async {
        let _ = create(&gw, BOB, WORK).await;
    })
    .await;
    let (a_status, a_body) = held_callback(&gw, &swept, async {
        gw.fixture.advance(601);
        let _ = journey_status(&gw, ALICE, &swept.id).await;
    })
    .await;
    // THEN
    for (status, body) in [(a_status, &a_body), (b_status, &b_body)] {
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("journey_gone; provider_revoked"), "{body}");
    }
    for (subject, flow, n) in [(ALICE, &swept, 2), (BOB, &superseded, 1)] {
        assert_eq!(
            journey_status(&gw, subject, &flow.id).await["status"],
            "expired"
        );
        assert_eq!(
            gw.fixture.state(&key_of(&gw, subject, WORK)).await,
            "absent"
        );
        assert_eq!(revoked(&gw, &refresh(n)), 1);
    }
}
