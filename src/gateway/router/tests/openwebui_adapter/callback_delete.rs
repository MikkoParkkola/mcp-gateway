// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The browser variant of `DELETE /accounts/v1/connections/{account_id}`
//! (design §8.3, rows T-REV browser half and the conflicting-credential
//! rule): the Open `WebUI` session names the principal, same-origin only.

use super::*;

fn browser_delete(account: &str, token: &str) -> axum::http::request::Builder {
    Request::delete(format!("/accounts/v1/connections/{account}"))
        .header("host", HOSTED_HOST)
        .header("origin", "https://chat.fixture.test")
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-dest", "empty")
        .header("cookie", cookie_of(token))
}

async fn json_of(gw: &Gateway, request: Request<Body>) -> (StatusCode, Value) {
    let (status, _, body) = send(gw, request).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// T-REV (browser credential): A's own session revokes A's grant at the
/// provider and leaves B connected.
#[tokio::test(flavor = "multi_thread")]
async fn t_rev_browser_session_revokes_only_its_own_account() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let alice = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &alice).await, "connected");
    let bob = begin(&gw, BOB, BOB_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &bob).await, "connected");
    // WHEN
    let request = browser_delete(WORK, ALICE_TOKEN)
        .body(Body::empty())
        .unwrap();
    let (status, body) = json_of(&gw, request).await;
    // THEN
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"schema_version": "accounts.v1", "account_id": WORK, "status": "revoked",
               "provider_revocation": "confirmed"})
    );
    let sent: Vec<String> = gw.fixture.received().into_iter().map(|(t, _)| t).collect();
    assert!(
        sent.contains(&"fresh-refresh-1-5c1d".to_owned()),
        "{sent:?}"
    );
    assert!(
        !sent.iter().any(|token| token.contains("-2-")),
        "B's tokens: {sent:?}"
    );
    assert_eq!(gw.fixture.state(&key_of(&gw, ALICE, WORK)).await, "revoked");
    assert_eq!(gw.fixture.state(&key_of(&gw, BOB, WORK)).await, "connected");
}

/// §8.3: both credentials at once, a missing `Origin`, and no credential are
/// each refused in the §9.1 envelope, and nothing is revoked.
#[tokio::test(flavor = "multi_thread")]
async fn browser_delete_refuses_conflicting_or_missing_credentials() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let alice = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &alice).await, "connected");
    let both = browser_delete(WORK, ALICE_TOKEN)
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(ALICE))
        .body(Body::empty())
        .unwrap();
    let no_origin = Request::delete(format!("/accounts/v1/connections/{WORK}"))
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "same-origin")
        .header("cookie", cookie_of(ALICE_TOKEN))
        .body(Body::empty())
        .unwrap();
    let anonymous = Request::delete(format!("/accounts/v1/connections/{WORK}"))
        .body(Body::empty())
        .unwrap();
    // WHEN
    let refusals = [
        (json_of(&gw, both).await, StatusCode::FORBIDDEN, "forbidden"),
        (
            json_of(&gw, no_origin).await,
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            json_of(&gw, anonymous).await,
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
        ),
    ];
    // THEN
    for ((status, body), expected, code) in refusals {
        assert_eq!(status, expected, "{body}");
        assert_eq!(body["schema_version"], "accounts.v1", "{body}");
        assert_eq!(body["error"]["code"], code, "{body}");
    }
    assert!(gw.fixture.received().is_empty());
    assert_eq!(
        gw.fixture.state(&key_of(&gw, ALICE, WORK)).await,
        "connected"
    );
}
