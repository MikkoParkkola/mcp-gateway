// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 5c: `GET /accounts/v1/callback` (design §6.2, §6.3, §7;
//! §11.2 rows T-C01, T-REF, T-REFERER, T-C02c, T-C03a-c/e, T-C04a/b, T-BC2,
//! T-COOKIE, T-GUARD2, T-LEAK and the oversize-state row). Real router, store
//! and custody; the provider is the in-process fake with `/token`.

use crate::personal_accounts::AccountKey;

use super::*;

const CODE: &str = "fixture-code-SECRET-7f3a";
const COMPLETE: &str = "/accounts/v1/complete";

/// A gateway whose custody asks for offline access, plus its Open `WebUI`.
async fn journey_gateway(endpoint: RevocationEndpoint) -> (FakeOwui, Gateway) {
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let fixture = RevokeFixture::start_journeys(&[WORK, HOME], RESOURCE, endpoint).await;
    let gw = gateway_on(&owui, 20, fixture).await;
    (owui, gw)
}

/// A started journey as the browser holds it.
struct Flow {
    id: String,
    state: String,
    cookie: String,
}

async fn begin(gw: &Gateway, subject: &str, token: &str, account: &str) -> Flow {
    let id = create(gw, subject, account).await;
    let (status, headers, body) = start(gw, &id, &[&cookie_of(token)]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    let location = headers[header::LOCATION].to_str().unwrap().to_owned();
    let state = one(&query_of(&location), "state").to_owned();
    let (name, value, _) = binding_cookie(&headers);
    Flow {
        id,
        state,
        cookie: format!("{name}={value}"),
    }
}

/// The provider's redirect back, with realistic cross-site navigation headers.
async fn callback(gw: &Gateway, query: &str, cookies: &[&str]) -> (StatusCode, HeaderMap, String) {
    send(gw, callback_request(query, cookies)).await
}

fn callback_request(query: &str, cookies: &[&str]) -> Request<Body> {
    let mut builder = Request::get(format!("/accounts/v1/callback?{query}"))
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document");
    for cookie in cookies {
        builder = builder.header("cookie", *cookie);
    }
    builder.body(Body::empty()).unwrap()
}

fn code_query(flow: &Flow) -> String {
    format!("code={CODE}&state={}", flow.state)
}

async fn complete(gw: &Gateway, flow: &Flow) -> (StatusCode, HeaderMap, String) {
    callback(gw, &code_query(flow), &[&flow.cookie]).await
}

/// The owner's `AccountKey`, derived as the router derives it.
fn key_of(gw: &Gateway, subject: &str, account: &str) -> AccountKey {
    use crate::personal_accounts::identity::{Principal, account_key};
    let descriptor = crate::config::account_bindings::compile_descriptors(&gw.config)
        .unwrap()
        .into_iter()
        .find(|compiled| compiled.descriptor_id == account)
        .unwrap()
        .account
        .unwrap();
    let identity = crate::key_server::oidc::VerifiedIdentity {
        subject: subject.to_owned(),
        email: String::new(),
        name: None,
        groups: Vec::new(),
        issuer: crate::gateway::openwebui_adapter::adapter_issuer(INSTALLATION),
    };
    account_key(Some(Principal::Verified(&identity)), &descriptor).unwrap()
}

/// §6.2 step 12: the callback renders the outcome itself, never a 3xx, and
/// the page is gateway HTML with no script.
fn assert_outcome(response: &(StatusCode, HeaderMap, String), needle: &str) {
    let (status, headers, body) = response;
    assert_eq!(*status, StatusCode::OK, "{body}");
    assert!(headers.get(header::LOCATION).is_none(), "{headers:?}");
    assert_hardened_page(headers, body);
    assert!(body.contains(needle), "{needle} not in {body}");
}

/// The `Set-Cookie` that expires this journey's binding, and only it.
fn assert_clears_binding(headers: &HeaderMap, id: &str) {
    let cleared: Vec<&str> = headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(cleared.len(), 1, "{cleared:?}");
    let expected = format!("__Secure-mcpgw-journey-{id}=;");
    assert!(cleared[0].starts_with(&expected), "{cleared:?}");
    assert!(cleared[0].contains("Max-Age=0"), "{cleared:?}");
}

#[path = "callback_abort.rs"]
mod abort;
#[path = "callback_delete.rs"]
mod delete;
#[path = "callback_refusals.rs"]
mod refusals;

/// T-C01, T-C01b, T-COOKIE (callback half), T-LEAK: the owner's journey
/// commits the owner's grant from exactly one exchange; the use carries the
/// exchanged token; nothing secret reaches a page, a header or a log line.
/// T-LEAK ceiling: capture is per thread, so store work on the custody's
/// blocking threads is outside it; the handler and provider calls are inside.
#[tokio::test(flavor = "current_thread")]
async fn t_c01_connect_commits_the_owners_grant_and_leaks_nothing() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let (captured, guard) = capture();
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    // WHEN
    let outcome = complete(&gw, &flow).await;
    let status = journey_status(&gw, ALICE, &flow.id).await;
    drop(guard);
    // THEN
    assert_outcome(&outcome, "connected");
    assert!(outcome.2.contains(COMPLETE), "{}", outcome.2);
    assert_clears_binding(&outcome.1, &flow.id);
    let exchanges = gw.fixture.exchanges();
    assert_eq!(exchanges.len(), 1, "{exchanges:?}");
    assert_eq!(exchanges[0]["code"], CODE);
    assert_eq!(exchanges[0]["code_verifier"].len(), 43);
    assert!(
        !exchanges[0].contains_key("resource"),
        "resource sent despite false"
    );
    assert_eq!(status["status"], "connected");
    let alice = gw.fixture.access_token(&key_of(&gw, ALICE, WORK)).await;
    assert_eq!(alice.as_deref(), Some("fresh-access-1-9e4a"));
    assert_eq!(gw.fixture.state(&key_of(&gw, BOB, WORK)).await, "absent");
    let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("/accounts/v1/callback"),
        "positive control: {logs}"
    );
    let binding = flow.cookie.split_once('=').unwrap().1;
    let surfaces = [
        format!("{:?}{}", outcome.1, outcome.2),
        status.to_string(),
        logs,
    ];
    let verifier = exchanges[0]["code_verifier"].clone();
    for secret in [
        CODE,
        &flow.state,
        binding,
        &verifier,
        ALICE_TOKEN,
        "SECRET@example.test",
        "fresh-access-1",
        "fresh-refresh-1",
    ] {
        for surface in &surfaces {
            assert!(!surface.contains(secret), "{secret} leaked: {surface}");
        }
    }
}

/// T-REF (design row): the exchanged grant expires, and the use refreshes it
/// at the fake `/token` with the exchanged refresh token.
#[tokio::test(flavor = "multi_thread")]
async fn t_ref_an_exchanged_grant_refreshes_when_it_expires() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    assert_outcome(&complete(&gw, &flow).await, "connected");
    // WHEN
    gw.fixture.advance(3601);
    let used = gw.fixture.refreshed_token(&key_of(&gw, ALICE, WORK)).await;
    // THEN
    let refreshes = gw.fixture.grants("refresh_token");
    assert_eq!(refreshes.len(), 1, "{refreshes:?}");
    assert_eq!(refreshes[0]["refresh_token"], "fresh-refresh-1-5c1d");
    assert_eq!(used.as_deref(), Some("fresh-access-2-9e4a"));
}

/// T-REFERER: the outcome page is served `no-referrer` and links only to
/// gateway paths, so nothing it links to learns the callback URL.
#[tokio::test(flavor = "multi_thread")]
async fn t_referer_outcome_page_leaks_no_referrer() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let flow = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    // WHEN
    let (_, headers, body) = complete(&gw, &flow).await;
    // THEN
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert!(
        !body.contains("http:") && !body.contains("https:"),
        "{body}"
    );
    assert!(body.contains("href=\"/\""), "return path link: {body}");
}

/// T-COOKIE (callback half): two journeys in one browser complete in reverse
/// order; each callback reads and clears only its own binding cookie.
#[tokio::test(flavor = "multi_thread")]
async fn t_cookie_parallel_journeys_complete_in_reverse_order() {
    // GIVEN
    let (_owui, gw) = journey_gateway(RevocationEndpoint::Configured).await;
    let work = begin(&gw, ALICE, ALICE_TOKEN, WORK).await;
    let home = begin(&gw, ALICE, ALICE_TOKEN, HOME).await;
    let both = [work.cookie.as_str(), home.cookie.as_str()];
    // WHEN
    let second = callback(&gw, &code_query(&home), &both).await;
    let first = callback(&gw, &code_query(&work), &both).await;
    // THEN
    assert_outcome(&second, "connected");
    assert_outcome(&first, "connected");
    assert_clears_binding(&second.1, &home.id);
    assert_clears_binding(&first.1, &work.id);
    for account in [WORK, HOME] {
        assert_eq!(
            gw.fixture.state(&key_of(&gw, ALICE, account)).await,
            "connected"
        );
    }
}
