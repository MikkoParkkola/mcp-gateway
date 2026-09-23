// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 5b: `GET /accounts/v1/journeys/{id}/start` through the Open
//! `WebUI` session bridge (design §4.2, §4.3; §11.2 rows T-A07, T-C02a-d,
//! T-BRIDGE-*, T-COOKIE, T-CT, T-HDR). Real router, store, custody and a real
//! loopback fake Open `WebUI`.
//!
//! The harness restates `hosted_routes.rs`'s config because the session
//! endpoint's port is per test and that module's helpers are private.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::super::create_router_with_accounts;
use super::super::{ResolvedAuthConfig, StreamingConfig, test_router_app_state_with};
use super::fake_owui::{Answer, FakeOwui, User};
use crate::personal_accounts::revoke_fixture::{RevocationEndpoint, RevokeFixture};

const WORK: &str = "work";
const HOME: &str = "home";
const RESOURCE: &str = "https://api.fixture.test/";
const HMAC: &str = "fixture-adapter-signing-secret-123456789";
const API_KEY: &str = "fixture-named-api-key";
const HOSTED_HOST: &str = "chat.fixture.test";
const INSTALLATION: &str = "fixture-installation";
const AUTHORIZE: &str = "https://accounts.fixture.test/authorize";
const ALICE: &str = "5c0e6f7a-3b1d-4e8a-9f2c-7d6b5a4c3e21";
const BOB: &str = "b7d9e1f3-0a2c-4e6d-8f1b-3c5e7a9d2f40";
const ALICE_TOKEN: &str = "owui-session-alice-SECRET-3f9a";
const BOB_TOKEN: &str = "owui-session-bob-SECRET-8c2d";
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'";

fn user(token: &'static str, id: &str, email: &'static str) -> User {
    User {
        token,
        id: json!(id),
        email,
        expires_at: json!(unix_now() + 3600),
    }
}

fn users() -> Vec<User> {
    vec![
        user(ALICE_TOKEN, ALICE, "alice-SECRET@example.test"),
        user(BOB_TOKEN, BOB, "bob-SECRET@example.test"),
    ]
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn descriptor_yaml(id: &str) -> String {
    format!(
        "    {id}:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: {RESOURCE}\n      issuer: https://issuer.fixture.test\n      \
         redirect_uri: https://chat.fixture.test/accounts/v1/callback\n"
    )
}

fn config(env: &std::path::Path, user_endpoint: &str, starts: u32) -> crate::config::Config {
    let descriptors = descriptor_yaml(WORK) + &descriptor_yaml(HOME);
    serde_yaml::from_str(&format!(
        r#"
env_files: ["{env}"]
auth:
  enabled: true
  public_paths: []
  api_keys:
    - name: owui
      key: {API_KEY}
accounts:
  schema_version: accounts.v1
  enabled: false
  deployment: single_process
  instance_id: router-fixture
  store_dir: /unused/router-fixture-store
  authority_dir: /unused/router-fixture-authority
  current_key_id: primary
  keys:
    primary: env:OWUI_ROUTE_STORE
  limits:
    journeys_created_per_minute: 50
    journeys_per_user: 10
    starts_per_minute_per_user: {starts}
  adapters:
    - kind: openwebui_signed_header
      installation_id: {INSTALLATION}
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_ROUTE_HMAC
      allowed_api_key_names: [owui]
      session:
        user_endpoint: {user_endpoint}
  descriptors:
{descriptors}  hosted:
    public_origin: https://chat.fixture.test
    return_paths: [/]
"#,
        env = env.display()
    ))
    .unwrap()
}

struct Gateway {
    router: axum::Router,
    config: crate::config::Config,
    _fixture: RevokeFixture,
    _dir: tempfile::TempDir,
}

async fn gateway(owui: &FakeOwui, starts: u32) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join("adapter.env");
    std::fs::write(
        &env,
        format!("OWUI_ROUTE_HMAC={HMAC}\nOWUI_ROUTE_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"),
    )
    .unwrap();
    let config = config(&env, &owui.url, starts);
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let (mut state, _store) =
        test_router_app_state_with(StreamingConfig::default(), config.clone()).await;
    Arc::get_mut(&mut state).unwrap().auth_config = auth;
    let fixture =
        RevokeFixture::start_accounts(&[WORK, HOME], RESOURCE, &[], RevocationEndpoint::Configured)
            .await;
    let router = create_router_with_accounts(state, None, Some(fixture.handles()));
    Gateway {
        router,
        config,
        _fixture: fixture,
        _dir: dir,
    }
}

fn assertion(subject: &str) -> String {
    let now = unix_now();
    let claims = json!({"iss":"open-webui","sub":subject,"iat":now,"exp":now+120});
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(HMAC.as_bytes()),
    )
    .unwrap()
}

async fn send(gw: &Gateway, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = gw.router.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, 256 * 1024).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// `POST /accounts/v1/journeys` as the tool-call adapter's `subject`.
async fn create(gw: &Gateway, subject: &str, account: &str) -> String {
    let request = Request::post("/accounts/v1/journeys")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(subject))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"account_id": account, "return_path": "/"}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(gw, request).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    serde_json::from_str::<Value>(&body).unwrap()["journey_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn journey_status(gw: &Gateway, subject: &str, id: &str) -> Value {
    let request = Request::get(format!("/accounts/v1/journeys/{id}"))
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(subject))
        .body(Body::empty())
        .unwrap();
    let (_, _, body) = send(gw, request).await;
    serde_json::from_str(&body).unwrap()
}

/// The link opened in a browser tab on the Open `WebUI` origin; each entry of
/// `cookies` is its own `Cookie` header line.
fn start_request(uri: &str, cookies: &[&str]) -> axum::http::request::Builder {
    let mut builder = Request::get(uri)
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "same-origin")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-dest", "document");
    for cookie in cookies {
        builder = builder.header("cookie", *cookie);
    }
    builder
}

async fn start(gw: &Gateway, id: &str, cookies: &[&str]) -> (StatusCode, HeaderMap, String) {
    let uri = format!("/accounts/v1/journeys/{id}/start");
    send(
        gw,
        start_request(&uri, cookies).body(Body::empty()).unwrap(),
    )
    .await
}

fn cookie_of(token: &str) -> String {
    format!("token={token}")
}

/// The journey owner's `AccountKey` digest, derived as the store derives it.
fn owner_digest(gw: &Gateway, subject: &str, account: &str) -> String {
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
    account_key(Some(Principal::Verified(&identity)), &descriptor)
        .unwrap()
        .digest()
        .unwrap()
}

/// §4.3: every start response carries the layer's headers; a page is
/// gateway HTML with no script and no inline style (the CSP forbids both).
fn assert_hardened_page(headers: &HeaderMap, body: &str) {
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
    let content_type = headers[header::CONTENT_TYPE].to_str().unwrap();
    assert!(content_type.starts_with("text/html"), "{content_type}");
    for forbidden in ["<script", "<style", "style=", "javascript:"] {
        assert!(!body.contains(forbidden), "{forbidden} in {body}");
    }
}

/// A refusal: no provider redirect, no binding cookie.
fn assert_no_start(response: &(StatusCode, HeaderMap, String)) {
    let (status, headers, body) = response;
    assert_ne!(*status, StatusCode::SEE_OTHER, "{body}");
    assert!(headers.get(header::LOCATION).is_none(), "{headers:?}");
    assert!(headers.get(header::SET_COOKIE).is_none(), "{headers:?}");
    assert_hardened_page(headers, body);
}

fn query_of(location: &str) -> Vec<(String, String)> {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect()
}

fn one<'a>(query: &'a [(String, String)], key: &str) -> &'a str {
    let values: Vec<&str> = query
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values.len(), 1, "{key} in {query:?}");
    values[0]
}

/// The one `Set-Cookie` of a successful start, split into name and value.
fn binding_cookie(headers: &HeaderMap) -> (String, String, String) {
    let all: Vec<_> = headers.get_all(header::SET_COOKIE).iter().collect();
    assert_eq!(all.len(), 1, "{all:?}");
    let line = all[0].to_str().unwrap().to_owned();
    let (pair, _) = line.split_once(';').unwrap();
    let (name, value) = pair.split_once('=').unwrap();
    (name.to_owned(), value.to_owned(), line.clone())
}

/// T-A07 (positive), T-CT: the owner's own Open `WebUI` session starts the
/// journey: 303 to the PINNED authorize endpoint with S256 and state, and the
/// per-journey binding cookie with exactly the §4.2 step 7 attributes.
#[tokio::test]
async fn start_same_principal_redirects_to_pinned_authorize_and_sets_binding() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN
    let (status, headers, body) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    // THEN
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::CONTENT_SECURITY_POLICY], CSP);
    let location = headers[header::LOCATION].to_str().unwrap();
    assert!(location.starts_with(&format!("{AUTHORIZE}?")), "{location}");
    let query = query_of(location);
    assert_eq!(one(&query, "response_type"), "code");
    assert_eq!(one(&query, "client_id"), "fixture-client");
    assert_eq!(one(&query, "code_challenge_method"), "S256");
    assert_eq!(one(&query, "state").len(), 43);
    assert_eq!(one(&query, "code_challenge").len(), 43);
    assert_ne!(one(&query, "state"), one(&query, "code_challenge"));
    let (name, value, line) = binding_cookie(&headers);
    assert_eq!(name, format!("__Secure-mcpgw-journey-{id}"));
    assert_eq!(value.len(), 43, "{line}");
    assert_eq!(
        line,
        format!(
            "{name}={value}; Secure; HttpOnly; SameSite=Lax; Path=/accounts/v1/callback; Max-Age=600"
        )
    );
    assert!(!location.contains(&value), "binding must not ride the URL");
    assert_eq!(owui.seen(), vec![format!("Bearer {ALICE_TOKEN}")]);
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "started");
    let digest = owner_digest(&gw, ALICE, WORK);
    assert!(crate::personal_accounts::digest_compared(
        crate::personal_accounts::DigestKind::Owner,
        &digest
    ));
}

/// The page a start with no session renders; every bridge refusal must be
/// byte-identical to it, so no response says which step failed (§4.2 step 6).
async fn sign_in_page(gw: &Gateway, id: &str) -> (StatusCode, String) {
    let response = start(gw, id, &[]).await;
    assert_no_start(&response);
    (response.0, response.2)
}

async fn assert_refused_like_sign_in(gw: &Gateway, id: &str, cookies: &[&str]) {
    let reference = sign_in_page(gw, id).await;
    let response = start(gw, id, cookies).await;
    assert_no_start(&response);
    assert_eq!((response.0, response.2), reference, "cookies {cookies:?}");
}

/// T-C02a, T-CT: A's link opened in B's browser. Refused like a missing
/// session, the journey stays pending, and B's digest was compared in constant
/// time. With one start per minute, A still starts after: the owner check
/// precedes rate admission.
#[tokio::test]
async fn start_as_another_owui_user_is_refused_and_spends_no_start() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 1).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(BOB_TOKEN)]).await;
    // THEN
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "pending");
    assert!(crate::personal_accounts::digest_compared(
        crate::personal_accounts::DigestKind::Owner,
        &owner_digest(&gw, BOB, WORK)
    ));
    let (status, _, body) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
}

/// T-C02b: no session, an empty one, a look-alike name, and a duplicated
/// `token` (in one header line and across two) are all refused before Open
/// `WebUI` is asked anything.
#[tokio::test]
async fn start_without_exactly_one_session_cookie_never_calls_owui() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let alice = cookie_of(ALICE_TOKEN);
    let doubled = format!("{alice}; {alice}");
    let bob = cookie_of(BOB_TOKEN);
    let cases: [&[&str]; 5] = [
        &["token="],
        &["tokenx=owui-session-alice-SECRET-3f9a; xtoken=a"],
        &[&doubled],
        &[&alice, &alice],
        &[&alice, &bob],
    ];
    // WHEN / THEN
    for cookies in cases {
        assert_refused_like_sign_in(&gw, &id, cookies).await;
    }
    assert!(owui.seen().is_empty(), "{:?}", owui.seen());
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "pending");
}

/// T-C02c (start half): a journey binding cookie is not a session; without
/// the Open `WebUI` cookie the start is refused, whatever else rides along.
#[tokio::test]
async fn start_with_only_a_binding_cookie_is_refused() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let swapped = format!("__Secure-mcpgw-journey-{id}={}", "Zq".repeat(21));
    // WHEN / THEN
    assert_refused_like_sign_in(&gw, &id, &[&swapped]).await;
    assert!(owui.seen().is_empty());
}

/// T-C02d: nothing but the Open `WebUI` session names the principal. A query
/// naming A, and A's valid tool-call assertion plus the API key, do not help
/// B's browser; a cross-site start is refused by the origin guard.
#[tokio::test]
async fn start_ignores_forged_principal_fields_and_cross_site_requests() {
    // GIVEN
    let owui = FakeOwui::start(users(), Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let bob = cookie_of(BOB_TOKEN);
    let reference = sign_in_page(&gw, &id).await;
    // WHEN: a forged query
    let uri = format!("/accounts/v1/journeys/{id}/start?sub={ALICE}&principal={ALICE}");
    let forged_query = send(
        &gw,
        start_request(&uri, &[&bob]).body(Body::empty()).unwrap(),
    )
    .await;
    // WHEN: A's adapter assertion and the API key alongside B's session
    let uri = format!("/accounts/v1/journeys/{id}/start");
    let with_assertion = start_request(&uri, &[&bob])
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-openwebui-assertion", assertion(ALICE))
        .body(Body::empty())
        .unwrap();
    let forged_assertion = send(&gw, with_assertion).await;
    // WHEN: cross-site, with A's own session
    let cross = Request::get(&uri)
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "cross-site")
        .header("origin", "https://evil.example")
        .header("cookie", cookie_of(ALICE_TOKEN))
        .body(Body::empty())
        .unwrap();
    let seen_before_cross = owui.seen().len();
    let (cross_status, cross_headers, _) = send(&gw, cross).await;
    // THEN
    for response in [&forged_query, &forged_assertion] {
        assert_no_start(response);
        assert_eq!((response.0, response.2.clone()), reference);
    }
    assert_eq!(cross_status, StatusCode::FORBIDDEN);
    assert!(cross_headers.get(header::SET_COOKIE).is_none());
    assert_eq!(owui.seen().len(), seen_before_cross, "guard runs first");
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "pending");
}

/// T-A07 (negative): the principal is the session's `id`, never its email.
/// B's session reporting A's email is still B.
#[tokio::test]
async fn start_matches_on_owui_id_never_on_email() {
    // GIVEN
    let impostor = user(BOB_TOKEN, BOB, "alice-SECRET@example.test");
    let owui = FakeOwui::start(vec![users()[0].clone(), impostor], Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN / THEN
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(BOB_TOKEN)]).await;
    assert_eq!(journey_status(&gw, ALICE, &id).await["status"], "pending");
}

/// §4.2 step 4: a past `expires_at` refuses; `null` (no expiry) and a future
/// one pass; a numeric `id` is refused (L7: upstream's id is a string).
#[tokio::test]
async fn start_refuses_expired_sessions_and_non_string_ids() {
    // GIVEN
    let mut expired = user(ALICE_TOKEN, ALICE, "a@example.test");
    expired.expires_at = json!(unix_now() - 5);
    let mut numeric = user(BOB_TOKEN, ALICE, "a@example.test");
    numeric.id = json!(42);
    let owui = FakeOwui::start(vec![expired, numeric], Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    // WHEN / THEN
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_refused_like_sign_in(&gw, &id, &[&cookie_of(BOB_TOKEN)]).await;
    let mut open_ended = user(ALICE_TOKEN, ALICE, "a@example.test");
    open_ended.expires_at = Value::Null;
    let owui = FakeOwui::start(vec![open_ended], Answer::Session).await;
    let gw = gateway(&owui, 5).await;
    let id = create(&gw, ALICE, WORK).await;
    let (status, _, body) = start(&gw, &id, &[&cookie_of(ALICE_TOKEN)]).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{body}");
}

#[path = "start_route_client.rs"]
mod client;
