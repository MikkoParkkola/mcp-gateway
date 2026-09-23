// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-6745 slice 5a: the hosted `/accounts/v1` surface (design §4.3, §5.3,
//! §6.4; §11.2 rows T-GUARD, T-GUARD2, T-HDR, T-POST-NOBRIDGE, T-C07a).
//! Real router, auth, adapter, origin guard, store and custody.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::super::super::create_router_with_accounts;
use super::super::{ResolvedAuthConfig, StreamingConfig, test_router_app_state_with};
use crate::personal_accounts::revoke_fixture::{RevocationEndpoint, RevokeFixture};

const ACCOUNT: &str = "work";
const RESOURCE: &str = "https://api.fixture.test/";
const HMAC: &str = "fixture-adapter-signing-secret-123456789";
const PLAIN_HMAC: &str = "fixture-plain-adapter-secret-9876543210";
const API_KEY: &str = "fixture-named-api-key";
const HOSTED_HOST: &str = "chat.fixture.test";
const CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'";

/// Whether `accounts.hosted` is configured. When it is, the first adapter
/// carries the `session` block that makes it a bridge; the `plain` adapter
/// never does.
#[derive(Clone, Copy)]
enum Shape {
    Bridged,
    NotHosted,
}

fn config(env: &std::path::Path, shape: Shape) -> crate::config::Config {
    let session = match shape {
        Shape::Bridged => {
            "      session:\n        user_endpoint: http://127.0.0.1:9/api/v1/auths/\n"
        }
        Shape::NotHosted => "",
    };
    let hosted = match shape {
        Shape::NotHosted => "",
        Shape::Bridged => {
            "  hosted:\n    public_origin: https://chat.fixture.test\n    return_paths: [/]\n"
        }
    };
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
    journeys_created_per_minute: 1
  adapters:
    - kind: openwebui_signed_header
      installation_id: fixture-installation
      header: x-openwebui-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_ROUTE_HMAC
      allowed_api_key_names: [owui]
{session}    - kind: openwebui_signed_header
      installation_id: plain
      header: x-plain-assertion
      issuer: open-webui
      hmac_secret_ref: env:OWUI_PLAIN_HMAC
      allowed_api_key_names: [owui]
  descriptors:
    {ACCOUNT}:
      mode: personal_managed
      provider: fixture
      resource: {RESOURCE}
      issuer: https://issuer.fixture.test
      redirect_uri: https://chat.fixture.test/accounts/v1/callback
{hosted}"#,
        env = env.display()
    ))
    .unwrap()
}

struct Gateway {
    router: axum::Router,
    _fixture: RevokeFixture,
    _dir: tempfile::TempDir,
}

async fn gateway(shape: Shape) -> Gateway {
    let dir = tempfile::tempdir().unwrap();
    let env = dir.path().join("adapter.env");
    std::fs::write(
        &env,
        format!("OWUI_ROUTE_HMAC={HMAC}\nOWUI_PLAIN_HMAC={PLAIN_HMAC}\nOWUI_ROUTE_STORE=UVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVE=\n"),
    )
    .unwrap();
    let config = config(&env, shape);
    let auth = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
    let (mut state, _store) = test_router_app_state_with(StreamingConfig::default(), config).await;
    Arc::get_mut(&mut state).unwrap().auth_config = auth;
    let fixture =
        RevokeFixture::start(ACCOUNT, RESOURCE, &[], RevocationEndpoint::Configured).await;
    let router = create_router_with_accounts(state, None, Some(fixture.handles()));
    Gateway {
        router,
        _fixture: fixture,
        _dir: dir,
    }
}

fn assertion(subject: &str) -> String {
    assertion_signed(HMAC, subject)
}

fn assertion_signed(secret: &str, subject: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"iss":"open-webui","sub":subject,"iat":now,"exp":now+120});
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// A request builder, authenticated as `subject` when one is given.
fn request(method: &str, uri: &str, subject: Option<&str>) -> axum::http::request::Builder {
    let builder = Request::builder().method(method).uri(uri);
    match subject {
        Some(subject) => builder
            .header("authorization", format!("Bearer {API_KEY}"))
            .header("x-openwebui-assertion", assertion(subject)),
        None => builder,
    }
}

async fn send(gw: &Gateway, request: Request<Body>) -> Response<Body> {
    gw.router.clone().oneshot(request).await.unwrap()
}

async fn json_of(response: Response<Body>) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create(gw: &Gateway, subject: &str, body: &Value) -> (StatusCode, Value) {
    let request = request("POST", "/accounts/v1/journeys", Some(subject))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    json_of(send(gw, request).await).await
}

async fn status_of(gw: &Gateway, subject: Option<&str>, id: &str) -> (StatusCode, Value) {
    let uri = format!("/accounts/v1/journeys/{id}");
    json_of(
        send(
            gw,
            request("GET", &uri, subject).body(Body::empty()).unwrap(),
        )
        .await,
    )
    .await
}

fn connect_body() -> Value {
    json!({"account_id": ACCOUNT, "return_path": "/"})
}

/// The Google redirect back, as a browser sends it (review L9).
fn callback(method: &str, path: &str, mode: &str, dest: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(format!("{path}?code=c&state=s"))
        .header("host", HOSTED_HOST)
        .header("sec-fetch-site", "cross-site")
        .header("sec-fetch-mode", mode)
        .header("sec-fetch-dest", dest)
}

async fn status_for(gw: &Gateway, builder: axum::http::request::Builder) -> StatusCode {
    send(gw, builder.body(Body::empty()).unwrap())
        .await
        .status()
}

const CALLBACK: &str = "/accounts/v1/callback";

/// T-GUARD: only the realistic top-level navigation reaches the callback.
#[tokio::test(flavor = "multi_thread")]
async fn guard_callback_navigation_reaches_handler_and_every_variant_is_refused() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    // WHEN / THEN: the real redirect reaches the 5c placeholder
    let reached = status_for(&gw, callback("GET", CALLBACK, "navigate", "document")).await;
    assert_eq!(reached, StatusCode::NOT_IMPLEMENTED);
    let refused = [
        callback("GET", CALLBACK, "cors", "document"),
        callback("GET", CALLBACK, "navigate", "iframe"),
        callback("POST", CALLBACK, "navigate", "document"),
        callback("GET", CALLBACK, "navigate", "document").header("origin", "null"),
        callback("GET", "/accounts/v1/callback/", "navigate", "document"),
        callback("GET", "/accounts/v1/callbackx", "navigate", "document"),
        callback(
            "GET",
            "/accounts/v1/journeys/x/start",
            "navigate",
            "document",
        ),
        callback("GET", "/accounts/v1/nope", "navigate", "document"),
        callback("GET", "/mcp", "navigate", "document"),
    ];
    for builder in refused {
        let label = format!("{:?}", builder.uri_ref());
        assert_eq!(
            status_for(&gw, builder).await,
            StatusCode::FORBIDDEN,
            "{label}"
        );
    }
}

/// T-GUARD: the hosted Host opens `/accounts/v1/` and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn guard_hosted_host_is_scoped_to_the_accounts_prefix() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    let on_host = |path: &str| Request::builder().uri(path).header("host", HOSTED_HOST);
    // WHEN / THEN
    assert_eq!(
        status_for(&gw, on_host("/accounts/v1/nope")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_for(&gw, on_host("/mcp")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        status_for(&gw, on_host("/accounts/v1")).await,
        StatusCode::FORBIDDEN
    );
    let same_origin = on_host("/accounts/v1/nope").header("origin", "https://chat.fixture.test");
    assert_eq!(status_for(&gw, same_origin).await, StatusCode::NOT_FOUND);
    let foreign = on_host("/accounts/v1/nope").header("origin", "https://evil.test");
    assert_eq!(status_for(&gw, foreign).await, StatusCode::FORBIDDEN);
}

/// T-GUARD2 (5a half): the exemption does not extend to `/complete`.
#[tokio::test(flavor = "multi_thread")]
async fn guard_cross_site_complete_is_refused() {
    let gw = gateway(Shape::Bridged).await;
    let complete = callback("GET", "/accounts/v1/complete", "navigate", "document");
    assert_eq!(status_for(&gw, complete).await, StatusCode::FORBIDDEN);
}

fn assert_hardened(response: &Response<Body>, label: &str) {
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(
        header("cache-control").as_deref(),
        Some("no-store"),
        "{label}"
    );
    assert_eq!(
        header("referrer-policy").as_deref(),
        Some("no-referrer"),
        "{label}"
    );
    assert_eq!(
        header("content-security-policy").as_deref(),
        Some(CSP),
        "{label}"
    );
}

/// T-HDR: the layer, not a handler, sets the three headers.
#[tokio::test(flavor = "multi_thread")]
async fn headers_every_accounts_response_is_hardened() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    let cases = [
        ("GET", "/accounts/v1/nope", None, StatusCode::NOT_FOUND),
        ("POST", CALLBACK, None, StatusCode::METHOD_NOT_ALLOWED),
        ("GET", CALLBACK, None, StatusCode::NOT_IMPLEMENTED),
        (
            "GET",
            "/accounts/v1/journeys/abc",
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/accounts/v1/journeys/abc",
            Some("alice"),
            StatusCode::NOT_FOUND,
        ),
    ];
    for (method, path, subject, expected) in cases {
        // WHEN
        let response = send(
            &gw,
            request(method, path, subject).body(Body::empty()).unwrap(),
        )
        .await;
        // THEN
        let label = format!("{method} {path}");
        assert_eq!(response.status(), expected, "{label}");
        assert_hardened(&response, &label);
    }
}

/// Without `accounts.hosted` the surface does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn not_hosted_accounts_prefix_is_plain_404() {
    let gw = gateway(Shape::NotHosted).await;
    for (method, path) in [("GET", CALLBACK), ("POST", "/accounts/v1/journeys")] {
        let response = send(
            &gw,
            request(method, path, Some("alice"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert!(response.headers().get("content-security-policy").is_none());
    }
    let on_host = Request::builder().uri(CALLBACK).header("host", HOSTED_HOST);
    assert_eq!(status_for(&gw, on_host).await, StatusCode::FORBIDDEN);
}

/// POST creates a pending journey whose status only its owner can read.
#[tokio::test(flavor = "multi_thread")]
async fn post_creates_journey_and_owner_reads_pending_status() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    // WHEN
    let (status, body) = create(&gw, "alice", &connect_body()).await;
    // THEN
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id = body["journey_id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 32);
    assert_eq!(
        body["start_url"],
        format!("https://chat.fixture.test/accounts/v1/journeys/{id}/start")
    );
    assert!(body["expires_at"].is_u64(), "{body}");
    let (status, view) = status_of(&gw, Some("alice"), &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["status"], "pending");
    assert!(!view.to_string().contains("token"), "{view}");
}

/// T-POST-NOBRIDGE: a principal of the adapter without `session` is refused
/// before the store, so the global creation budget of one is still unspent.
#[tokio::test(flavor = "multi_thread")]
async fn post_without_bridge_is_403_and_consumes_no_capacity() {
    // GIVEN: journeys_created_per_minute is 1
    let gw = gateway(Shape::Bridged).await;
    let plain = Request::builder()
        .method("POST")
        .uri("/accounts/v1/journeys")
        .header("authorization", format!("Bearer {API_KEY}"))
        .header("x-plain-assertion", assertion_signed(PLAIN_HMAC, "carol"))
        .header("content-type", "application/json")
        .body(Body::from(connect_body().to_string()))
        .unwrap();
    // WHEN
    let (status, body) = json_of(send(&gw, plain).await).await;
    // THEN: refused, and the one creation is still available afterwards
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "forbidden");
    assert_eq!(
        create(&gw, "alice", &connect_body()).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        create(&gw, "bob", &connect_body()).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// T-POST-NOBRIDGE (capacity half): refusals ahead of the store spend no
/// budget, so the one allowed creation still succeeds after them.
#[tokio::test(flavor = "multi_thread")]
async fn post_refused_before_store_leaves_creation_budget_intact() {
    // GIVEN: journeys_created_per_minute is 1
    let gw = gateway(Shape::Bridged).await;
    let long_account = json!({"account_id": "a".repeat(65), "return_path": "/"});
    let long_path = json!({"account_id": ACCOUNT, "return_path": format!("/{}", "p".repeat(256))});
    // WHEN
    let refusals = [
        create(&gw, "alice", &long_account).await,
        create(&gw, "alice", &long_path).await,
        create(
            &gw,
            "alice",
            &json!({"account_id": ACCOUNT, "return_path": "/x"}),
        )
        .await,
        create(
            &gw,
            "alice",
            &json!({"account_id": ACCOUNT, "return_path": "/", "principal": "bob"}),
        )
        .await,
    ];
    // THEN
    for (status, body) in refusals {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_request");
    }
    assert_eq!(
        create(&gw, "alice", &connect_body()).await.0,
        StatusCode::CREATED
    );
    let (status, body) = create(&gw, "bob", &connect_body()).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "budget of one is now spent"
    );
    assert_eq!(body["error"]["code"], "capacity_exceeded");
}

/// T-C07a (status half): neither anonymity nor another owner learns whether
/// a journey exists.
#[tokio::test(flavor = "multi_thread")]
async fn status_anonymous_and_other_owner_disclose_nothing() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    let (_, created) = create(&gw, "alice", &connect_body()).await;
    let id = created["journey_id"].as_str().unwrap();
    let missing = "0".repeat(32);
    // WHEN
    let anonymous_real = status_of(&gw, None, id).await;
    let anonymous_missing = status_of(&gw, None, &missing).await;
    let bob_real = status_of(&gw, Some("bob"), id).await;
    let bob_missing = status_of(&gw, Some("bob"), &missing).await;
    // THEN
    assert_eq!(anonymous_real.0, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous_real, anonymous_missing);
    assert_eq!(bob_real.0, StatusCode::NOT_FOUND);
    assert_eq!(bob_real, bob_missing);
    assert!(!bob_real.1.to_string().contains(ACCOUNT), "{}", bob_real.1);
}

#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every span and event at TRACE, on this thread only. The global registry
/// keeps callsite interest live when another test registered it first.
fn capture_trace() -> (Captured, tracing::subscriber::DefaultGuard) {
    use tracing_subscriber::fmt::format::FmtSpan;
    use tracing_subscriber::prelude::*;
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::Registry::default()
                .with(tracing::level_filters::LevelFilter::TRACE),
        );
    });
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(move || writer.clone())
        .finish();
    (captured, tracing::subscriber::set_default(subscriber))
}

/// §4.3: the accounts span records method and matched path only, and the
/// authenticated routes' `TraceLayer` never sees an `/accounts/v1` request.
#[tokio::test(flavor = "current_thread")]
async fn trace_accounts_requests_record_no_query_or_cookie() {
    // GIVEN
    let gw = gateway(Shape::Bridged).await;
    let (captured, guard) = capture_trace();
    // WHEN
    for path in [CALLBACK, "/accounts/v1/journeys/abc", "/accounts/v1/nope"] {
        let request = Request::builder()
            .uri(format!("{path}?code=SECRETQUERY&state=SECRETSTATE"))
            .header("cookie", "token=SECRETCOOKIE")
            .header("authorization", format!("Bearer {API_KEY}"))
            .body(Body::empty())
            .unwrap();
        send(&gw, request).await;
    }
    drop(guard);
    // THEN
    let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(
        output.contains("/accounts/v1/callback"),
        "positive control: {output}"
    );
    assert!(
        output.contains("/accounts/v1/journeys/{id}"),
        "matched path: {output}"
    );
    for secret in [
        "SECRETQUERY",
        "SECRETSTATE",
        "SECRETCOOKIE",
        API_KEY,
        "code=",
    ] {
        assert!(!output.contains(secret), "{secret} leaked: {output}");
    }
}
