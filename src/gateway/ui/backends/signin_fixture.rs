// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A gateway with one OAuth backend whose issuer is a loopback double, driven
//! through the real router with dashboard sessions, for the sign-in rows. The
//! flow is a real one: the link the start route returns is followed the way a
//! person's browser follows it.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig, OAuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
use crate::gateway::router::{AppState, create_router, tests::FixtureDir};
use crate::oauth::TokenInfo;
use crate::oauth::client::authorize_tests::{BACKEND, RESOURCE, client_on, token_endpoint};

pub(super) const ADMIN_KEY: &str = "signin-admin-key";
const STANDARD_KEY: &str = "signin-standard-key";
const AUTHORITY: &str = "127.0.0.1:39400";

/// Who calls: a dashboard session by its handle, or an admin bearer key alone.
#[derive(Clone)]
pub(super) enum Who {
    Dashboard(String),
    BearerOnly,
    /// A key without admin rights.
    Standard,
}

pub(super) struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    pub(super) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// The forms a token endpoint double received.
pub(super) type Forms = Arc<std::sync::Mutex<Vec<std::collections::HashMap<String, String>>>>;

pub(super) struct Gw {
    pub state: Arc<AppState>,
    pub backend: Arc<Backend>,
    pub issuer: String,
    pub store: std::sync::Arc<tempfile::TempDir>,
    pub forms: Forms,
    /// Every link the client announced at the terminal.
    pub announced: Arc<std::sync::Mutex<Vec<String>>>,
    /// The audit log the gateway appends admin actions to.
    pub log: Arc<crate::security::TransparencyLogger>,
    _fixture: FixtureDir,
}

fn api_key(secret: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: secret.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn oauth_block() -> OAuthConfig {
    OAuthConfig {
        enabled: true,
        scopes: Vec::new(),
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: None,
        shared_account: false,
    }
}

/// Whether the gateway has an audit log configured.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Audit {
    On,
    Off,
}

impl Gw {
    /// A gateway whose backend `BACKEND` signs in at a token endpoint that
    /// answers `access-a`.
    pub(super) async fn new() -> Self {
        let (issuer, forms) = token_endpoint(Some("access-a")).await;
        Self::over(issuer, forms).await
    }

    /// As [`Gw::new`], over the token endpoint at `issuer`.
    pub(super) async fn over(issuer: String, forms: Forms) -> Self {
        Self::over_on(issuer, forms, "127.0.0.1").await
    }

    /// As [`Gw::over`], with the callback server on `callback_host`.
    pub(super) async fn over_on(issuer: String, forms: Forms, callback_host: &str) -> Self {
        let store = crate::test_dir_keep::kept_tempdir();
        Self::build(issuer, forms, callback_host, store, Audit::On).await
    }

    /// A gateway process started again over the same issuer and token store:
    /// everything in memory is new, everything on disk is what `self` left.
    /// `self` is dropped first.
    pub(super) async fn restarted(self) -> Self {
        let (issuer, forms) = (self.issuer.clone(), Arc::clone(&self.forms));
        let Self { store, .. } = self;
        Self::build(issuer, forms, "127.0.0.1", store, Audit::On).await
    }

    /// As [`Gw::new`], on a gateway with no audit log configured: the admin
    /// layer then passes requests straight through to the handler.
    pub(super) async fn new_without_audit_log() -> Self {
        let (issuer, forms) = token_endpoint(Some("access-a")).await;
        let store = crate::test_dir_keep::kept_tempdir();
        Self::build(issuer, forms, "127.0.0.1", store, Audit::Off).await
    }

    async fn build(
        issuer: String,
        forms: Forms,
        callback_host: &str,
        store: std::sync::Arc<tempfile::TempDir>,
        audit: Audit,
    ) -> Self {
        let auth = AuthConfig {
            enabled: true,
            api_keys: vec![api_key(ADMIN_KEY, true), api_key(STANDARD_KEY, false)],
            ..AuthConfig::default()
        };
        let (mut state, fixture) =
            crate::gateway::router::tests::audience_state(&auth, (None, None), |m| m).await;
        let log = Arc::new(
            crate::security::TransparencyLogger::open(Arc::new(
                crate::security::transparency_log::TransparencyLogConfig {
                    enabled: true,
                    path: fixture
                        .path()
                        .join("audit.jsonl")
                        .to_string_lossy()
                        .into_owned(),
                    key_id: "signin".to_string(),
                    ..Default::default()
                },
            ))
            .expect("open log"),
        );
        if audit == Audit::On {
            Arc::get_mut(&mut state)
                .expect("state is unique")
                .transparency_log = Some(Arc::clone(&log));
        }
        let config = BackendConfig {
            oauth: Some(oauth_block()),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            BACKEND,
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let announced = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&announced);
        let oauth = client_on(store.path(), Some(&issuer), callback_host)
            .with_sign_in_status(Arc::clone(&backend.sign_in.status))
            .with_announce(Arc::new(move |url: &str| {
                recorder.lock().unwrap().push(url.to_owned());
            }));
        backend.install_oauth_client_for_test(oauth);
        assert!(
            state.backends.register(Arc::clone(&backend)),
            "registration"
        );
        Self {
            state,
            backend,
            issuer,
            store,
            forms,
            announced,
            log,
            _fixture: fixture,
        }
    }

    /// A new dashboard session.
    pub(super) fn session(&self) -> Who {
        Who::Dashboard(session_handle(&self.state))
    }

    /// Send `method` `path` as `who` with `content_type` and `body`.
    pub(super) async fn send(
        &self,
        who: &Who,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> Reply {
        self.send_from(AUTHORITY, who, method, path, content_type, body)
            .await
    }

    /// As [`Gw::send`], addressed to `authority`.
    pub(super) async fn send_from(
        &self,
        authority: &str,
        who: &Who,
        method: &str,
        path: &str,
        content_type: &str,
        body: &str,
    ) -> Reply {
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("http://{authority}{path}"))
            .header(header::CONTENT_TYPE, content_type);
        builder = match who {
            Who::Dashboard(handle) => {
                builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"))
            }
            Who::BearerOnly => builder.header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}")),
            Who::Standard => {
                builder.header(header::AUTHORIZATION, format!("Bearer {STANDARD_KEY}"))
            }
        };
        let request = builder
            .body(Body::from(body.to_owned()))
            .expect("request builds");
        let response = create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("the router is infallible");
        let (status, headers) = (response.status(), response.headers().clone());
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body reads");
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    fn signin_path(name: &str, suffix: &str) -> String {
        format!("/ui/api/backends/{name}/signin{suffix}")
    }

    /// `POST .../signin` with `{}`.
    pub(super) async fn start(&self, who: &Who) -> Reply {
        self.start_named(who, BACKEND).await
    }

    /// `POST /ui/api/backends/{name}/signin` with `{}`.
    pub(super) async fn start_named(&self, who: &Who, name: &str) -> Reply {
        self.send(
            who,
            "POST",
            &Self::signin_path(name, ""),
            "application/json",
            "{}",
        )
        .await
    }

    /// `POST .../signin/confirm` with an attempt id and a decision.
    pub(super) async fn confirm(&self, who: &Who, attempt_id: &str, decision: &str) -> Reply {
        let body = json!({ "attempt_id": attempt_id, "decision": decision }).to_string();
        self.send(
            who,
            "POST",
            &Self::signin_path(BACKEND, "/confirm"),
            "application/json",
            &body,
        )
        .await
    }

    /// The `authorization_url` and `attempt_id` of a start answer.
    pub(super) fn link(reply: &Reply) -> (String, String) {
        let body = reply.json();
        let text = |key: &str| body[key].as_str().unwrap_or_default().to_owned();
        let url = text("authorization_url");
        // Every row that follows a link first needs a started flow: a missing
        // link fails here, naming the start answer, not later in a URL parse.
        assert!(
            reply.status == StatusCode::OK && !url.is_empty(),
            "the start answer carries an authorization link: {} {}",
            reply.status,
            reply.body
        );
        (url, text("attempt_id"))
    }

    /// The person approving at the identity provider: follow the redirect
    /// URI with a code and the link's own state.
    pub(super) async fn approve(&self, url: &str) -> String {
        self.try_approve(url).await.expect("the callback answers")
    }

    /// [`Gw::approve`] for a callback that may find nobody listening: `None`
    /// when the connection is refused.
    pub(super) async fn try_approve(&self, url: &str) -> Option<String> {
        let link = url::Url::parse(url).expect("an authorization URL");
        let query: std::collections::HashMap<String, String> =
            link.query_pairs().into_owned().collect();
        let mut callback = url::Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("code", "fixture-code"),
                ("state", query["state"].as_str()),
                ("iss", self.issuer.as_str()),
            ],
        )
        .expect("a callback URL");
        // Never resolve a name: connect to the literal address and send the
        // configured name as `Host`.
        let named = callback.host_str().map(str::to_owned).unwrap_or_default();
        if named == "localhost" {
            callback
                .set_host(Some("127.0.0.1"))
                .expect("a literal host");
        }
        let page = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .header(
                header::HOST,
                format!("{named}:{}", link_port(&query["redirect_uri"])),
            )
            .send()
            .await
            .ok()?;
        Some(page.text().await.unwrap_or_default())
    }

    /// The backend's row in `GET /ui/api/status`.
    pub(super) async fn row(&self) -> Value {
        self.row_named(BACKEND).await
    }

    /// The row of `name` in `GET /ui/api/status`.
    pub(super) async fn row_named(&self, name: &str) -> Value {
        let reply = self
            .send(
                &Who::BearerOnly,
                "GET",
                "/ui/api/status",
                "application/json",
                "",
            )
            .await;
        let rows = reply.json()["servers"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        rows.into_iter()
            .find(|row| row["name"] == name)
            .unwrap_or(Value::Null)
    }

    /// The token the store holds for this backend, if any.
    pub(super) fn saved(&self) -> Option<TokenInfo> {
        let key = crate::oauth::client::storage_key(BACKEND, &self.issuer);
        crate::oauth::TokenStorage::new(self.store.path().to_path_buf())
            .ok()?
            .load(&key, RESOURCE)
    }

    /// Every `admin_action` record the gateway has appended, as JSON.
    pub(super) fn admin_actions(&self) -> Vec<Value> {
        std::fs::read_to_string(self.log.path())
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|entry| entry["event"] == "admin_action")
            .collect()
    }

    /// Revoke a dashboard session through the store's own path.
    pub(super) fn revoke(&self, who: &Who) {
        let Who::Dashboard(handle) = who else { return };
        let config = self.state.live_config.get();
        let limits = SessionLimits::from(&config.auth.dashboard_session);
        assert!(
            self.state
                .dashboard_bootstrap
                .revoke(handle, Now::read(), &limits)
        );
    }

    /// Register one more backend.
    pub(super) fn add_backend(&self, backend: Backend) {
        assert!(
            self.state.backends.register(Arc::new(backend)),
            "registration"
        );
    }

    /// Open the UI event stream as `who`.
    pub(super) async fn open_stream(&self, who: &Who) -> axum::body::BodyDataStream {
        let mut builder = Request::builder()
            .uri(format!("http://{AUTHORITY}/ui/api/stream"))
            .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                52_346,
            ))));
        if let Who::Dashboard(handle) = who {
            builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
        }
        let request = builder.body(Body::empty()).expect("request builds");
        let response = create_router(Arc::clone(&self.state))
            .oneshot(request)
            .await
            .expect("infallible");
        assert_eq!(response.status(), StatusCode::OK, "the stream opens");
        response.into_body().into_data_stream()
    }
}

/// The port of a redirect URI.
fn link_port(redirect_uri: &str) -> u16 {
    url::Url::parse(redirect_uri)
        .ok()
        .and_then(|u| u.port())
        .unwrap_or(80)
}

/// Everything the stream sends until `needle` has arrived or `span` of the real
/// clock has passed.
pub(super) async fn stream_until(
    stream: &mut axum::body::BodyDataStream,
    needle: &str,
    span: Duration,
) -> String {
    use futures::StreamExt;
    let mut text = String::new();
    let end = std::time::Instant::now() + span;
    while !text.contains(needle) {
        let Some(left) = end.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match tokio::time::timeout(left, stream.next()).await {
            Ok(Some(Ok(chunk))) => text.push_str(&String::from_utf8_lossy(&chunk)),
            _ => break,
        }
    }
    text
}

/// The handle of a new dashboard session in `state`, as a redeemed link
/// would issue it.
pub(super) fn session_handle(state: &AppState) -> String {
    let config = state.live_config.get();
    let limits = SessionLimits::from(&config.auth.dashboard_session);
    state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits)
}

impl Gw {
    /// Wait, without moving any clock, until the flow holds the token the
    /// callback bought: the exchange has finished. A row that pauses time
    /// does so only after this, so a paused clock never runs ahead of a
    /// request still in flight.
    pub(super) async fn wait_until_held(&self) {
        for _ in 0..20_000 {
            if self
                .backend
                .with_flow(|slot| slot.as_ref().is_some_and(|flow| flow.grant.is_some()))
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the exchange did not finish");
    }
}
