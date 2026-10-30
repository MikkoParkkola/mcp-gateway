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
use crate::oauth::client::authorize_tests::{BACKEND, RESOURCE, client, token_endpoint};

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
    pub store: tempfile::TempDir,
    pub forms: Forms,
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

impl Gw {
    /// A gateway whose backend `BACKEND` signs in at a token endpoint that
    /// answers `access-a`.
    pub(super) async fn new() -> Self {
        let (issuer, forms) = token_endpoint(Some("access-a")).await;
        Self::over(issuer, forms).await
    }

    /// As [`Gw::new`], over the token endpoint at `issuer`.
    pub(super) async fn over(issuer: String, forms: Forms) -> Self {
        let auth = AuthConfig {
            enabled: true,
            api_keys: vec![api_key(ADMIN_KEY, true), api_key(STANDARD_KEY, false)],
            ..AuthConfig::default()
        };
        let (state, fixture) =
            crate::gateway::router::tests::audience_state(&auth, (None, None), |m| m).await;
        let store = tempfile::tempdir().expect("token store");
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
        let oauth = client(store.path(), Some(&issuer))
            .with_sign_in_status(Arc::clone(&backend.sign_in_status));
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
            _fixture: fixture,
        }
    }

    /// A new dashboard session.
    pub(super) fn session(&self) -> Who {
        let config = self.state.live_config.get();
        let limits = SessionLimits::from(&config.auth.dashboard_session);
        Who::Dashboard(
            self.state
                .dashboard_bootstrap
                .issue_session_at(Now::read(), &limits),
        )
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
        let mut builder = Request::builder()
            .method(method)
            .uri(format!("http://{AUTHORITY}{path}"))
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
        (text("authorization_url"), text("attempt_id"))
    }

    /// The person approving at the identity provider: follow the redirect
    /// URI with a code and the link's own state.
    pub(super) async fn approve(&self, url: &str) {
        let link = url::Url::parse(url).expect("an authorization URL");
        let query: std::collections::HashMap<String, String> =
            link.query_pairs().into_owned().collect();
        let callback = url::Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("code", "fixture-code"),
                ("state", query["state"].as_str()),
                ("iss", self.issuer.as_str()),
            ],
        )
        .expect("a callback URL");
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .send()
            .await
            .expect("the callback answers");
    }

    /// The backend's row in `GET /ui/api/status`.
    pub(super) async fn row(&self) -> Value {
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
            .find(|row| row["name"] == BACKEND)
            .unwrap_or(Value::Null)
    }

    /// The token the store holds for this backend, if any.
    pub(super) fn saved(&self) -> Option<TokenInfo> {
        let key = crate::oauth::client::storage_key(BACKEND, &self.issuer);
        crate::oauth::TokenStorage::new(self.store.path().to_path_buf())
            .ok()?
            .load(&key, RESOURCE)
    }
}
