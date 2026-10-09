// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! COV.3 wave 7: the branches of the grants and of `initialize` no other test
//! reaches: a shared login's joiner, an unchanged stored token, the refusals
//! of the client-credentials and code-exchange answers, and their telemetry.

use std::sync::Arc;

use super::*;
use crate::oauth::login_gate::{Begin, LoginGate};

const RESOURCE: &str = "https://backend.example.com/mcp";
const BACKEND: &str = "grants-backend";
const CLIENT_ID: &str = "grants-client";

/// An endpoint on loopback answering every POST to `/token` with `status`
/// and `body`. Returns its base URL, which also serves as the issuer.
async fn token_endpoint(status: u16, body: &'static str) -> String {
    use axum::{Router, http::StatusCode, routing::post};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/token",
        post(move || async move {
            (
                StatusCode::from_u16(status).unwrap(),
                [("content-type", "application/json")],
                body,
            )
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    base
}

/// A client with a configured id whose authorization server is `issuer`,
/// advertising `grants` in `grant_types_supported`.
fn client(dir: &std::path::Path, issuer: &str, grants: &[&str]) -> OAuthClient {
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::new(
        Client::builder().no_proxy().build().unwrap(),
        BACKEND.to_string(),
        RESOURCE.to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            client_id: Some(CLIENT_ID.to_string()),
            ..OAuthClientConfig::default()
        },
    );
    client.auth_metadata = Some(
        serde_json::from_value(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "grant_types_supported": grants,
        }))
        .unwrap(),
    );
    client
}

fn live_token(access: &str) -> TokenInfo {
    TokenInfo::from_response(
        access.to_string(),
        Some("Bearer".to_string()),
        Some("refresh".to_string()),
        Some(3600),
        None,
    )
}

/// Run `work` on a current-thread runtime under a TRACE log capture, so the
/// fields of every event are evaluated; returns its output and the records.
fn logged<T>(work: impl std::future::Future<Output = T>) -> (T, Vec<serde_json::Value>) {
    let mut out = None;
    let records = crate::test_log_capture::records(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        out = Some(runtime.block_on(work));
    });
    (out.expect("the work ran"), records)
}

/// The one record whose message is `message`.
fn record<'a>(records: &'a [serde_json::Value], message: &str) -> &'a serde_json::Value {
    let found: Vec<_> = records
        .iter()
        .filter(|r| r["fields"]["message"] == message)
        .collect();
    let [one] = found.as_slice() else {
        panic!("one {message:?} record, got: {records:?}");
    };
    one
}

// ---------------------------------------------------------------------------
// authorize_shared
// ---------------------------------------------------------------------------

/// A caller that is not interactive never begins or joins a login: it is told
/// authorization is required, naming its backend.
#[tokio::test]
async fn a_non_interactive_caller_is_told_authorization_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://as.example", &[])
        .with_login_gate(Arc::new(LoginGate::default()));

    let refused = client.authorize_shared(false, None).await;

    assert!(
        matches!(refused, Err(Error::AuthorizationRequired { ref backend }) if backend == BACKEND),
        "{refused:?}"
    );
}

/// A gate that refuses (the backend stopped) ends the caller as cancelled.
#[tokio::test]
async fn a_refusing_gate_ends_the_caller_as_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    gate.close().await;
    let client = client(dir.path(), "https://as.example", &[]).with_login_gate(gate);

    let refused = client.authorize_shared(true, None).await;

    assert!(
        matches!(refused, Err(Error::AuthorizationCancelled { ref backend }) if backend == BACKEND),
        "{refused:?}"
    );
}

/// A joiner whose shared login ended without a token gets that login's
/// outcome as its own typed error.
#[tokio::test]
async fn a_joiner_of_a_failed_login_gets_its_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    let Begin::Lead(lead) = gate.begin(None) else {
        panic!("no login in flight, so the test leads");
    };
    let client = client(dir.path(), "https://as.example", &[]).with_login_gate(gate);

    let (joined, ()) = tokio::join!(client.authorize_shared(true, None), async {
        tokio::task::yield_now().await;
        lead.end(Some(&Error::OAuth("invalid_grant from the AS".to_string())));
    });

    assert!(
        matches!(joined, Err(Error::OAuth(ref m)) if m == "invalid_grant from the AS"),
        "{joined:?}"
    );
}

/// A joiner whose shared login completed but stored no token gets an OAuth
/// error saying so, never a token it does not have.
#[tokio::test]
async fn a_joiner_of_a_login_that_stored_no_token_gets_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new(LoginGate::default());
    let Begin::Lead(lead) = gate.begin(None) else {
        panic!("no login in flight, so the test leads");
    };
    let client = client(dir.path(), "https://as.example", &[]).with_login_gate(gate);

    let (joined, ()) = tokio::join!(client.authorize_shared(true, None), async {
        tokio::task::yield_now().await;
        lead.end(None);
    });

    assert!(
        matches!(joined, Err(Error::OAuth(ref m)) if m.contains("stored no token")),
        "{joined:?}"
    );
}

/// A joiner whose shared login stored a live token takes that token up.
#[tokio::test]
async fn a_joiner_of_a_login_that_stored_a_token_takes_it_up() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = "https://as.example";
    let gate = Arc::new(LoginGate::default());
    let Begin::Lead(lead) = gate.begin(None) else {
        panic!("no login in flight, so the test leads");
    };
    let client = client(dir.path(), issuer, &[]).with_login_gate(gate);
    let key = storage_key(BACKEND, issuer);

    let (joined, ()) = tokio::join!(client.authorize_shared(true, None), async {
        tokio::task::yield_now().await;
        client
            .storage
            .save(&key, RESOURCE, &live_token("shared-access"))
            .unwrap();
        lead.end(None);
    });

    assert_eq!(joined.unwrap(), "shared-access");
}

// ---------------------------------------------------------------------------
// adopt_if_fresher
// ---------------------------------------------------------------------------

/// A stored token identical to this client's live cached one is no fresher:
/// nothing is adopted and the refresh goes ahead.
#[test]
fn a_stored_token_equal_to_the_live_cached_one_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://as.example", &[]);
    let token = live_token("same-access");
    *client.current_token.write() = Some(token.clone());

    let adopted = RefreshCaller::adopt(&client, Some(&token));

    assert_eq!(adopted, None);
    assert_eq!(
        client
            .current_token
            .read()
            .as_ref()
            .map(|t| t.access_token.as_str()),
        Some("same-access")
    );
}

// ---------------------------------------------------------------------------
// try_client_credentials
// ---------------------------------------------------------------------------

/// A server that does not advertise `client_credentials` is never sent one.
#[tokio::test]
async fn client_credentials_is_refused_when_the_server_does_not_advertise_it() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), "https://as.example", &["authorization_code"]);

    let refused = client.try_client_credentials().await;

    assert!(
        matches!(refused, Err(Error::OAuth(ref m)) if m == "Server does not support client_credentials grant"),
        "{refused:?}"
    );
}

/// A refused client-credentials request is an OAuth error naming the grant
/// and the status.
#[tokio::test]
async fn a_refused_client_credentials_request_is_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = token_endpoint(401, r#"{"error":"invalid_client"}"#).await;
    let client = client(dir.path(), &issuer, &["client_credentials"]);

    let refused = client.try_client_credentials().await;

    let Err(Error::OAuth(message)) = refused else {
        panic!("an OAuth error: {refused:?}");
    };
    assert!(
        message.starts_with("Client credentials failed"),
        "{message}"
    );
    assert!(message.contains("401"), "{message}");
    assert!(!client.has_valid_token(), "no token was cached");
}

/// A 2xx client-credentials answer that is not a token response is an OAuth
/// parse error, and nothing is cached or stored.
#[tokio::test]
async fn an_unparseable_client_credentials_answer_is_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = token_endpoint(200, r#"{"not":"a token"}"#).await;
    let client = client(dir.path(), &issuer, &["client_credentials"]);

    let refused = client.try_client_credentials().await;

    assert!(
        matches!(refused, Err(Error::OAuth(ref m)) if m.starts_with("Failed to parse credentials response")),
        "{refused:?}"
    );
    let key = storage_key(BACKEND, &issuer);
    assert!(
        client.storage.load(&key, RESOURCE).is_none(),
        "nothing stored"
    );
}

/// A granted client-credentials token is returned, cached, stored, and
/// logged as a renewal for this backend.
#[test]
fn a_granted_client_credentials_token_is_stored_and_logged() {
    let dir = tempfile::tempdir().unwrap();
    let ((access, client, issuer), records) = logged(async {
        let issuer = token_endpoint(
            200,
            r#"{"access_token":"cc-access","token_type":"Bearer","expires_in":3600}"#,
        )
        .await;
        let client = client(dir.path(), &issuer, &["client_credentials"]);
        let access = client.try_client_credentials().await.unwrap();
        (access, client, issuer)
    });

    assert_eq!(access, "cc-access");
    assert!(client.has_valid_token());
    let stored = client
        .storage
        .load(&storage_key(BACKEND, &issuer), RESOURCE);
    assert_eq!(stored.map(|t| t.access_token).as_deref(), Some("cc-access"));
    let renewed = record(&records, "Token renewed via client_credentials");
    assert_eq!(renewed["fields"]["backend"], BACKEND);
}

// ---------------------------------------------------------------------------
// exchange_code
// ---------------------------------------------------------------------------

/// A refused code exchange is an OAuth error, and its failure event carries
/// the HTTP status for the operator.
#[test]
fn a_refused_code_exchange_logs_its_status_and_is_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let (refused, records) = logged(async {
        let issuer = token_endpoint(400, r#"{"error":"invalid_grant"}"#).await;
        let client = client(dir.path(), &issuer, &[]);
        client
            .exchange_code("code", "http://127.0.0.1:9/cb", "verifier")
            .await
    });

    let Err(Error::OAuth(message)) = refused else {
        panic!("an OAuth error: {refused:?}");
    };
    assert!(message.starts_with("Token exchange failed"), "{message}");
    let failure = record(&records, "OAuth token exchange failed");
    assert_eq!(failure["fields"]["http_status"], 400);
    assert_eq!(failure["fields"]["event"], "oauth.token_exchange.failure");
}

/// A 2xx code-exchange answer that is not a token response is an OAuth parse
/// error.
#[tokio::test]
async fn an_unparseable_code_exchange_answer_is_an_oauth_error() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = token_endpoint(200, "not json at all").await;
    let client = client(dir.path(), &issuer, &[]);

    let refused = client
        .exchange_code("code", "http://127.0.0.1:9/cb", "verifier")
        .await;

    assert!(
        matches!(refused, Err(Error::OAuth(ref m)) if m.starts_with("Failed to parse token response")),
        "{refused:?}"
    );
}

/// A successful code exchange returns the token, and its success event says
/// whether a refresh token came with it.
#[test]
fn a_successful_code_exchange_logs_whether_a_refresh_token_came() {
    let dir = tempfile::tempdir().unwrap();
    let (token, records) = logged(async {
        let issuer = token_endpoint(
            200,
            r#"{"access_token":"code-access","token_type":"Bearer","expires_in":60,"refresh_token":"r1"}"#,
        )
        .await;
        let client = client(dir.path(), &issuer, &[]);
        client
            .exchange_code("code", "http://127.0.0.1:9/cb", "verifier")
            .await
            .unwrap()
    });

    assert_eq!(token.access_token, "code-access");
    assert_eq!(token.refresh_token.as_deref(), Some("r1"));
    let success = record(&records, "OAuth token exchange succeeded");
    assert_eq!(success["fields"]["has_refresh_token"], true);
    assert_eq!(success["fields"]["expires_in"], 60);
}

// ---------------------------------------------------------------------------
// initialize / restore_persisted_client_id
// ---------------------------------------------------------------------------

/// Serve a protected-resource document that names no authorization server
/// but advertises `scopes`, and authorization-server metadata whose issuer is
/// the serving origin. Returns that origin.
async fn discovery_documents(scopes: &'static [&'static str]) -> String {
    use axum::{Json, Router, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let as_body = serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
    });
    let prm_body = serde_json::json!({ "resource": base, "scopes_supported": scopes });
    let app = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(move || async move { Json(as_body) }),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(move || async move { Json(prm_body) }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await });
    base
}

/// `initialize` with no configured scopes takes the resource's advertised
/// ones, loads the token already stored under the discovered issuer, and
/// logs both the resource document and its completion.
#[test]
fn initialize_adopts_advertised_scopes_and_the_stored_token() {
    let dir = tempfile::tempdir().unwrap();
    let ((initialized, client), records) = logged(async {
        let base = discovery_documents(&["read", "write"]).await;
        let storage = Arc::new(TokenStorage::new(dir.path().to_path_buf()).unwrap());
        storage
            .save(
                &storage_key(BACKEND, &base),
                &format!("{base}/mcp"),
                &live_token("cached-access"),
            )
            .unwrap();
        let mut client = OAuthClient::new(
            Client::builder().no_proxy().build().unwrap(),
            BACKEND.to_string(),
            format!("{base}/mcp"),
            vec![],
            storage,
            OAuthClientConfig::default(),
        );
        let initialized = client.initialize().await;
        (initialized, client)
    });

    initialized.expect("discovery succeeds");
    assert_eq!(client.scopes, vec!["read".to_string(), "write".to_string()]);
    assert_eq!(
        client
            .current_token
            .read()
            .as_ref()
            .map(|t| t.access_token.clone()),
        Some("cached-access".to_string()),
        "the stored token is loaded"
    );
    assert!(
        records
            .iter()
            .any(|r| r["fields"]["message"] == "Found protected resource metadata")
    );
    let done = record(&records, "OAuth client initialized");
    assert_eq!(done["fields"]["backend"], BACKEND);
}

/// Before an issuer is discovered there is no key to restore a registered id
/// under: the restore is a no-op and leaves no id behind.
#[test]
fn restoring_a_client_id_without_a_discovered_issuer_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client(dir.path(), "https://as.example", &[]);
    *client.client_id.write() = None;
    *client.client_id_source.write() = None;
    client.auth_metadata = None;

    client.restore_persisted_client_id();

    assert!(client.client_id.read().is_none());
    assert!(client.client_id_source.read().is_none());
}
