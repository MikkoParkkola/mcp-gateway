// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: the authorization-code flow end to end, against a mock
//! authorization server on loopback, and `get_token`'s three ways to a token.
//!
//! The browser is the one seam: `open_browser` hands the authorization URL to
//! the test, which plays the person who approves it by calling the callback.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;

const RESOURCE: &str = "https://backend.example.com/mcp";
const BACKEND: &str = "cov3-backend";
const CLIENT_ID: &str = "cov3-client";
/// The code the person at the browser approves: distinctive, so a log search
/// for it cannot match anything else.
const APPROVED_CODE: &str = "code-7f3a91e2-never-logged";

/// Every form the token endpoint received, in arrival order.
type Forms = Arc<Mutex<Vec<HashMap<String, String>>>>;

/// A token endpoint on loopback. `Some(token)` answers with that access token;
/// `None` refuses every request with `invalid_grant`.
async fn token_endpoint(answer: Option<&'static str>) -> (String, Forms) {
    token_endpoint_issuing(answer, Some("r-next")).await
}

/// As [`token_endpoint`], answering with `refresh` as the refresh token, or
/// with none at all, as a server that keeps its refresh tokens does.
async fn token_endpoint_issuing(
    answer: Option<&'static str>,
    refresh: Option<&'static str>,
) -> (String, Forms) {
    use axum::{Form, Json, Router, http::StatusCode, response::IntoResponse, routing::post};
    let forms: Forms = Arc::default();
    let seen = Arc::clone(&forms);
    let app = Router::new().route(
        "/token",
        post(move |Form(form): Form<HashMap<String, String>>| {
            seen.lock().unwrap().push(form);
            async move {
                match answer {
                    Some(token) => {
                        let mut body = serde_json::json!({
                            "access_token": token,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        });
                        if let Some(refresh) = refresh {
                            body["refresh_token"] = refresh.into();
                        }
                        Json(body).into_response()
                    }
                    None => (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "invalid_grant" })),
                    )
                        .into_response(),
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });
    (base, forms)
}

/// A client whose authorization server is `issuer`, with a configured client
/// id (no registration) and a loopback callback on a port the OS picks.
fn client(dir: &std::path::Path, issuer: Option<&str>) -> OAuthClient {
    let storage = Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap());
    let mut client = OAuthClient::new(
        Client::builder().no_proxy().build().unwrap(),
        BACKEND.to_string(),
        RESOURCE.to_string(),
        vec![],
        storage,
        OAuthClientConfig {
            client_id: Some(CLIENT_ID.to_string()),
            callback_host: Some("127.0.0.1".to_string()),
            ..OAuthClientConfig::default()
        },
    );
    client.auth_metadata = issuer.map(|issuer| {
        serde_json::from_value(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        }))
        .unwrap()
    });
    client
}

#[derive(Clone, Copy)]
enum Expiry {
    Live,
    Expired,
}

fn token(access: &str, refresh: Option<&str>, expiry: Expiry) -> TokenInfo {
    let mut token = TokenInfo::from_response(
        access.to_string(),
        Some("Bearer".to_string()),
        refresh.map(str::to_string),
        Some(3600),
        None,
    );
    if matches!(expiry, Expiry::Expired) {
        token.expires_at = Some(1);
    }
    token
}

/// Which call starts the flow.
#[derive(Clone, Copy)]
enum Entry {
    Authorize,
    GetToken,
}

/// Whether the system browser opened. When it did not, the URL is printed
/// for the person to visit by hand, and the flow goes on the same way.
#[derive(Clone, Copy)]
enum Browser {
    Opens,
    Fails,
}

/// Run the flow while playing the person at the browser: read the URL it
/// hands over, then call its callback with `code`, the URL's own state and
/// `iss`. Returns the flow's outcome and the authorization URL's query.
async fn approve(client: &mut OAuthClient, iss: &str) -> (Result<String>, HashMap<String, String>) {
    approve_via(client, iss, Entry::Authorize, Browser::Opens).await
}

async fn approve_via(
    client: &mut OAuthClient,
    iss: &str,
    entry: Entry,
    browser: Browser,
) -> (Result<String>, HashMap<String, String>) {
    let (url_tx, mut url_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    client.open_browser = Box::new(move |url| {
        url_tx.send(url.to_string()).is_ok() && matches!(browser, Browser::Opens)
    });
    let person = async move {
        let opened = tokio::time::timeout(Duration::from_secs(10), url_rx.recv())
            .await
            .expect("authorize opens the browser")
            .expect("an authorization URL");
        let mut query: HashMap<String, String> = Url::parse(&opened)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        query.insert("__url".to_string(), opened.clone());
        // Follow the advertised redirect URI as given, as a browser does.
        let callback = Url::parse_with_params(
            &query["redirect_uri"],
            &[
                ("code", APPROVED_CODE),
                ("state", query["state"].as_str()),
                ("iss", iss),
            ],
        )
        .unwrap();
        Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(callback)
            .send()
            .await
            .expect("the callback answers");
        query
    };
    let flow = async {
        match entry {
            Entry::Authorize => client.authorize().await,
            Entry::GetToken => client.get_token().await,
        }
    };
    let (outcome, query) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(flow, person)
    })
    .await
    .expect("the flow finishes");
    (outcome, query)
}

#[tokio::test]
async fn authorize_redeems_a_code_only_after_the_callback_proves_state_and_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-a")).await;
    let mut client = client(dir.path(), Some(&issuer));

    let (outcome, query) = approve(&mut client, &issuer).await;

    assert_eq!(outcome.expect("the flow completes"), "access-a");
    assert_eq!(query["response_type"], "code");
    assert!(
        query["__url"].starts_with(&format!("{issuer}/authorize?")),
        "the browser is sent to the configured authorization endpoint: {}",
        query["__url"]
    );
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(
        query["redirect_uri"].starts_with("http://127.0.0.1:"),
        "the redirect names the configured callback host"
    );
    assert!(!query["state"].is_empty(), "a CSRF state is sent");

    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "exactly one code redemption: {forms:?}");
    let form = &forms[0];
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], APPROVED_CODE);
    assert_eq!(form["redirect_uri"], query["redirect_uri"]);
    // PKCE: the verifier redeemed is the one the challenge in the URL commits to.
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form["code_verifier"].as_bytes()));
    assert_eq!(challenge, query["code_challenge"]);

    assert!(client.has_valid_token());
    let saved = TokenStorage::new(dir.path().to_path_buf())
        .unwrap()
        .load(&storage_key(BACKEND, &issuer), RESOURCE)
        .expect("the token is saved under this issuer");
    assert_eq!(saved.access_token, "access-a");
}

// An authorization code is a credential: no log line may carry it, at any
// level up to DEBUG, anywhere in the flow that receives and redeems it, on
// success or on either refusal after the code has arrived.
#[tokio::test]
async fn the_authorization_code_never_reaches_the_log() {
    enum Path {
        Redeemed,
        RedemptionRefused,
        AnotherIssuer,
    }
    for path in [Path::Redeemed, Path::RedemptionRefused, Path::AnotherIssuer] {
        let (guard, buffer) = crate::oauth::callback::tests::capture();
        let dir = tempfile::tempdir().unwrap();
        let answer = match path {
            Path::RedemptionRefused => None,
            _ => Some("access-a"),
        };
        let (issuer, _forms) = token_endpoint(answer).await;
        let mut client = client(dir.path(), Some(&issuer));
        let iss = match path {
            Path::AnotherIssuer => "https://other-as.example".to_string(),
            _ => issuer.clone(),
        };

        let (outcome, _query) = approve(&mut client, &iss).await;
        drop(guard);

        assert_eq!(outcome.is_ok(), matches!(path, Path::Redeemed));
        let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("oauth.callback.success"),
            "the capture saw the flow's DEBUG events: {log}"
        );
        assert!(
            !log.contains(APPROVED_CODE),
            "the authorization code was logged: {log}"
        );
    }
}

#[tokio::test]
async fn authorize_refuses_a_code_from_another_issuer_without_redeeming_it() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-a")).await;
    let mut client = client(dir.path(), Some(&issuer));

    let (outcome, _) = approve(&mut client, "https://other-as.example").await;

    let error = outcome.expect_err("a code from another issuer is refused");
    assert!(
        error.to_string().to_lowercase().contains("issuer"),
        "{error}"
    );
    assert!(
        forms.lock().unwrap().is_empty(),
        "the code must never reach this server's token endpoint"
    );
    assert!(!client.has_valid_token());
    assert!(
        TokenStorage::new(dir.path().to_path_buf())
            .unwrap()
            .load(&storage_key(BACKEND, &issuer), RESOURCE)
            .is_none()
    );
}

#[tokio::test]
async fn get_token_serves_a_live_cached_token_without_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-b")).await;
    let client = client(dir.path(), Some(&issuer));
    *client.current_token.write() = Some(token("access-live", Some("r1"), Expiry::Live));

    assert_eq!(client.get_token().await.unwrap(), "access-live");
    assert!(
        forms.lock().unwrap().is_empty(),
        "a live token costs no request"
    );
}

#[tokio::test]
async fn get_token_refreshes_an_expired_token() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-b")).await;
    let client = client(dir.path(), Some(&issuer));
    cache_and_store(&client, token("access-old", Some("r1"), Expiry::Expired));

    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "{forms:?}");
    assert_eq!(forms[0]["grant_type"], "refresh_token");
    assert_eq!(forms[0]["refresh_token"], "r1");
}

/// Cache `token` in `client` and store it as the credential, as a login does:
/// a refresh sends the stored refresh token, never an in-memory one (MIK-8018).
fn cache_and_store(client: &OAuthClient, token: TokenInfo) {
    let key = client.credential_key().unwrap();
    client.storage.save(&key, RESOURCE, &token).unwrap();
    *client.current_token.write() = Some(token);
}

/// Expire the stored record and the cached copy alike, so the next
/// `get_token` refreshes rather than taking up a fresher stored token
/// (MIK-8018: a client adopts a fresh stored token instead of refreshing).
fn expire_stored_and_cached(client: &OAuthClient) {
    let key = client.credential_key().unwrap();
    let mut stored = client.storage.load(&key, RESOURCE).expect("a stored token");
    stored.expires_at = Some(1);
    client.storage.save(&key, RESOURCE, &stored).unwrap();
    *client.current_token.write() = Some(stored);
}

/// MIK-8021.KEEPRT.1: a server that answers a refresh without a new refresh
/// token means "keep the one you have" (RFC 6749 section 6). The kept token
/// must survive in memory and in storage, so the next expiry refreshes again
/// instead of sending the user through a login.
#[tokio::test]
async fn a_refresh_without_a_new_refresh_token_keeps_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint_issuing(Some("access-b"), None).await;
    let client = client(dir.path(), Some(&issuer));
    cache_and_store(&client, token("access-old", Some("r1"), Expiry::Expired));

    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let cached = client.current_token.read().clone().expect("a cached token");
    assert_eq!(cached.refresh_token.as_deref(), Some("r1"), "cached");
    let key = client.credential_key().unwrap();
    let stored = client.storage.load(&key, RESOURCE).expect("a stored token");
    assert_eq!(stored.refresh_token.as_deref(), Some("r1"), "stored");

    // The next expiry refreshes headlessly with the kept token.
    expire_stored_and_cached(&client);
    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 2, "{forms:?}");
    assert_eq!(forms[1]["refresh_token"], "r1");
}

/// MIK-8021.KEEPRT.2: a server that rotates is still followed.
#[tokio::test]
async fn a_refresh_with_a_new_refresh_token_stores_the_new_one() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-b")).await;
    let client = client(dir.path(), Some(&issuer));
    cache_and_store(&client, token("access-old", Some("r1"), Expiry::Expired));

    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let cached = client.current_token.read().clone().expect("a cached token");
    assert_eq!(cached.refresh_token.as_deref(), Some("r-next"), "cached");
    let key = client.credential_key().unwrap();
    let stored = client.storage.load(&key, RESOURCE).expect("a stored token");
    assert_eq!(stored.refresh_token.as_deref(), Some("r-next"), "stored");

    // The next refresh sends the rotated token, never the replaced one.
    expire_stored_and_cached(&client);
    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 2, "{forms:?}");
    assert_eq!(forms[1]["refresh_token"], "r-next");
}

/// No authorization server known: the refresh cannot run, the fall-back to
/// authorize cannot either, and nothing is keyed to an issuer that does not exist.
#[tokio::test]
async fn without_an_authorization_server_get_token_fails_and_no_key_is_invented() {
    let dir = tempfile::tempdir().unwrap();
    let client = client(dir.path(), None);
    *client.current_token.write() = Some(token("access-old", Some("r1"), Expiry::Expired));

    let error = client.get_token().await.expect_err("no server, no token");
    assert!(error.to_string().contains("not initialized"), "{error}");

    let key = client.credential_key().expect_err("no issuer, no key");
    assert!(key.to_string().contains("no issuer"), "{key}");

    client.drop_credentials_from_other_issuer(Some("https://as-before.example"));
    assert!(
        client.current_token.read().is_some(),
        "with no current issuer there is no change of issuer to drop credentials for"
    );
}

/// No token at all: `get_token` runs the whole flow, and the browser failing
/// to open only means the person visits the printed URL instead.
#[tokio::test]
async fn get_token_authorizes_from_scratch_even_when_the_browser_does_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let (issuer, forms) = token_endpoint(Some("access-c")).await;
    let mut client = client(dir.path(), Some(&issuer));

    let (outcome, _) = approve_via(&mut client, &issuer, Entry::GetToken, Browser::Fails).await;

    assert_eq!(outcome.expect("the flow completes"), "access-c");
    assert_eq!(forms.lock().unwrap().len(), 1, "one code redemption");
}

/// An authorization endpoint that is not a URL is refused before a browser
/// is pointed anywhere.
#[tokio::test]
async fn an_unparseable_authorization_endpoint_is_refused_before_any_browser_opens() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client(dir.path(), Some("https://as.example"));
    if let Some(meta) = client.auth_metadata.as_mut() {
        meta.authorization_endpoint = "not a url".to_string();
    }
    let opened = Arc::new(Mutex::new(0_usize));
    let count = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        *count.lock().unwrap() += 1;
        true
    });

    let error = tokio::time::timeout(Duration::from_secs(10), client.authorize())
        .await
        .expect("refused promptly")
        .expect_err("an unparseable endpoint is refused");
    assert!(
        error.to_string().contains("Invalid auth endpoint"),
        "{error}"
    );
    assert_eq!(*opened.lock().unwrap(), 0, "no browser is opened");
}

/// The callback listener on `port` is gone: the port binds again. An aborted
/// listener drops on its next poll, so this allows it a moment.
async fn assert_port_released(port: u16) {
    let released = async {
        while tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), released)
        .await
        .expect("the callback listener is released");
}

/// A client whose callback listens on a known port, and whose browser opens
/// without anyone approving: `opened` fires once the URL is handed over. The
/// release is proved by binding the port again, so it comes from the
/// reserved range no parallel port-0 bind can take first (MIK-8211).
async fn unanswered_client(dir: &std::path::Path) -> (OAuthClient, u16, Arc<tokio::sync::Notify>) {
    let mut client = client(dir, Some("https://as.example"));
    let port = crate::test_ports::reserved_port();
    client.callback_port = Some(port);
    let opened = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        signal.notify_one();
        true
    });
    (client, port, opened)
}

/// MIK-7982.BOUND.1: an authorization nobody completes ends on its own when
/// the 300 s authorization window passes, naming the backend and telling the
/// caller to retry, and its callback port is free afterwards.
#[tokio::test(start_paused = true)]
async fn an_unanswered_authorization_ends_at_the_window_and_frees_the_port() {
    let dir = tempfile::tempdir().unwrap();
    let (client, port, _opened) = unanswered_client(dir.path()).await;

    let outcome = tokio::time::timeout(Duration::from_secs(301), client.authorize()).await;

    let error = outcome
        .expect("an unanswered authorization must end on its own within the 300 s window")
        .expect_err("no callback arrived, so there is no token");
    let text = error.to_string();
    assert!(
        text.contains(BACKEND) && text.contains("300s") && text.contains("retry"),
        "the error names the backend, the window and the remedy: {text}"
    );
    assert_port_released(port).await;
}

/// MIK-7982.BOUND.3 (root cause F2): an authorization whose future is dropped
/// mid-wait (a cancelled or timed-out caller) closes its callback listener
/// rather than leaving it running detached.
#[tokio::test]
async fn a_dropped_authorization_closes_its_callback_listener() {
    let dir = tempfile::tempdir().unwrap();
    let (client, port, opened) = unanswered_client(dir.path()).await;

    tokio::select! {
        _ = client.authorize() => panic!("nobody approved, so the flow cannot finish"),
        () = opened.notified() => {}
    }

    assert_port_released(port).await;
}

impl OAuthClient {
    /// A live (one-hour) token in place, as a completed flow would leave it,
    /// for a transport test that needs `get_token` to answer without a flow.
    pub(crate) fn install_live_token_for_test(&self, access_token: &str) {
        *self.current_token.write() = Some(TokenInfo::from_response(
            access_token.to_string(),
            Some("Bearer".to_string()),
            None,
            Some(3600),
            None,
        ));
    }
}

/// MIK-7982 (delta review): a client holding a dynamically registered id that
/// takes up a login another client of its backend stored also takes up the id
/// that login stored. Keeping its own would present a stale id on refresh.
#[tokio::test]
async fn taking_up_a_shared_login_takes_up_its_registered_client_id() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = "https://as.example";
    let client = client(dir.path(), Some(issuer))
        .with_login_gate(Arc::new(crate::oauth::login_gate::LoginGate::default()));
    *client.client_id.write() = Some("stale-registered-id".to_string());
    *client.client_id_source.write() = Some(ClientIdSource::Registered);
    let key = storage_key(BACKEND, issuer);
    let shared = token("shared-access", None, Expiry::Live);
    client.storage.save(&key, RESOURCE, &shared).unwrap();
    client
        .storage
        .save_client_id(&key, RESOURCE, "fresh-registered-id")
        .unwrap();

    let access = client.authorize_shared(true, None).await.unwrap();

    assert_eq!(access, "shared-access", "the stored login is taken up");
    assert_eq!(
        client.client_id.read().as_deref(),
        Some("fresh-registered-id"),
        "the shared login's registered id replaces the stale one"
    );
}

/// MIK-7982: a client with a configured id that takes up a stored login keeps
/// its configured id, whatever registered id that login stored.
#[tokio::test]
async fn taking_up_a_shared_login_keeps_a_configured_client_id() {
    let dir = tempfile::tempdir().unwrap();
    let issuer = "https://as.example";
    let client = client(dir.path(), Some(issuer))
        .with_login_gate(Arc::new(crate::oauth::login_gate::LoginGate::default()));
    let key = storage_key(BACKEND, issuer);
    let shared = token("shared-access", None, Expiry::Live);
    client.storage.save(&key, RESOURCE, &shared).unwrap();
    client
        .storage
        .save_client_id(&key, RESOURCE, "another-registered-id")
        .unwrap();

    let access = client.authorize_shared(true, None).await.unwrap();

    assert_eq!(access, "shared-access", "the stored login is taken up");
    assert_eq!(
        client.client_id.read().as_deref(),
        Some(CLIENT_ID),
        "a configured id is never replaced by a stored one"
    );
}

/// MIK-7982: a stored login is taken up only when its token is live and was
/// stored under this client's own key (backend and issuer) and resource;
/// otherwise the caller opens its own.
#[tokio::test]
async fn an_expired_or_foreign_stored_login_is_not_taken_up() {
    let issuer = "https://as.example";
    for (stored_issuer, resource, expiry, case) in [
        (issuer, RESOURCE, Expiry::Expired, "an expired token"),
        (
            issuer,
            "https://other.example.com/mcp",
            Expiry::Live,
            "another resource's token",
        ),
        (
            "https://other-as.example",
            RESOURCE,
            Expiry::Live,
            "another issuer's token",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut client = client(dir.path(), Some(issuer));
        let opened = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&opened);
        client.open_browser = Box::new(move |_| {
            signal.notify_one();
            true
        });
        let client =
            client.with_login_gate(Arc::new(crate::oauth::login_gate::LoginGate::default()));
        let stored = token("stored-access", None, expiry);
        client
            .storage
            .save(&storage_key(BACKEND, stored_issuer), resource, &stored)
            .unwrap();

        let opened_own = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                taken = client.authorize_shared(true, None) => panic!("{case} was taken up: {taken:?}"),
                () = opened.notified() => {}
            }
        })
        .await;
        assert!(opened_own.is_ok(), "{case}: no login opened within 10 s");
    }
}

/// MIK-7982.BOUND.1: when the window passes, the callback listener is closed
/// before the wait returns, not on a later poll of an aborted task: the port
/// binds again with no await in between.
#[tokio::test(start_paused = true)]
async fn the_window_closes_the_callback_listener_before_the_wait_returns() {
    let server = crate::oauth::callback::start_callback_server(
        "window-state".to_string(),
        Some("127.0.0.1"),
        None,
        None,
    )
    .await
    .expect("the callback listener binds");
    let port = url::Url::parse(&server.callback_url)
        .ok()
        .and_then(|url| url.port())
        .expect("the callback URL names the port the listener holds");
    let cancel = tokio_util::sync::CancellationToken::new();

    let ended = server.wait_within(Duration::from_secs(1), &cancel).await;

    assert!(
        matches!(ended, Err(crate::oauth::callback::Unanswered::Window)),
        "nobody called back, so the window ends the wait"
    );
    std::net::TcpListener::bind(("127.0.0.1", port))
        .expect("the window's end closes the callback listener before it returns");
}

/// MIK-7982: a login cancelled before it registers (a restart or shutdown of
/// the backend) ends as cancelled and opens no browser.
#[tokio::test]
async fn a_login_cancelled_before_registration_opens_no_browser() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = client(dir.path(), Some("https://as.example"));
    let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&opened);
    client.open_browser = Box::new(move |_| {
        seen.store(true, std::sync::atomic::Ordering::SeqCst);
        true
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    cancel.cancel();

    let ended = tokio::time::timeout(
        Duration::from_secs(10),
        client.authorize_until(&cancel, None),
    )
    .await
    .expect("a cancelled login ends at once");

    assert!(
        matches!(ended, Err(crate::Error::AuthorizationCancelled { ref backend }) if backend == BACKEND),
        "{ended:?}"
    );
    assert!(
        !opened.load(std::sync::atomic::Ordering::SeqCst),
        "no browser opens for a cancelled login"
    );
}
