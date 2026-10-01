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

/// Every form the token endpoint received, in arrival order.
type Forms = Arc<Mutex<Vec<HashMap<String, String>>>>;

/// A token endpoint on loopback. `Some(token)` answers with that access token;
/// `None` refuses every request with `invalid_grant`.
async fn token_endpoint(answer: Option<&'static str>) -> (String, Forms) {
    use axum::{Form, Json, Router, http::StatusCode, response::IntoResponse, routing::post};
    let forms: Forms = Arc::default();
    let seen = Arc::clone(&forms);
    let app = Router::new().route(
        "/token",
        post(move |Form(form): Form<HashMap<String, String>>| {
            seen.lock().unwrap().push(form);
            async move {
                match answer {
                    Some(token) => Json(serde_json::json!({
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "r-next"
                    }))
                    .into_response(),
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
                ("code", "c1"),
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
    assert_eq!(form["code"], "c1");
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
    *client.current_token.write() = Some(token("access-old", Some("r1"), Expiry::Expired));

    assert_eq!(client.get_token().await.unwrap(), "access-b");
    let forms = forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1, "{forms:?}");
    assert_eq!(forms[0]["grant_type"], "refresh_token");
    assert_eq!(forms[0]["refresh_token"], "r1");
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
