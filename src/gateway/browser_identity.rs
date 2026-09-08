// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Production browser-session identity verifier.
//!
//! Validates Open WebUI session cookies against a loopback HTTPS-or-literal-loopback
//! HTTP session endpoint. No injectable bypass. No route/config wiring in this slice.

use std::time::Duration;

use crate::key_server::oidc::VerifiedIdentity;
use http::HeaderMap;
use reqwest::redirect::Policy;
use serde::Deserialize;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY: usize = 64 * 1024;
const MAX_TOKEN: usize = 8 * 1024;
const TOKEN_COOKIE: &str = "token";

#[derive(Debug)]
pub(crate) enum BrowserIdentityError {
    Unauthenticated,
    Unavailable,
    InvalidConfig,
}

impl std::fmt::Display for BrowserIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unauthenticated => "browser session is unauthenticated",
            Self::Unavailable => "browser identity service is unavailable",
            Self::InvalidConfig => "browser identity verifier configuration is invalid",
        })
    }
}

impl std::error::Error for BrowserIdentityError {}

pub(crate) struct BrowserIdentityVerifier {
    installation_id: String,
    public_origin: String,
    session_endpoint: String,
    client: reqwest::Client,
}

pub(crate) struct VerifiedBrowserIdentity {
    inner: VerifiedIdentity,
}

impl std::fmt::Debug for VerifiedBrowserIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedBrowserIdentity")
            .field("subject", &self.inner.subject)
            .finish_non_exhaustive()
    }
}

impl VerifiedBrowserIdentity {
    pub(crate) fn identity(&self) -> &VerifiedIdentity {
        &self.inner
    }
}

impl BrowserIdentityVerifier {
    pub(crate) fn new(
        installation_id: String,
        public_origin: &str,
        session_endpoint: &str,
    ) -> Result<Self, BrowserIdentityError> {
        if installation_id.is_empty() {
            return Err(BrowserIdentityError::InvalidConfig);
        }
        validate_https_origin(public_origin)?;
        validate_session_endpoint(session_endpoint)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(|_| BrowserIdentityError::InvalidConfig)?;
        Ok(Self {
            installation_id,
            public_origin: public_origin.to_string(),
            session_endpoint: session_endpoint.to_string(),
            client,
        })
    }

    pub(crate) fn origin_matches(&self, origin: &str) -> bool {
        origin == self.public_origin
    }

    pub(crate) async fn verify(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedBrowserIdentity, BrowserIdentityError> {
        let token = extract_token_cookie(headers)?;
        let response = self
            .client
            .get(&self.session_endpoint)
            .header(http::header::COOKIE, format!("{TOKEN_COOKIE}={token}"))
            .send()
            .await
            .map_err(|_| BrowserIdentityError::Unavailable)?;
        let status = response.status();
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return Err(BrowserIdentityError::Unauthenticated);
        }
        if !status.is_success() {
            return Err(BrowserIdentityError::Unavailable);
        }
        let mut body = Vec::new();
        let mut stream = response;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|_| BrowserIdentityError::Unavailable)?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(BrowserIdentityError::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let parsed: SessionBody =
            serde_json::from_slice(&body).map_err(|_| BrowserIdentityError::Unavailable)?;
        let id = parsed.id.ok_or(BrowserIdentityError::Unavailable)?;
        if id.is_empty() {
            return Err(BrowserIdentityError::Unavailable);
        }
        let namespaced = super::openwebui_adapter::namespaced_issuer(&self.installation_id);
        Ok(VerifiedBrowserIdentity {
            inner: VerifiedIdentity {
                subject: id,
                email: String::new(),
                name: None,
                groups: Vec::new(),
                issuer: namespaced,
            },
        })
    }
}

#[derive(Deserialize)]
struct SessionBody {
    id: Option<String>,
}

fn validate_https_origin(origin: &str) -> Result<(), BrowserIdentityError> {
    let parsed = url::Url::parse(origin).map_err(|_| BrowserIdentityError::InvalidConfig)?;
    if parsed.scheme() != "https" {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    if parsed.path() != "/" && parsed.path() != "" {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    if parsed.host_str().is_none() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    Ok(())
}

fn validate_session_endpoint(endpoint: &str) -> Result<(), BrowserIdentityError> {
    let parsed = url::Url::parse(endpoint).map_err(|_| BrowserIdentityError::InvalidConfig)?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    match parsed.scheme() {
        "https" => {}
        "http" => {
            let host = parsed
                .host_str()
                .ok_or(BrowserIdentityError::InvalidConfig)?;
            if host != "127.0.0.1" && host != "::1" && host != "[::1]" {
                return Err(BrowserIdentityError::InvalidConfig);
            }
        }
        _ => return Err(BrowserIdentityError::InvalidConfig),
    }
    if parsed.path().is_empty() {
        return Err(BrowserIdentityError::InvalidConfig);
    }
    Ok(())
}

fn extract_token_cookie(headers: &HeaderMap) -> Result<String, BrowserIdentityError> {
    let mut token: Option<String> = None;
    for value in headers.get_all(http::header::COOKIE) {
        let raw = value
            .to_str()
            .map_err(|_| BrowserIdentityError::Unauthenticated)?;
        if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(BrowserIdentityError::Unauthenticated);
        }
        for part in raw.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((name, value)) = part.split_once('=') else {
                return Err(BrowserIdentityError::Unauthenticated);
            };
            let name = name.trim();
            let value = value.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
                return Err(BrowserIdentityError::Unauthenticated);
            }
            if !value.is_ascii() || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
                return Err(BrowserIdentityError::Unauthenticated);
            }
            if name == TOKEN_COOKIE {
                if token.is_some() {
                    return Err(BrowserIdentityError::Unauthenticated);
                }
                if value.is_empty() || value.len() > MAX_TOKEN {
                    return Err(BrowserIdentityError::Unauthenticated);
                }
                token = Some(value.to_string());
            }
        }
    }
    token.ok_or(BrowserIdentityError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Request;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    struct Capture {
        count: AtomicUsize,
        cookies: Mutex<Vec<String>>,
        auths: Mutex<Vec<Option<String>>>,
        redirect_hits: AtomicUsize,
    }

    async fn spawn(
        capture: Arc<Capture>,
        status: StatusCode,
        body: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let app = {
            let capture = Arc::clone(&capture);
            let body = Arc::new(body);
            Router::new()
                .route(
                    "/api/v1/auths/",
                    get(move |req: Request| {
                        let capture = Arc::clone(&capture);
                        let body = Arc::clone(&body);
                        async move {
                            capture.count.fetch_add(1, Ordering::SeqCst);
                            let cookie = req
                                .headers()
                                .get(http::header::COOKIE)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            capture.cookies.lock().unwrap().push(cookie);
                            let auth = req
                                .headers()
                                .get(http::header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_string);
                            capture.auths.lock().unwrap().push(auth);
                            (status, body.as_slice().to_vec()).into_response()
                        }
                    }),
                )
                .route(
                    "/redirect-target",
                    get({
                        let capture = Arc::clone(&capture);
                        move || async move {
                            capture.redirect_hits.fetch_add(1, Ordering::SeqCst);
                            StatusCode::OK
                        }
                    }),
                )
        };
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (
            format!("http://127.0.0.1:{}/api/v1/auths/", addr.port()),
            handle,
        )
    }

    fn headers_with(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::COOKIE, cookie.parse().unwrap());
        h
    }

    fn origin() -> &'static str {
        "https://chat.example.com"
    }

    #[tokio::test]
    async fn valid_id_discards_profile() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let body = br#"{"id":"user-1","email":"a@b.c","name":"N","profile":{"x":1}}"#.to_vec();
        let (url, _h) = spawn(Arc::clone(&capture), StatusCode::OK, body).await;
        let v = BrowserIdentityVerifier::new("inst-a".into(), origin(), &url).unwrap();
        let id = v
            .verify(&headers_with("token=abc; other=keep"))
            .await
            .unwrap();
        assert_eq!(id.identity().subject, "user-1");
        assert!(id.identity().email.is_empty());
        assert!(id.identity().name.is_none());
        assert!(id.identity().groups.is_empty());
        assert_eq!(
            id.identity().issuer,
            super::super::openwebui_adapter::namespaced_issuer("inst-a")
        );
        let cookies = capture.cookies.lock().unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0], "token=abc");
        assert!(!cookies[0].contains("other"));
        assert!(capture.auths.lock().unwrap()[0].is_none());
        assert_eq!(capture.count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn same_installation_shares_namespace() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let a = BrowserIdentityVerifier::new("same".into(), origin(), &url).unwrap();
        let b = BrowserIdentityVerifier::new("same".into(), origin(), &url).unwrap();
        let ia = a.verify(&headers_with("token=t")).await.unwrap();
        let ib = b.verify(&headers_with("token=t")).await.unwrap();
        assert_eq!(ia.identity().issuer, ib.identity().issuer);
        assert_eq!(
            ia.identity().stable_actor_id(),
            ib.identity().stable_actor_id()
        );
    }

    #[tokio::test]
    async fn distinct_installations_differ() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let a = BrowserIdentityVerifier::new("one".into(), origin(), &url).unwrap();
        let b = BrowserIdentityVerifier::new("two".into(), origin(), &url).unwrap();
        let ia = a.verify(&headers_with("token=t")).await.unwrap();
        let ib = b.verify(&headers_with("token=t")).await.unwrap();
        assert_ne!(ia.identity().issuer, ib.identity().issuer);
        assert_ne!(
            ia.identity().stable_actor_id(),
            ib.identity().stable_actor_id()
        );
    }

    #[tokio::test]
    async fn missing_cookie_sends_no_request() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&HeaderMap::new()).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unauthenticated));
        assert_eq!(capture.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicate_token_across_headers_sends_no_request() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let mut h = HeaderMap::new();
        h.append(http::header::COOKIE, "token=a".parse().unwrap());
        h.append(http::header::COOKIE, "token=b".parse().unwrap());
        let err = v.verify(&h).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unauthenticated));
        assert_eq!(capture.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn malformed_cookie_sends_no_request() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("not-a-pair")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unauthenticated));
        assert_eq!(capture.count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn status_401_is_unauthenticated() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::UNAUTHORIZED,
            b"no".to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unauthenticated));
    }

    #[tokio::test]
    async fn status_503_is_unavailable() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::SERVICE_UNAVAILABLE,
            b"no".to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn missing_id_is_unavailable() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"user_id":"x"}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn empty_id_is_unavailable() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":""}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn malformed_json_is_unavailable() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(Arc::clone(&capture), StatusCode::OK, b"not-json".to_vec()).await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn oversized_body_is_unavailable() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let mut body = br#"{"id":""#.to_vec();
        body.extend(std::iter::repeat_n(b'a', MAX_BODY + 8));
        body.extend_from_slice(b"\"}");
        let (url, _h) = spawn(Arc::clone(&capture), StatusCode::OK, body).await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
    }

    #[tokio::test]
    async fn redirect_is_not_followed() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let capture_app = Arc::clone(&capture);
        let app = Router::new()
            .route(
                "/api/v1/auths/",
                get({
                    let capture = Arc::clone(&capture_app);
                    move || async move {
                        capture.count.fetch_add(1, Ordering::SeqCst);
                        (
                            StatusCode::FOUND,
                            [(http::header::LOCATION, "/redirect-target")],
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/redirect-target",
                get({
                    let capture = Arc::clone(&capture_app);
                    move || async move {
                        capture.redirect_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let url = format!("http://127.0.0.1:{}/api/v1/auths/", addr.port());
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let err = v.verify(&headers_with("token=x")).await.unwrap_err();
        assert!(matches!(err, BrowserIdentityError::Unavailable));
        assert_eq!(capture.redirect_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn config_refusals() {
        assert!(
            BrowserIdentityVerifier::new("i".into(), "http://chat.example.com", "https://x/y")
                .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://chat.example.com",
                "http://8.8.8.8/y"
            )
            .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new("".into(), "https://chat.example.com", "https://x/y")
                .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://user:pass@chat.example.com",
                "https://x/y"
            )
            .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new("i".into(), "https://chat.example.com?q=1", "https://x/y")
                .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new("i".into(), "https://chat.example.com#f", "https://x/y")
                .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://chat.example.com",
                "http://user:pass@127.0.0.1/y"
            )
            .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://chat.example.com",
                "http://127.0.0.1/y?q=1"
            )
            .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://chat.example.com",
                "http://127.0.0.1/y#f"
            )
            .is_err()
        );
        assert!(
            BrowserIdentityVerifier::new(
                "i".into(),
                "https://chat.example.com",
                "ftp://127.0.0.1/y"
            )
            .is_err()
        );
        let ok = BrowserIdentityVerifier::new(
            "i".into(),
            "https://chat.example.com",
            "http://127.0.0.1/api/v1/auths/",
        );
        assert!(ok.is_ok());
        assert!(ok.unwrap().origin_matches("https://chat.example.com"));
    }

    #[tokio::test]
    async fn ignores_unrelated_cookies_and_incoming_authorization() {
        let capture = Arc::new(Capture {
            count: AtomicUsize::new(0),
            cookies: Mutex::new(Vec::new()),
            auths: Mutex::new(Vec::new()),
            redirect_hits: AtomicUsize::new(0),
        });
        let (url, _h) = spawn(
            Arc::clone(&capture),
            StatusCode::OK,
            br#"{"id":"u"}"#.to_vec(),
        )
        .await;
        let v = BrowserIdentityVerifier::new("i".into(), origin(), &url).unwrap();
        let mut h = HeaderMap::new();
        h.insert(
            http::header::COOKIE,
            "sid=keep; token=secret; theme=dark".parse().unwrap(),
        );
        h.insert(
            http::header::AUTHORIZATION,
            "Bearer leaked".parse().unwrap(),
        );
        v.verify(&h).await.unwrap();
        let cookies = capture.cookies.lock().unwrap();
        assert_eq!(cookies[0], "token=secret");
        assert!(capture.auths.lock().unwrap()[0].is_none());
    }
}
