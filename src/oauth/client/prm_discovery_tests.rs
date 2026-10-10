// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8320 / MIK-8324: protected-resource discovery.
//!
//! One test server plays the backend: it answers the unauthenticated probe
//! (`POST /mcp`), serves the hinted, path-inserted and origin metadata
//! documents, and records every request so a row can assert what was fetched
//! and in which order.

use super::*;
use std::sync::Mutex;

/// What the backend answers to the unauthenticated MCP probe.
#[derive(Clone)]
enum Probe {
    /// 401 with `WWW-Authenticate: Bearer resource_metadata="<base><path>"`.
    Hint(&'static str),
    /// 401 with a bearer challenge naming no metadata.
    Plain401,
    /// 302 to `<base>/elsewhere`.
    Redirect,
    /// 401 hinting an absolute URL.
    HintAbsolute(&'static str),
}

/// One metadata document slot.
#[derive(Clone)]
enum Doc {
    Absent,
    /// 200 with an HTML body.
    Html,
    /// The handler panics, so the connection drops: a transport failure.
    Abort,
    /// A document whose `resource` is `<base><suffix>` (or `suffix` verbatim
    /// when it starts with `http`).
    Names(&'static str),
}

#[derive(Clone)]
struct Backend {
    probe: Probe,
    hint: Doc,
    path: Doc,
    origin: Doc,
}

struct Served {
    base: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Served {
    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

fn document(doc: &Doc, base: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    match doc {
        Doc::Absent => axum::http::StatusCode::NOT_FOUND.into_response(),
        Doc::Abort => panic!("drop the connection: a transport failure for the client"),
        Doc::Html => (
            [(axum::http::header::CONTENT_TYPE, "text/html")],
            "<html>not metadata</html>",
        )
            .into_response(),
        Doc::Names(suffix) => {
            let resource = if suffix.starts_with("http") {
                (*suffix).to_string()
            } else {
                format!("{base}{suffix}")
            };
            axum::Json(serde_json::json!({
                "resource": resource,
                "authorization_servers": [base],
            }))
            .into_response()
        }
    }
}

async fn serve(backend: Backend) -> Served {
    use axum::response::IntoResponse;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (b, s) = (base.clone(), seen.clone());
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let (base, seen, backend) = (b.clone(), s.clone(), backend.clone());
        async move {
            let (method, path) = (req.method().clone(), req.uri().path().to_string());
            seen.lock().unwrap().push(format!("{method} {path}"));
            match (method.as_str(), path.as_str()) {
                ("POST", "/mcp") => match backend.probe {
                    Probe::Hint(p) => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        [(
                            axum::http::header::WWW_AUTHENTICATE,
                            format!("Bearer realm=\"t\", resource_metadata=\"{base}{p}\""),
                        )],
                    )
                        .into_response(),
                    Probe::Plain401 => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        [(
                            axum::http::header::WWW_AUTHENTICATE,
                            "Bearer realm=\"t\"".to_string(),
                        )],
                    )
                        .into_response(),
                    Probe::HintAbsolute(url) => (
                        axum::http::StatusCode::UNAUTHORIZED,
                        [(
                            axum::http::header::WWW_AUTHENTICATE,
                            format!("Bearer resource_metadata=\"{url}\""),
                        )],
                    )
                        .into_response(),
                    Probe::Redirect => (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, format!("{base}/elsewhere"))],
                    )
                        .into_response(),
                },
                ("GET", "/hinted-prm") => document(&backend.hint, &base),
                ("GET", "/.well-known/oauth-protected-resource/mcp") => {
                    document(&backend.path, &base)
                }
                ("GET", "/.well-known/oauth-protected-resource") => {
                    document(&backend.origin, &base)
                }
                ("GET", "/.well-known/oauth-authorization-server") => {
                    axum::Json(serde_json::json!({
                        "issuer": base,
                        "authorization_endpoint": format!("{base}/authorize"),
                        "token_endpoint": format!("{base}/token"),
                    }))
                    .into_response()
                }
                _ => axum::http::StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Served { base, seen }
}

/// A gateway-owned client (`with_destination`, as production builds it).
fn owned_client(resource_url: &str, dir: &std::path::Path) -> OAuthClient {
    OAuthClient::with_destination(
        crate::security::ssrf::DestinationPolicy::Private,
        Client::new(),
        "prm-discovery".to_string(),
        resource_url.to_string(),
        vec![],
        Arc::new(TokenStorage::new(dir.to_path_buf()).unwrap()),
        OAuthClientConfig::default(),
    )
}

async fn initialize(backend: Backend) -> (Served, Result<()>) {
    let served = serve(backend).await;
    let dir = tempfile::tempdir().unwrap();
    let mut client = owned_client(&format!("{}/mcp", served.base), dir.path());
    let result = client.initialize().await;
    (served, result)
}

const PATH: &str = "GET /.well-known/oauth-protected-resource/mcp";
const ORIGIN: &str = "GET /.well-known/oauth-protected-resource";
const HINTED: &str = "GET /hinted-prm";

fn backend(probe: Probe, hint: Doc, path: Doc, origin: Doc) -> Backend {
    Backend {
        probe,
        hint,
        path,
        origin,
    }
}

fn position(seen: &[String], what: &str) -> Option<usize> {
    seen.iter().position(|s| s == what)
}

/// Both requests happened, `first` before `then`.
fn in_order(seen: &[String], first: &str, then: &str) -> bool {
    matches!((position(seen, first), position(seen, then)), (Some(a), Some(b)) if a < b)
}

// ── AC1: a document naming another resource is refused (RFC 9728 §3.3) ────

#[tokio::test]
async fn a_path_document_naming_another_resource_is_refused_naming_both() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Names("/other"),
        Doc::Absent,
    ))
    .await;
    let err = result
        .expect_err("metadata naming /other must not be used for /mcp")
        .to_string();
    assert!(err.contains(&format!("{}/other", served.base)), "{err}");
    assert!(err.contains(&format!("{}/mcp", served.base)), "{err}");
}

#[tokio::test]
async fn a_path_document_naming_this_resource_is_used() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Names("/mcp"),
        Doc::Absent,
    ))
    .await;
    result.expect("a document naming the configured resource is used");
    assert!(
        position(&served.seen(), PATH).is_some(),
        "{:?}",
        served.seen()
    );
}

/// Ruling (A): the origin document is held to the configured resource too.
#[tokio::test]
async fn an_origin_document_naming_the_origin_is_refused_for_a_path_resource() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Absent,
        Doc::Names(""),
    ))
    .await;
    let err = result
        .expect_err("the origin's metadata is not this /mcp resource's")
        .to_string();
    assert!(err.contains(&format!("{}/mcp", served.base)), "{err}");
}

// ── AC2: the path-inserted URL first, then the origin (MCP 2025-11-25) ─────

#[tokio::test]
async fn the_path_inserted_document_is_tried_before_the_origin() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Absent,
        Doc::Names("/mcp"),
    ))
    .await;
    result.expect("an origin document naming this resource is used");
    let seen = served.seen();
    let (path, origin) = (position(&seen, PATH), position(&seen, ORIGIN));
    assert!(
        matches!((path, origin), (Some(p), Some(o)) if p < o),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_path_answer_that_is_not_a_document_falls_through_to_the_origin() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Html,
        Doc::Names("/mcp"),
    ))
    .await;
    result.expect("an HTML answer is not a document; the origin is tried next");
    let seen = served.seen();
    assert!(in_order(&seen, PATH, ORIGIN), "{seen:?}");
}

// ── MIK-8324: the 401 resource_metadata hint comes first ───────────────────

#[tokio::test]
async fn the_hinted_document_is_fetched_first_and_used() {
    let (served, result) = initialize(backend(
        Probe::Hint("/hinted-prm"),
        Doc::Names("/mcp"),
        Doc::Names("/other"),
        Doc::Absent,
    ))
    .await;
    result.expect("the hinted document names this resource");
    let seen = served.seen();
    assert!(position(&seen, HINTED).is_some(), "{seen:?}");
    assert!(
        position(&seen, PATH).is_none(),
        "the hint answered first: {seen:?}"
    );
}

#[tokio::test]
async fn a_hinted_document_naming_another_resource_is_refused_with_no_fallback() {
    let (served, result) = initialize(backend(
        Probe::Hint("/hinted-prm"),
        Doc::Names("/other"),
        Doc::Names("/mcp"),
        Doc::Absent,
    ))
    .await;
    result.expect_err("a mismatch is an answer, not a missing document");
    assert!(
        position(&served.seen(), PATH).is_none(),
        "{:?}",
        served.seen()
    );
}

#[tokio::test]
async fn a_401_without_a_hint_falls_through_to_the_well_known_order() {
    let (served, result) = initialize(backend(
        Probe::Plain401,
        Doc::Absent,
        Doc::Names("/mcp"),
        Doc::Absent,
    ))
    .await;
    result.expect("no hint: the path-inserted document");
    let seen = served.seen();
    assert!(in_order(&seen, "POST /mcp", PATH), "{seen:?}");
}

/// Ruling (B): the probe follows no redirect.
#[tokio::test]
async fn a_redirected_probe_gives_no_hint_and_its_location_is_never_fetched() {
    let (served, result) = initialize(backend(
        Probe::Redirect,
        Doc::Absent,
        Doc::Names("/mcp"),
        Doc::Absent,
    ))
    .await;
    result.expect("a 302 gives no hint; the well-known order applies");
    let seen = served.seen();
    assert!(position(&seen, "GET /elsewhere").is_none(), "{seen:?}");
    assert!(position(&seen, PATH).is_some(), "{seen:?}");
}

#[tokio::test]
async fn a_hint_to_a_refused_destination_is_refused() {
    let (_served, result) = initialize(backend(
        Probe::HintAbsolute("http://169.254.169.254/latest/meta-data"),
        Doc::Absent,
        Doc::Names("/mcp"),
        Doc::Absent,
    ))
    .await;
    result.expect_err("a hint to the metadata service must not be fetched");
}

/// Fall-through past a failure is safe only because every candidate is held to
/// the configured resource: neither a non-document (HTML) nor a transport
/// failure on the path document may let the origin's own metadata through.
#[tokio::test]
async fn a_failed_path_fetch_does_not_let_an_origin_named_document_through() {
    for failure in [Doc::Html, Doc::Abort] {
        let (served, result) = initialize(backend(
            Probe::Plain401,
            Doc::Absent,
            failure,
            Doc::Names(""),
        ))
        .await;
        let err = result
            .expect_err("the origin document names the origin, not /mcp")
            .to_string();
        assert!(err.contains(&format!("{}/mcp", served.base)), "{err}");
        let seen = served.seen();
        assert!(in_order(&seen, PATH, ORIGIN), "fell through: {seen:?}");
    }
}
