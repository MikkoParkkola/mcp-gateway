// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The web UI goes out compressed by the router's one rule, `compression()`,
//! and `src/gateway/ui/compression.json` states that rule for the fixture
//! server. Every request but the contract rows goes through `create_router`,
//! so the real merge order decides each answer.

use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::get;
use futures::StreamExt;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, compression, create_router};
use crate::config::AuthConfig;

const SHELL: &[u8] = include_bytes!("../ui/shell/index.html");
const CLASSIC: &[u8] = include_bytes!("../ui/index.html");
const CONTRACT: &str = include_str!("../ui/compression.json");
const BEARER: &str = "gzip-bearer";
const GUARD: Duration = Duration::from_secs(30);

/// The contract, as the fixture server reads it.
struct Contract {
    min_bytes: usize,
    never_prefixes: Vec<String>,
    except_types: Vec<String>,
}

impl Contract {
    fn load() -> Self {
        let v: serde_json::Value = serde_json::from_str(CONTRACT).expect("compression.json parses");
        assert_eq!(
            v["encoding"], "gzip",
            "the one encoding the gateway builds with"
        );
        let list = |key: &str| -> Vec<String> {
            v[key]
                .as_array()
                .expect("a contract list")
                .iter()
                .map(|s| s.as_str().expect("a string").to_owned())
                .collect()
        };
        Self {
            min_bytes: v["min_bytes"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .expect("min_bytes is a count"),
            never_prefixes: list("never_prefixes"),
            except_types: list("except_types"),
        }
    }

    /// Whether a body of this type and length is gzip for a client asking.
    fn gzips(&self, content_type: &str, len: usize) -> bool {
        let never = self
            .never_prefixes
            .iter()
            .any(|p| content_type.starts_with(p.as_str()))
            && !self
                .except_types
                .iter()
                .any(|e| content_type.starts_with(e.as_str()));
        len >= self.min_bytes && !never
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &header::HeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// The body as sent, decoded when it is gzip.
    fn decoded(&self) -> Vec<u8> {
        if self.header(&header::CONTENT_ENCODING) != Some("gzip") {
            return self.body.clone();
        }
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&self.body[..])
            .read_to_end(&mut out)
            .expect("a gzip body decompresses");
        out
    }
}

async fn fixture() -> (Arc<AppState>, impl Sized) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

fn request(uri: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_347))));
    for (name, value) in extra {
        b = b.header(name, *value);
    }
    b.body(Body::empty()).expect("request builds")
}

async fn read(app: Router, req: Request<Body>) -> Reply {
    let response = tokio::time::timeout(GUARD, app.oneshot(req))
        .await
        .expect("the request finished")
        .expect("the router is infallible");
    let (status, headers) = (response.status(), response.headers().clone());
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

async fn send(state: &Arc<AppState>, uri: &str, extra: &[(&str, &str)]) -> Reply {
    read(create_router(Arc::clone(state)), request(uri, extra)).await
}

/// Every hashed asset file in the shell directory, with its bytes.
fn shell_assets() -> Vec<(String, Vec<u8>)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gateway/ui/shell");
    let mut out = Vec::new();
    for dir in [root.clone(), root.join("fonts")] {
        for entry in std::fs::read_dir(&dir).expect("the shell directory") {
            let path = entry.expect("an entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            let hashed = name
                .rsplit('.')
                .nth(1)
                .is_some_and(|h| h.len() == 12 && h.bytes().all(|b| b.is_ascii_hexdigit()));
            if path.is_file() && hashed {
                out.push((name, std::fs::read(&path).expect("asset bytes")));
            }
        }
    }
    out.sort();
    out
}

const GZIP: (&str, &str) = ("accept-encoding", "gzip");

/// GZIP.1: /ui, /ui/classic, the shell document and every asset are gzip
/// when asked, decompress to the plain answer, and are plain otherwise.
#[tokio::test]
async fn z1_the_ui_pages_and_every_asset_gzip_when_asked() {
    let (state, _dir) = fixture().await;
    let contract = Contract::load();
    let mut cases = vec![
        ("/ui".to_owned(), CLASSIC.to_vec()),
        ("/ui/classic".to_owned(), CLASSIC.to_vec()),
        ("/ui/overview/status".to_owned(), SHELL.to_vec()),
    ];
    let assets = shell_assets();
    for ext in [".css", ".js", ".woff2", ".json"] {
        assert!(
            assets.iter().any(|(n, _)| n.ends_with(ext)),
            "an asset ends {ext}"
        );
    }
    cases.extend(
        assets
            .into_iter()
            .map(|(n, b)| (format!("/ui/assets/{n}"), b)),
    );
    for (uri, plain) in cases {
        let asked = send(&state, &uri, &[GZIP]).await;
        assert_eq!(asked.status, StatusCode::OK, "{uri}");
        let content_type = asked
            .header(&header::CONTENT_TYPE)
            .unwrap_or_default()
            .to_owned();
        let want = contract.gzips(&content_type, plain.len());
        // The pages and the text assets are what this change compresses.
        if !uri.ends_with(".woff2") {
            assert!(
                want,
                "{uri} ({content_type}) is compressible by the contract"
            );
        }
        assert_eq!(
            asked.header(&header::CONTENT_ENCODING),
            want.then_some("gzip"),
            "{uri} with Accept-Encoding: gzip"
        );
        assert_eq!(
            asked.decoded(),
            plain,
            "{uri}: decompressed, the plain bytes"
        );
        if want {
            assert!(
                asked
                    .header(&header::VARY)
                    .is_some_and(|v| v.to_ascii_lowercase().contains("accept-encoding")),
                "{uri} varies by Accept-Encoding"
            );
        }
        let bare = send(&state, &uri, &[]).await;
        assert_eq!(
            bare.header(&header::CONTENT_ENCODING),
            None,
            "{uri} unasked"
        );
        assert_eq!(bare.body, plain, "{uri} unasked: the plain bytes");
    }
}

/// GZIP.2: /ui/api was compressed before this change; a JSON answer still is.
#[tokio::test]
async fn z2_a_ui_api_json_answer_is_gzip_when_asked() {
    let (state, _dir) = fixture().await;
    let bearer = format!("Bearer {BEARER}");
    let reply = send(
        &state,
        "/ui/api/status",
        &[GZIP, ("authorization", bearer.as_str())],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        reply
            .header(&header::CONTENT_TYPE)
            .is_some_and(|v| v.starts_with("application/json")),
        "a JSON answer"
    );
    assert_eq!(reply.header(&header::CONTENT_ENCODING), Some("gzip"));
    let decoded = reply.decoded();
    serde_json::from_slice::<serde_json::Value>(&decoded).expect("decompressed, it is JSON");
}

/// GZIP.2: the live stream is never compressed, so no event waits in a
/// gzip buffer. Read to its first event, never to the end: it does not end.
#[tokio::test]
async fn z2b_the_ui_stream_is_never_compressed() {
    let (state, _dir) = fixture().await;
    let bearer = format!("Bearer {BEARER}");
    let req = request(
        "/ui/api/stream",
        &[GZIP, ("authorization", bearer.as_str())],
    );
    let response = tokio::time::timeout(GUARD, create_router(Arc::clone(&state)).oneshot(req))
        .await
        .expect("the stream answered")
        .expect("the router is infallible");
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    assert_eq!(
        headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(headers.get(header::CONTENT_ENCODING), None, "{headers:?}");
    let mut body = response.into_body().into_data_stream();
    let first = tokio::time::timeout(GUARD, body.next())
        .await
        .expect("an event arrived")
        .expect("the stream is open")
        .expect("a chunk");
    let text = String::from_utf8(first.to_vec()).expect("an uncompressed event is text");
    assert!(text.contains("\n\n"), "a whole event: {text:?}");
}

/// GZIP.4 (BREACH): nothing html_router serves depends on the caller, so
/// different cookies, credentials and paths get byte-identical bodies.
#[tokio::test]
async fn z4_the_ui_bodies_do_not_depend_on_the_caller() {
    let (state, _dir) = fixture().await;
    let asset = shell_assets()
        .into_iter()
        .find(|(n, _)| n.starts_with("shell.") && n.ends_with(".js"))
        .map(|(n, _)| format!("/ui/assets/{n}"))
        .expect("the shell script");
    let callers: [&[(&str, &str)]; 3] = [
        &[GZIP],
        &[
            GZIP,
            ("cookie", "mcpg_session=first-session; theme=x"),
            ("authorization", "Bearer secret-one"),
        ],
        &[
            GZIP,
            ("cookie", "mcpg_session=second-session-longer"),
            ("authorization", "Bearer secret-two-longer"),
        ],
    ];
    for paths in [
        [
            "/ui/overview/status",
            "/ui/servers/secret-one",
            "/ui/keys?q=secret-two",
        ],
        [asset.as_str(), asset.as_str(), asset.as_str()],
    ] {
        let mut bodies = Vec::new();
        for (path, caller) in paths.iter().zip(callers) {
            let reply = send(&state, path, caller).await;
            assert_eq!(reply.status, StatusCode::OK, "{path}");
            assert_eq!(
                reply.header(&header::CONTENT_ENCODING),
                Some("gzip"),
                "{path}"
            );
            bodies.push(reply.decoded());
        }
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "{paths:?}: identical bodies"
        );
    }
}

/// GZIP.3: the router's one rule answers exactly as the contract the fixture
/// server applies says, on the boundary cases, so neither can drift. A
/// test-only router, never a listener route.
#[tokio::test]
async fn z3_the_gateway_rule_is_the_contract() {
    let contract = Contract::load();
    let mut cases: Vec<(String, usize)> = [
        ("text/plain", 31),
        ("text/plain", 32),
        ("text/html; charset=utf-8", 100),
        ("application/json", 100),
        ("image/png", 100),
        ("image/svg+xml", 100),
        ("text/event-stream; charset=utf-8", 100),
        ("application/grpc", 100),
        ("application/grpc+proto", 100),
        ("application/grpc-web", 100),
        ("application/grpc-web+proto", 100),
        ("font/woff2", 100),
    ]
    .into_iter()
    .map(|(t, n)| (t.to_owned(), n))
    .collect();
    for listed in contract.never_prefixes.iter().chain(&contract.except_types) {
        cases.push((format!("{listed}x"), 100));
    }
    let mut app = Router::new();
    for (i, (content_type, len)) in cases.iter().enumerate() {
        let (content_type, body) = (content_type.clone(), vec![b'a'; *len]);
        app = app.route(
            &format!("/c{i}"),
            get(move || {
                let (content_type, body) = (content_type.clone(), body.clone());
                async move { ([(header::CONTENT_TYPE, content_type)], body) }
            }),
        );
    }
    let app = app.layer(compression());
    for (i, (content_type, len)) in cases.iter().enumerate() {
        let reply = read(app.clone(), request(&format!("/c{i}"), &[GZIP])).await;
        assert_eq!(
            reply.header(&header::CONTENT_ENCODING) == Some("gzip"),
            contract.gzips(content_type, *len),
            "{content_type}, {len} bytes"
        );
        assert_eq!(reply.decoded(), vec![b'a'; *len], "{content_type}");
    }
}

/// GZIP.3: the gateway negotiates Accept-Encoding as compression.json's
/// negotiation rows say, so the fixture server, which reads the same rows,
/// cannot compress where the gateway would not.
#[tokio::test]
async fn z4_accept_encoding_negotiation_matches_the_contract_rows() {
    let v: serde_json::Value = serde_json::from_str(CONTRACT).expect("compression.json parses");
    let rows = v["negotiation"].as_array().expect("negotiation rows");
    assert!(
        rows.len() >= 10,
        "the negotiation rows cover the q-value cases"
    );
    let (state, _dir) = fixture().await;
    for row in rows {
        let accept = row["accept_encoding"].as_str().expect("a header value");
        let want = row["gzip"].as_bool().expect("a yes or no");
        let reply = send(
            &state,
            "/ui/overview/status",
            &[("accept-encoding", accept)],
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK, "{accept}");
        assert_eq!(
            reply.header(&header::CONTENT_ENCODING) == Some("gzip"),
            want,
            "Accept-Encoding: {accept}"
        );
        assert_eq!(reply.decoded(), SHELL, "{accept}: the plain document");
    }
}
