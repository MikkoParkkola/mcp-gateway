// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Baselines: how many copies of a caller's credential a dispatch keeps alive
//! at the send, and how many it frees unwiped. Measurement rows, not limits:
//! each writes one line to the file named by `MCPGW_BASELINE_OUT` (when set)
//! and asserts only its premises. The numbers set the budgets the copy and
//! wipe work is judged by.
//!
//! The peer is a real loopback HTTP server in this process; its handler takes
//! the live census while the gateway is mid-send. The HTTP client's own
//! buffers hold the credential too, so a client-only row sends the same header
//! through a bare client, and the gateway's share is the difference.

use std::io::Write as _;
use std::sync::Arc;

use axum::body::to_bytes;
use axum::http::HeaderMap;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::gateway::alloc_meter::{Census, Scanned, isolate_reporting, scan_dispatch, take_census};
use crate::gateway::server::signing_allocation_tests::fixed_token_mint::{
    FixedTokenMint, LONG, SHORT, token,
};
use crate::identity_propagation::{
    IdentityPropagationConfig, PropagationStrategyKind, SessionMode,
};
use crate::key_server::oidc::VerifiedIdentity;

const BACKEND: &str = "baseline";
const TOOL: &str = "lookup";

/// Run `name` in an isolated child; in the parent, echo the child's baseline
/// lines and return `true`.
fn in_child(name: &str) -> bool {
    match isolate_reporting(&test_path(name)) {
        Some(stdout) => {
            stdout
                .lines()
                .filter(|line| line.starts_with("BASELINE"))
                .for_each(|line| println!("{line}"));
            true
        }
        None => false,
    }
}

fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// One baseline line: the path, the token length, what the scan and the
/// census saw, and how many requests reached the peer.
fn report(path: &str, len: usize, scanned: Scanned, census: Census, sends: usize) {
    let line = format!(
        "BASELINE\t{path}\t{len}\tunwiped_frees={}\tsearched={}\tlive_at_send={}\tcensuses={}\tsends={sends}\n",
        scanned.hits, scanned.searched, census.most_live_copies, census.taken
    );
    print!("{line}");
    if let Some(out) = std::env::var_os("MCPGW_BASELINE_OUT") {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .and_then(|mut file| file.write_all(line.as_bytes()))
            .expect("the baseline file is writable");
    }
}

/// A streamable HTTP MCP peer on loopback that takes a census on every
/// request it serves, then answers. Returns its URL and a send counter.
async fn peer() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&sends);
    let app = axum::Router::new().fallback(
        move |_headers: HeaderMap, axum::Json(message): axum::Json<Value>| {
            let counted = Arc::clone(&counted);
            async move {
                take_census();
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let method = message["method"].as_str().unwrap_or_default().to_owned();
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let result = match method.as_str() {
                    "server/discover" => json!({
                        "supportedVersions": [crate::protocol::meta::MODERN_VERSIONS[0]],
                        "capabilities": {"tools": {}}
                    }),
                    "tools/list" => json!({"tools": [{
                        "name": TOOL,
                        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
                    }]}),
                    "tools/call" => json!({"content": [{"type": "text", "text": "ok"}]}),
                    _ => json!({}),
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    tokio::spawn(async move { axum::serve(listener, app).await });
    (url, sends)
}

/// A router whose one backend, at `url`, has a required per-user binding
/// minted by the fixed-token strategy, so each caller's slot is lent-only.
async fn gateway(url: String, minted: &'static str) -> (axum::Router, tempfile::TempDir) {
    let backend = Arc::new(crate::backend::Backend::new(
        BACKEND,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            identity_propagation: Some(IdentityPropagationConfig {
                strategy: PropagationStrategyKind::SignedAssertion,
                audience: "https://baseline.internal".to_string(),
                required: true,
                session_mode: SessionMode::PerUser,
                token_exchange_endpoint: None,
                token_exchange_scope: None,
            }),
            ..BackendConfig::r2_off()
        },
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(backend), "the backend registers");
    let meta = crate::gateway::meta_mcp::MetaMcp::new(Arc::clone(&registry));
    meta.set_identity_propagation(Arc::new(FixedTokenMint { token: minted }));
    let auth = crate::config::AuthConfig::default();
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = registry;
    state_mut.meta_mcp = Arc::new(meta);
    (super::create_router(state), store)
}

fn caller() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    }
}

async fn post_direct(router: &axum::Router, body: &Value) -> axum::http::StatusCode {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(caller());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let status = response.status();
    let _ = to_bytes(response.into_body(), usize::MAX).await;
    status
}

/// A direct-route `tools/call` on a required per-user backend.
async fn direct_call(len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = token(len);
    let (url, sends) = peer().await;
    let (router, _store) = gateway(url, minted).await;
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    // Warm: the slot starts and lists once outside the measurement.
    assert_eq!(
        post_direct(&router, &call).await,
        axum::http::StatusCode::OK
    );
    let before = sends.load(std::sync::atomic::Ordering::SeqCst);
    let (status, scanned, census) =
        scan_dispatch(minted.as_bytes(), || post_direct(&router, &call)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "premise: the call was served"
    );
    let sent = sends.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert!(
        census.taken >= 1,
        "premise: a census ran mid-send: {census:?}"
    );
    report("direct tools/call", len, scanned, census, sent);
}

#[tokio::test]
async fn baseline_direct_call_long() {
    direct_call(LONG, "baseline_direct_call_long").await;
}

#[tokio::test]
async fn baseline_direct_call_short() {
    direct_call(SHORT, "baseline_direct_call_short").await;
}

/// The HTTP client alone: the same `Authorization` header sent by a bare
/// client to the same peer. Its frees and live copies are the client's share,
/// subtracted from each gateway path's numbers.
async fn client_only(len: usize, name: &str) {
    if in_child(name) {
        return;
    }
    let minted = token(len);
    let (url, sends) = peer().await;
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"q": "x"}}});
    let send = || async {
        client
            .post(&url)
            .header("Authorization", format!("Bearer {minted}"))
            .json(&body)
            .send()
            .await
            .expect("sent")
            .bytes()
            .await
            .expect("read")
    };
    let _ = send().await;
    let (_, scanned, census) = scan_dispatch(minted.as_bytes(), send).await;
    let sent = sends.load(std::sync::atomic::Ordering::SeqCst) - 1;
    report("client only", len, scanned, census, sent);
}

#[tokio::test]
async fn baseline_client_only_long() {
    client_only(LONG, "baseline_client_only_long").await;
}

#[tokio::test]
async fn baseline_client_only_short() {
    client_only(SHORT, "baseline_client_only_short").await;
}
