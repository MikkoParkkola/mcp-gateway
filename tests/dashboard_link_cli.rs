// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5-T23 (MIK-7570.SESSION.1): `mcp-gateway dashboard-link` sends the admin
//! credential straight to the gateway, never through a proxy named in the
//! environment. `HTTP_PROXY`/`ALL_PROXY` would otherwise carry the bearer off
//! the machine even for a loopback URL.
//!
//! Driven through the built binary because the proxy comes from the process
//! environment, which a library test cannot set without `unsafe`.

use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::{HeaderMap, StatusCode};

/// A listener on loopback serving `app`; returns its base URL.
async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_credential_bypasses_an_environment_proxy() {
    // The gateway stand-in: a link for the right bearer only.
    let gateway = serve(axum::Router::new().route(
        "/ui/api/dashboard-link",
        axum::routing::post(|headers: HeaderMap| async move {
            let ok =
                headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer tok");
            if ok {
                Ok(axum::Json(serde_json::json!({
                    "link": "http://127.0.0.1:39400/dashboard?bootstrap=abc"
                })))
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }),
    ))
    .await;

    // The proxy stand-in: counts every request it is handed and fails it.
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&hits);
    let proxy = serve(axum::Router::new().fallback(move || {
        let seen = Arc::clone(&seen);
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            StatusCode::BAD_GATEWAY
        }
    }))
    .await;

    let home = tempfile::tempdir().expect("temp dir");
    let out = tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_mcp-gateway"))
            .args(["dashboard-link", "--url", &gateway])
            .env("MCP_GATEWAY_TOKEN", "tok")
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("all_proxy", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .env("HOME", home.path())
            .env("MCP_GATEWAY_CONFIG_DIR", home.path())
            .output()
            .expect("the command runs")
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the request went through the proxy; stderr: {stderr}"
    );
    assert!(
        out.status.success(),
        "exit {:?}; stderr: {stderr}",
        out.status
    );
    assert!(
        stdout.contains("/dashboard?bootstrap=abc"),
        "stdout: {stdout}"
    );
}
