// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8660 T7d: `mcp-gateway stats` sends its request straight to the
//! gateway, never through a proxy named in the environment.
//!
//! Driven through the built binary because the proxy comes from the process
//! environment, which a library test cannot set without `unsafe`.

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;

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
async fn the_stats_command_bypasses_an_environment_proxy() {
    // The gateway stand-in: the T7a stats payload on POST /mcp.
    let gateway = serve(axum::Router::new().route(
        "/mcp",
        axum::routing::post(|| async {
            axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "content": [{
                        "type": "text",
                        "text": "{\"invocations\":3,\"cache_hits\":1,\"cache_hit_rate\":0.5,\"tools_discovered\":2,\"tools_available\":2,\"top_tools\":[]}"
                    }]
                }
            }))
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
        gateway_bin::command(home.path(), gateway_bin::Inherit::Environment)
            .args(["stats", "--url", &gateway])
            .env("HTTP_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("all_proxy", &proxy)
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
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
    assert!(stdout.contains("Invocations:"), "stdout: {stdout}");
}
