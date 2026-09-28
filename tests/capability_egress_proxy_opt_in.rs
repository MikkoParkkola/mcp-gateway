// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `capabilities.egress_proxy` is the only proxy route for capability calls (#1881).
//!
//! Lives in its own test binary because it sets the environment:
//! `env::set_var` is unsafe in edition 2024, the library forbids unsafe, and
//! this is the only test in the process, so nothing else reads the
//! environment meanwhile.

#![allow(unsafe_code)] // set_var is unsafe in edition 2024

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_gateway::capability::{CapabilityDefinition, CapabilityExecutor, parse_capability};
use mcp_gateway::config::CapabilityConfig;

/// A loopback listener standing in for a proxy: it counts connections and
/// answers each with a 200, so a proxied call would succeed.
async fn recording_proxy() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let body = r#"{"ok":true}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    (url, seen)
}

const PROBE: &str = "http://proxy-bypass-probe.example";

fn capability_at(base_url: &str) -> CapabilityDefinition {
    parse_capability(&format!(
        r"
name: proxy_bypass_probe
description: Probe for proxy egress
providers:
  primary:
    service: rest
    config:
      base_url: {base_url}
      path: /probe
      method: GET
"
    ))
    .expect("probe capability parses")
}

fn egress_proxy(url: &str) -> CapabilityConfig {
    CapabilityConfig {
        egress_proxy: Some(url.to_string()),
        ..CapabilityConfig::default()
    }
}

/// The opt-in: `capabilities.egress_proxy` carries every capability call to
/// the named proxy, and the environment proxy still carries none. The proxy is
/// named by a host that resolves to loopback: the pin must not refuse the proxy
/// hop itself. An IP-literal destination is still refused.
#[tokio::test]
async fn capabilities_egress_proxy_is_the_only_proxy_route() {
    let (from_env, env_seen) = recording_proxy().await;
    // SAFETY: the only test in this binary; nothing else reads the environment.
    unsafe {
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
        ] {
            std::env::set_var(var, &from_env);
        }
    }
    let (configured, seen) = recording_proxy().await;
    let configured = configured.replace("127.0.0.1", "localhost");
    let executor = CapabilityExecutor::for_config(&egress_proxy(&configured));

    let result = executor
        .execute(&capability_at(PROBE), serde_json::json!({}))
        .await;
    assert!(result.is_ok(), "the configured proxy answers: {result:?}");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "one call, through the proxy"
    );

    let literal = executor
        .execute(&capability_at("http://10.0.0.1"), serde_json::json!({}))
        .await;
    assert!(
        literal.is_err(),
        "a private literal is refused before the proxy"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "the refused call never left"
    );
    assert_eq!(
        env_seen.load(Ordering::SeqCst),
        0,
        "the environment proxy carried a call"
    );
}
