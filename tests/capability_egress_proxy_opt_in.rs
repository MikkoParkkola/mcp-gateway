// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `capabilities.egress_proxy` is the only proxy route for capability calls (#1881).
//!
//! Lives in its own test binary because it sets the environment:
//! `env::set_var` is unsafe in edition 2024, the library forbids unsafe, and
//! the one other test in the process, the home-routing row, holds the same
//! lock ([`ALONE`]), so nothing else reads the environment meanwhile.

#![allow(unsafe_code)] // set_var is unsafe in edition 2024

#[path = "common/private_home.rs"]
#[macro_use]
mod private_home;
#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use mcp_gateway::capability::{CapabilityDefinition, CapabilityExecutor, parse_capability};
use mcp_gateway::config::CapabilityConfig;

/// A loopback listener standing in for a proxy, bound before any runtime or
/// thread exists so the environment can be set first. Serve it with
/// [`serve_recording_proxy`]; it counts connections and answers each with a
/// 200, so a proxied call would succeed.
fn bind_recording_proxy() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (listener, url)
}

fn serve_recording_proxy(listener: std::net::TcpListener) -> Arc<AtomicUsize> {
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
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
    seen
}

/// The two tests here never overlap. The proxy row changes the environment,
/// which no other thread may read meanwhile; the routing row reads it to start
/// its child. Each holds this lock for its whole run.
static ALONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn alone() -> std::sync::MutexGuard<'static, ()> {
    ALONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Set every proxy variable to `proxy`. Called with [`ALONE`] held, before
/// the runtime starts, so nothing reads the environment meanwhile.
fn set_env_proxy(proxy: &str) {
    // SAFETY: the caller holds ALONE and no runtime runs yet; the only other
    // test waits on ALONE, so no thread reads the environment (see above).
    unsafe {
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
        ] {
            std::env::set_var(var, proxy);
        }
        for var in ["NO_PROXY", "no_proxy"] {
            std::env::remove_var(var);
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
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
#[test]
fn capabilities_egress_proxy_is_the_only_proxy_route() {
    require_private_home!();
    let _alone = alone();
    let (from_env, env_url) = bind_recording_proxy();
    set_env_proxy(&env_url);
    runtime().block_on(check_opt_in(from_env));
}

async fn check_opt_in(from_env: std::net::TcpListener) {
    let env_seen = serve_recording_proxy(from_env);
    let (configured, configured_url) = bind_recording_proxy();
    let seen = serve_recording_proxy(configured);
    let configured = configured_url.replace("127.0.0.1", "localhost");
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

/// T3-T5: this binary's gateway home routes to the test-home override.
#[test]
fn private_home_routes_to_the_override() {
    let _alone = alone();
    private_home::assert_routes_to_the_override(
        module_path!(),
        "private_home_routes_to_the_override",
    );
}
