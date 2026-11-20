// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability egress ignores `HTTP_PROXY`/`HTTPS_PROXY` from the environment (#1881).
//!
//! A proxied request is never resolved by the gateway, so it would skip the
//! SSRF pin: the proxy, not the gateway, would decide what is reached. The
//! destination here is a reserved name (RFC 2606) that resolves nowhere, so
//! the only way the call can reach anything is through the proxy.
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

use mcp_gateway::capability::{
    CapabilityDefinition, CapabilityExecutor, OpenApiConverter, parse_capability,
};
#[cfg(feature = "discovery")]
use mcp_gateway::capability::{DiscoveryEngine, DiscoveryOptions};
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

#[test]
fn an_environment_proxy_carries_no_capability_import_or_discovery_traffic() {
    require_private_home!();
    let _alone = alone();
    let (listener, proxy) = bind_recording_proxy();
    set_env_proxy(&proxy);
    runtime().block_on(check_no_env_proxy_traffic(listener));
}

async fn check_no_env_proxy_traffic(listener: std::net::TcpListener) {
    let seen = serve_recording_proxy(listener);

    // Capability execution, by both constructors.
    let capability = capability_at(PROBE);
    let result = CapabilityExecutor::new()
        .execute(&capability, serde_json::json!({}))
        .await;
    assert!(
        result.is_err(),
        "the probe host resolves nowhere: {result:?}"
    );
    let result = CapabilityExecutor::for_config(&CapabilityConfig::default())
        .execute(&capability, serde_json::json!({}))
        .await;
    assert!(
        result.is_err(),
        "the probe host resolves nowhere: {result:?}"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "capability egress went through the environment proxy"
    );

    // OpenAPI import by URL.
    let imported = OpenApiConverter::new()
        .convert_url(&format!("{PROBE}/openapi.json"))
        .await;
    assert!(imported.is_err(), "the probe host resolves nowhere");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        0,
        "OpenAPI import went through the environment proxy"
    );

    // Capability discovery.
    #[cfg(feature = "discovery")]
    {
        let discovered = DiscoveryEngine::new(DiscoveryOptions::default())
            .discover(PROBE)
            .await;
        assert!(discovered.is_err(), "the probe host resolves nowhere");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "capability discovery went through the environment proxy"
        );
    }
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
