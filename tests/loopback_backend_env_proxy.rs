// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An `http://` backend on a loopback host never goes through an
//! environment proxy, whatever the posture (CodeQL #426/#427/#488/#489).
//!
//! Cleartext to loopback is allowed because it never leaves the machine;
//! that includes an OAuth bearer (`require_secure_oauth_target`). An
//! inherited `HTTP_PROXY` would carry that request, credential and all, to
//! the proxy in cleartext. The control shows the environment proxy is live
//! for a non-loopback backend, so a zero below is not a dead proxy.
//!
//! Lives in its own test binary because it sets the environment:
//! `env::set_var` is unsafe in edition 2024, the library forbids unsafe, and
//! this is the only test in the process.

#![allow(unsafe_code)] // set_var is unsafe in edition 2024

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::Config;
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use serde_json::json;

/// A loopback listener, bound before any runtime or thread exists so the
/// environment can be set first.
fn bind() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Count every connection the listener receives and drop it.
fn count_connections(listener: std::net::TcpListener) -> Arc<AtomicUsize> {
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    seen
}

/// Set every proxy variable to `proxy` and clear the bypass list. Called
/// from the test's only thread, before the runtime starts.
fn set_env_proxy(proxy: &str) {
    // SAFETY: single-threaded at this point (see above).
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

/// Start a standard-posture backend at `http_url`.
async fn start(http_url: &str) -> mcp_gateway::Result<()> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gateway.yaml");
    let document = json!({
        "backends": {"probe": {"http_url": http_url, "enabled": true, "timeout": "2s"}}
    });
    mcp_gateway::gateway::test_helpers::write_owner_only(
        &path,
        serde_yaml::to_string(&document).unwrap(),
    )
    .unwrap();
    let evaluated = Config::load_evaluated(Some(&path)).expect("valid fixture");
    let registry = Arc::new(BackendRegistry::new());
    let (name, config) = evaluated.config.backends.iter().next().unwrap();
    let backend = Arc::new(Backend::new(
        name,
        config.clone(),
        &evaluated.config.failsafe,
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    let _context = ReloadContext::new(
        path,
        Arc::new(LiveConfig::new(evaluated.config.clone())),
        registry,
        evaluated.config.failsafe,
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config");
    backend.ensure_started().await
}

#[test]
fn a_loopback_http_backend_never_uses_the_environment_proxy() {
    let (proxy_listener, proxy_port) = bind();
    let (backend_listener, backend_port) = bind();
    set_env_proxy(&format!("http://127.0.0.1:{proxy_port}"));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let proxied = count_connections(proxy_listener);
            let direct = count_connections(backend_listener);

            for host in ["127.0.0.1", "localhost"] {
                let _ = start(&format!("http://{host}:{backend_port}/mcp")).await;
            }
            assert_eq!(
                proxied.load(Ordering::SeqCst),
                0,
                "a loopback backend's cleartext request went to the environment proxy"
            );
            assert!(
                direct.load(Ordering::SeqCst) > 0,
                "the loopback backend was reached directly"
            );

            // Control: a non-loopback backend still honours the proxy.
            let _ = start("http://backend.invalid/mcp").await;
            assert!(
                proxied.load(Ordering::SeqCst) > 0,
                "control: a non-loopback backend uses the environment proxy"
            );
        });
}
