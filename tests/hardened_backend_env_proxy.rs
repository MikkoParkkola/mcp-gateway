// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T11 of the HARDEN 4b test plan: under `security.posture: hardened` a
//! backend's traffic ignores `HTTP_PROXY`/`HTTPS_PROXY` from the environment.
//!
//! A proxied request is never resolved by the gateway, so it would skip the
//! DNS pin: the proxy, not the gateway, would decide what is reached. The
//! backend here is a reserved name (RFC 2606) that resolves nowhere, so the
//! only way its start can reach anything is through the proxy. `standard`
//! keeps today's behaviour and does go through it.
//!
//! Lives in its own test binary because it sets the environment:
//! `env::set_var` is unsafe in edition 2024, the library forbids unsafe, and
//! this is the only test in the process, so nothing else reads the
//! environment meanwhile.

#![allow(unsafe_code)] // set_var is unsafe in edition 2024

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::Config;
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use serde_json::json;

/// A loopback listener standing in for a proxy, bound before any runtime or
/// thread exists so the environment can be set first.
fn bind_recording_proxy() -> (std::net::TcpListener, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (listener, url)
}

/// Count every connection the proxy receives and drop it.
fn serve_recording_proxy(listener: std::net::TcpListener) -> Arc<AtomicUsize> {
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

/// Set every proxy variable to `proxy`. Called from the test's only thread,
/// before the runtime starts, so nothing reads the environment meanwhile.
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

/// Start the one backend of a config under `posture`, the way an embedder
/// pairs its own registry with a config (`ReloadContext::new`).
async fn start_probe(posture: &str) -> mcp_gateway::Result<()> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("gateway.yaml");
    let document = json!({
        "backends": {"probe": {
            "http_url": "http://backend.invalid/mcp",
            "enabled": true,
            "timeout": "2s"
        }},
        "security": {"posture": posture}
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
    );
    backend.ensure_started().await
}

#[test]
fn proxy_env_does_not_bypass_policy() {
    let (listener, proxy) = bind_recording_proxy();
    set_env_proxy(&proxy);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let seen = serve_recording_proxy(listener);

            let hardened = start_probe("hardened").await;
            assert!(
                hardened.is_err(),
                "the probe host resolves nowhere: {hardened:?}"
            );
            assert_eq!(
                seen.load(Ordering::SeqCst),
                0,
                "a hardened backend went through the environment proxy"
            );

            // Control: standard honours the proxy, so the probe above is live.
            let _ = start_probe("standard").await;
            assert!(
                seen.load(Ordering::SeqCst) > 0,
                "control: a standard backend uses the environment proxy"
            );
        });
}
