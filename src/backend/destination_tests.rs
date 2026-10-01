// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T3 and T4: a backend in a `hardened` registry never connects to a private
//! address, whether the URL spells it as a literal or as a name that resolves
//! to one. `ensure_started` is called directly, so the router's proxy-time
//! check cannot be what refuses.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::{Backend, BackendRegistry};
use crate::config::{BackendConfig, FailsafeConfig, TransportConfig};
use crate::security::ssrf::DestinationPolicy;

/// A loopback listener that counts connections and drops each at once.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (port, accepted)
}

fn transport(template: &str, port: u16) -> TransportConfig {
    let url = template.replace("{port}", &port.to_string());
    if url.starts_with("ws") {
        TransportConfig::WebSocket {
            ws_url: url,
            protocol_version: None,
        }
    } else {
        TransportConfig::Http {
            http_url: url,
            streamable_http: !template.contains("sse"),
            protocol_version: None,
        }
    }
}

/// Start one backend at `template` in a registry under `policy`.
async fn start(template: &str, policy: DestinationPolicy) -> (crate::Result<()>, usize) {
    let (port, accepted) = counting_listener().await;
    let registry = BackendRegistry::new();
    registry.enforce_destinations(policy, &[]);
    let config = BackendConfig {
        transport: transport(template, port),
        // Long enough for a `localhost` control on Windows, which tries `::1`
        // first and waits about 2s on its refusal before trying 127.0.0.1.
        timeout: Duration::from_secs(10),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "b",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    let started = backend.ensure_started().await;
    // Read after the start returned: every connection it made is counted.
    (started, accepted.load(Ordering::SeqCst))
}

fn assert_refused(template: &str, started: &crate::Result<()>, accepted: usize) {
    let error = started.as_ref().expect_err(template);
    assert!(
        error.to_string().contains("SSRF blocked"),
        "{template}: {error}"
    );
    assert_eq!(error.to_rpc_code(), -32600, "{template}: {error}");
    assert_eq!(accepted, 0, "{template}: nothing may connect");
}

#[tokio::test]
async fn hardened_backend_refuses_private_literal() {
    for template in [
        "http://127.0.0.1:{port}/mcp",
        "http://127.0.0.1:{port}/sse",
        "ws://127.0.0.1:{port}/",
        "http://[::ffff:127.0.0.1]:{port}/mcp",
        "http://[2002:7f00:1::]:{port}/mcp",
    ] {
        let (started, accepted) = start(template, DestinationPolicy::Public).await;
        assert_refused(template, &started, accepted);
    }
}

#[tokio::test]
async fn hardened_backend_pins_private_hostname() {
    for template in [
        "http://localhost:{port}/mcp",
        "http://localhost:{port}/sse",
        "ws://localhost:{port}/",
    ] {
        let (started, accepted) = start(template, DestinationPolicy::Public).await;
        assert_refused(template, &started, accepted);
        // Control: standard connects to the same place.
        let (_, accepted) = start(template, DestinationPolicy::Configured).await;
        assert!(accepted > 0, "{template}: standard reaches the listener");
    }
}

/// T8 through the backend: an OAuth backend's discovery runs on the client
/// `create_oauth_client` builds, so under `Public` its first request is pinned
/// and never reaches a name that resolves to loopback. Discovery fails before
/// any token is read or written; the storage directory is the default one.
#[tokio::test]
async fn hardened_backend_oauth_discovery_is_pinned() {
    for (policy, reaches) in [
        (DestinationPolicy::Public, false),
        (DestinationPolicy::Configured, true),
    ] {
        let (port, accepted) = counting_listener().await;
        let registry = BackendRegistry::new();
        registry.enforce_destinations(policy, &[]);
        let config = BackendConfig {
            transport: transport("http://localhost:{port}/mcp", port),
            timeout: Duration::from_secs(2),
            oauth: Some(crate::config::OAuthConfig {
                enabled: true,
                scopes: vec![],
                client_id: None,
                client_secret: None,
                callback_host: None,
                callback_port: None,
                callback_path: None,
                token_refresh_buffer_secs: 300,
                shared_account: false,
            }),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "oauth",
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        assert!(registry.register(Arc::clone(&backend)));
        let started = backend.ensure_started().await;
        assert!(started.is_err(), "{policy:?}: nothing serves discovery");
        let seen = accepted.load(Ordering::SeqCst);
        assert_eq!(seen > 0, reaches, "{policy:?}: {seen} connections");
    }
}

/// The registry's policy is set once: a later `Configured` call cannot
/// downgrade a `Public` registry or the backends it holds or will hold.
#[test]
fn enforced_public_is_never_downgraded() {
    let backend = |name: &str| {
        Arc::new(Backend::new(
            name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    };
    let registry = BackendRegistry::new();
    let before = backend("before");
    assert!(registry.register(Arc::clone(&before)));
    registry.enforce_destinations(DestinationPolicy::Public, &[]);
    registry.enforce_destinations(DestinationPolicy::Configured, &[]);
    let after = backend("after");
    assert!(registry.register(Arc::clone(&after)));
    assert_eq!(before.destination(), DestinationPolicy::Public);
    assert_eq!(after.destination(), DestinationPolicy::Public);
}

/// A standard pairing first does not stop a later hardened one: only
/// `Public` is recorded.
#[test]
fn configured_first_does_not_block_public() {
    let registry = BackendRegistry::new();
    registry.enforce_destinations(DestinationPolicy::Configured, &[]);
    let backend = Arc::new(Backend::new(
        "b",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    registry.enforce_destinations(DestinationPolicy::Public, &[]);
    assert_eq!(backend.destination(), DestinationPolicy::Public);
    let later = Arc::new(Backend::new(
        "later",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&later)));
    assert_eq!(later.destination(), DestinationPolicy::Public);
}

/// Start backend `name` at `template` in a hardened registry listing `listed`.
async fn start_listed(template: &str, name: &str, listed: &[&str]) -> (crate::Result<()>, usize) {
    let (port, accepted) = counting_listener().await;
    let registry = BackendRegistry::new();
    let listed: Vec<String> = listed.iter().map(|n| (*n).to_string()).collect();
    registry.enforce_destinations(DestinationPolicy::Public, &listed);
    let config = BackendConfig {
        transport: transport(template, port),
        timeout: Duration::from_secs(10),
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        name,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    let started = backend.ensure_started().await;
    (started, accepted.load(Ordering::SeqCst))
}

/// Row 13: a listed backend reaches loopback, by literal and by name, and an
/// RFC 1918 literal is not refused by the policy; link-local, the IPv4 metadata
/// address and the IPv6 metadata address inside `fc00::/7` never are. An
/// unlisted backend in the same registry is still held to `Public`.
#[tokio::test]
async fn listed_private_backend_policy() {
    for template in [
        "http://127.0.0.1:{port}/mcp",
        "http://localhost:{port}/mcp",
        "ws://127.0.0.1:{port}/ws",
    ] {
        let (started, accepted) = start_listed(template, "local", &["local"]).await;
        if let Err(error) = &started {
            assert!(
                !error.to_string().contains("SSRF blocked"),
                "{template}: a listed backend was refused: {error}"
            );
        }
        assert!(
            accepted >= 1,
            "{template}: the listed backend never connected"
        );
    }
    for template in [
        "http://169.254.169.254:{port}/mcp",
        "http://[fe80::1]:{port}/mcp",
        "http://[fd00:ec2::254]:{port}/mcp",
        "ws://[fd00:ec2::254]:{port}/ws",
    ] {
        let (started, accepted) = start_listed(template, "local", &["local"]).await;
        assert_refused(template, &started, accepted);
    }
    let (started, accepted) =
        start_listed("http://127.0.0.1:{port}/mcp", "other", &["local"]).await;
    assert_refused("unlisted loopback", &started, accepted);
}

/// Reload stamping: a backend registered after the snapshot is stamped from
/// it: listed names `Private`, every other `Public`.
#[test]
fn reload_stamps_listed_backends_private() {
    let registry = BackendRegistry::new();
    registry.enforce_destinations(DestinationPolicy::Public, &["listed".to_string()]);
    let backend = |name: &str| {
        Arc::new(Backend::new(
            name,
            BackendConfig::default(),
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ))
    };
    let (listed, other) = (backend("listed"), backend("other"));
    assert!(registry.register(Arc::clone(&listed)));
    assert!(registry.register(Arc::clone(&other)));
    assert_eq!(listed.destination(), DestinationPolicy::Private);
    assert_eq!(other.destination(), DestinationPolicy::Public);
    // A second pairing cannot replace the snapshot.
    registry.enforce_destinations(DestinationPolicy::Public, &["later".to_string()]);
    let later = backend("later");
    assert!(registry.register(Arc::clone(&later)));
    assert_eq!(later.destination(), DestinationPolicy::Public);
}

/// A loopback listener that accepts every connection and never writes: no
/// TLS handshake, no upgrade answer.
async fn stalling_listener() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

/// T14: the WebSocket connect timeout bounds the whole pinned connect. A
/// listed backend's loopback server that stalls the upgrade (`ws`) or the TLS
/// handshake (`wss`) fails with the timeout, not a hang.
#[tokio::test]
async fn pinned_websocket_connect_times_out_whole() {
    for scheme in ["ws", "wss"] {
        let port = stalling_listener().await;
        let registry = BackendRegistry::new();
        registry.enforce_destinations(DestinationPolicy::Public, &["slow".to_string()]);
        let config = BackendConfig {
            transport: transport(&format!("{scheme}://127.0.0.1:{{port}}/ws"), port),
            timeout: Duration::from_secs(1),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "slow",
            config,
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        assert!(registry.register(Arc::clone(&backend)));
        assert_eq!(backend.destination(), DestinationPolicy::Private);
        let started = tokio::time::timeout(Duration::from_secs(20), backend.ensure_started())
            .await
            .unwrap_or_else(|_| panic!("{scheme}: the connect was not bounded"));
        let error = started.expect_err(scheme);
        assert!(
            error.to_string().contains("WebSocket connect timed out"),
            "{scheme}: {error}"
        );
    }
}

/// Row 16: under `standard` the list is inert. Nothing is recorded, so a
/// listed backend stays `Configured`.
#[test]
fn standard_does_not_stamp_listed_backends() {
    let registry = BackendRegistry::new();
    registry.enforce_destinations(DestinationPolicy::Configured, &["listed".to_string()]);
    let backend = Arc::new(Backend::new(
        "listed",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    assert_eq!(backend.destination(), DestinationPolicy::Configured);
}
