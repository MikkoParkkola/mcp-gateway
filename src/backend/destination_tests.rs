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
            streamable_http: Some(!template.contains("sse")),
            protocol_version: None,
        }
    }
}

/// Start one backend at `template` in a registry under `policy`.
async fn start(template: &str, policy: DestinationPolicy) -> (crate::Result<()>, usize) {
    let (port, accepted) = counting_listener().await;
    let registry = BackendRegistry::new();
    registry
        .enforce_destinations(policy, &[])
        .expect("the registry pairs");
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
        registry
            .enforce_destinations(policy, &[])
            .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Public, &[])
        .expect("the registry pairs");
    registry
        .enforce_destinations(DestinationPolicy::Configured, &[])
        .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Configured, &[])
        .expect("the registry pairs");
    let backend = Arc::new(Backend::new(
        "b",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    registry
        .enforce_destinations(DestinationPolicy::Public, &[])
        .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Public, &listed)
        .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Public, &["listed".to_string()])
        .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Public, &["later".to_string()])
        .expect("the registry pairs");
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
        registry
            .enforce_destinations(DestinationPolicy::Public, &["slow".to_string()])
            .expect("the registry pairs");
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
    registry
        .enforce_destinations(DestinationPolicy::Configured, &["listed".to_string()])
        .expect("the registry pairs");
    let backend = Arc::new(Backend::new(
        "listed",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    assert_eq!(backend.destination(), DestinationPolicy::Configured);
}

/// A transport that stands in for one already started; records its close in
/// a flag the test keeps.
struct Started(Arc<std::sync::atomic::AtomicBool>);

#[async_trait::async_trait]
impl crate::transport::Transport for Started {
    async fn request(
        &self,
        _method: &str,
        _params: Option<serde_json::Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        Err(crate::Error::Transport("not used".into()))
    }

    async fn notify(&self, _method: &str, _params: Option<serde_json::Value>) -> crate::Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        true
    }

    async fn close(&self) -> crate::Result<()> {
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}

fn backend_at(transport: TransportConfig) -> Arc<Backend> {
    Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

fn http() -> TransportConfig {
    transport("http://127.0.0.1:{port}/mcp", 9)
}

/// Pair `registry` with a hardened config the way an embedder does.
fn pair_hardened(
    registry: Arc<BackendRegistry>,
) -> crate::Result<crate::config_reload::ReloadContext> {
    let mut running = crate::config::Config::default();
    running.security.posture = crate::security::posture::SecurityPosture::Hardened;
    crate::config_reload::ReloadContext::new(
        std::path::PathBuf::from("unused.yaml"),
        Arc::new(crate::config_reload::LiveConfig::new(running)),
        registry,
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
}

/// A backend at a loopback listener that has really started once (the
/// listener drops the connection, so the start itself fails).
async fn started_at_loopback() -> (Arc<Backend>, Arc<AtomicUsize>) {
    let (port, accepted) = counting_listener().await;
    let backend = Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: transport("http://127.0.0.1:{port}/mcp", port),
            timeout: Duration::from_secs(10),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    (backend, accepted)
}

// MIK-7700: an HTTP backend that started before a hardened pairing built an
// unpinned connection, which cannot be re-pinned in place (closing it would
// itself send to the address). Pairing is refused, naming the backend, and
// stamps nothing.
#[tokio::test]
async fn hardened_pairing_refuses_a_backend_started_unpinned() {
    let registry = Arc::new(BackendRegistry::new());
    let (backend, accepted) = started_at_loopback().await;
    assert!(registry.register(Arc::clone(&backend)));
    let _ = backend.ensure_started().await;
    assert!(
        accepted.load(Ordering::SeqCst) > 0,
        "the start connected unpinned"
    );
    let error = pair_hardened(Arc::clone(&registry))
        .err()
        .expect("pairing over an unpinned start must be refused");
    assert!(
        error.to_string().contains("'b'"),
        "names the backend: {error}"
    );
    assert!(!error.to_string().contains("127.0.0.1"), "no URL: {error}");
    assert_eq!(backend.destination(), DestinationPolicy::Configured);
}

// The shipped binary's order: pair the empty registry, then start. Every
// later pairing (reload contexts) must still succeed.
#[tokio::test]
async fn a_paired_registry_pairs_again_with_started_backends() {
    let registry = Arc::new(BackendRegistry::new());
    registry
        .enforce_destinations(DestinationPolicy::Public, &[])
        .expect("an empty registry pairs");
    let (backend, _) = started_at_loopback().await;
    assert!(registry.register(Arc::clone(&backend)));
    assert!(
        backend.ensure_started().await.is_err(),
        "pinned: loopback refused"
    );
    assert!(pair_hardened(registry).is_ok());
    assert_eq!(backend.destination(), DestinationPolicy::Public);
}

// A stdio child reaches no network destination of its own.
#[tokio::test]
async fn hardened_pairing_accepts_a_started_stdio_backend() {
    let registry = Arc::new(BackendRegistry::new());
    let backend = backend_at(TransportConfig::Stdio {
        command: "true".to_string(),
        cwd: None,
        protocol_version: None,
    });
    assert!(registry.register(Arc::clone(&backend)));
    backend.connected_unpinned.store(true, Ordering::SeqCst);
    assert!(pair_hardened(registry).is_ok());
}

// The other order: a backend started on its own, then registered into a
// registry already paired with a hardened config, is refused registration.
#[tokio::test]
async fn registering_a_started_unpinned_backend_into_a_hardened_registry_is_refused() {
    let registry = BackendRegistry::new();
    registry
        .enforce_destinations(DestinationPolicy::Public, &[])
        .expect("an empty registry pairs");
    let (backend, _) = started_at_loopback().await;
    let _ = backend.ensure_started().await;
    assert!(!registry.register(Arc::clone(&backend)));
    assert_eq!(backend.destination(), DestinationPolicy::Configured);
}

// A start that read the policy before a stamp and publishes after it is
// refused, so nothing built unpinned lands in the pool after pairing. The same
// transport built under the stamped policy publishes.
#[test]
fn a_start_built_before_the_stamp_is_not_published() {
    let backend = backend_at(http());
    let built_under = backend.destination();
    backend.stamp_destination(DestinationPolicy::Public);
    let entry = backend.shared_entry();
    let started: Arc<dyn crate::transport::Transport> = Arc::new(Started(Arc::default()));
    assert!(
        backend
            .publish(&entry, (&started, None), built_under)
            .is_err()
    );
    assert!(
        backend
            .pooled_transport_for_test(&super::PoolKey::Shared)
            .is_none()
    );
    assert!(
        backend
            .publish(&entry, (&started, None), DestinationPolicy::Public)
            .is_ok()
    );
}

/// An HTTP backend whose start is refused before anything can connect: its own
/// enabled OAuth beside identity propagation, which `create_oauth_client`
/// refuses at the sink.
fn refused_before_connecting() -> Arc<Backend> {
    let idp = crate::identity_propagation::IdentityPropagationConfig {
        strategy: crate::identity_propagation::PropagationStrategyKind::Passthrough,
        audience: "https://backend.example".to_string(),
        required: true,
        session_mode: crate::identity_propagation::SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    let oauth = crate::config::OAuthConfig {
        enabled: true,
        scopes: vec![],
        client_id: None,
        client_secret: None,
        callback_host: None,
        callback_port: None,
        callback_path: None,
        token_refresh_buffer_secs: 300,
        shared_account: false,
    };
    Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: http(),
            oauth: Some(oauth),
            identity_propagation: Some(idp),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

/// A backend at `transport` with `headers`, built without config validation
/// the way an embedder can build one.
fn unvalidated(transport: TransportConfig, headers: &[(&str, &str)]) -> Arc<Backend> {
    Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ))
}

// MIK-7855: a start refused before anything connects built nothing, so it
// leaves the backend un-marked and a later hardened pairing is not refused.
#[tokio::test]
async fn a_start_refused_before_connecting_does_not_block_a_hardened_pairing() {
    let ws = |url: &str| TransportConfig::WebSocket {
        ws_url: url.to_string(),
        protocol_version: None,
    };
    let http_at = |url: &str| TransportConfig::Http {
        http_url: url.to_string(),
        streamable_http: Some(true),
        protocol_version: None,
    };
    for (kind, backend) in [
        ("http oauth clash", refused_before_connecting()),
        (
            "http scheme",
            unvalidated(http_at("ftp://localhost/mcp"), &[]),
        ),
        ("http url", unvalidated(http_at("not a url"), &[])),
        (
            "websocket header",
            unvalidated(ws("ws://127.0.0.1:9/"), &[("bad header", "v")]),
        ),
        (
            "websocket scheme",
            unvalidated(ws("http://localhost/"), &[]),
        ),
        ("websocket url", unvalidated(ws("not a url"), &[])),
    ] {
        let registry = Arc::new(BackendRegistry::new());
        assert!(registry.register(Arc::clone(&backend)));
        assert!(
            backend.ensure_started().await.is_err(),
            "{kind}: the start is refused before connecting"
        );
        assert!(
            !backend.started_unpinned(),
            "{kind}: nothing connected, so nothing is unpinned"
        );
        assert!(pair_hardened(registry).is_ok(), "{kind}");
        assert_eq!(backend.destination(), DestinationPolicy::Public, "{kind}");
    }
}

/// Bounds a wait in a window test, so a regression fails instead of hanging.
async fn within<T>(what: &str, wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), wait)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within 30s"))
}

/// A loopback HTTP backend with its own OAuth client enabled.
async fn oauth_at_loopback() -> (Arc<Backend>, Arc<AtomicUsize>) {
    let (port, accepted) = counting_listener().await;
    let backend = Arc::new(Backend::new(
        "b",
        BackendConfig {
            transport: transport("http://127.0.0.1:{port}/mcp", port),
            timeout: Duration::from_secs(10),
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
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    (backend, accepted)
}

// MIK-7855: a start that read its policy before a hardened pairing stamped
// one, and is held in that window while the pairing runs: before it builds
// its OAuth client or transport, and before it marks. Nothing is marked yet,
// so the pairing succeeds and stamps; the start must then notice the stamp it
// did not build under and refuse rather than connect unpinned, its OAuth
// discovery included.
#[tokio::test]
async fn a_pairing_inside_the_start_window_stops_the_start_connecting() {
    for (kind, (backend, accepted)) in [
        ("plain", started_at_loopback().await),
        ("oauth", oauth_at_loopback().await),
    ] {
        let registry = Arc::new(BackendRegistry::new());
        assert!(registry.register(Arc::clone(&backend)));
        let gate = Arc::new(super::MarkWindowGate::default());
        *backend.mark_window_gate.lock() = Some(Arc::clone(&gate));

        let start = tokio::spawn({
            let backend = Arc::clone(&backend);
            async move { backend.ensure_started().await }
        });
        within("the start reaching the window", gate.reached.notified()).await;
        assert!(
            !backend.started_unpinned(),
            "{kind}: held before the mark, so nothing is marked yet"
        );
        assert!(
            pair_hardened(Arc::clone(&registry)).is_ok(),
            "{kind}: nothing connected or marked, so the pairing succeeds"
        );
        assert_eq!(backend.destination(), DestinationPolicy::Public, "{kind}");
        gate.release.notify_one();

        let started = within("the start returning", start)
            .await
            .expect("start task");
        assert!(
            matches!(started, Err(crate::Error::BackendUnavailable(_))),
            "{kind}: the start built under the old policy is refused, got {started:?}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "{kind}: a successful pairing left an unpinned connection"
        );
        assert!(!backend.started_unpinned(), "{kind}");
    }
}

#[path = "destination_race_tests.rs"]
mod race;
