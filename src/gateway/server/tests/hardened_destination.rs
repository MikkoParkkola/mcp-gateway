// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T5 of the HARDEN 4b test plan: a backend the production constructor
//! registers at startup is pinned under `hardened`. Its name resolves to
//! loopback, so the pinning resolver refuses it on the first connect, typed
//! `-32600 SSRF blocked`, and nothing reaches the listener. `standard`
//! connects to the same place.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::Gateway;
use crate::security::SecurityPosture;

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

/// Boot `Gateway::new` with one HTTP backend at `localhost:{port}` and start it.
async fn start_under(posture: SecurityPosture) -> (crate::Result<()>, usize) {
    let (port, accepted) = counting_listener().await;
    let mut config = Config::default();
    config.security.posture = posture;
    // Hardened forces signing, which needs a secret (row 6).
    config.security.message_signing.shared_secret =
        crate::security::posture::tests::SIGNING_SECRET.to_string();
    config.backends.insert(
        "local".to_string(),
        BackendConfig {
            transport: TransportConfig::Http {
                http_url: format!("http://localhost:{port}/mcp"),
                streamable_http: true,
                protocol_version: None,
            },
            enabled: true,
            timeout: Duration::from_secs(2),
            ..BackendConfig::default()
        },
    );
    let gateway = Gateway::new(config)
        .await
        .expect("the production constructor accepts this configuration");
    let backend = gateway
        .backends
        .get("local")
        .expect("startup registered the backend");
    let started = backend.ensure_started().await;
    // Read after the start returned: every connection it made is counted.
    (started, accepted.load(Ordering::SeqCst))
}

#[tokio::test]
async fn hardened_startup_backend_is_pinned() {
    let (started, accepted) = start_under(SecurityPosture::Hardened).await;
    let error = started.expect_err("loopback is private under hardened");
    assert!(error.to_string().contains("SSRF blocked"), "{error}");
    assert_eq!(error.to_rpc_code(), -32600, "{error}");
    assert_eq!(accepted, 0, "nothing may connect");

    let (_, accepted) = start_under(SecurityPosture::Standard).await;
    assert!(accepted > 0, "control: standard reaches the listener");
}
