// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T10: the pinned upgrade connects to the checked address yet keeps the
//! configured name for SNI and `Host`, after exactly one lookup. The address
//! check itself is exercised with `Configured` here (loopback is the only
//! server a test has); `Public` refusing that address is the last test.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use super::connect_pinned;
use crate::Result;
use crate::security::ssrf::{DestinationPolicy, HostResolver};

const WAIT: Duration = Duration::from_secs(5);

/// Answers every name with loopback and counts lookups.
#[derive(Default)]
struct Loopback {
    lookups: Arc<AtomicUsize>,
}

impl HostResolver for Loopback {
    fn lookup(
        &self,
        _host: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>>> + Send + '_>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]) })
    }
}

#[tokio::test]
async fn pinned_websocket_keeps_sni() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sni_tx, sni_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let acceptor = tokio_rustls::LazyConfigAcceptor::new(
            tokio_rustls::rustls::server::Acceptor::default(),
            stream,
        );
        if let Ok(start) = acceptor.await {
            let _ = sni_tx.send(start.client_hello().server_name().map(str::to_owned));
        }
    });
    let resolver = Loopback::default();
    let request = format!("wss://sni.test:{port}/")
        .into_client_request()
        .unwrap();
    // No certificate is ever offered, so the upgrade fails; the ClientHello is
    // what this checks.
    let _ = tokio::time::timeout(
        WAIT,
        connect_pinned(request, DestinationPolicy::Configured, &resolver),
    )
    .await;
    let sni = tokio::time::timeout(WAIT, sni_rx)
        .await
        .expect("the pinned address received a TLS ClientHello")
        .unwrap();
    assert_eq!(
        sni.as_deref(),
        Some("sni.test"),
        "SNI is the configured name"
    );
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1, "resolved once");
}

#[tokio::test]
async fn pinned_websocket_keeps_host() {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (host_tx, host_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let callback = |request: &Request, response: Response| {
            let host = request
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let _ = host_tx.send(host);
            Ok(response)
        };
        let _ = tokio_tungstenite::accept_hdr_async(stream, callback).await;
    });
    let resolver = Loopback::default();
    let request = format!("ws://sni.test:{port}/")
        .into_client_request()
        .unwrap();
    tokio::time::timeout(
        WAIT,
        connect_pinned(request, DestinationPolicy::Configured, &resolver),
    )
    .await
    .expect("upgrade must not hang")
    .expect("the pinned address completes the upgrade");
    let host = host_rx.await.unwrap();
    assert_eq!(
        host,
        Some(format!("sni.test:{port}")),
        "Host is the configured name"
    );
    assert_eq!(resolver.lookups.load(Ordering::SeqCst), 1, "resolved once");
}

#[tokio::test]
async fn public_refuses_a_name_that_resolves_private() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let resolver = Loopback::default();
    let request = format!("ws://sni.test:{port}/")
        .into_client_request()
        .unwrap();
    let error = tokio::time::timeout(
        WAIT,
        connect_pinned(request, DestinationPolicy::Public, &resolver),
    )
    .await
    .expect("refusal must not hang")
    .expect_err("loopback is private")
    .to_string();
    assert!(error.contains("SSRF blocked"), "{error}");
    assert!(error.contains("sni.test"), "names the host: {error}");
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing connected");
}
