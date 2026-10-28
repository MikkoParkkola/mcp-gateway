// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! With `capabilities.egress_proxy` set, loopback skips the proxy (#3013),
//! so the direct leg is the only guard a capability URL naming loopback
//! meets. A name that resolves to loopback must be refused there exactly as
//! its IP literal is refused by the synchronous check.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::CapabilityExecutor;
use crate::capability::CapabilityExecutionContext;
use crate::config::CapabilityConfig;

/// A loopback listener that answers every request and counts it.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .await;
        }
    });
    (port, hits)
}

/// A REST capability whose endpoint is `base_url`.
fn capability(base_url: &str) -> crate::capability::CapabilityDefinition {
    crate::capability::parse_capability(&format!(
        r"
name: proxy_ssrf_probe
description: Loopback probe
providers:
  primary:
    service: rest
    config:
      base_url: {base_url}
      path: /probe
      method: GET
"
    ))
    .unwrap()
}

/// One call to `base_url` through an executor whose egress proxy is a
/// counting listener, with no loopback egress allowed: the result, how often
/// the proxy was reached, and how often the target was.
async fn call_through_proxy(base_url: impl Fn(u16) -> String) -> (bool, usize, usize) {
    let (proxy, via_proxy) = counting_listener().await;
    let (target, direct) = counting_listener().await;
    let executor = CapabilityExecutor::for_config(&CapabilityConfig {
        egress_proxy: Some(format!("http://127.0.0.1:{proxy}")),
        ..CapabilityConfig::default()
    });
    let result = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        executor.execute_with_context(
            &capability(&base_url(target)),
            json!({}),
            CapabilityExecutionContext::default(),
        ),
    )
    .await
    .expect("bounded");
    (
        result.is_ok(),
        via_proxy.load(Ordering::SeqCst),
        direct.load(Ordering::SeqCst),
    )
}

/// A capability URL naming `localhost` is refused on the proxied route, and
/// the loopback listener is never reached.
#[tokio::test]
async fn a_capability_naming_localhost_is_refused_through_the_proxy() {
    let (ok, via_proxy, direct) =
        call_through_proxy(|port| format!("http://localhost:{port}")).await;
    assert_eq!(
        via_proxy, 0,
        "premise: loopback never goes to the proxy (#3013)"
    );
    assert_eq!(
        direct, 0,
        "a name resolving to loopback reached the listener"
    );
    assert!(!ok, "the call succeeded");
}

/// Control: the loopback literal is refused by the synchronous check today.
#[tokio::test]
async fn a_capability_naming_the_loopback_literal_is_refused_through_the_proxy() {
    let (ok, via_proxy, direct) =
        call_through_proxy(|port| format!("http://127.0.0.1:{port}")).await;
    assert_eq!((via_proxy, direct), (0, 0), "a listener was reached");
    assert!(!ok, "the call succeeded");
}
