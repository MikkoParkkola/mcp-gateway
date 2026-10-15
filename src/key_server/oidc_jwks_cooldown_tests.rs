// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Cooldown rows for forced `JwksCache` refreshes.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;

use super::JwksCache;

async fn counting_jwks_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            served.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                // Hold the first fetch open so the other seven arrive inside
                // its window; without single-flight each would fetch alone.
                tokio::time::sleep(Duration::from_millis(50)).await;
                let mut buf = vec![0_u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = r#"{"keys":[]}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            });
        }
    });
    (format!("http://{addr}/.well-known/jwks.json"), hits)
}

#[tokio::test]
async fn eight_concurrent_forced_refreshes_share_one_fetch() {
    let (uri, hits) = counting_jwks_server().await;
    let cache = Arc::new(JwksCache::with_http_client(reqwest::Client::new()));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let uri = uri.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get_or_fetch("https://cooldown.example", &uri, true)
                .await
        }));
    }
    for task in tasks {
        let fetched = task.await.expect("task joins");
        assert!(fetched.is_ok(), "a forced refresh serves");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "one shared fetch");
}

#[tokio::test]
async fn second_forced_refresh_inside_cooldown_fetches_nothing() {
    let (uri, hits) = counting_jwks_server().await;
    let cache = JwksCache::with_http_client(reqwest::Client::new());
    let first = cache
        .get_or_fetch("https://cooldown.example", &uri, true)
        .await;
    assert!(first.is_ok(), "a forced refresh serves");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the first fetch");
    let second = cache
        .get_or_fetch("https://cooldown.example", &uri, true)
        .await;
    assert!(second.is_ok(), "the cooldown serves the cache");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "no second fetch");
}

#[tokio::test]
async fn zero_cooldown_forces_a_second_fetch() {
    let (uri, hits) = counting_jwks_server().await;
    let mut cache = JwksCache::with_http_client(reqwest::Client::new());
    cache.forced_cooldown = Duration::ZERO;
    let first = cache
        .get_or_fetch("https://cooldown.example", &uri, true)
        .await;
    assert!(first.is_ok(), "a forced refresh serves");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the first fetch");
    let second = cache
        .get_or_fetch("https://cooldown.example", &uri, true)
        .await;
    assert!(second.is_ok(), "no cooldown fetches fresh");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "a second fetch");
}
