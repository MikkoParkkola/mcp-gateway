// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! F26 C1: the capability response cache must not replay an error either.
//!
//! A non-2xx upstream never reaches this cache (it becomes an `Err` before the
//! store), but a 2xx body carrying `isError: true` does, and the meta layer
//! then reads that body as a tool error. Before F26 the capability cache kept
//! it for `cache.ttl`, so a backend that had recovered kept answering with the
//! stale error. C2 is the control: a success is still cached.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

use crate::capability::CapabilityExecutionContext;
use crate::capability::executor::CapabilityExecutor;
use crate::identity_grants::GrantSubject;

/// A loopback server answering `/probe` with `first` once and `ok: true` after,
/// behind a cacheable Shared capability (`cache.ttl` 60 s). Returns the
/// executor, the capability and the count of requests that reached the server.
async fn scripted_executor(
    first: Value,
) -> (
    CapabilityExecutor,
    crate::capability::CapabilityDefinition,
    Arc<AtomicUsize>,
) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_for_handler = Arc::clone(&hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/probe",
                get(move || {
                    let hits = Arc::clone(&hits_for_handler);
                    let first = first.clone();
                    async move {
                        let n = hits.fetch_add(1, Ordering::SeqCst);
                        Json(if n == 0 { first } else { json!({"ok": true}) })
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });

    let mut executor =
        CapabilityExecutor::new().with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    // `localhost` clears SSRF without relaxing loopback egress; a finite
    // timeout keeps a hung listener from stalling the suite.
    executor.client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let capability = crate::capability::parse_capability(&format!(
        r"
name: cache_error_probe
description: Shared cacheable probe
cache:
  ttl: 60
  strategy: memory
providers:
  primary:
    service: rest
    config:
      base_url: http://localhost:{port}
      path: /probe
      method: GET
"
    ))
    .unwrap();
    (executor, capability, hits)
}

/// A context the capability cache will key: a caller, a known revision, a
/// routing profile and a policy epoch (the CACHE.4 conditions).
fn cacheable_context() -> CapabilityExecutionContext {
    let mut context = CapabilityExecutionContext::with_caller_identity(GrantSubject::new(
        "cloudflare_access",
        "alice",
        None,
    ));
    context.protocol_revision = Some(crate::protocol::PROTOCOL_VERSION.to_owned());
    context.routing_profile = Some("default".to_owned());
    context.policy_epoch = Some(0);
    context
}

/// F26 C1: a 2xx `isError: true` body is not replayed. The upstream errs once
/// and then answers; the same call twice must reach it twice.
#[tokio::test]
async fn a_capability_error_body_is_not_replayed_from_the_cache() {
    let failed = json!({"content": [{"type": "text", "text": "quota"}], "isError": true});
    let (executor, capability, hits) = scripted_executor(failed).await;

    let first = executor
        .execute_with_context(&capability, json!({}), cacheable_context())
        .await
        .unwrap();
    assert_eq!(first.get("isError"), Some(&json!(true)), "{first}");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let second = executor
        .execute_with_context(&capability, json!({}), cacheable_context())
        .await
        .unwrap();
    assert_eq!(
        second,
        json!({"ok": true}),
        "the upstream has recovered; a cached error answered instead"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "both calls reached upstream"
    );
}

/// F26 C2, the control: a success is still cached, so C1 cannot pass by the
/// cache being unreachable in this fixture.
#[tokio::test]
async fn a_capability_success_is_still_cached() {
    let (executor, capability, hits) = scripted_executor(json!({"ok": true})).await;
    for _ in 0..2 {
        executor
            .execute_with_context(&capability, json!({}), cacheable_context())
            .await
            .unwrap();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the second call is a hit");
}
