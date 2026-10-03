// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 red tests F1 and F2 (design §11): a capability's response
//! transform can drop the key that names a tenant, so attribution is taken
//! from the raw response before the transform, and a cache hit restores the
//! attribution stored beside the transformed value.
//!
//! The upstream answers `{"customer_id": "cust-b", "note": "x"}`; the
//! capability projects only `note`. Without pre-transform attribution the
//! delivered value names no tenant and a B read after an A read passes.

use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

use crate::capability::CapabilityExecutionContext;
use crate::capability::executor::CapabilityExecutor;
use crate::gateway::outbound::{Payload, delivered};
use crate::identity_grants::GrantSubject;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::tenant_reads::{ReadAttribution, ReadVerdict, with_read_scope};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;

const KEY: &str = "api_key:one";

fn firewall() -> Arc<Firewall> {
    Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                enabled: false,
                window_secs: 3600,
                arg_keys: vec!["customer_id".to_string()],
                cross_tenant_reads: CrossTenantReads::Observe,
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ))
}

/// A loopback upstream naming B, behind a cacheable capability whose
/// transform keeps only `note`.
async fn projecting_executor() -> (CapabilityExecutor, crate::capability::CapabilityDefinition) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/rows",
                get(|| async { Json(json!({ "customer_id": "cust-b", "note": "x" })) }),
            ),
        )
        .await
        .unwrap();
    });
    let mut executor =
        CapabilityExecutor::new().with_policy_epoch(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    executor.client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let capability = crate::capability::parse_capability(&format!(
        r"
name: tenant_rows
description: Shared cacheable rows with a projecting transform
cache:
  ttl: 60
  strategy: memory
transform:
  project: [note]
providers:
  primary:
    service: rest
    config:
      base_url: http://localhost:{port}
      path: /rows
      method: GET
"
    ))
    .unwrap();
    (executor, capability)
}

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

/// One call inside a read scope: the delivered value and the attribution the
/// scope collected.
async fn read(
    fw: &Arc<Firewall>,
    executor: &CapabilityExecutor,
    capability: &crate::capability::CapabilityDefinition,
) -> (Value, ReadAttribution) {
    let (value, hidden) = with_read_scope(
        Arc::clone(fw),
        executor.execute_with_context(capability, json!({}), cacheable_context()),
    )
    .await;
    (value.expect("the capability answers"), hidden)
}

/// The transformed B value, judged after an A read under one key.
fn judged_after_a(fw: &Firewall, value: Value, hidden: &ReadAttribution) -> Option<ReadVerdict> {
    let a = JsonRpcResponse::success(RequestId::Number(1), json!({ "customer_id": "cust-a" }));
    let _a = delivered(fw, Some(KEY), Payload::Response(a), None, None);
    let b = JsonRpcResponse::success(RequestId::Number(2), value);
    delivered(fw, Some(KEY), Payload::Response(b), None, Some(hidden)).verdict()
}

/// F1: a transform that drops B's key keeps B's attribution.
#[tokio::test]
async fn capability_transform_keeps_pre_transform_tenants() {
    let fw = firewall();
    let (executor, capability) = projecting_executor().await;
    let (value, hidden) = read(&fw, &executor, &capability).await;
    assert_eq!(
        value,
        json!({ "note": "x" }),
        "premise: the transform drops the tenant key"
    );
    assert!(
        hidden.tenants.contains(&hash_argument(&json!("cust-b"))),
        "the raw response named B before the transform: {hidden:?}"
    );
    assert_eq!(
        judged_after_a(&fw, value, &hidden),
        Some(ReadVerdict::Flagged),
        "a transformed B read after an A read is flagged"
    );
}

/// F2: a cache hit of the transformed B value restores B's attribution.
#[tokio::test]
async fn capability_executor_cache_restores_attribution() {
    let fw = firewall();
    let (executor, capability) = projecting_executor().await;
    let _miss = read(&fw, &executor, &capability).await;
    let (value, hidden) = read(&fw, &executor, &capability).await;
    assert_eq!(
        value,
        json!({ "note": "x" }),
        "premise: the hit is transformed"
    );
    assert!(
        hidden.tenants.contains(&hash_argument(&json!("cust-b"))),
        "a cache hit restores the stored attribution: {hidden:?}"
    );
    assert_eq!(
        judged_after_a(&fw, value, &hidden),
        Some(ReadVerdict::Flagged),
        "a cached B read after an A read is flagged"
    );
}
