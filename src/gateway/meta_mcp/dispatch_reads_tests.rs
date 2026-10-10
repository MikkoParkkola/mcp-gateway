// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.2 rows 13 and 18 at the dispatch (design §4.4): an inner
//! dispatch's raw reading reaches the request's read scope once its response
//! gates passed, with no transparency log, and a refused dispatch adds nothing.

use std::sync::Arc;

use serde_json::json;

use super::MetaMcp;
use crate::backend::BackendRegistry;
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};
use crate::security::hash_argument;
use crate::security::tenant_reads::with_read_scope;

fn firewall() -> Arc<Firewall> {
    Arc::new(
        Firewall::from_config(
            FirewallConfig {
                tenant_guard: TenantGuardConfig {
                    enabled: false,
                    arg_keys: vec!["customer_id".to_string()],
                    cross_tenant_reads: CrossTenantReads::Observe,
                    ..TenantGuardConfig::default()
                },
                ..FirewallConfig::default()
            },
            None,
        )
        .keyed_for_test(),
    )
}

fn meta(fw: &Arc<Firewall>, action_mode: bool) -> MetaMcp {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_firewall(Some(Arc::clone(fw)));
    meta.share_keyring_with_for_test(fw);
    if action_mode {
        meta.enable_response_inspection_action_mode();
    }
    meta
}

/// Row 18: a dispatch's reading of B is noted with no logger installed.
#[tokio::test]
async fn hidden_attribution_without_logger() {
    let fw = firewall();
    let meta = meta(&fw, false);
    let (gated, noted) = with_read_scope(Arc::clone(&fw), async {
        meta.apply_response_gates(
            "demo",
            "rows",
            None,
            "t1",
            json!({ "customer_id": "cust-b" }),
        )
    })
    .await;
    assert!(gated.is_ok(), "premise: the gates pass");
    assert!(
        noted.tenants.contains(&hash_argument(&json!("cust-b"))),
        "a delivered dispatch's reading of B reaches the read scope: {noted:?}"
    );
}

/// Row 13: a dispatch its gates refused adds nothing to the read scope.
#[tokio::test]
async fn refused_dispatch_notes_nothing() {
    let fw = firewall();
    let meta = meta(&fw, true);
    let canary = format!("ghp_{}", "abcdefghijklmnopqrstuvwxyz1234567890");
    let (gated, noted) = with_read_scope(Arc::clone(&fw), async {
        meta.apply_response_gates(
            "demo",
            "rows",
            None,
            "t2",
            json!({ "customer_id": "cust-b", "content": [{ "type": "text", "text": canary }] }),
        )
    })
    .await;
    assert!(gated.is_err(), "premise: anomaly screening refuses it");
    assert!(
        noted.is_empty(),
        "a refused dispatch must not count as a read: {noted:?}"
    );
}

/// Row 18, argument half: an inner invocation whose own arguments name B
/// reads B, though the outer request and the answer show neither.
#[tokio::test]
async fn inner_invocation_arguments_are_a_read() {
    use crate::gateway::authz::AllowAll;
    use crate::gateway::meta_mcp::authz_tests::{counted_backend, ctx};

    let fw = firewall();
    let (registry, _calls) = counted_backend("alpha");
    let mut meta = MetaMcp::new(registry);
    meta.set_firewall(Some(Arc::clone(&fw)));
    meta.share_keyring_with_for_test(&fw);
    let args =
        json!({ "server": "alpha", "tool": "read", "arguments": { "customer_id": "cust-b" } });
    let caller = ctx(&AllowAll);
    let (result, noted) =
        with_read_scope(Arc::clone(&fw), meta.invoke_tool(&args, None, &caller)).await;
    assert!(result.is_ok(), "premise: the step is delivered: {result:?}");
    assert!(
        noted.tenants.contains(&hash_argument(&json!("cust-b"))),
        "the step's own arguments named B: {noted:?}"
    );
}
