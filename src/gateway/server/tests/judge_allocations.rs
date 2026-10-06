// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7942 D6.CATALOGUE.8: judging a response for tenant reads must not copy
//! the result. The emitted-document scan serialized the whole response, then
//! put a clone of the raw `result` back over the clamped one: two copies of a
//! large result per judged frame.
//!
//! Differential, as `visibility_allocations`: the same judgement of a small
//! and of a 1 MiB result. A copy shows up as the size difference; the rest
//! cancels out. Cumulative bytes asked of the allocator inside `admit` only;
//! the fixtures are built before the meter starts.

use serde_json::json;

use super::alloc_meter::measure;
use super::signing_nonce_allocations_support::isolate;
use crate::gateway::outbound::{Payload, admit};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::firewall::tenant_guard::{CrossTenantReads, TenantGuardConfig};
use crate::security::firewall::{Firewall, FirewallConfig};

const PAD: usize = 1024 * 1024;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

fn judging() -> Firewall {
    Firewall::from_config(
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
    )
}

fn bytes_for(fw: &Firewall, text: &str) -> u64 {
    let response = JsonRpcResponse::success(
        RequestId::Number(1),
        json!({ "content": [{ "type": "text", "text": text }], "cacheScope": "public" }),
    );
    let payload = Payload::Response(response);
    let (admission, measured) = measure(|| admit(fw, Some("api_key:one"), payload, None));
    drop(admission);
    measured.bytes
}

#[test]
fn judging_a_response_does_not_copy_its_result() {
    if isolate(&test_path("judging_a_response_does_not_copy_its_result")) {
        return;
    }
    let fw = judging();
    let big = "x".repeat(PAD);
    // Warm once so lazily built state is not billed to either reading.
    bytes_for(&fw, "x");
    bytes_for(&fw, &big);
    let small_bytes = bytes_for(&fw, "x");
    let big_bytes = bytes_for(&fw, &big);
    assert!(
        big_bytes < small_bytes + (PAD as u64) / 2,
        "judging allocated {big_bytes} B for a {PAD} B result vs {small_bytes} B for a tiny \
         one: the result is being copied per judged frame"
    );
}
