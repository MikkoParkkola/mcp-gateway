// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.12: a fresh tools slot is checked without the fill
//! machinery. `tools_for_check` on a slot whose list is within its TTL fetches
//! nothing, so it takes no pool lease, builds no abandon hook, boxes no fill
//! and arms no deadline: it allocates nothing. The stale and cold paths keep
//! the lease (`backend::pool_tests::fill_lease`).

use std::time::Duration;

use serde_json::json;

use super::alloc_meter::measure_async;
use super::signing_nonce_allocations_support::{isolate, runtime};
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig};

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

fn listed_backend() -> Backend {
    let backend = Backend::new(
        "demo",
        BackendConfig::default(),
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    backend.remember_listed_tools(
        None,
        false,
        &[json!({
            "name": "search",
            "description": "probe",
            "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}}
        })],
    );
    backend
}

/// Mutant: `tools_for_check` taking the lease-and-fill path on a fresh slot
/// again (lease bookkeeping, abandon hook, boxed fill).
#[test]
fn a_fresh_slot_check_allocates_nothing() {
    if isolate(&test_path("a_fresh_slot_check_allocates_nothing")) {
        return;
    }
    runtime().block_on(fresh_slot_check());
}

async fn fresh_slot_check() {
    let backend = listed_backend();
    // Warm: anything built once per backend is billed to no measured call.
    let warm = backend
        .tools_for_check(None, crate::transport::LentCredential::default(), true)
        .await;
    assert!(warm.is_ok(), "the fresh slot answers");
    let (checked, measured) = measure_async(|| {
        backend.tools_for_check(None, crate::transport::LentCredential::default(), true)
    })
    .await;
    let (tools, completeness) = checked.expect("the fresh slot answers");
    assert_eq!(tools.len(), 1);
    // `Completeness` is private to `backend`; its Debug form names the variant.
    assert_eq!(format!("{completeness:?}"), "Complete");
    assert_eq!(
        measured.calls, 0,
        "checking a fresh tools slot allocated {} times ({} B); a held list needs no \
         lease, abandon hook, boxed fill or deadline (MIK-8014 PERF.12)",
        measured.calls, measured.bytes
    );
}
