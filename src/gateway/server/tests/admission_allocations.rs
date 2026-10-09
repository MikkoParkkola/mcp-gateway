// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #613: a legacy `gateway_invoke` with no idempotency key is admitted
//! `Unprotected`, and nothing it would have been keyed by is ever read. The
//! admission representation (which embeds the active routing profile's
//! description) must therefore not be built on that path.
//!
//! Differential, like `visibility_allocations`: the same call with a tiny and
//! a 64 KiB profile description. Building the representation shows up as the
//! size difference; everything else the call allocates cancels out.

use std::sync::Arc;

use serde_json::json;

use super::alloc_meter::measure;
use super::signing_nonce_allocations_support::isolate;
use crate::backend::BackendRegistry;
use crate::gateway::meta_mcp::admission::SyncAdmission;
use crate::gateway::meta_mcp::{MetaMcp, anonymous_caller};
use crate::protocol::RequestId;
use crate::routing_profile::{ProfileRegistry, RoutingProfileConfig};

const PAD: usize = 64 * 1024;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

fn meta_with(description: &str) -> MetaMcp {
    let profiles = std::collections::HashMap::from([(
        "open".to_string(),
        RoutingProfileConfig {
            description: description.to_string(),
            ..RoutingProfileConfig::default()
        },
    )]);
    MetaMcp::new(Arc::new(BackendRegistry::new()))
        .with_profile_registry(ProfileRegistry::from_config(&profiles, "open"))
}

fn bytes_for(meta: &MetaMcp) -> u64 {
    let mut caller = anonymous_caller();
    caller.is_modern = false;
    let args = json!({
        "server": "workload",
        "tool": "workload_probe",
        "arguments": {"case_reference": "042"}
    });
    let (result, measured) = measure(|| {
        meta.admit_meta_sync(
            crate::gateway::meta_mcp::AdmissionOwner::for_test(caller.owner_principal()),
            &caller,
            "gateway_invoke",
            &args,
            None,
            &RequestId::Number(1),
        )
    });
    // Reaching `Unprotected` proves the policy check passed and the unkeyed
    // branch ran; any earlier refusal would make this test vacuous.
    assert!(
        matches!(result, Ok(SyncAdmission::Unprotected)),
        "an unkeyed legacy call must be admitted unprotected"
    );
    measured.bytes
}

#[test]
fn unkeyed_admission_does_not_build_the_representation() {
    if isolate(&test_path(
        "unkeyed_admission_does_not_build_the_representation",
    )) {
        return;
    }
    let small = meta_with("x");
    let big = meta_with(&"x".repeat(PAD));
    // A fixture that never installed the pad would read as two equal totals.
    assert_eq!(small.active_profile(None).description.len(), 1);
    assert_eq!(big.active_profile(None).description.len(), PAD);
    // Warm both once so lazily built state is not billed to either reading.
    bytes_for(&small);
    bytes_for(&big);
    let small_bytes = bytes_for(&small);
    let big_bytes = bytes_for(&big);

    assert!(
        big_bytes < small_bytes + (PAD as u64) / 4,
        "unkeyed admission allocated {big_bytes} B with a {PAD} B profile description vs \
         {small_bytes} B with a tiny one: the discarded representation is being built (#613)"
    );
}
