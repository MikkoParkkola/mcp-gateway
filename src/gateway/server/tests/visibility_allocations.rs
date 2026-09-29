// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2110: `may_invoke` runs once per tool on every `initialize` and
//! `tools/list`, so what it allocates must not grow with the size of the
//! capability definition it checks. It used to clone the whole definition
//! twice per call (admin-capability rule, then identity-grant rule).
//!
//! The check is differential: the same call against a small and a 64 KiB
//! definition. A clone shows up as the size difference; everything else the
//! call allocates is the same in both and cancels out.

use std::sync::Arc;

use super::alloc_meter::measure;
use super::signing_nonce_allocations_support::isolate;
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::gateway::meta_mcp::{MetaMcp, anonymous_caller};

const PAD: usize = 64 * 1024;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// A read-only GET capability, so the admin rule passes it and the call
/// reaches the identity-grant rule too.
async fn meta_with(dir: &std::path::Path, description: &str) -> MetaMcp {
    std::fs::create_dir_all(dir).unwrap();
    crate::gateway::test_helpers::write_owner_only(
        dir.join("lookup.yaml"),
        format!(
            r#"fulcrum: "1.0"
name: lookup
description: "{description}"
schema:
  input:
    type: object
providers:
  primary:
    service: rest
    config:
      base_url: https://example.invalid
      path: /lookup
      method: GET
auth:
  required: false
  type: none
"#
        ),
    )
    .unwrap();
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    backend
        .load_from_directory(dir.to_str().unwrap())
        .await
        .unwrap();
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.set_capabilities(backend);
    meta
}

fn bytes_for(meta: &MetaMcp) -> u64 {
    let caller = anonymous_caller();
    let (result, measured) = measure(|| meta.may_invoke("caps", "lookup", caller.scope(), None));
    // Ok, or refused by the identity-grant rule: either way both definition
    // rules ran. Any earlier refusal would make this test vacuous.
    if let Err(e) = &result {
        assert!(
            e.to_string().contains("Identity grant denied"),
            "may_invoke stopped before the definition rules: {e}"
        );
    }
    measured.bytes
}

#[test]
fn may_invoke_allocation_does_not_scale_with_definition_size() {
    if isolate(&test_path(
        "may_invoke_allocation_does_not_scale_with_definition_size",
    )) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let small = rt.block_on(meta_with(&dir.path().join("small"), "x"));
    let big = rt.block_on(meta_with(&dir.path().join("big"), &"x".repeat(PAD)));

    // Warm both once so lazily built state is not billed to either reading.
    bytes_for(&small);
    bytes_for(&big);
    let small_bytes = bytes_for(&small);
    let big_bytes = bytes_for(&big);

    assert!(
        big_bytes < small_bytes + (PAD as u64) / 4,
        "may_invoke allocated {big_bytes} B for a {PAD} B definition vs {small_bytes} B \
         for a tiny one: the definition is being copied per call (#2110)"
    );
}
