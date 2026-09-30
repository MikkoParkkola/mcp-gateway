// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #613: the input-key check runs on every backend `tools/call`. When the slot
//! already holds a fresh schema, it must judge that schema in place: no clone
//! of the cached tool, and no per-call build of the fill machinery that only a
//! stale or missing slot needs.
//!
//! Differential, like `visibility_allocations`: the same call against a tool
//! with a tiny and a 64 KiB description. A clone of the tool shows up as the
//! size difference. The absolute ceiling catches a large per-call future.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::alloc_meter::measure_async;
use super::signing_nonce_allocations_support::isolate;
use crate::backend::Backend;
use crate::config::{BackendConfig, FailsafeConfig, InputSchemaEnforcement};

const PAD: usize = 64 * 1024;
/// Well above a ready future and the judge's own small maps, well below the
/// fill state machine a miss builds.
const CEILING: u64 = 4 * 1024;

/// Same as `signing_nonce_allocations::test_path`; it must expand here.
fn test_path(name: &str) -> String {
    let module = module_path!();
    let module = module
        .split_once("::")
        .map_or(module, |(_crate, rest)| rest);
    format!("{module}::{name}")
}

/// A backend whose shared slot holds one fresh tool with `description`.
fn backend_with(description: &str) -> Arc<Backend> {
    let config = BackendConfig {
        input_schema_enforcement: InputSchemaEnforcement::Closed,
        ..BackendConfig::default()
    };
    let backend = Arc::new(Backend::new(
        "keys",
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ));
    backend.remember_listed_tools(
        None,
        false,
        &[json!({
            "name": "probe",
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {"case_reference": {"type": "string"}},
                "additionalProperties": false
            }
        })],
    );
    // A stale or empty slot would take the fetch path and make this vacuous.
    assert!(
        backend.has_cached_tools_for(None),
        "the listing did not land"
    );
    backend
}

async fn bytes_for(backend: &Backend) -> u64 {
    let arguments = json!({"case_reference": "042"});
    let (answer, measured) =
        measure_async(|| backend.undeclared_key_refusal(None, &[], "probe", &arguments)).await;
    // Declared keys only: the call must be admitted, or the check never judged.
    assert_eq!(answer.expect("no fetch on a fresh slot"), None);
    measured.bytes
}

#[test]
fn held_schema_check_does_not_clone_the_tool_or_build_the_fill() {
    if isolate(&test_path(
        "held_schema_check_does_not_clone_the_tool_or_build_the_fill",
    )) {
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let small = backend_with("x");
        let big = backend_with(&"x".repeat(PAD));
        // Warm both once so lazily built state is not billed to either reading.
        bytes_for(&small).await;
        bytes_for(&big).await;
        let small_bytes = bytes_for(&small).await;
        let big_bytes = bytes_for(&big).await;

        assert!(
            big_bytes < small_bytes + (PAD as u64) / 4,
            "the key check allocated {big_bytes} B with a {PAD} B description vs {small_bytes} B \
             with a tiny one: the cached tool is being cloned per call (#613)"
        );
        assert!(
            small_bytes < CEILING,
            "the key check allocated {small_bytes} B per call on a fresh slot, over {CEILING} B: \
             the fill machinery is being built for an answer already held (#613)"
        );
    });
}
