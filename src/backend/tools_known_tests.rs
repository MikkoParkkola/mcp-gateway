// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The `tools_known` pair: an unenumerated backend versus an enumerated empty one.
//!
//! Split out of `tests.rs` so it stays under the file-size ceiling
//! `scripts/dev/check-file-size.py` gates. A `#[path]` child, not a sibling
//! module: `use super::*` still resolves to the backend's own items.

use super::*;

#[tokio::test]
async fn cached_tools_known_is_false_before_any_enumeration() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));

    assert_eq!(backend.cached_tools_count(), 0);
    assert!(!backend.cached_tools_known());
}

/// The other half of the pair: enumerated, and genuinely empty.
#[tokio::test]
async fn cached_tools_known_is_true_for_an_enumerated_backend_with_no_tools() {
    let backend = Arc::new(Backend::new(
        "test",
        BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let response = JsonRpcResponse::success_serialized(
        RequestId::Number(1),
        ToolsListResult {
            tools: Vec::new(),
            next_cursor: None,
        },
    );
    let transport = Arc::new(MockTransport::new(response, Duration::from_millis(0)));
    let transport_dyn: Arc<dyn Transport> = transport.clone();
    backend.set_transport_for_test(transport_dyn);

    let tools = backend.get_tools().await.expect("enumeration succeeds");

    assert!(tools.is_empty());
    assert_eq!(backend.cached_tools_count(), 0);
    assert!(
        backend.cached_tools_known(),
        "an empty answer is still an answer — the backend has been enumerated"
    );

    // Discarding an empty list must not un-enumerate the backend.
    backend.invalidate_tools_cache();
    assert!(
        backend.cached_tools_known(),
        "discarding the cached answer must not claim the backend was never asked"
    );
}
