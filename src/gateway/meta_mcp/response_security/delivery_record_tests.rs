// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.9: with no transparency log, recording a delivery attempt
//! must not build the record's value. The bytes it allocates must not grow
//! with the response.

use std::sync::Arc;

use serde_json::json;

use super::ResponseCorrelation;
use crate::gateway::alloc_meter::measure;

const LARGE: usize = 1024 * 1024;
const SMALL: usize = 1024;

fn correlation() -> ResponseCorrelation<'static> {
    ResponseCorrelation {
        session_id: "s",
        caller: "c",
        external_server: "gateway",
        external_tool: "gateway_invoke",
        subject: None,
    }
}

/// Bytes one response delivery record allocates, with no log configured.
fn record_bytes(meta: &crate::gateway::meta_mcp::MetaMcp, size: usize) -> u64 {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let response = crate::protocol::JsonRpcResponse::success_serialized(
        crate::protocol::RequestId::Number(1),
        json!({"content": [{"type": "text", "text": "x".repeat(size)}]}),
    );
    let correlation = correlation();
    let (delivered, measured) =
        measure(|| runtime.block_on(meta.record_delivery_of(&response, &correlation, None)));
    assert!(delivered, "with no log a delivery is never withheld");
    measured.bytes
}

#[test]
fn no_log_builds_no_delivery_record() {
    let meta =
        crate::gateway::meta_mcp::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    // Warm both sizes so lazily built state is billed to neither.
    record_bytes(&meta, SMALL);
    record_bytes(&meta, LARGE);
    let grown = record_bytes(&meta, LARGE).saturating_sub(record_bytes(&meta, SMALL));
    // Positive control: one copy of the payload is at least its size.
    let ((), unit) = measure(|| drop("x".repeat(LARGE - SMALL)));
    assert!(
        unit.bytes >= (LARGE - SMALL) as u64,
        "the meter is blind: {unit}"
    );
    assert!(
        grown < unit.bytes / 4,
        "with no transparency log, recording a delivery allocated {grown} B more for a \
         {LARGE} B response than for a {SMALL} B one: the record's value was built \
         and dropped (MIK-8014 PERF.9)"
    );
}
