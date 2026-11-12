// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 R0 (stdio): one `transport_finalized` record per frame,
//! under the trace of that frame's own invocation record.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::signing_nonce_allocations_support::{Fixture, SESSION, invoke};
use crate::gateway::meta_mcp::grant_audit_fixture::{entries, invocations, log_path};

/// The production stdio entry point, called as `run_stdio` calls it.
async fn dispatch(fixture: &Fixture, request: Value) -> Value {
    super::super::Gateway::dispatch_single_for_client(
        &fixture.meta,
        &crate::gateway::authz::published_line(&fixture.meta),
        &fixture.mtls_policy,
        request,
        super::super::StdioClient {
            session_id: SESSION,
            channel: &crate::gateway::input_bridge::NoClientChannel,
            handshake_capabilities: crate::protocol::meta::Declared::NONE,
            tasks: None,
            serving: crate::gateway::server::stdio_single::ModernServing::Enabled,
            discover: crate::gateway::server::stdio_single::DiscoverListing::Configured,
            sanitize: crate::gateway::server::stdio_single::InputSanitizing::Off,
        },
    )
    .await
    .expect("a request carrying an id must produce a response")
}

#[tokio::test]
async fn r0_each_stdio_frame_writes_one_record_under_its_own_trace() {
    let dir = Arc::new(tempfile::tempdir().expect("a private log directory"));
    let fixture = Fixture::start_audited(&log_path(&dir)).await;
    for (id, note) in [("f1", "one"), ("f2", "two")] {
        let answer = dispatch(&fixture, invoke(id, None, json!({"note": note}))).await;
        assert!(answer.get("error").is_none(), "{answer}");
    }
    assert_eq!(fixture.backend.tools_call_count(), 2, "both frames ran");
    let calls = invocations(&dir);
    assert_eq!(calls.len(), 2, "{calls:?}");
    let mut expected = BTreeMap::new();
    for call in &calls {
        let trace = call["trace_id"].as_str().expect("a trace").to_string();
        expected.insert(trace, 1usize);
    }
    assert_eq!(expected.len(), 2, "two frames, two traces");
    let mut counts = BTreeMap::new();
    for entry in entries(&dir) {
        if entry["event"] == "response_delivery_attempt"
            && entry["response_stage"] == "transport_finalized"
        {
            let trace = entry["trace_id"].as_str().expect("a trace").to_string();
            *counts.entry(trace).or_default() += 1usize;
        }
    }
    assert_eq!(counts, expected);
}
