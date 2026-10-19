// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.11: validating the protocol fields reads `params` members by
//! key, not by JSON pointer. `Value::pointer` unescapes every segment into a
//! new string, so each constant `/params/<key>` lookup allocated on every call.

use serde_json::{Value, json};

use super::{ProtocolRoute, validate_protocol_fields};
use crate::gateway::alloc_meter::measure;

/// The `gateway_invoke` request `benchmarks/workload/cpu_per_call.py` sends.
fn workload_request() -> Value {
    json!({
        "jsonrpc": "2.0", "id": "1-tools/call", "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {
            "server": "workload", "tool": "workload_probe",
            "arguments": {"case_reference": "042"}}},
    })
}

/// Allocations `validate_protocol_fields` may make on the workload request:
/// what reading it by key leaves (the sanitized tool name and the argument
/// checks). Reading by pointer made 22.
const MAX_ALLOCATIONS: u64 = 6;

/// Mutant: any of the four `params` lookups taken by `pointer` again.
#[test]
fn validating_the_workload_request_allocates_at_most_six_times() {
    let request = workload_request();
    let run = || {
        validate_protocol_fields(
            &request,
            &crate::gateway::PROTOCOL_NONCES,
            ProtocolRoute::Meta,
        )
    };
    run().expect("warm: the workload request is valid");
    let (outcome, measured) = measure(run);
    outcome.expect("the workload request is valid");
    assert!(
        measured.calls <= MAX_ALLOCATIONS,
        "validate_protocol_fields allocated {} times ({} B) on the workload request; \
         the bound is {MAX_ALLOCATIONS} (MIK-8014 PERF.11)",
        measured.calls,
        measured.bytes
    );
}

/// The keyed read answers exactly as the pointer did for every shape `params`
/// can take, for the five keys the request path reads: none is numeric or
/// escaped, so `pointer` and `get` agree. Pins the equivalence the change
/// rests on.
#[test]
fn a_keyed_params_read_answers_as_the_pointer_did() {
    let shapes = [
        json!({"params": {"_meta": {"a": 1}, "capabilities": {}, "name": "n",
                          "arguments": {"x": 1}, "task": {"ttl": 1}}}),
        json!({"params": {}}),
        json!({"params": null}),
        json!({"params": "string"}),
        json!({"params": [0, 1, 2]}),
        json!({"params": {"_meta": null, "name": null}}),
        json!({}),
        json!([{"params": {"name": "n"}}]),
        json!("not an object"),
    ];
    for request in &shapes {
        for key in ["_meta", "capabilities", "name", "arguments", "task"] {
            assert_eq!(
                request.get("params").and_then(|params| params.get(key)),
                request.pointer(&format!("/params/{key}")),
                "{key} in {request}"
            );
        }
    }
}
