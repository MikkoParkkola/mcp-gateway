// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8499 INTAKE.2(b): sanitizing a clean request in place allocates a
//! fixed amount, not one proportional to the payload. Before MIK-8499 it
//! rebuilt the tree: 8,981,467 B at 1 MiB and 27,051,067 B at 3 MiB.

use serde_json::{Value, json};

use crate::gateway::alloc_meter::measure;

use super::{ProtocolRoute, sanitize_request_in_place};

/// At most this much allocated sanitizing a clean request, at any size.
const CLEAN_BUDGET: u64 = 16 * 1024;
/// The two sizes may differ by at most this much.
const SIZE_SLACK: u64 = 1024;

fn nested(target: usize) -> Value {
    let leaf = json!({"note": "n".repeat(512), "flags": [true, false, true],
        "ids": (0..16).collect::<Vec<u32>>()});
    let leaf_bytes = serde_json::to_vec(&leaf).expect("leaf").len();
    let branch = Value::Array((0..=target / leaf_bytes).map(|_| leaf.clone()).collect());
    json!({"folder": "inbox", "filter": {"nested": {"deep": {"batch": branch}}}})
}

fn request(size: usize) -> Value {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "gateway_invoke", "arguments": {"server": "work-mail",
        "tool": "read", "arguments": nested(size)}}})
}

#[test]
fn sanitizing_a_clean_request_in_place_costs_a_fixed_amount() {
    for (route, label) in [
        (ProtocolRoute::Meta, "Meta"),
        (ProtocolRoute::Direct, "Direct"),
    ] {
        let mut readings = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let mut req = request(size);
            let before = req.clone();
            let ((), cost) = measure(|| {
                sanitize_request_in_place(&mut req, route).expect("clean");
            });
            assert_eq!(req, before, "premise: the clean request is unchanged");
            assert!(
                cost.bytes <= CLEAN_BUDGET,
                "INTAKE.2(b) {label} {size}: sanitizing a clean request allocated {cost}, above {CLEAN_BUDGET} B"
            );
            readings.push(cost.bytes);
        }
        assert!(
            readings[1].abs_diff(readings[0]) <= SIZE_SLACK,
            "INTAKE.2(b) {label}: the cost grows with the payload: {readings:?}"
        );
    }
}

/// A key to rewrite that is itself the bulk: one 1 or 3 MiB argument key with
/// a control character in it. It is cleaned where it lies and never copied,
/// so the cost stays fixed (a copy of the key as sent would be the payload).
#[test]
fn a_dirty_key_as_long_as_the_payload_costs_a_fixed_amount() {
    for (route, label) in [
        (ProtocolRoute::Meta, "Meta"),
        (ProtocolRoute::Direct, "Direct"),
    ] {
        let mut readings = Vec::new();
        for size in [1usize << 20, 3 << 20] {
            let mut key = "k".repeat(size);
            key.insert(1, '\u{1}');
            let mut arguments = serde_json::Map::new();
            arguments.insert(key, json!(1));
            let mut req = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": "backend_tool"}});
            req["params"]["arguments"] = Value::Object(arguments);
            let ((), cost) = measure(|| {
                sanitize_request_in_place(&mut req, route).expect("a key to strip");
            });
            assert_eq!(
                req["params"]["arguments"]
                    .as_object()
                    .and_then(|map| map.keys().next())
                    .map(String::len),
                Some(size),
                "premise: the control character was stripped"
            );
            assert!(
                cost.bytes <= CLEAN_BUDGET,
                "{label} {size}: sanitizing one dirty bulk key allocated {cost}, above {CLEAN_BUDGET} B"
            );
            readings.push(cost.bytes);
        }
        assert!(
            readings[1].abs_diff(readings[0]) <= SIZE_SLACK,
            "{label}: the dirty-key cost grows with the payload: {readings:?}"
        );
    }
}
