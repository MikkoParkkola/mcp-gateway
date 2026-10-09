// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8014 PERF.1a: a backend line is deserialized once. The untagged enum
//! buffers each line into serde's `Content` tree before trying each variant:
//! a parallel tree, one more allocation per JSON element than parsing the
//! line into a `Value` (measured on base: 6.01 against 5.01 calls, 1034
//! against 713 bytes per element).

use super::super::JsonRpcMessage;
use crate::gateway::alloc_meter::{Measured, measure};

const MANY: usize = 1000;
const FEW: usize = 10;

/// A response whose result holds `n` small content items.
fn response_line(n: usize) -> String {
    let content: Vec<_> = (0..n)
        .map(|i| serde_json::json!({"type": "text", "text": format!("t{i}")}))
        .collect();
    serde_json::json!({"jsonrpc": "2.0", "id": 7, "result": {"content": content}}).to_string()
}

/// Allocator calls per extra element, between the `MANY` and `FEW` lines.
fn per_element(parse: impl Fn(&str) -> Measured) -> f64 {
    let (many, few) = (response_line(MANY), response_line(FEW));
    parse(&few);
    parse(&many);
    let grown = parse(&many).calls - parse(&few).calls;
    f64::from(u32::try_from(grown).expect("small"))
        / f64::from(u32::try_from(MANY - FEW).expect("small"))
}

#[test]
fn a_response_line_is_deserialized_once() {
    let classify = per_element(|line| {
        let (message, measured) = measure(|| JsonRpcMessage::from_line(line));
        assert!(message.expect("a response").is_response());
        measured
    });
    // The floor: the line parsed once into a `Value`, the tree a response's
    // result is anyway.
    let once = per_element(|line| measure(|| serde_json::from_str::<serde_json::Value>(line)).1);
    assert!(
        classify <= once + 0.1,
        "classifying a response line took {classify:.2} allocator calls per JSON element, \
         against {once:.2} for parsing it once: the line is buffered before it is typed \
         (MIK-8014 PERF.1a)"
    );
}
