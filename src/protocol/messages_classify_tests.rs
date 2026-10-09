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

/// Lines across every branch: each must classify exactly as the derived,
/// untagged parse does (same variant, same message), or be refused by both.
const CORPUS: &[&str] = &[
    // responses
    r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#,
    r#"{"jsonrpc":"2.0","id":"a","result":null}"#,
    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#,
    r#"{"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-1,"message":"x"}}"#,
    r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}"#,
    r#"{"jsonrpc":"2.0","result":5}"#,
    r#"{"jsonrpc":"2.0","id":1}"#,
    r#"{"jsonrpc":"2.0","id":1,"result":{},"extra":[1,2]}"#,
    r#"{"jsonrpc":"2.0","id":1,"error":null,"result":3}"#,
    // notifications
    r#"{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}"#,
    r#"{"jsonrpc":"2.0","method":"n"}"#,
    r#"{"jsonrpc":"2.0","method":"n","params":null}"#,
    r#"{"jsonrpc":"2.0","method":"n","id":null}"#,
    r#"{"jsonrpc":"2.0","method":"n","id":{"x":1}}"#,
    r#"{"jsonrpc":"2.0","method":"n","id":1.5}"#,
    r#"{"jsonrpc":"2.0","method":"n","result":{"ignored":true},"error":5}"#,
    // requests
    r#"{"jsonrpc":"2.0","id":3,"method":"sampling/createMessage","params":{"a":1}}"#,
    r#"{"jsonrpc":"2.0","id":"r","method":"roots/list"}"#,
    // refused by both
    r#"{"jsonrpc":"2.0","id":1,"method":null}"#,
    r#"{"jsonrpc":"2.0","id":1,"method":7,"result":1}"#,
    r#"{"id":1,"result":1}"#,
    r#"{"jsonrpc":2,"id":1,"result":1}"#,
    r#"{"jsonrpc":"2.0","id":{"x":1},"result":1}"#,
    r#"{"jsonrpc":"2.0","id":1,"error":{"code":"x"}}"#,
    r#"{"jsonrpc":"2.0","id":1,"error":5}"#,
    r#"[{"jsonrpc":"2.0","id":1,"result":1}]"#,
    r#"{"jsonrpc":"2.0","id":1,"result":1"#,
    // duplicated keys: each must classify as the untagged parse does
    r#"{"jsonrpc":"2.0","method":"n","id":1,"id":2}"#,
    r#"{"jsonrpc":"2.0","method":"n","id":1,"result":1,"result":2}"#,
    r#"{"jsonrpc":"2.0","method":"n","id":1,"error":1,"error":2}"#,
    r#"{"jsonrpc":"2.0","method":"n","params":{},"params":{}}"#,
    r#"{"jsonrpc":"2.0","method":"n","method":"m"}"#,
    r#"{"jsonrpc":"2.0","jsonrpc":"2.0","method":"n"}"#,
    r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"result":1}"#,
    r#"{"jsonrpc":"2.0","id":1,"result":1,"params":1,"params":2}"#,
    r#"{"jsonrpc":"2.0","id":1,"id":2,"result":1}"#,
    r#"{"jsonrpc":"2.0","id":1,"result":1,"result":2}"#,
    r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"a"},"error":{"code":2,"message":"b"}}"#,
    r#"{"jsonrpc":"2.0","id":1,"result":1,"x":1,"x":2}"#,
    r#"{"jsonrpc":"2.0","method":"n","x":1,"x":2}"#,
    "",
    "null",
];

fn shape(message: &JsonRpcMessage) -> (&'static str, serde_json::Value) {
    let kind = if message.is_request() {
        "request"
    } else if message.is_response() {
        "response"
    } else {
        "notification"
    };
    (kind, serde_json::to_value(message).expect("serializes"))
}

#[test]
fn every_line_classifies_as_the_untagged_parse_does() {
    for line in CORPUS {
        let new = JsonRpcMessage::from_line(line);
        let old = serde_json::from_str::<JsonRpcMessage>(line);
        match (&new, &old) {
            (Ok(n), Ok(o)) => assert_eq!(shape(n), shape(o), "line {line}"),
            (Err(_), Err(_)) => {}
            _ => panic!("line {line}: from_line {new:?}, untagged {old:?}"),
        }
    }
}

/// MIK-8019 through the new path: a frame carrying `method`, null included,
/// is never a response that could complete a pending caller.
#[test]
fn a_frame_with_method_is_never_a_response() {
    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":null,"result":{"ok":true}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"x","result":{"ok":true}}"#,
    ] {
        assert!(
            !JsonRpcMessage::from_line(line).is_ok_and(|m| m.is_response()),
            "{line}"
        );
    }
}
