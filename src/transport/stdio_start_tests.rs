// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What the stdio reader logs for a line it could not handle: the line can
//! hold an injected value, so only the gateway's own refusal keeps its words.

/// Backend text an error might carry.
const NEEDLE: &str = "stdio-unhandled-secret-3e9a";

/// What `log_unhandled_line` logs for `error`.
fn logged(error: &crate::Error) -> String {
    let records = crate::test_log_capture::records(|| super::log_unhandled_line(40, error));
    serde_json::to_string(&records).expect("records serialise")
}

/// Every kind but the two named ones is logged by kind: its text, which can
/// be the backend's, is not.
#[test]
fn an_unhandled_line_of_another_kind_is_named_not_quoted() {
    let log = logged(&crate::Error::Transport(format!("broke at {NEEDLE}")));
    assert!(log.contains("the line could not be handled"), "{log}");
    assert!(!log.contains(NEEDLE), "the log quotes the error: {log}");
}

/// A line that is not JSON-RPC is named, never quoted.
#[test]
fn a_line_that_is_not_json_rpc_is_named_not_quoted() {
    let parse =
        serde_json::from_str::<serde_json::Value>(&format!("{{{NEEDLE}")).expect_err("not JSON");
    let log = logged(&crate::Error::Json(parse));
    assert!(log.contains("the line is not a JSON-RPC message"), "{log}");
    assert!(!log.contains(NEEDLE), "the log quotes the line: {log}");
}

/// The gateway's own refusal keeps its fixed text.
#[test]
fn the_gateways_own_refusal_keeps_its_words() {
    let log = logged(&crate::Error::Protocol("refused by the gateway".into()));
    assert!(log.contains("refused by the gateway"), "{log}");
}
