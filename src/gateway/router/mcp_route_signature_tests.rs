// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7116 MIN.2 typing: every handler registered on an MCP path is declared
//! to return `OutboundReply`, so a new body cannot reach a caller without
//! naming its origin (judged, stream or gateway refusal). The compiler checks
//! the declared type; this test checks that the registration table lists only
//! handlers that carry it, which the compiler cannot (axum accepts any
//! `IntoResponse`).

use std::path::Path;

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|e| panic!("{relative}: {e}"))
}

/// The handler names registered on `/mcp` paths in the router table.
fn registered_mcp_handlers() -> Vec<String> {
    let table = read("src/gateway/router/mod.rs");
    let mut names = Vec::new();
    let mut open = false;
    for line in table.lines() {
        if line.contains(".route(") || line.contains("Router::new") {
            open = false;
        }
        if line.contains("\"/mcp") {
            open = true;
        }
        if line.contains("\"/") && !line.contains("\"/mcp") {
            open = false;
        }
        if !open {
            continue;
        }
        let mut rest = line;
        while let Some(at) = rest.find("handlers::") {
            let tail = &rest[at + "handlers::".len()..];
            let end = tail
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(tail.len());
            names.push(tail[..end].to_owned());
            rest = &tail[end..];
        }
    }
    names.sort();
    names.dedup();
    names
}

/// The text of `fn name`'s signature, up to its body.
fn signature(name: &str) -> String {
    for file in [
        "src/gateway/router/handlers.rs",
        "src/gateway/router/backend_handlers.rs",
    ] {
        let source = read(file);
        let needle = format!("fn {name}(");
        if let Some(at) = source.find(&needle) {
            let rest = &source[at..];
            return rest[..rest.find(" {\n").expect("a body")].to_owned();
        }
    }
    panic!("handler {name} not found");
}

#[test]
fn the_mcp_routes_carry_the_expected_handlers() {
    assert_eq!(
        registered_mcp_handlers(),
        [
            "backend_handler",
            "mcp_delete_handler",
            "mcp_sse_handler",
            "meta_mcp_handler"
        ],
        "a handler on an MCP path must be added here and return OutboundReply"
    );
}

#[test]
fn every_mcp_handler_returns_an_outbound_reply() {
    for name in registered_mcp_handlers() {
        let sig = signature(&name);
        assert!(
            sig.contains("-> crate::gateway::outbound::OutboundReply")
                || sig.contains("-> OutboundReply"),
            "{name} must return OutboundReply, found: {sig}"
        );
    }
}
