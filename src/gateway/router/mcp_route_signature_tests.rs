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

/// The handler names registered on `/mcp` paths in `table`, or why the table
/// cannot be read: every method registration in an `/mcp` block must name a
/// `handlers::` function, so a closure, an unqualified function or a nested
/// router fails closed instead of going unchecked.
fn registered_in(table: &str) -> Result<Vec<String>, String> {
    // Composition forms this scanner cannot follow: refused anywhere in the
    // table, so a nested or merged router cannot carry an MCP route unseen.
    for form in [".nest(", ".nest_service(", ".route_service("] {
        if table.contains(form) {
            return Err(format!("unsupported router composition: {form}"));
        }
    }
    let methods = [
        "post(", "get(", "delete(", "put(", "patch(", "any(", "on(", "head(", "options(", "trace(",
        "connect(",
    ];
    let mut names = Vec::new();
    let mut open = false;
    for line in table.lines() {
        if line.contains(".route(") || line.contains("Router::new") || line.contains(".nest") {
            open = false;
        }
        if line.contains("\"/mcp") {
            open = true;
        }
        if !open {
            continue;
        }
        let registrations: usize = methods
            .iter()
            .map(|m| {
                line.match_indices(m)
                    .filter(|(at, _)| {
                        !line[..*at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_')
                    })
                    .count()
            })
            .sum();
        let mut found = 0;
        let mut rest = line;
        while let Some(at) = rest.find("handlers::") {
            let tail = &rest[at + "handlers::".len()..];
            let end = tail
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(tail.len());
            names.push(tail[..end].to_owned());
            found += 1;
            rest = &tail[end..];
        }
        if registrations != found {
            return Err(format!("unresolved MCP registration: {line}"));
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn registered_mcp_handlers() -> Vec<String> {
    registered_in(&read("src/gateway/router/mod.rs")).expect("the MCP routes are resolvable")
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

#[test]
fn an_unresolvable_mcp_registration_fails_closed() {
    for table in [
        ".route(\"/mcp\", post(|| async { \"raw\" }))",
        ".route(\"/mcp\", post(meta_mcp_handler))",
        ".route(\"/mcp\", post(handlers::meta_mcp_handler).get(local_handler))",
        ".route(\"/mcp\", handlers::prebuilt_router())\n.nest(\"/mcp\", inner)",
        ".route(\"/mcp\", post(handlers::meta_mcp_handler))\n.nest_service(\"/mcp\", svc)",
        ".route(\"/mcp\", post(handlers::meta_mcp_handler).head(local_handler))",
        ".route(\"/mcp\",\n    post(handlers::meta_mcp_handler)\n    .options(local))",
    ] {
        assert!(registered_in(table).is_err(), "must not pass: {table}");
    }
    let ok = ".route(\"/mcp\", post(handlers::meta_mcp_handler))";
    assert_eq!(registered_in(ok), Ok(vec!["meta_mcp_handler".to_owned()]));
}
