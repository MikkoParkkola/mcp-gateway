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
///
/// Threat model: accidental composition in this repository's own router
/// source, caught at review time. A lexical scan cannot stop a deliberate
/// evasion (a macro, an alias, a spelling it does not list), and is not
/// meant to; the compiler-checked `OutboundReply` return type is the guard
/// for handlers it does see.
fn registered_in(table: &str) -> Result<Vec<String>, String> {
    // Composition forms this scanner cannot follow: refused anywhere in the
    // table, so a nested or merged router cannot carry an MCP route unseen.
    for form in [
        ".nest(",
        ".nest_service(",
        ".route_service(",
        ".merge::<",
        "::merge",
    ] {
        if table.contains(form) {
            return Err(format!("unsupported router composition: {form}"));
        }
    }
    // A merged router is scanned nowhere, so each one is a reviewed entry.
    let mut rest = table;
    while let Some(at) = rest.find(".merge(") {
        let tail = &rest[at + ".merge(".len()..];
        let arg = merged_argument(tail).ok_or("an unclosed .merge(")?;
        if !MERGED_WITHOUT_MCP_ROUTES.contains(&arg) {
            return Err(format!("unreviewed merged router: {arg}"));
        }
        rest = tail;
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

/// Routers merged into the application router in `router/mod.rs`, each
/// reviewed as registering no `/mcp` path. `extra` is the webhook receiver
/// (`WebhookRegistry::create_dynamic_routes`), mounted under
/// `webhooks.base_path`.
const MERGED_WITHOUT_MCP_ROUTES: &[&str] = &[
    "super::ui::admin_audit::audited_api_router(&state)",
    "unauthenticated_routes()",
    "ks_routes",
    "jwks_route",
    "protected_resource_route",
    "metrics_route(&startup_config)",
    "super::ui::html_router()",
    "extra",
    "accounts_router",
];

/// The argument of a `.merge(` call, given the text after the parenthesis.
fn merged_argument(tail: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in tail.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(tail[..i].trim()),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn registered_mcp_handlers() -> Vec<String> {
    registered_in(&read("src/gateway/router/mod.rs")).expect("the MCP routes are resolvable")
}

/// The declared return type in a signature: the `where` clause cut off
/// first (its bounds may name `-> OutboundReply`), then the text after the
/// last `->`, or `None` when nothing is declared.
fn return_type(sig: &str) -> Option<&str> {
    let cut = sig
        .match_indices("where")
        .find(|(at, _)| {
            let before = sig[..*at].chars().next_back();
            let after = sig[at + "where".len()..].chars().next();
            before.is_some_and(char::is_whitespace) && after.is_none_or(char::is_whitespace)
        })
        .map_or(sig.len(), |(at, _)| at);
    let (_, after) = sig[..cut].rsplit_once("->")?;
    Some(after.trim())
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
            matches!(
                return_type(&sig),
                Some("OutboundReply" | "crate::gateway::outbound::OutboundReply")
            ),
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

/// MIK-7827: the return type is compared whole, so a type that only
/// mentions `OutboundReply` does not pass.
#[test]
fn only_a_declared_outbound_reply_passes() {
    for (sig, ok) in [
        ("async fn h(s: State) -> OutboundReply", true),
        (
            "async fn h(s: State) -> crate::gateway::outbound::OutboundReply",
            true,
        ),
        ("fn h<T>(t: T) -> OutboundReply where T: Send", true),
        (
            "fn h<F>(f: F) -> Response\nwhere\n    F: Fn() -> OutboundReply,",
            false,
        ),
        (
            "fn h<F>(f: F) -> OutboundReply\nwhere\n    F: Fn() -> Response,",
            true,
        ),
        (
            "async fn h(s: State) -> Result<OutboundReply, Error>",
            false,
        ),
        ("async fn h(s: State) -> OutboundReplyRaw", false),
        ("async fn h(f: fn() -> OutboundReply) -> Response", false),
        // The last arrow, not the first: a parameter's arrow comes earlier.
        ("async fn h(f: fn() -> Response) -> OutboundReply", true),
        ("async fn h(s: State)", false),
    ] {
        let passes = matches!(
            return_type(sig),
            Some("OutboundReply" | "crate::gateway::outbound::OutboundReply")
        );
        assert_eq!(passes, ok, "{sig}");
    }
}

/// MIK-7827: a router merged in without review fails closed, as a nested one
/// does; the reviewed merges in `router/mod.rs` resolve.
#[test]
fn an_unreviewed_merged_router_fails_closed() {
    let route = ".route(\"/mcp\", post(handlers::meta_mcp_handler))";
    for merge in [
        "\n.merge(mcp_router)",
        "\napp = app.merge(build(\"/mcp\"))",
        "\napp.merge(",
        "\napp = app.merge::<Router<()>>(mcp_router);",
        "\napp = Router::merge(app, mcp_router);",
        "\napp = Router::merge::<Router<()>>(app, mcp_router);",
    ] {
        let table = format!("{route}{merge}");
        assert!(registered_in(&table).is_err(), "must not pass: {table}");
    }
    let reviewed = format!("{route}\napp = app.merge(extra);");
    assert_eq!(
        registered_in(&reviewed),
        Ok(vec!["meta_mcp_handler".to_owned()])
    );
}
