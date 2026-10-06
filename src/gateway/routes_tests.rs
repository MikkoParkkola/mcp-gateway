// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8002 test 3 (I6): every route the gateway listener registers names a
//! `routes::` constant, so the owned set `webhooks.base_path` is checked
//! against is the set the router registers.
//!
//! Threat model: accidental composition in this repository's own router
//! source, caught at review time. Not a defence against deliberate evasion
//! (macros, aliases, unlisted spellings); a new spelling gets a written
//! not-a-defect disposition, not a new scan rule.

/// The files whose routers `create_router_with_accounts` composes into the
/// gateway HTTP listener.
const LISTENER_FILES: &[&str] = &[
    "src/gateway/router/mod.rs",
    "src/gateway/router/accounts.rs",
    "src/gateway/router/accounts/complete.rs",
    "src/gateway/router/accounts/connections.rs",
    "src/gateway/router/accounts/hosted.rs",
    "src/gateway/ui/mod.rs",
    "src/gateway/ui/backends.rs",
    "src/gateway/ui/capabilities.rs",
    "src/gateway/ui/control_plane.rs",
    "src/gateway/ui/events.rs",
    "src/gateway/ui/import.rs",
    "src/gateway/ui/session.rs",
    "src/key_server/handler.rs",
];

const REGISTRATIONS: &[&str] = &[".route(", ".route_service(", ".nest(", ".nest_service("];

/// Each registration's path argument that is not a `routes::` constant, as
/// `file:line: argument`.
fn unowned_registrations(file: &str, text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for call in REGISTRATIONS {
        for (at, _) in text.match_indices(call) {
            let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
            if text[line_start..at].trim_start().starts_with("//") {
                continue;
            }
            let argument = text[at + call.len()..].trim_start();
            if !argument.starts_with("routes::") {
                let line = text[..at].matches('\n').count() + 1;
                let shown: String = argument.chars().take(40).collect();
                found.push(format!("{file}:{line}: {shown}"));
            }
        }
    }
    found
}

#[test]
fn every_listener_registration_names_a_routes_constant() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for file in LISTENER_FILES {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        found.extend(unowned_registrations(file, &text));
    }
    assert!(
        found.is_empty(),
        "registrations not using a routes:: constant:\n{}",
        found.join("\n")
    );
}

/// The scan itself: a literal, a local constant and a commented-out call.
#[test]
fn the_scan_tells_a_constant_from_a_literal() {
    let text = "Router::new()\n    .route(routes::MCP, post(h))\n    .route(\"/x\", get(h))\n    // .route(\"/y\", get(h))\n    .nest(\n        LOCAL, r)\n";
    let found = unowned_registrations("f.rs", text);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].starts_with("f.rs:3: \"/x\""), "{found:?}");
    assert!(found[1].starts_with("f.rs:5: LOCAL"), "{found:?}");
}
