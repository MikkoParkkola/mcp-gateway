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

/// Every `.merge(` in a scanned file, reviewed: (file, argument prefix, the
/// file that registers the merged router's routes). That file must be
/// scanned too, so a router merged inside a sub-router is followed. `None`
/// is the webhook receiver, whose own `base_path` is what the owned set
/// is checked against.
const REVIEWED_MERGES: &[(&str, &str, Option<&str>)] = &[
    (
        "src/gateway/router/mod.rs",
        "super::ui::admin_audit::audited_api_router(",
        Some("src/gateway/ui/mod.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "unauthenticated_routes()",
        Some("src/gateway/router/mod.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "ks_routes",
        Some("src/key_server/handler.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "jwks_route",
        Some("src/gateway/router/mod.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "protected_resource_route",
        Some("src/gateway/router/mod.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "metrics_route(",
        Some("src/gateway/router/mod.rs"),
    ),
    (
        "src/gateway/router/mod.rs",
        "super::ui::html_router()",
        Some("src/gateway/ui/mod.rs"),
    ),
    ("src/gateway/router/mod.rs", "extra", None),
    (
        "src/gateway/router/mod.rs",
        "accounts_router",
        Some("src/gateway/router/accounts.rs"),
    ),
    (
        "src/gateway/router/accounts.rs",
        "browser",
        Some("src/gateway/router/accounts.rs"),
    ),
    (
        "src/gateway/router/accounts.rs",
        "complete::routes(",
        Some("src/gateway/router/accounts/complete.rs"),
    ),
    (
        "src/gateway/ui/session.rs",
        "handoff",
        Some("src/gateway/ui/session.rs"),
    ),
    (
        "src/gateway/ui/mod.rs",
        "capabilities::capabilities_router()",
        Some("src/gateway/ui/capabilities.rs"),
    ),
    (
        "src/gateway/ui/mod.rs",
        "control_plane::control_plane_router()",
        Some("src/gateway/ui/control_plane.rs"),
    ),
    (
        "src/gateway/ui/mod.rs",
        "backends::backends_router()",
        Some("src/gateway/ui/backends.rs"),
    ),
    (
        "src/gateway/ui/mod.rs",
        "events::events_router()",
        Some("src/gateway/ui/events.rs"),
    ),
    (
        "src/gateway/ui/mod.rs",
        "import::import_router()",
        Some("src/gateway/ui/import.rs"),
    ),
];

/// `(line, argument)` for each `call` in `text` outside a line comment.
fn calls<'t>(text: &'t str, call: &'t str) -> impl Iterator<Item = (usize, &'t str)> {
    text.match_indices(call).filter_map(move |(at, _)| {
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        if text[line_start..at].trim_start().starts_with("//") {
            return None;
        }
        let line = text[..at].matches('\n').count() + 1;
        Some((line, text[at + call.len()..].trim_start()))
    })
}

fn shown(argument: &str) -> String {
    argument.chars().take(40).collect()
}

/// Each registration's path argument that is not a `routes::` constant, as
/// `file:line: argument`.
fn unowned_registrations(file: &str, text: &str) -> Vec<String> {
    REGISTRATIONS
        .iter()
        .flat_map(|call| calls(text, call))
        .filter(|(_, argument)| !argument.starts_with("routes::"))
        .map(|(line, argument)| format!("{file}:{line}: {}", shown(argument)))
        .collect()
}

/// Each `.merge(` in `file` with no reviewed entry, or whose entry's
/// registering file is outside `scanned`.
fn unreviewed_merges(
    file: &str,
    text: &str,
    reviewed: &[(&str, &str, Option<&str>)],
    scanned: &[&str],
) -> Vec<String> {
    calls(text, ".merge(")
        .filter_map(|(line, argument)| {
            let entry = reviewed
                .iter()
                .find(|(f, prefix, _)| *f == file && argument.starts_with(prefix));
            match entry {
                None => Some(format!(
                    "{file}:{line}: unreviewed merge {}",
                    shown(argument)
                )),
                Some((_, _, Some(registering))) if !scanned.contains(registering) => Some(format!(
                    "{file}:{line}: {registering} registers merged routes but is not scanned"
                )),
                Some(_) => None,
            }
        })
        .collect()
}

#[test]
fn every_listener_registration_names_a_routes_constant() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    for file in LISTENER_FILES {
        let text =
            std::fs::read_to_string(root.join(file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        found.extend(unowned_registrations(file, &text));
        found.extend(unreviewed_merges(
            file,
            &text,
            REVIEWED_MERGES,
            LISTENER_FILES,
        ));
    }
    assert!(
        found.is_empty(),
        "listener routes the owned set does not cover:\n{}",
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

/// Test 4c: an unreviewed merge inside a scanned sub-router fails, and so
/// does a reviewed merge whose registering file is not scanned.
#[test]
fn the_scan_follows_merges() {
    let reviewed: &[(&str, &str, Option<&str>)] = &[
        ("sub.rs", "inner()", Some("inner.rs")),
        ("sub.rs", "outside()", Some("outside.rs")),
    ];
    let scanned = &["sub.rs", "inner.rs"];
    let ok = unreviewed_merges("sub.rs", "r.merge(inner())\n", reviewed, scanned);
    assert!(ok.is_empty(), "{ok:?}");
    let unreviewed = unreviewed_merges("sub.rs", "r.merge(other())\n", reviewed, scanned);
    assert_eq!(unreviewed.len(), 1, "{unreviewed:?}");
    let unscanned = unreviewed_merges("sub.rs", "r.merge(outside())\n", reviewed, scanned);
    assert!(unscanned[0].contains("outside.rs"), "{unscanned:?}");
}
