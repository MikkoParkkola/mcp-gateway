// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8002: `webhooks.base_path` may not sit on, under or over a route the
//! gateway listener owns, nor take a form axum refuses at startup.

use super::*;
use crate::gateway::test_helpers::write_owner_only;

fn load_webhooks(enabled: bool, base_path: &str) -> crate::Result<Config> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("gateway.yaml");
    let body = format!("webhooks:\n  enabled: {enabled}\n  base_path: '{base_path}'\n");
    write_owner_only(&path, body).expect("write");
    Config::load(Some(&path))
}

fn assert_refused(base_path: &str) {
    let err = load_webhooks(true, base_path)
        .err()
        .unwrap_or_else(|| panic!("base_path {base_path:?} was accepted"))
        .to_string();
    assert!(err.contains("webhooks.base_path"), "{base_path}: {err}");
}

fn assert_accepted(base_path: &str) {
    if let Err(err) = load_webhooks(true, base_path) {
        panic!("base_path {base_path:?} was refused: {err}");
    }
}

/// Test 1 (I1, I2, I3): an owned route, or a path under one, is refused; a
/// path outside every owned route is accepted.
#[test]
fn a_base_path_on_or_under_a_gateway_route_is_refused() {
    for path in [
        "/mcp",
        "/mcp/hooks",
        "/ui/api/x",
        "/.well-known/jwks.json/x",
        "/health",
    ] {
        assert_refused(path);
    }
    for path in ["/webhooks", "/hooks/in"] {
        assert_accepted(path);
    }
}

/// Test 1 (I4): a disabled receiver mounts nothing, so its path is unchecked.
#[test]
fn a_disabled_receiver_is_not_checked() {
    for path in ["/mcp", "/mcp/hooks", "/health", "/"] {
        if let Err(err) = load_webhooks(false, path) {
            panic!("disabled receiver with {path:?} was refused: {err}");
        }
    }
}

/// Test 4 (I7): forms axum refuses at startup, or that escape the prefix,
/// are refused at load.
#[test]
fn a_malformed_base_path_is_refused() {
    for path in [
        "/",
        "/x/",
        "/x//y",
        "/x/../mcp",
        "/x/./y",
        "/x/{y}",
        "/:hooks",
        "/*hooks",
        "hooks",
    ] {
        assert_refused(path);
    }
}

/// Test 4b (I2, I2b, I3): matching is per segment against the real owned
/// set: a parameter route matches any segment, an owned ancestor covers its
/// subtree, an owned route under the path refuses it, and a shared string
/// prefix is not a shared segment.
#[test]
fn matching_is_per_segment_on_the_owned_set() {
    for path in ["/mcp/x", "/mcp/x/y", "/ui/apix", "/ui/api", "/.well-known"] {
        assert_refused(path);
    }
    for path in ["/mcpx", "/healthz", "/uix"] {
        assert_accepted(path);
    }
}
