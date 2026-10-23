// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8782.AUTO.4–5 and MIK-8783.AUTO.7: the docs and the surface inventory
//! agree with the code about the seven retired settings. The inventory and
//! fragment checkers enforce structure only, so the meaning is pinned here.

use std::path::Path;

const RETIRED: [&str; 7] = [
    "capabilities.stale_check_secs",
    "cache.enabled",
    "failsafe.retry.enabled",
    "failsafe.circuit_breaker.enabled",
    "auth.client_circuit_breaker.enabled",
    "security.signature_chain.max_links",
    "server.protocol_revision_window",
];

fn read(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// The surface inventory row for `id`, split into its cells.
fn row(surface: &str, id: &str) -> Option<Vec<String>> {
    let head = format!("| `{id}` |");
    surface
        .lines()
        .find(|l| l.starts_with(&head))
        .map(|l| l.split('|').map(|c| c.trim().to_owned()).collect())
}

/// T3.1: each retired setting is a REMOVE row defined at the loader's list,
/// and the window's flag and env var are INTERNAL.
#[test]
fn the_surface_inventory_retires_the_seven_settings() {
    let surface = read("docs/design/surface-4.0.md");
    for key in RETIRED {
        let cells = row(&surface, key).unwrap_or_else(|| panic!("{key}: no surface row"));
        assert_eq!(cells[2], "REMOVE", "{key}: class");
        assert_eq!(cells[6], "src/config/strict_keys.rs", "{key}: defined-at");
    }
    for id in [
        "mcp-gateway --protocol-revision-window",
        "MCP_GATEWAY_PROTOCOL_REVISION_WINDOW",
    ] {
        let line = surface
            .lines()
            .find(|l| l.starts_with(&format!("| `{id}` |")))
            .unwrap_or_else(|| panic!("{id}: no surface row"));
        let cells: Vec<String> = line.split('|').map(|c| c.trim().to_owned()).collect();
        assert_eq!(cells[2], "INTERNAL", "{id}: class");
    }
}

/// T3.3: no pre-release note still tells an operator to set one of them,
/// and one fragment names all seven and the window's new switch.
#[test]
fn the_upgrade_notes_stop_advertising_the_retired_settings() {
    for (file, stale) in [
        ("upgrading.d/8651.md", "stale_check_secs"),
        // changelog.d is not shipped in the crate (PACKED.2), so its fragment
        // is checked by hand, not here.
        (
            "upgrading.d/3920.md",
            "New setting `server.protocol_revision_window`",
        ),
        (
            "changelog.d/3920.added.md",
            "A new setting, `server.protocol_revision_window`",
        ),
        (
            "docs/UPGRADING-4.0.md",
            "`capabilities.stale_check_secs` (default 60, `0` turns it off)",
        ),
    ] {
        assert!(
            !read(file).contains(stale),
            "{file} still advertises: {stale}"
        );
    }
    let fragment = read("upgrading.d/8783.md");
    for key in RETIRED {
        assert!(
            fragment.contains(key),
            "upgrading.d/8783.md must name {key}"
        );
    }
    assert!(
        fragment.contains("--protocol-revision-window"),
        "the fragment names the flag"
    );
    assert!(
        fragment.contains("client_circuit_breaker: {}"),
        "the fragment gives the keep-on edit"
    );
}
