// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
const ROADMAP: &str = include_str!("../docs/roadmap/trust-fabric.md");
const README: &str = include_str!("../README.md");

/// The public roadmap says what ships and what does not. Those two lists are
/// the page; a rewrite that loses either one has stopped being a roadmap.
#[test]
fn mik_6550_roadmap_lists_shipped_and_not_shipped_work() {
    for heading in ["\n## Shipped in 4.0.0\n", "\n## Not in 4.0.0\n"] {
        assert!(
            ROADMAP.contains(heading),
            "public roadmap is missing its section {heading:?}",
        );
    }
}

/// Ticket identifiers are internal tracking; the public page names features.
#[test]
fn mik_6550_public_roadmap_names_no_internal_tickets() {
    assert!(
        !ROADMAP.contains("MIK-"),
        "public roadmap must not cite internal ticket identifiers",
    );
}

#[test]
fn mik_6550_public_boundary_has_no_blocked_terms() {
    for forbidden in [
        concat!("competitive", " intelligence"),
        concat!("internal", " competitor", " analysis"),
        concat!("private", " strategy"),
        concat!("private", " roadmap", " reasoning"),
        concat!("roadmap", " reasoning"),
        concat!("build-vs-integrate", " licensing"),
        concat!("licensing", " strategy"),
        concat!("Positioning", " summary"),
        concat!("OPSEC", " review"),
        concat!("customer-sensitive", " artifact"),
        concat!("protected", " auth", " material"),
    ] {
        assert!(
            !ROADMAP.to_lowercase().contains(&forbidden.to_lowercase()),
            "public roadmap contains blocked marker: {forbidden}",
        );
    }
}

/// Public text names features, not competitors: the comparison section is gone
/// and the README links the public roadmap instead.
#[test]
fn mik_6550_readme_links_the_roadmap_without_a_comparison_section() {
    assert!(
        README.contains("docs/roadmap/trust-fabric.md"),
        "README must link the public roadmap",
    );
    assert!(
        !README.contains("Public MCP Gateway Comparison"),
        "README must not carry a competitor comparison section",
    );
}
