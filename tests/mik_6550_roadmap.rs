// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
const ROADMAP: &str = include_str!("../docs/roadmap/mik-6550-trust-fabric-roadmap.md");
const README: &str = include_str!("../README.md");

const CHILDREN: [&str; 12] = [
    "MIK-6551", "MIK-6552", "MIK-6553", "MIK-6554", "MIK-6555", "MIK-6556", "MIK-6557", "MIK-6558",
    "MIK-6559", "MIK-6560", "MIK-6561", "MIK-6562",
];

const REQUIRED_FIELDS: [&str; 13] = [
    "User outcome:",
    "Contribution class:",
    "License tier:",
    "Build vs integrate:",
    "Dependencies:",
    "Target areas:",
    "Threat model:",
    "Rollback:",
    "Risks:",
    "Fail-fast checks:",
    "Acceptance criteria:",
    "Implementation plan:",
    "Test plan:",
];

fn child_section(ticket: &str) -> &str {
    let marker = format!("## {ticket}:");
    let start = ROADMAP
        .find(&marker)
        .unwrap_or_else(|| panic!("missing section for {ticket}"));
    let after_marker = &ROADMAP[start + marker.len()..];
    let next = after_marker
        .find("\n## MIK-")
        .map_or(after_marker.len(), |idx| idx);
    &ROADMAP[start..start + marker.len() + next]
}

#[test]
fn mik_6550_child_rows_have_canonical_dor_fields() {
    let child_heading_count = ROADMAP.matches("\n## MIK-").count();
    assert_eq!(
        child_heading_count,
        CHILDREN.len(),
        "roadmap must enumerate exactly the current child ticket set",
    );

    for ticket in CHILDREN {
        let section = child_section(ticket);
        for field in REQUIRED_FIELDS {
            assert!(
                section.contains(field),
                "{ticket} is missing canonical field {field}",
            );
        }
        assert!(
            section.contains(&format!("{ticket}.")),
            "{ticket} must include at least one stable acceptance criterion id",
        );
    }
}

#[test]
fn mik_6550_dependencies_and_identity_disposition_are_explicit() {
    for phrase in [
        "MIK-6553 provides identity grants before TrustCard ownership evidence",
        "MIK-6556 TrustCard and CBOM metadata unblock MIK-6557 TrustLab evaluation",
        "MIK-6555 RuntimeProvider isolation strengthens MIK-6557 active evaluation",
        "MIK-6558 ControlPlaneUI depends on identity grants",
        "MIK-6561 ProtocolImports feed MIK-6557 TrustLab and MIK-6562 ranking",
        "local ranking must not require enterprise analytics",
        "MIK-6207 caller identity propagation is\nreused",
        "MIK-6208 per-user vault precedent is reused",
        "MIK-6209 personal versus\npublic gating is superseded",
    ] {
        assert!(
            ROADMAP.contains(phrase),
            "roadmap dependency or disposition phrase missing: {phrase}",
        );
    }
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

#[test]
fn mik_6550_public_competitor_comparison_is_present() {
    for phrase in [
        "Public MCP Gateway Comparison",
        "This table compares public, user-facing behavior",
        "docs/OWASP_AGENTIC_AI_COMPLIANCE.md",
        "docs/trustcard.md",
        "docs/adaptive_ranking.md",
        "https://docs.docker.com/ai/mcp-catalog-and-toolkit/",
        "https://github.com/mcpjungle/MCPJungle",
        "https://github.com/open-webui/mcpo",
        "https://github.com/supercorp-ai/supergateway",
        "Docker MCP Gateway / Toolkit",
        "MCPJungle",
        "mcpo",
        "Supergateway",
        "docs/roadmap/mik-6550-trust-fabric-roadmap.md",
    ] {
        assert!(
            README.contains(phrase),
            "README public comparison or roadmap link is missing: {phrase}",
        );
    }
}
