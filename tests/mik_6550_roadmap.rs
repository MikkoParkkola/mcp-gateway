//! Integration tests for MIK-6550 — Trust Fabric Roadmap.
//!
//! These tests validate the public roadmap manifest at
//! `docs/roadmap/mik-6550-trust-fabric-roadmap.md` against the acceptance
//! criteria defined in the MIK-6550 ticket.

use std::fs;
use std::path::Path;

const ROADMAP_PATH: &str = "docs/roadmap/mik-6550-trust-fabric-roadmap.md";

fn read_roadmap() -> String {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(base.join(ROADMAP_PATH))
        .expect("roadmap file must exist at docs/roadmap/mik-6550-trust-fabric-roadmap.md")
}

/// MIK-6550.AC.1 — Public roadmap manifest exists and enumerates exactly
/// MIK-6551 through MIK-6562, each with canonical DoR fields: user outcome,
/// contribution class, license tier, build-vs-integrate decision, dependencies,
/// target code/docs areas, threat model, rollback, risks, fail-fast checks,
/// stable acceptance criteria, implementation plan, and test plan.
/// CHECK: `cargo test --test mik_6550_roadmap -- mik_6550_child_rows_have_canonical_dor_fields` exits 0
#[test]
fn mik_6550_child_rows_have_canonical_dor_fields() {
    let content = read_roadmap();

    let child_ids: Vec<String> = (6551..=6562).map(|n| format!("MIK-{n}")).collect();

    let required_fields: &[&str] = &[
        "user outcome",
        "contribution class",
        "license tier",
        "build-vs-integrate decision",
        "dependencies",
        "target code/docs areas",
        "threat model",
        "rollback",
        "risks",
        "fail-fast checks",
        "stable acceptance criteria",
        "implementation plan",
        "test plan",
    ];

    let mut errors: Vec<String> = Vec::new();

    for id in &child_ids {
        if !content.contains(id) {
            errors.push(format!("Missing child row: {id}"));
            continue;
        }

        let content_lower = content.to_lowercase();
        let id_pos = content.find(id).unwrap();

        let next_section_start = content[id_pos + id.len()..]
            .find("\n## ")
            .map(|p| id_pos + id.len() + p)
            .unwrap_or(content.len());

        let section = &content[id_pos..next_section_start];
        let section_lower = section.to_lowercase();

        for field in required_fields {
            if !section_lower.contains(field) {
                errors.push(format!("{id}: missing DoR field '{field}'"));
            }
        }

        // Also verify the field labels exist in their canonical form (case-insensitive)
        let _ = &content_lower; // suppress unused warning
    }

    assert!(
        errors.is_empty(),
        "Roadmap DoR validation failed:\n{}",
        errors.join("\n")
    );
}

/// MIK-6550.AC.2 — The roadmap encodes explicit dependency ordering across
/// identity grants, TrustCard/CBOM metadata, RuntimeProvider isolation,
/// ControlPlaneUI governance, Kubernetes HA, ProtocolImports, and
/// AdaptiveRanking, and it links MIK-6207, MIK-6208, and MIK-6209 with a
/// disposition before duplicate identity implementation can begin.
/// CHECK: `cargo test --test mik_6550_roadmap -- mik_6550_dependencies_and_identity_disposition_are_explicit` exits 0
#[test]
fn mik_6550_dependencies_and_identity_disposition_are_explicit() {
    let content = read_roadmap();

    let mut errors: Vec<String> = Vec::new();

    // 1. Verify dependency graph section exists
    let content_lower = content.to_lowercase();
    if !content_lower.contains("dependency graph") {
        errors.push("Missing 'Dependency Graph' section".to_string());
    }

    // 2. Verify dependency ordering mentions required capabilities
    let required_dependency_mentions: &[(&str, &str)] = &[
        ("identity grants", "MIK-6552"),
        ("TrustCard/CBOM metadata", "MIK-6555"),
        ("RuntimeProvider isolation", "MIK-6554"),
        ("ControlPlaneUI governance", "MIK-6557"),
        ("Kubernetes HA", "MIK-6559"),
        ("ProtocolImports", "MIK-6560"),
        ("AdaptiveRanking", "MIK-6561"),
    ];

    for (capability, ticket_id) in required_dependency_mentions {
        if !content.contains(ticket_id) {
            errors.push(format!(
                "Dependency graph missing {capability} ({ticket_id})"
            ));
        }
    }

    // 3. Verify dependency edges exist (child depends on parent)
    // The MIK-6555 section must reference MIK-6552 as a dependency
    // The MIK-6554 section must reference MIK-6555 as a dependency
    // The MIK-6557 section must reference MIK-6554 as a dependency
    // The MIK-6559 section must reference MIK-6557 as a dependency
    // The MIK-6560 section must reference MIK-6552 as a dependency
    // The MIK-6561 section must reference MIK-6560 as a dependency
    let dependency_edges: &[(&str, &str)] = &[
        ("MIK-6555", "MIK-6552"),
        ("MIK-6554", "MIK-6555"),
        ("MIK-6557", "MIK-6554"),
        ("MIK-6559", "MIK-6557"),
        ("MIK-6560", "MIK-6552"),
        ("MIK-6561", "MIK-6560"),
    ];

    for (child, parent) in dependency_edges {
        // Find the child's section and check it references the parent as dependency
        let child_marker = format!("## {child}:");
        if let Some(pos) = content.find(&child_marker) {
            let section_end = content[pos + child_marker.len()..]
                .find("\n## ")
                .map(|p| pos + child_marker.len() + p)
                .unwrap_or(content.len());
            let section = &content[pos..section_end];

            // Check that the Dependencies field in this section mentions the parent
            let deps_start = section.find("**Dependencies:**");
            if let Some(d_pos) = deps_start {
                let deps_section = &section[d_pos..d_pos + 200.min(section.len() - d_pos)];
                if !deps_section.contains(parent) {
                    errors.push(format!(
                        "{child} does not list {parent} as a dependency"
                    ));
                }
            } else {
                errors.push(format!("{child}: no Dependencies field found"));
            }
        } else {
            errors.push(format!("{child}: section not found"));
        }
    }

    // 4. Verify prior ticket dispositions (MIK-6207, MIK-6208, MIK-6209)
    let prior_tickets: &[&str] = &["MIK-6207", "MIK-6208", "MIK-6209"];
    for ticket in prior_tickets {
        if !content.contains(ticket) {
            errors.push(format!(
                "Prior identity ticket {ticket} not referenced in roadmap"
            ));
        }
    }

    // 5. Verify disposition language exists (superseded or equivalent)
    let disposition_keywords: &[&str] = &["superseded", "disposition"];
    let has_disposition = disposition_keywords
        .iter()
        .any(|kw| content_lower.contains(kw));
    if !has_disposition {
        errors.push(
            "No disposition language found for prior identity tickets".to_string(),
        );
    }

    assert!(
        errors.is_empty(),
        "Dependency and disposition validation failed:\n{}",
        errors.join("\n")
    );
}

/// MIK-6550.AC.3 — Public-repo boundary is preserved: the committed roadmap
/// contains public user outcomes, tier placement, and implementation surfaces,
/// but excludes private strategy, customer-specific pricing rationale, private
/// Linear-only reasoning, and competitive attack language.
/// CHECK: `cargo test --test mik_6550_roadmap -- mik_6550_public_boundary_has_no_private_strategy_terms` exits 0
#[test]
fn mik_6550_public_boundary_has_no_private_strategy_terms() {
    let content = read_roadmap();
    let content_lower = content.to_lowercase();

    let banned_terms: &[&str] = &[
        "private strategy",
        "internal only",
        "confidential",
        "do not share",
        "customer-specific pricing",
        "pricing rationale",
        "competitive attack",
        "kill switch for competitor",
        "undercut",
        "steal customer",
        "steal market",
        "linear-only",
        "private linear",
        "private pricing",
        "do not publish",
        "trade secret",
        "proprietary strategy",
        "internal roadmap rationale",
        "moat strategy",
        "competitive moat",
        "lock-in strategy",
        "vendor lock-in plan",
    ];

    let mut violations: Vec<String> = Vec::new();

    for term in banned_terms {
        if content_lower.contains(term) {
            violations.push(format!("Banned term found: '{term}'"));
        }
    }

    assert!(
        violations.is_empty(),
        "Public boundary violation — private strategy terms found:\n{}",
        violations.join("\n")
    );
}
