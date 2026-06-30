//! Acceptance-criterion tests for MIK-5843.
//!
//! - AC.1: Willow competitive landscape page at `docs/competitive/willow-enterprise-agent-governance.md` names Willow/Webrix, positions mcp-gateway on sovereign/self-hosted deployment, signed `.state` / attestation receipts vs audit logs.
//! - AC.2: Feature-bar table with Connectors, `IdP`, Shadow, Runtime guards, Audit, Attestation; `LEAD`/`MATCH`/`LAG` verdicts; 1000+; `Okta`/`Entra`/`JumpCloud`.
//! - AC.3: Shadow-AI detection documented with `config_scanner.rs`, `process_scanner.rs`, network proxy boundary, `SIEM`, `discover --shadow`.
//! - AC.4: `cargo test --test mik_5843_willow_competitive_docs` passes (separate test binary).
//! - AC.5: Page linked from at least one index file under docs/.

use std::fs;

const WILLOW_DOC_PATH: &str = "docs/competitive/willow-enterprise-agent-governance.md";
const RFC_0132_PATH: &str = "docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md";

fn read_doc(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"))
}

/// MIK-5843.AC.1 AC.1: Willow competitive landscape page names Willow/Webrix as an
/// enterprise identity + gateway + audit competitor and positions mcp-gateway on
/// sovereign/self-hosted deployment plus signed `.state` or per-action attestation
/// receipts versus ordinary audit logs.
///
/// CHECK: `rg -n "Willow|Webrix|withwillow\.ai|sovereign|self-hosted|signed .*\.state|attestation receipt|audit log" docs/competitive/willow-enterprise-agent-governance.md` exits 0
#[test]
fn ac_1_mik_5843_ac_1_ac_1_add_a_willow_competitive_lan() {
    let doc = read_doc(WILLOW_DOC_PATH);

    // Must name Willow
    assert!(doc.contains("Willow"), "doc must name Willow as competitor");
    // Must name Webrix
    assert!(doc.contains("Webrix"), "doc must name Webrix");
    // Must reference withwillow.ai
    assert!(
        doc.contains("withwillow.ai"),
        "doc must reference withwillow.ai"
    );
    // Must position on sovereign deployment
    assert!(
        doc.contains("sovereign"),
        "doc must position mcp-gateway as sovereign"
    );
    // Must position on self-hosted deployment
    assert!(
        doc.contains("self-hosted"),
        "doc must position mcp-gateway as self-hosted"
    );
    // Must reference signed .state
    assert!(
        doc.contains(".state"),
        "doc must reference signed .state files"
    );
    // Must claim attestation receipts
    assert!(
        doc.contains("attestation receipt"),
        "doc must claim attestation receipts"
    );
    // Must contrast with audit log
    assert!(
        doc.contains("audit log"),
        "doc must reference audit log for contrast"
    );
}

/// MIK-5843.AC.2 AC.2: Feature-bar table comparing mcp-gateway versus Willow across
/// connectors count, `IdP` integration, shadow-AI/unmanaged-MCP detection, runtime guards,
/// audit trail, and cryptographic attestation, with explicit LEAD/MATCH/LAG verdicts.
///
/// CHECK: `rg -n "\|.*Connectors.*IdP.*Shadow.*Runtime guards.*Audit.*Attestation|LEAD|MATCH|LAG|1000\+|Okta|Entra|JumpCloud" docs/competitive/willow-enterprise-agent-governance.md` exits 0
#[test]
fn ac_2_mik_5843_ac_2_ac_2_the_willow_page_includes_a_f() {
    let doc = read_doc(WILLOW_DOC_PATH);

    // Feature-bar table headings
    assert!(doc.contains("Connectors"), "table must include Connectors");
    assert!(doc.contains("IdP"), "table must include IdP");
    assert!(
        doc.contains("Shadow-AI") || doc.contains("shadow-AI"),
        "table must include Shadow-AI"
    );
    assert!(
        doc.contains("Runtime guards") || doc.contains("runtime guards"),
        "table must include Runtime guards"
    );
    assert!(
        doc.contains("Audit trail") || doc.contains("Audit"),
        "table must include Audit trail"
    );
    assert!(
        doc.contains("attestation"),
        "table must include Attestation"
    );

    // Verdicts
    assert!(doc.contains("LEAD"), "table must have LEAD verdicts");
    assert!(doc.contains("MATCH"), "table must have MATCH verdicts");
    assert!(doc.contains("LAG"), "table must have LAG verdicts");

    // Competitor detail terms
    assert!(
        doc.contains("1000+"),
        "table must reference 1000+ connectors"
    );
    assert!(doc.contains("Okta"), "table must reference Okta");
    assert!(doc.contains("Entra"), "table must reference Entra");
    assert!(doc.contains("JumpCloud"), "table must reference JumpCloud");
}

/// MIK-5843.AC.3 AC.3: Document shadow-AI detection as a net-new mcp-gateway capability
/// candidate, bounded to config scanning, process scanning, and exported network/SIEM rules
/// unless mcp-gateway becomes a network proxy; include concrete implementation pointers to
/// `src/discovery/config_scanner.rs` and `src/discovery/process_scanner.rs`.
///
/// CHECK: `rg -n "shadow-AI|unmanaged MCP|config_scanner\.rs|process_scanner\.rs|network proxy|SIEM|discover --shadow" docs/competitive/willow-enterprise-agent-governance.md docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md` exits 0
#[test]
fn ac_3_mik_5843_ac_3_ac_3_document_shadow_ai_detection() {
    let willow = read_doc(WILLOW_DOC_PATH);
    let rfc = read_doc(RFC_0132_PATH);

    // Shadow-AI term must appear in at least one of the two docs
    let shadow_ai = willow.contains("shadow-AI") || rfc.contains("shadow-AI");
    assert!(shadow_ai, "shadow-AI must appear in willow doc or RFC-0132");

    // Unmanaged MCP
    let unmanaged = willow.contains("unmanaged MCP") || rfc.contains("unmanaged MCP");
    assert!(
        unmanaged,
        "unmanaged MCP must appear in willow doc or RFC-0132"
    );

    // config_scanner.rs
    let config_scanner =
        willow.contains("config_scanner.rs") || rfc.contains("config_scanner.rs");
    assert!(
        config_scanner,
        "config_scanner.rs must appear in willow doc or RFC-0132"
    );

    // process_scanner.rs
    let process_scanner =
        willow.contains("process_scanner.rs") || rfc.contains("process_scanner.rs");
    assert!(
        process_scanner,
        "process_scanner.rs must appear in willow doc or RFC-0132"
    );

    // network proxy boundary
    let net_proxy = willow.contains("network proxy") || rfc.contains("network proxy");
    assert!(
        net_proxy,
        "network proxy boundary must appear in willow doc or RFC-0132"
    );

    // SIEM
    let siem = willow.contains("SIEM") || rfc.contains("SIEM");
    assert!(siem, "SIEM must appear in willow doc or RFC-0132");

    // discover --shadow
    let discover = willow.contains("discover --shadow") || rfc.contains("discover --shadow");
    assert!(
        discover,
        "discover --shadow must appear in willow doc or RFC-0132"
    );
}

/// MIK-5843.AC.4 AC.4: Regression test exists at `tests/mik_5843_willow_competitive_docs.rs`.
///
/// CHECK: `cargo test --test mik_5843_willow_competitive_docs` exits 0.
/// This test verifies the file exists and contains the expected test functions.
#[test]
fn ac_4_mik_5843_ac_4_ac_4_add_a_committed_regression_d() {
    let test_file = "tests/mik_5843_willow_competitive_docs.rs";
    let content = fs::read_to_string(test_file)
        .unwrap_or_else(|e| panic!("regression test file {test_file} must exist: {e}"));

    // Must contain test for competitor name
    assert!(
        content.contains("fn doc_names_willow_and_webrix_as_competitor"),
        "regression test must assert competitor name"
    );
    // Must contain test for sovereign/self-hosted positioning
    assert!(
        content.contains("fn doc_positions_on_sovereign_self_hosted"),
        "regression test must assert sovereign/self-hosted positioning"
    );
    // Must contain test for attestation receipts
    assert!(
        content.contains("fn doc_claims_signed_state_and_attestation_receipts"),
        "regression test must assert attestation receipts"
    );
    // Must contain test for feature-bar headings
    assert!(
        content.contains("fn doc_has_feature_bar_table_with_verdicts"),
        "regression test must assert feature-bar headings"
    );
    // Must contain test for shadow-AI scope
    assert!(
        content.contains("fn doc_documents_shadow_ai_detection_scope"),
        "regression test must assert shadow-AI scope"
    );
}

/// MIK-5843.AC.5 AC.deploy: Page linked from at least one index file under docs/.
///
/// CHECK: `rg -l 'willow-enterprise-agent-governance' docs/` finds at least one index file.
#[test]
fn ac_5_mik_5843_ac_5_ac_deploy_page_committed_to_main() {
    let docs_dir = std::path::Path::new("docs");
    let mut found_link = false;

    // Check competitive README
    let competitive_readme = docs_dir.join("competitive").join("README.md");
    if competitive_readme.exists() {
        let content = fs::read_to_string(&competitive_readme).unwrap_or_default();
        if content.contains("willow-enterprise-agent-governance") {
            found_link = true;
        }
    }

    // Check RFC-0132
    let rfc_0132 = docs_dir.join("design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md");
    if rfc_0132.exists() {
        let content = fs::read_to_string(&rfc_0132).unwrap_or_default();
        if content.contains("willow-enterprise-agent-governance") {
            found_link = true;
        }
    }

    assert!(
        found_link,
        "Willow page must be linked from at least one docs index file"
    );
}

/// AC.deploy: Diff merged to main, release binary built and deployed.
/// This is a deployment-gate AC verified by CI, not by unit test.
/// The test here confirms the doc and test artifacts exist.
#[test]
fn ac_6_ac_deploy_diff_merged_to_main_target_main() {
    // Deployment AC is verified by CI pipeline, not unit test.
    // This test confirms the artifacts are in place.
    assert!(
        std::path::Path::new(WILLOW_DOC_PATH).exists(),
        "Willow competitive doc must exist"
    );
    assert!(
        std::path::Path::new("tests/mik_5843_willow_competitive_docs.rs").exists(),
        "Regression test must exist"
    );
}
