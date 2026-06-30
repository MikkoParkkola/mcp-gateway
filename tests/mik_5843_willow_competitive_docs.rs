//! Regression tests for MIK-5843: Willow competitive landscape documentation.
//!
//! These tests ensure the Willow competitive document retains its core claims:
//! competitor name, sovereign/self-hosted positioning, attestation receipts,
//! feature-bar headings, and shadow-AI scope.
//!
//! Acceptance criteria covered:
//! - AC.4: `cargo test --test mik_5843_willow_competitive_docs` exits 0

use std::fs;

const WILLOW_DOC_PATH: &str = "docs/competitive/willow-enterprise-agent-governance.md";

fn read_willow_doc() -> String {
    fs::read_to_string(WILLOW_DOC_PATH)
        .unwrap_or_else(|e| panic!("failed to read {WILLOW_DOC_PATH}: {e}"))
}

/// AC.1: The Willow page names Willow/Webrix as an enterprise identity + gateway +
/// audit competitor and positions mcp-gateway on sovereign/self-hosted deployment
/// plus signed `.state` or per-action attestation receipts versus ordinary audit logs.
///
/// CHECK: `rg -n "Willow|Webrix|withwillow\.ai|sovereign|self-hosted|signed .*\.state|attestation receipt|audit log"` exits 0
#[test]
fn doc_names_willow_and_webrix_as_competitor() {
    let doc = read_willow_doc();
    assert!(
        doc.contains("Willow"),
        "Willow competitive doc must name 'Willow' as competitor"
    );
    assert!(
        doc.contains("Webrix"),
        "Willow competitive doc must name 'Webrix' as the company behind Willow"
    );
}

/// AC.1 (cont): doc references withwillow.ai
#[test]
fn doc_references_withwillow_url() {
    let doc = read_willow_doc();
    assert!(
        doc.contains("withwillow.ai"),
        "Willow competitive doc must reference withwillow.ai"
    );
}

/// AC.1 (cont): doc positions mcp-gateway on sovereign/self-hosted deployment
#[test]
fn doc_positions_on_sovereign_self_hosted() {
    let doc = read_willow_doc();
    assert!(
        doc.contains("sovereign"),
        "Willow competitive doc must position mcp-gateway as sovereign"
    );
    assert!(
        doc.contains("self-hosted"),
        "Willow competitive doc must position mcp-gateway as self-hosted"
    );
}

/// AC.1 (cont): doc mentions signed .state and attestation receipts vs audit logs
#[test]
fn doc_claims_signed_state_and_attestation_receipts() {
    let doc = read_willow_doc();
    assert!(
        doc.contains(".state"),
        "Willow competitive doc must reference signed .state files"
    );
    assert!(
        doc.contains("attestation receipt"),
        "Willow competitive doc must claim attestation receipts as differentiator"
    );
    assert!(
        doc.contains("audit log"),
        "Willow competitive doc must contrast against ordinary audit log"
    );
}

/// AC.2: Feature-bar table comparing mcp-gateway vs Willow with LEAD/MATCH/LAG verdicts
/// and key terms (1000+, `Okta`, `Entra`, `JumpCloud`).
#[test]
fn doc_has_feature_bar_table_with_verdicts() {
    let doc = read_willow_doc();
    // Table must have a Connectors row
    assert!(
        doc.contains("Connectors"),
        "Feature-bar table must include Connectors row"
    );
    // Table must reference IdP
    assert!(
        doc.contains("IdP"),
        "Feature-bar table must include IdP integration row"
    );
    // Shadow-AI detection row
    assert!(
        doc.contains("Shadow-AI") || doc.contains("shadow-AI"),
        "Feature-bar table must include Shadow-AI detection row"
    );
    // Runtime guards row
    assert!(
        doc.contains("Runtime guards") || doc.contains("runtime guards"),
        "Feature-bar table must include Runtime guards row"
    );
    // Audit trail row
    assert!(
        doc.contains("Audit trail") || doc.contains("Audit"),
        "Feature-bar table must include Audit trail row"
    );
    // Cryptographic attestation row
    assert!(
        doc.contains("Cryptographic attestation") || doc.contains("attestation"),
        "Feature-bar table must include Attestation row"
    );
    // Verdicts
    assert!(
        doc.contains("LEAD"),
        "Feature-bar must include LEAD verdicts"
    );
    assert!(
        doc.contains("MATCH"),
        "Feature-bar must include MATCH verdicts"
    );
    assert!(
        doc.contains("LAG"),
        "Feature-bar must include LAG verdicts"
    );
    // Key competitor terms
    assert!(
        doc.contains("1000+"),
        "Feature-bar must reference Willow's 1000+ connectors"
    );
    assert!(
        doc.contains("Okta"),
        "Feature-bar must reference Okta as IdP provider"
    );
    assert!(
        doc.contains("Entra"),
        "Feature-bar must reference Entra as IdP provider"
    );
    assert!(
        doc.contains("JumpCloud"),
        "Feature-bar must reference JumpCloud as IdP provider"
    );
}

/// AC.3: Shadow-AI detection documented with implementation pointers
/// to `config_scanner.rs` and `process_scanner.rs`, bounded scope, `SIEM` export.
#[test]
fn doc_documents_shadow_ai_detection_scope() {
    let doc = read_willow_doc();
    assert!(
        doc.contains("shadow-AI") || doc.contains("Shadow-AI"),
        "Willow doc must document shadow-AI detection"
    );
    assert!(
        doc.contains("unmanaged MCP"),
        "Willow doc must mention unmanaged MCP detection"
    );
    assert!(
        doc.contains("config_scanner.rs"),
        "Willow doc must reference config_scanner.rs implementation"
    );
    assert!(
        doc.contains("process_scanner.rs"),
        "Willow doc must reference process_scanner.rs implementation"
    );
    assert!(
        doc.contains("network proxy"),
        "Willow doc must note network proxy boundary"
    );
    assert!(
        doc.contains("SIEM"),
        "Willow doc must mention SIEM rule export"
    );
    assert!(
        doc.contains("discover --shadow"),
        "Willow doc must reference discover --shadow subcommand"
    );
}

/// AC.5 (partial, in-repo): The Willow page is linked from at least one index file under docs/.
#[test]
fn doc_is_linked_from_index() {
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

    // Check design RFC-0132
    let rfc_0132 = docs_dir.join("design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md");
    if rfc_0132.exists() {
        let content = fs::read_to_string(&rfc_0132).unwrap_or_default();
        if content.contains("willow-enterprise-agent-governance") {
            found_link = true;
        }
    }

    // Check docs-level README
    let docs_readme = docs_dir.join("README.md");
    if docs_readme.exists() {
        let content = fs::read_to_string(&docs_readme).unwrap_or_default();
        if content.contains("willow-enterprise-agent-governance") {
            found_link = true;
        }
    }

    assert!(
        found_link,
        "Willow competitive page must be linked from at least one index file under docs/"
    );
}
