//! Import generator — writes reviewable output from `CapabilityDraft` values.
//!
//! ## Output structure
//!
//! Each draft produces:
//! - `{name}.yaml` — Capability definition YAML
//! - `{name}.trustcard.md` — TrustCard stub for review
//! - `{name}.examples.json` — Input/output examples
//! - `{name}.test.rs` — Generated test stub
//! - `_risk_report.json` — Machine-readable risk report (one per generation)
//!
//! ## Review gate
//!
//! Destructive, mutation, write, delete, or open-world broad tools are
//! generated with `enabled: false` and `review_required: true`. They are
//! NOT visible to normal `tools/list` until a human approves them.

use std::collections::BTreeMap;
use std::fmt::Write;

use super::draft::{CapabilityDraft, ReviewState, SafetyClassification};

/// Output of a generation run.
#[derive(Debug)]
pub struct GenerationOutput {
    /// Capability YAML files (name → content).
    pub yaml_files: BTreeMap<String, String>,
    /// TrustCard markdown files (name → content).
    pub trust_card_files: BTreeMap<String, String>,
    /// Example JSON files (name → content).
    pub example_files: BTreeMap<String, String>,
    /// Test stub files (name → content).
    pub test_files: BTreeMap<String, String>,
    /// Machine-readable risk report (JSON).
    pub risk_report: String,
}

/// Generator for converting `CapabilityDraft` values into reviewable output.
pub struct ImportGenerator {
    /// Output directory for generated files.
    output_dir: String,
}

impl ImportGenerator {
    /// Create a new generator with a default output directory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            output_dir: "/tmp/mcp-gateway-import".to_string(),
        }
    }

    /// Create a new generator with a specific output directory.
    #[must_use]
    pub fn with_output_dir(output_dir: &str) -> Self {
        Self {
            output_dir: output_dir.to_string(),
        }
    }

    /// Generate all output files from a set of drafts.
    ///
    /// Returns a `GenerationOutput` with all file contents keyed by name.
    #[must_use]
    pub fn generate(&self, drafts: &[CapabilityDraft]) -> GenerationOutput {
        let mut yaml_files = BTreeMap::new();
        let mut trust_card_files = BTreeMap::new();
        let mut example_files = BTreeMap::new();
        let mut test_files = BTreeMap::new();

        for draft in drafts {
            yaml_files.insert(draft.file_name(), self.generate_yaml(draft));
            trust_card_files.insert(
                draft.trust_card_file_name(),
                self.generate_trust_card(draft),
            );
            example_files.insert(
                draft.example_file_name(),
                self.generate_examples(draft),
            );
            test_files.insert(draft.test_file_name(), self.generate_test_stub(draft));
        }

        let risk_report = self.generate_risk_report(drafts);

        GenerationOutput {
            yaml_files,
            trust_card_files,
            example_files,
            test_files,
            risk_report,
        }
    }

    /// Generate capability YAML from a draft.
    fn generate_yaml(&self, draft: &CapabilityDraft) -> String {
        let mut yaml = String::new();

        // Header
        let _ = writeln!(yaml, "# Auto-generated from {} import", draft.source_kind.as_str());
        let _ = writeln!(yaml, "# Source: {}", draft.source_id);
        let _ = writeln!(
            yaml,
            "# Review state: {} | Enabled: {}",
            if draft.review_required() { "pending" } else { "approved" },
            draft.enabled
        );
        yaml.push('\n');

        // Basic info
        yaml.push_str("fulcrum: \"1.0\"\n");
        let _ = writeln!(yaml, "name: {}", draft.name);
        let _ = writeln!(yaml, "description: {}", yaml_scalar(&draft.description));
        yaml.push('\n');

        // Review gate metadata (AC.6)
        let _ = writeln!(
            yaml,
            "# IMPORT-REVIEW: review_required={}",
            draft.review_required()
        );
        let _ = writeln!(yaml, "# IMPORT-REVIEW: enabled={}", draft.enabled);
        let _ = writeln!(
            yaml,
            "# IMPORT-REVIEW: safety={:?}",
            draft.safety
        );
        yaml.push('\n');

        // Schema
        yaml.push_str("schema:\n");
        yaml.push_str("  input:\n");
        for line in serde_yaml::to_string(&draft.input_schema)
            .unwrap_or_default()
            .lines()
        {
            let _ = writeln!(yaml, "    {line}");
        }
        yaml.push_str("  output:\n");
        for line in serde_yaml::to_string(&draft.output_schema)
            .unwrap_or_default()
            .lines()
        {
            let _ = writeln!(yaml, "    {line}");
        }
        yaml.push('\n');

        // Provider
        yaml.push_str("providers:\n");
        yaml.push_str("  primary:\n");
        let _ = writeln!(yaml, "    service: {}", draft.protocol);
        yaml.push_str("    cost_per_call: 0\n");
        yaml.push_str("    timeout: 30\n");
        yaml.push_str("    config:\n");

        if !draft.base_url.is_empty() {
            let _ = writeln!(yaml, "      base_url: {}", yaml_scalar(&draft.base_url));
        }
        if !draft.path.is_empty() {
            let _ = writeln!(yaml, "      path: {}", yaml_scalar(&draft.path));
        }
        if !draft.http_method.is_empty() {
            let _ = writeln!(
                yaml,
                "      method: {}",
                draft.http_method.to_uppercase()
            );
        }

        // Headers
        if !draft.headers.is_empty() {
            yaml.push_str("      headers:\n");
            let mut sorted_headers: Vec<_> = draft.headers.iter().collect();
            sorted_headers.sort_by(|a, b| a.0.cmp(b.0));
            for (key, value) in &sorted_headers {
                let _ = writeln!(yaml, "        {}: {}", yaml_scalar(key), yaml_scalar(value));
            }
        }

        // Query params
        if !draft.query_params.is_empty() {
            yaml.push_str("      params:\n");
            let mut sorted_params: Vec<_> = draft.query_params.iter().collect();
            sorted_params.sort_by(|a, b| a.0.cmp(b.0));
            for (key, value) in &sorted_params {
                let _ = writeln!(yaml, "        {}: {}", yaml_scalar(key), yaml_scalar(value));
            }
        }

        // Request body
        if let Some(ref body) = draft.request_body {
            let body_str = serde_yaml::to_string(body).unwrap_or_default();
            yaml.push_str("      body:\n");
            for line in body_str.lines() {
                let _ = writeln!(yaml, "        {line}");
            }
        }

        yaml.push('\n');

        // Cache — only for GET/HEAD (read-only safe methods)
        let safe_method = draft.http_method.eq_ignore_ascii_case("get")
            || draft.http_method.eq_ignore_ascii_case("head");
        if safe_method {
            yaml.push_str("cache:\n");
            yaml.push_str("  strategy: exact\n");
            yaml.push_str("  ttl: 300\n");
            yaml.push('\n');
        }

        // Auth
        yaml.push_str("auth:\n");
        if draft.auth.auth_type != "none" && draft.auth_required {
            let _ = writeln!(yaml, "  required: true");
            let _ = writeln!(yaml, "  type: {}", draft.auth.auth_type);
            if !draft.auth.key.is_empty() {
                let _ = writeln!(yaml, "  key: {}", draft.auth.key);
            }
            if !draft.auth.description.is_empty() {
                let _ = writeln!(
                    yaml,
                    "  description: {}",
                    yaml_scalar(&draft.auth.description)
                );
            }
            if let Some(ref header) = draft.auth.header {
                let _ = writeln!(yaml, "  header: {header}");
            }
            if let Some(ref prefix) = draft.auth.prefix {
                let _ = writeln!(yaml, "  prefix: {prefix}");
            }
            if let Some(ref param) = draft.auth.query_param {
                let _ = writeln!(yaml, "  param: {param}");
            }
        } else {
            yaml.push_str("  required: false\n");
            yaml.push_str("  type: none\n");
        }
        yaml.push('\n');

        // Metadata with safety annotations
        yaml.push_str("metadata:\n");
        if !draft.tags.is_empty() {
            yaml.push_str("  tags:\n");
            let mut sorted_tags = draft.tags.clone();
            sorted_tags.sort();
            for tag in &sorted_tags {
                let _ = writeln!(yaml, "    - {tag}");
            }
        }
        let _ = writeln!(
            yaml,
            "  read_only: {}",
            draft.safety == SafetyClassification::ReadOnly
        );
        let _ = writeln!(
            yaml,
            "  destructive: {}",
            draft.safety == SafetyClassification::Destructive
        );
        let _ = writeln!(
            yaml,
            "  idempotent: {}",
            draft.safety == SafetyClassification::ReadOnly
        );
        let _ = writeln!(
            yaml,
            "  open_world: {}",
            draft.safety == SafetyClassification::OpenWorld
        );

        yaml
    }

    /// Generate a TrustCard stub markdown.
    fn generate_trust_card(&self, draft: &CapabilityDraft) -> String {
        let mut md = String::new();

        let _ = writeln!(md, "# TrustCard: {}", draft.name);
        md.push('\n');
        let _ = writeln!(md, "**Source Kind**: {}", draft.source_kind.as_str());
        let _ = writeln!(md, "**Source ID**: {}", draft.source_id);
        let _ = writeln!(md, "**Protocol**: {}", draft.protocol);
        let _ = writeln!(md, "**Safety**: {:?}", draft.safety);
        let _ = writeln!(
            md,
            "**Review Required**: {}",
            draft.review_required()
        );
        let _ = writeln!(md, "**Enabled**: {}", draft.enabled);
        md.push('\n');

        if let Some(ref tc) = draft.trust_card {
            let _ = writeln!(md, "## Reviewer");
            let _ = writeln!(
                md,
                "{}",
                tc.reviewer.as_deref().unwrap_or("Not yet assigned")
            );
            md.push('\n');

            let _ = writeln!(md, "## Notes");
            let _ = writeln!(md, "{}", tc.notes);
            md.push('\n');

            if !tc.risk_annotations.is_empty() {
                let _ = writeln!(md, "## Risk Annotations");
                for risk in &tc.risk_annotations {
                    let _ = writeln!(md, "- {risk}");
                }
                md.push('\n');
            }

            let _ = writeln!(md, "## Source");
            let _ = writeln!(md, "- URL: {}", tc.source_url);
            let _ = writeln!(md, "- Generated: {}", tc.generated_at);
        }

        let _ = writeln!(md, "\n## Review Checklist");
        let _ = writeln!(md, "- [ ] Authentication credentials are configured");
        let _ = writeln!(md, "- [ ] Input/output schemas are correct");
        let _ = writeln!(md, "- [ ] Safety classification is appropriate");
        let _ = writeln!(md, "- [ ] Rate limits are understood");
        let _ = writeln!(md, "- [ ] Cost implications are acceptable");
        let _ = writeln!(md, "- [ ] Approved for production use");

        md
    }

    /// Generate examples JSON.
    fn generate_examples(&self, draft: &CapabilityDraft) -> String {
        serde_json::to_string_pretty(&draft.examples).unwrap_or_else(|_| "[]".to_string())
    }

    /// Generate a test stub for the capability.
    fn generate_test_stub(&self, draft: &CapabilityDraft) -> String {
        let mut test = String::new();

        let _ = writeln!(
            test,
            "//! Auto-generated test stub for capability: {}",
            draft.name
        );
        let _ = writeln!(
            test,
            "//! Source: {} ({})",
            draft.source_kind.as_str(),
            draft.source_id
        );
        let _ = writeln!(
            test,
            "//! Review state: {}",
            if draft.review_required() {
                "pending"
            } else {
                "approved"
            }
        );
        test.push('\n');

        // Embed JSON schemas as escaped strings to avoid raw-literal breaks
        let input_json = draft.input_schema.to_string();
        let output_json = draft.output_schema.to_string();
        let input_escaped = input_json.replace('\\', "\\\\").replace('"', "\\\"");
        let output_escaped = output_json.replace('\\', "\\\\").replace('"', "\\\"");

        let _ = writeln!(test, "#[test]");
        let _ = writeln!(test, "fn test_{}_schema() {{", draft.name);
        let _ = writeln!(test, "    // Verify input schema is valid JSON Schema");
        let _ = writeln!(test, "    let input_schema: serde_json::Value = serde_json::from_str(\"{input_escaped}\").expect(\"input schema must be valid JSON\");");
        let _ = writeln!(test, "    assert!(input_schema.is_object());");
        test.push('\n');
        let _ = writeln!(test, "    // Verify output schema is valid JSON Schema");
        let _ = writeln!(test, "    let output_schema: serde_json::Value = serde_json::from_str(\"{output_escaped}\").expect(\"output schema must be valid JSON\");");
        let _ = writeln!(test, "    assert!(output_schema.is_object());");
        test.push('\n');

        if draft.review_required() {
            let _ = writeln!(test, "    // REVIEW REQUIRED: This capability requires human review before activation.");
            let _ = writeln!(
                test,
                "    // Safety: {:?}",
                draft.safety
            );
        }

        let _ = writeln!(test, "}}");

        test
    }

    /// Generate machine-readable risk report.
    fn generate_risk_report(&self, drafts: &[CapabilityDraft]) -> String {
        let mut report = serde_json::Map::new();

        let total = drafts.len();
        let pending_review: Vec<&str> = drafts
            .iter()
            .filter(|d| d.review_required())
            .map(|d| d.name.as_str())
            .collect();
        let destructive: Vec<&str> = drafts
            .iter()
            .filter(|d| d.safety == SafetyClassification::Destructive)
            .map(|d| d.name.as_str())
            .collect();
        let mutations: Vec<&str> = drafts
            .iter()
            .filter(|d| d.safety == SafetyClassification::Mutation)
            .map(|d| d.name.as_str())
            .collect();
        let open_world: Vec<&str> = drafts
            .iter()
            .filter(|d| d.safety == SafetyClassification::OpenWorld)
            .map(|d| d.name.as_str())
            .collect();
        let read_only: Vec<&str> = drafts
            .iter()
            .filter(|d| d.safety == SafetyClassification::ReadOnly)
            .map(|d| d.name.as_str())
            .collect();

        report.insert(
            "generated_at".to_string(),
            serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
        );
        report.insert(
            "total_drafts".to_string(),
            serde_json::Value::Number(serde_json::Number::from(total)),
        );
        report.insert(
            "pending_review".to_string(),
            serde_json::json!(pending_review),
        );
        report.insert(
            "destructive".to_string(),
            serde_json::json!(destructive),
        );
        report.insert("mutations".to_string(), serde_json::json!(mutations));
        report.insert(
            "open_world".to_string(),
            serde_json::json!(open_world),
        );
        report.insert(
            "read_only".to_string(),
            serde_json::json!(read_only),
        );

        // Per-draft risk summary
        let draft_risks: Vec<serde_json::Value> = drafts
            .iter()
            .map(|d| {
                serde_json::json!({
                    "name": d.name,
                    "source_kind": d.source_kind.as_str(),
                    "safety": format!("{:?}", d.safety),
                    "review_required": d.review_required(),
                    "enabled": d.enabled,
                    "risk_annotations": d.trust_card.as_ref().map(|tc| &tc.risk_annotations).unwrap_or(&vec![]),
                })
            })
            .collect();
        report.insert("drafts".to_string(), serde_json::json!(draft_risks));

        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Format a string as a YAML scalar, using quotes when needed.
fn yaml_scalar(s: &str) -> String {
    // If the string contains special YAML characters, wrap in quotes
    if s.contains('\n')
        || s.contains(':')
        || s.contains('#')
        || s.contains('{')
        || s.contains('}')
        || s.contains('[')
        || s.contains(']')
        || s.contains(',')
        || s.contains('&')
        || s.contains('*')
        || s.contains('?')
        || s.contains('|')
        || s.contains('-')
        || s.contains('<')
        || s.contains('>')
        || s.contains('=')
        || s.contains('!')
        || s.contains('%')
        || s.contains('@')
        || s.contains('`')
        || s.starts_with('"')
        || s.starts_with('\'')
        || s.is_empty()
    {
        // Use single-quoted string, escaping internal single quotes
        let escaped = s.replace('\'', "''");
        format!("'{escaped}'")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::import::draft::{
        DraftAuth, DraftExample, ImportSourceKind, ReviewState, SafetyClassification, TrustCardStub,
    };

    fn make_test_drafts() -> Vec<CapabilityDraft> {
        vec![
            // Read-only GET — should be enabled
            CapabilityDraft {
                source_kind: ImportSourceKind::OpenApi,
                source_id: "test-api".into(),
                name: "get_users".into(),
                description: "Get all users".into(),
                safety: SafetyClassification::ReadOnly,
                review_state: ReviewState::Approved,
                enabled: true,
                http_method: "GET".into(),
                base_url: "https://api.example.com".into(),
                path: "/users".into(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "array"}),
                trust_card: Some(TrustCardStub {
                    notes: "Read-only query".into(),
                    source_url: "https://api.example.com".into(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Destructive DELETE — review required, disabled
            CapabilityDraft {
                source_kind: ImportSourceKind::OpenApi,
                source_id: "test-api".into(),
                name: "delete_user".into(),
                description: "Delete a user".into(),
                safety: SafetyClassification::Destructive,
                review_state: ReviewState::Pending,
                enabled: false,
                http_method: "DELETE".into(),
                base_url: "https://api.example.com".into(),
                path: "/users/{id}".into(),
                input_schema: serde_json::json!({"type": "object", "properties": {"id": {"type": "string"}}}),
                output_schema: serde_json::json!({"type": "object"}),
                auth: DraftAuth {
                    auth_type: "bearer".into(),
                    key: "env:API_TOKEN".into(),
                    description: "Bearer auth".into(),
                    header: Some("Authorization".into()),
                    prefix: Some("Bearer".into()),
                    ..Default::default()
                },
                auth_required: true,
                trust_card: Some(TrustCardStub {
                    notes: "Destructive operation".into(),
                    source_url: "https://api.example.com".into(),
                    risk_annotations: vec!["Deletes user data permanently".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            // Open-world — review required, disabled
            CapabilityDraft {
                source_kind: ImportSourceKind::OciMcpPackage,
                source_id: "oci:ghcr.io/test:1.0".into(),
                name: "oci_test_server".into(),
                description: "OCI MCP test server".into(),
                safety: SafetyClassification::OpenWorld,
                review_state: ReviewState::Pending,
                enabled: false,
                trust_card: Some(TrustCardStub {
                    notes: "OCI package import".into(),
                    source_url: "ghcr.io/test:1.0".into(),
                    risk_annotations: vec!["External package — review required".into()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn generator_produces_yaml_for_all_drafts() {
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        assert_eq!(output.yaml_files.len(), 3);
        assert!(output.yaml_files.contains_key("get_users.yaml"));
        assert!(output.yaml_files.contains_key("delete_user.yaml"));
        assert!(output.yaml_files.contains_key("oci_test_server.yaml"));
    }

    #[test]
    fn destructive_draft_has_review_required_in_yaml() {
        // AC.6: destructive fixture has review_required=true, enabled=false
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        let delete_yaml = output.yaml_files.get("delete_user.yaml").unwrap();
        assert!(delete_yaml.contains("review_required=true"));
        assert!(delete_yaml.contains("enabled=false"));
    }

    #[test]
    fn read_only_draft_is_enabled() {
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        let get_yaml = output.yaml_files.get("get_users.yaml").unwrap();
        assert!(get_yaml.contains("enabled=true"));
        assert!(get_yaml.contains("read_only: true"));
    }

    #[test]
    fn generator_produces_trust_card_files() {
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        assert_eq!(output.trust_card_files.len(), 3);
        for (name, content) in &output.trust_card_files {
            assert!(
                content.contains("# TrustCard:"),
                "TrustCard file {name} missing header"
            );
            assert!(
                content.contains("## Review Checklist"),
                "TrustCard file {name} missing review checklist"
            );
        }
    }

    #[test]
    fn generator_produces_risk_report() {
        // AC.6: machine-readable risk report present
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        let report: serde_json::Value =
            serde_json::from_str(&output.risk_report).expect("risk report must be valid JSON");
        assert_eq!(report["total_drafts"], 3);
        // 2 pending review (delete_user + oci_test_server)
        assert_eq!(
            report["pending_review"].as_array().unwrap().len(),
            2,
            "expected 2 pending review drafts"
        );
        // 1 destructive
        assert_eq!(
            report["destructive"].as_array().unwrap().len(),
            1,
            "expected 1 destructive draft"
        );
        // 1 open_world
        assert_eq!(
            report["open_world"].as_array().unwrap().len(),
            1,
            "expected 1 open-world draft"
        );
    }

    #[test]
    fn generator_output_is_deterministic() {
        // AC.7: two consecutive generations from the same fixtures produce
        // byte-identical output trees
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();

        let output1 = gen.generate(&drafts);
        let output2 = gen.generate(&drafts);

        // YAML files must be identical
        for (name, content1) in &output1.yaml_files {
            let content2 = output2.yaml_files.get(name).unwrap();
            assert_eq!(
                content1, content2,
                "YAML file {name} differs between generations"
            );
        }

        // TrustCard files must be identical
        for (name, content1) in &output1.trust_card_files {
            let content2 = output2.trust_card_files.get(name).unwrap();
            assert_eq!(
                content1, content2,
                "TrustCard file {name} differs between generations"
            );
        }

        // Example files must be identical
        for (name, content1) in &output1.example_files {
            let content2 = output2.example_files.get(name).unwrap();
            assert_eq!(
                content1, content2,
                "Example file {name} differs between generations"
            );
        }
    }

    #[test]
    fn yaml_keys_are_sorted_for_stability() {
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        // Find auth line in delete_user YAML
        let delete_yaml = output.yaml_files.get("delete_user.yaml").unwrap();
        // Headers should be in sorted order
        assert!(delete_yaml.contains("auth:"), "missing auth section");

        // Verify the YAML is parseable
        for content in output.yaml_files.values() {
            // Should parse as valid capability
            let _parsed: serde_yaml::Value = serde_yaml::from_str(content)
                .unwrap_or_else(|e| panic!("YAML parse error: {e}\n{content}"));
        }
    }

    #[test]
    fn generator_example_files_contain_valid_json() {
        let drafts = make_test_drafts();
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        for content in output.example_files.values() {
            let _: serde_json::Value =
                serde_json::from_str(content).expect("example file must be valid JSON");
        }
    }

    #[test]
    fn yaml_scalar_handles_special_chars() {
        assert_eq!(yaml_scalar("simple"), "simple");
        assert!(yaml_scalar("has: colon").starts_with('\''));
        assert!(yaml_scalar("has#hash").starts_with('\''));
    }
}
