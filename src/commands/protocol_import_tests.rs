// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use mcp_gateway::protocol_imports::{ImportRiskKind, ImportSourceKind};

use super::*;

#[test]
fn guard_rejects_yaml_alias_bomb() {
    // A billion-laughs-style alias amplification must be rejected before
    // serde_yaml expands it.
    use std::fmt::Write as _;
    let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
    for (i, prev) in ('b'..='z').zip('a'..='y') {
        let _ = writeln!(
            bomb,
            "{i}: &{i} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]"
        );
    }
    let err = guard_untrusted_yaml(&bomb).expect_err("alias bomb must be rejected");
    assert!(err.contains("alias"), "got: {err}");
}

#[test]
fn guard_allows_normal_yaml_without_aliases() {
    let ok = "openapi: 3.0.0\ninfo:\n  title: x\npaths: {}\n";
    assert!(guard_untrusted_yaml(ok).is_ok());
}

#[test]
fn guard_rejects_oversized_document() {
    let big = "x".repeat(MAX_SPEC_BYTES + 1);
    let err = guard_untrusted_yaml(&big).expect_err("oversized doc must be rejected");
    assert!(err.contains("exceeds"), "got: {err}");
}

#[test]
fn count_yaml_aliases_ignores_scalar_stars() {
    // `*` inside scalar text (not in node position) must not be counted.
    assert_eq!(count_yaml_aliases("note: see 2 * 3 for math\n"), 0);
    assert_eq!(count_yaml_aliases("ref: *anchor\n"), 1);
    assert_eq!(count_yaml_aliases("list:\n  - *a\n  - *b\n"), 2);
}

const OPENAPI_SPEC: &str = r#"
openapi: 3.0.0
info:
  title: Pets
  version: "1.0"
servers:
  - url: https://api.example.test
paths:
  /pets:
    get:
      operationId: listPets
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
    post:
      operationId: createPet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: created
"#;

#[tokio::test]
async fn preview_openapi_file_returns_disabled_reversible_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("pets.yaml");
    tokio::fs::write(&spec, OPENAPI_SPEC)
        .await
        .expect("write spec");

    let plan = preview_plan_from_file(
        ProtocolImportKind::OpenApi,
        &spec,
        Some("petstore".to_string()),
        "imported_tool_baseline".to_string(),
    )
    .await
    .expect("preview plan");

    assert_eq!(plan.source.name, "petstore");
    assert_eq!(plan.source.kind, ImportSourceKind::OpenApi);
    assert!(plan.reversible);
    assert!(!plan.safe_defaults.drafts_enabled);
    assert!(!plan.drafts.is_empty());
    assert!(plan.drafts.iter().all(|draft| !draft.enabled));
    assert!(
        plan.drafts
            .iter()
            .any(|draft| draft.review_gates.iter().any(|gate| gate.non_inferable))
    );
}

#[tokio::test]
async fn preview_oci_package_metadata_preserves_supply_chain_gates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("package.yaml");
    tokio::fs::write(
        &spec,
        r"
name: demo-tools
image_ref: ghcr.io/example/demo-tools:latest
tools:
  - name: export_data
    description: Export account data
    input_schema:
      type: object
      properties:
        account_id:
          type: string
",
    )
    .await
    .expect("write package");

    let plan = preview_plan_from_file(
        ProtocolImportKind::OciMcpPackage,
        &spec,
        None,
        "imported_tool_baseline".to_string(),
    )
    .await
    .expect("preview plan");

    assert_eq!(plan.source.kind, ImportSourceKind::OciMcpPackage);
    assert!(plan.drafts.iter().all(|draft| !draft.enabled));
    assert!(plan.drafts.iter().any(|draft| {
        draft
            .risks
            .iter()
            .any(|risk| risk.kind == ImportRiskKind::SupplyChainProvenance)
    }));
}

#[tokio::test]
async fn apply_openapi_file_writes_inactive_drafts_and_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("pets.yaml");
    let output = dir.path().join("capability-drafts");
    tokio::fs::write(&spec, OPENAPI_SPEC)
        .await
        .expect("write spec");

    let report = apply_plan_from_file(
        ProtocolImportKind::OpenApi,
        &spec,
        &output,
        Some("petstore".to_string()),
        "imported_tool_baseline".to_string(),
        false,
    )
    .await
    .expect("apply plan");

    assert_eq!(report.activation_state, "inactive_draft_directory");
    assert!(!report.written.is_empty());
    assert!(report.skipped.is_empty());
    assert!(
        report
            .written
            .iter()
            .all(|draft| !draft.enabled && draft.path.contains("capability-drafts"))
    );

    let first_draft = &report.written[0];
    let draft_yaml = tokio::fs::read_to_string(&first_draft.path)
        .await
        .expect("draft yaml");
    assert!(draft_yaml.contains("# mcp-gateway protocol import draft"));
    assert!(draft_yaml.contains("# inactive until this file is reviewed"));
    assert!(draft_yaml.contains("fulcrum: \"1.0\""));

    let manifest = tokio::fs::read_to_string(&report.manifest_path)
        .await
        .expect("manifest");
    let value: serde_json::Value = serde_json::from_str(&manifest).expect("manifest json");
    assert_eq!(value["schema_version"], "protocol_import.apply_report.v1");
    assert_eq!(value["activation_state"], "inactive_draft_directory");
    assert_eq!(
        value["written"].as_array().unwrap().len(),
        report.written.len()
    );
    assert!(
        value["rollback"]["command"]
            .as_str()
            .unwrap()
            .contains(&first_draft.path)
    );
}

#[tokio::test]
async fn apply_graphql_file_writes_inactive_draft_and_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("graphql.yaml");
    let output = dir.path().join("graphql-drafts");
    tokio::fs::write(
        &spec,
        r#"
endpoint: https://api.example.test/graphql
operations:
  - name: Viewer
    operation_type: query
    query: "query Viewer($first: Int) { viewer { login repositories(first: $first) { nodes { name } } } }"
    variables_schema:
      type: object
      properties:
        first:
          type: integer
"#,
    )
    .await
    .expect("write graphql spec");

    let report = apply_plan_from_file(
        ProtocolImportKind::Graphql,
        &spec,
        &output,
        Some("github-graphql".to_string()),
        "imported_tool_baseline".to_string(),
        false,
    )
    .await
    .expect("apply plan");

    assert_eq!(report.activation_state, "inactive_draft_directory");
    assert_eq!(report.written.len(), 1);
    assert!(report.skipped.is_empty());
    assert!(!report.written[0].enabled);

    let draft_yaml = tokio::fs::read_to_string(&report.written[0].path)
        .await
        .expect("graphql draft yaml");
    let value: serde_json::Value = serde_yaml::from_str(&draft_yaml).expect("graphql yaml");
    assert_eq!(value["providers"]["primary"]["service"], "graphql");
    assert_eq!(
        value["providers"]["primary"]["config"]["endpoint"],
        "https://api.example.test/graphql"
    );
    assert_eq!(value["metadata"]["read_only"], true);

    let manifest = tokio::fs::read_to_string(&report.manifest_path)
        .await
        .expect("manifest");
    let value: serde_json::Value = serde_json::from_str(&manifest).expect("manifest json");
    assert_eq!(value["written"].as_array().unwrap().len(), 1);
    assert!(
        value["rollback"]["command"]
            .as_str()
            .unwrap()
            .contains("rm --")
    );
}

#[tokio::test]
async fn apply_postman_file_writes_inactive_draft_and_manifest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("collection.json");
    let output = dir.path().join("postman-drafts");
    tokio::fs::write(
        &spec,
        r#"{
  "info": { "name": "Admin API", "_postman_id": "collection-1" },
  "item": [
    {
      "name": "Delete All Users",
      "request": {
        "method": "DELETE",
        "url": {
          "raw": "https://api.example.test/users",
          "query": [{ "key": "confirm" }]
        }
      }
    }
  ]
}"#,
    )
    .await
    .expect("write postman collection");

    let report = apply_plan_from_file(
        ProtocolImportKind::Postman,
        &spec,
        &output,
        None,
        "imported_tool_baseline".to_string(),
        false,
    )
    .await
    .expect("apply plan");

    assert_eq!(report.activation_state, "inactive_draft_directory");
    assert_eq!(report.written.len(), 1);
    assert!(report.skipped.is_empty());
    assert!(!report.written[0].enabled);

    let draft_yaml = tokio::fs::read_to_string(&report.written[0].path)
        .await
        .expect("postman draft yaml");
    let value: serde_json::Value = serde_yaml::from_str(&draft_yaml).expect("postman yaml");
    assert_eq!(value["providers"]["primary"]["service"], "rest");
    assert_eq!(value["providers"]["primary"]["config"]["method"], "DELETE");
    assert_eq!(
        value["providers"]["primary"]["config"]["param_map"]["confirm"],
        "confirm"
    );
    assert_eq!(value["metadata"]["read_only"], false);
}

#[tokio::test]
async fn apply_oci_package_without_reversible_yaml_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let spec = dir.path().join("package.yaml");
    tokio::fs::write(
        &spec,
        r"
name: demo-tools
image_ref: ghcr.io/example/demo-tools:latest
tools:
  - name: export_data
    description: Export account data
    input_schema:
      type: object
",
    )
    .await
    .expect("write package");

    let err = apply_plan_from_file(
        ProtocolImportKind::OciMcpPackage,
        &spec,
        &dir.path().join("drafts"),
        None,
        "imported_tool_baseline".to_string(),
        false,
    )
    .await
    .expect_err("unsupported apply should fail closed");

    assert!(err.contains("no reversible capability YAML drafts"));
    assert!(!dir.path().join("drafts").exists());
}
