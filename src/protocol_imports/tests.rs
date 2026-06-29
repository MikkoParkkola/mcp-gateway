use serde_json::json;

use super::*;

const OPENAPI_SPEC: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "Users", "version": "1.0" },
  "servers": [{ "url": "https://api.example.test" }],
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "description": "List users",
        "responses": { "200": { "description": "OK" } }
      },
      "post": {
        "operationId": "createUser",
        "description": "Create user",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "email": { "type": "string" },
                  "name": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": { "200": { "description": "OK" } }
      }
    }
  }
}"#;

#[test]
fn openapi_plan_creates_disabled_drafts_with_review_gates() {
    let plan = ProtocolImportPlanner::new()
        .plan_openapi("users-api", OPENAPI_SPEC)
        .unwrap();

    assert_eq!(plan.source.kind, ImportSourceKind::OpenApi);
    assert_eq!(plan.drafts.len(), 2);
    assert!(plan.drafts.iter().all(|draft| !draft.enabled));
    assert!(plan.reversible);
    assert!(!plan.source_digest_sha256.is_empty());
    assert!(!plan.plan_digest_sha256.is_empty());

    let create = plan
        .drafts
        .iter()
        .find(|draft| draft.name == "createuser")
        .unwrap();
    assert!(create.generated_yaml.is_some());
    assert!(create.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::DestructiveOperation && risk.level == ImportRiskLevel::High
    }));
    assert!(create.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::SensitiveDataSurface && risk.field.as_deref() == Some("email")
    }));
    assert!(create.review_gates.iter().any(|gate| {
        gate.kind == ImportReviewGateKind::DestructiveAction && gate.non_inferable
    }));
    assert_eq!(
        create.policy_defaults.activation,
        ReviewAction::Confirm,
        "mutating imported operations must be confirm-gated"
    );
    assert_eq!(
        create.trust_card.activation_review.verdict,
        TrustCardRiskVerdict::NeedsReview
    );
    assert_eq!(
        create.trust_card.activation_review.highest_risk_level,
        Some(ImportRiskLevel::High)
    );
    assert_eq!(
        create.trust_card.activation_review.risk_count,
        create.risks.len()
    );
    assert_eq!(
        create.trust_card.activation_review.review_gate_count,
        create.review_gates.len()
    );
    assert!(create.trust_card.activation_review.human_review_required);
    assert!(!create.trust_card.activation_review.enabled_by_default);
}

#[test]
fn openapi_plan_is_deterministic() {
    let planner = ProtocolImportPlanner::new();
    let first = planner.plan_openapi("users-api", OPENAPI_SPEC).unwrap();
    let second = planner.plan_openapi("users-api", OPENAPI_SPEC).unwrap();

    assert_eq!(first.plan_digest_sha256, second.plan_digest_sha256);
    assert_eq!(
        first
            .drafts
            .iter()
            .map(|draft| draft.id.as_str())
            .collect::<Vec<_>>(),
        second
            .drafts
            .iter()
            .map(|draft| draft.id.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn graphql_mutation_and_unbounded_query_are_gated() {
    let spec = GraphqlImportSpec {
        endpoint: "https://api.example.test/graphql".to_string(),
        operations: vec![
            GraphqlOperationImport {
                name: "Viewer".to_string(),
                operation_type: GraphqlOperationType::Query,
                query: "query Viewer { viewer { id email } }".to_string(),
                variables_schema: empty_object_schema(),
                response_schema: empty_object_schema(),
            },
            GraphqlOperationImport {
                name: "DeleteProject".to_string(),
                operation_type: GraphqlOperationType::Mutation,
                query: "mutation DeleteProject($id: ID!) { deleteProject(id: $id) { ok } }"
                    .to_string(),
                variables_schema: json!({
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" }
                    }
                }),
                response_schema: empty_object_schema(),
            },
        ],
    };

    let plan = ProtocolImportPlanner::new()
        .plan_graphql("graphql-api", &spec)
        .unwrap();
    let viewer = plan
        .drafts
        .iter()
        .find(|draft| draft.name == "viewer")
        .unwrap();
    let delete_project = plan
        .drafts
        .iter()
        .find(|draft| draft.name == "deleteproject")
        .unwrap();

    assert!(viewer.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::UnboundedQuery && risk.level == ImportRiskLevel::Medium
    }));
    assert!(delete_project.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::DestructiveOperation && risk.level == ImportRiskLevel::High
    }));
    assert!(
        delete_project
            .review_gates
            .iter()
            .any(|gate| { gate.kind == ImportReviewGateKind::DestructiveAction })
    );
}

#[test]
fn postman_collection_imports_requests_as_disabled_drafts() {
    let collection = r#"{
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
    }"#;

    let plan = ProtocolImportPlanner::new()
        .plan_postman(collection)
        .unwrap();
    let draft = &plan.drafts[0];

    assert_eq!(draft.source_kind, ImportSourceKind::Postman);
    assert!(!draft.enabled);
    assert_eq!(draft.route.method.as_deref(), Some("DELETE"));
    assert!(draft.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::DestructiveOperation && risk.level == ImportRiskLevel::High
    }));
    assert_eq!(
        draft.input_schema["properties"]["confirm"]["type"],
        "string"
    );
}

#[test]
fn oci_package_preserves_license_and_verified_provenance() {
    let package = OciMcpPackageImport {
        name: "maps-tools".to_string(),
        image_ref: "registry.example.test/maps/tools@sha256:abc".to_string(),
        digest_sha256: Some("abc".to_string()),
        license: Some("Apache-2.0".to_string()),
        provenance: Some("slsa://maps-tools/build/1".to_string()),
        tools: vec![OciToolImport {
            name: "geocode".to_string(),
            description: "Geocode an address".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": { "type": "string" }
                }
            }),
            output_schema: empty_object_schema(),
        }],
    };

    let plan = ProtocolImportPlanner::new()
        .plan_oci_package(&package)
        .unwrap();
    let draft = &plan.drafts[0];

    assert_eq!(draft.trust_card.license.as_deref(), Some("Apache-2.0"));
    assert_eq!(draft.trust_card.evidence, TrustEvidenceLevel::Verified);
    assert_eq!(
        draft.trust_card.activation_review.verdict,
        TrustCardRiskVerdict::NeedsReview
    );
    assert_eq!(
        draft.trust_card.activation_review.highest_risk_level,
        Some(ImportRiskLevel::Medium)
    );
    assert_eq!(draft.trust_card.activation_review.review_gate_count, 0);
    assert!(!draft.trust_card.activation_review.human_review_required);
    assert!(!draft.risks.iter().any(|risk| {
        matches!(
            risk.kind,
            ImportRiskKind::LicenseUnknown | ImportRiskKind::SupplyChainProvenance
        )
    }));
    assert!(draft.risks.iter().any(|risk| {
        risk.kind == ImportRiskKind::SensitiveDataSurface
            && risk.field.as_deref() == Some("address")
    }));
}

#[test]
fn oci_package_missing_metadata_is_review_gated() {
    let package = OciMcpPackageImport {
        name: "unknown-tools".to_string(),
        image_ref: "registry.example.test/unknown/tools:latest".to_string(),
        digest_sha256: None,
        license: None,
        provenance: None,
        tools: vec![OciToolImport {
            name: "lookup".to_string(),
            description: "Lookup something".to_string(),
            input_schema: empty_object_schema(),
            output_schema: empty_object_schema(),
        }],
    };

    let plan = ProtocolImportPlanner::new()
        .plan_oci_package(&package)
        .unwrap();

    assert!(
        plan.review_gates
            .iter()
            .any(|gate| { gate.kind == ImportReviewGateKind::LicenseReview && gate.non_inferable })
    );
    assert!(plan.review_gates.iter().any(|gate| {
        gate.kind == ImportReviewGateKind::ProvenanceVerification && gate.can_auto_resolve
    }));
    let review = &plan.drafts[0].trust_card.activation_review;
    assert_eq!(review.verdict, TrustCardRiskVerdict::NeedsReview);
    assert_eq!(review.highest_risk_level, Some(ImportRiskLevel::High));
    assert_eq!(review.risk_count, plan.drafts[0].risks.len());
    assert_eq!(review.review_gate_count, plan.drafts[0].review_gates.len());
    assert!(review.human_review_required);
    assert!(review.manual_review_gate_count > 0);
    assert!(review.auto_resolvable_gate_count > 0);
}
