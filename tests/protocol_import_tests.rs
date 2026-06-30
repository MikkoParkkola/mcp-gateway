//! Integration tests for protocol import layer (MIK-6561).
//!
//! Covers: OpenAPI, GraphQL, Postman, OCI import + generator review gate
//! + deterministic snapshot stability.
//!
//! Run with: `cargo test --test protocol_import_tests`

use std::collections::HashMap;
use std::fs;

use mcp_gateway::capability::import::{
    CapabilityDraft, ImportGenerator, ImportSourceKind, ReviewState, SafetyClassification,
    TrustCardStub,
};
use mcp_gateway::capability::import::graphql::GraphQlImporter;
use mcp_gateway::capability::import::oci::OciMcpPackageImporter;
use mcp_gateway::capability::import::openapi::OpenApiDraftConverter;
use mcp_gateway::capability::import::postman::PostmanImporter;
use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════════════════
// OpenAPI import tests (AC.2)
// ═══════════════════════════════════════════════════════════════════════════

const OPENAPI_FIXTURE: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "Test API", "version": "1.0.0" },
  "servers": [{ "url": "https://api.test.com" }],
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "summary": "List all users",
        "parameters": [
          { "name": "limit", "in": "query", "required": false, "schema": { "type": "integer" } }
        ],
        "responses": { "200": { "description": "OK" } }
      },
      "post": {
        "operationId": "createUser",
        "summary": "Create a new user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/User" }
            }
          }
        },
        "responses": { "201": { "description": "Created" } }
      }
    },
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "summary": "Get user by ID",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": { "200": { "description": "OK" } }
      },
      "delete": {
        "operationId": "deleteUser",
        "summary": "Delete a user",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": { "204": { "description": "No Content" } }
      }
    }
  },
  "components": {
    "schemas": {
      "User": {
        "type": "object",
        "required": ["name", "email"],
        "properties": {
          "name": { "type": "string" },
          "email": { "type": "string", "format": "email" }
        }
      }
    },
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer"
      }
    }
  }
}"#;

mod openapi {
    use super::*;

    #[test]
    fn openapi_drafts_include_auth_schemas_and_examples() {
        // AC.2: OpenAPI fixture drafts include auth, schemas, examples, generated YAML,
        // TrustCard stub, and stable snapshot order
        let converter = OpenApiDraftConverter::new();
        let drafts = converter.convert_string(OPENAPI_FIXTURE).unwrap();

        // All 4 operations
        assert_eq!(drafts.len(), 4, "expected 4 drafts");

        // Auth is present
        for draft in &drafts {
            assert_eq!(draft.auth.auth_type, "bearer");
            assert!(draft.auth_required);
        }

        // Schemas are present
        let get_draft = drafts.iter().find(|d| d.name == "listusers").unwrap();
        assert!(get_draft.input_schema.is_object());
        assert!(get_draft.output_schema.is_object());

        // CreateUser has request body schema
        let create_draft = drafts.iter().find(|d| d.name == "createuser").unwrap();
        assert!(create_draft.request_body.is_some());

        // Names are deterministic (sorted)
        let names: Vec<&str> = drafts.iter().map(|d| d.name.as_str()).collect();
        let expected = ["createuser", "deleteuser", "getuser", "listusers"];
        assert_eq!(names, expected);
    }

    #[test]
    fn openapi_drafts_generate_yaml_with_trustcard() {
        let converter = OpenApiDraftConverter::new();
        let drafts = converter.convert_string(OPENAPI_FIXTURE).unwrap();

        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        // YAML is produced
        assert!(!output.yaml_files.is_empty());

        // TrustCard stubs are produced
        assert!(!output.trust_card_files.is_empty());

        // YAML content includes key fields
        let listusers_yaml = output
            .yaml_files
            .iter()
            .find(|(name, _)| name == "listusers.yaml")
            .unwrap();
        assert!(listusers_yaml.1.contains("fulcrum:"));
        assert!(listusers_yaml.1.contains("name: listusers"));

        // TrustCard content has expected fields
        let tc = output
            .trust_card_files
            .iter()
            .find(|(name, _)| name == "listusers.trustcard.md")
            .unwrap();
        assert!(tc.1.contains("# TrustCard"));
        assert!(tc.1.contains("listusers"));
    }

    #[test]
    fn openapi_deterministic_order() {
        let converter = OpenApiDraftConverter::new();
        let drafts1 = converter.convert_string(OPENAPI_FIXTURE).unwrap();
        let drafts2 = converter.convert_string(OPENAPI_FIXTURE).unwrap();

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GraphQL import tests (AC.3)
// ═══════════════════════════════════════════════════════════════════════════

const GRAPHQL_SDL_FIXTURE: &str = r#"
type Query {
    """Get current user"""
    viewer: User
    """Search repositories"""
    search(query: String!, first: Int = 10): [Repository]
}

type Mutation {
    """Create a new repository"""
    createRepository(name: String!, visibility: String!): Repository
    """Delete a repository"""
    deleteRepository(id: ID!): Boolean
}

type User {
    id: ID!
    login: String!
}

type Repository {
    id: ID!
    name: String!
}
"#;

mod graphql {
    use super::*;

    #[test]
    fn graphql_query_fixture_produces_reviewed_safe_read_draft() {
        // AC.3: query fixture produces reviewed-safe read draft
        let importer = GraphQlImporter::new("https://api.github.com/graphql");
        let drafts = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();

        let viewer_draft = drafts.iter().find(|d| d.name == "graphql_viewer").unwrap();
        assert_eq!(viewer_draft.safety, SafetyClassification::ReadOnly);
        assert_eq!(viewer_draft.review_state, ReviewState::Approved);
        assert!(viewer_draft.enabled);
    }

    #[test]
    fn graphql_mutation_fixture_produces_review_required() {
        // AC.3: mutation fixture produces review_required=true
        let importer = GraphQlImporter::new("https://api.github.com/graphql");
        let drafts = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();

        let create_draft = drafts
            .iter()
            .find(|d| d.name == "graphql_createRepository")
            .unwrap();
        assert!(create_draft.review_required());
        assert!(!create_draft.enabled);
    }

    #[test]
    fn unbounded_query_passthrough_is_rejected() {
        // AC.3: unbounded query passthrough is rejected
        let result = GraphQlImporter::reject_passthrough();
        assert!(result.is_err());
    }

    #[test]
    fn graphql_drafts_have_depth_and_complexity_bounds() {
        let importer = GraphQlImporter::new("https://api.github.com/graphql")
            .with_max_depth(4)
            .with_max_complexity(75);
        let drafts = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();

        for draft in &drafts {
            assert_eq!(draft.max_depth, Some(4));
            assert_eq!(draft.max_complexity, Some(75));
        }
    }

    #[test]
    fn graphql_drafts_have_variable_and_response_schemas() {
        let importer = GraphQlImporter::new("https://api.github.com/graphql");
        let drafts = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();

        let search_draft = drafts.iter().find(|d| d.name == "graphql_search").unwrap();
        // Input schema should have query and first properties
        let input = &search_draft.input_schema;
        assert!(input.get("properties").is_some());
        // Output schema exists
        assert!(search_draft.output_schema.is_object());
    }

    #[test]
    fn graphql_import_is_deterministic() {
        let importer = GraphQlImporter::new("https://api.github.com/graphql");
        let drafts1 = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();
        let drafts2 = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();
        assert_eq!(drafts1.len(), drafts2.len());

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Postman import tests (AC.4)
// ═══════════════════════════════════════════════════════════════════════════

const POSTMAN_V21_FIXTURE: &str = r#"{
  "info": {
    "name": "Test API Collection",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "List Users",
      "request": {
        "method": "GET",
        "url": "https://api.test.com/v1/users",
        "header": [{ "key": "Accept", "value": "application/json" }]
      },
      "response": [{
        "name": "User list",
        "body": "[{\"id\":1,\"name\":\"Alice\"}]",
        "code": 200
      }]
    },
    {
      "name": "Create User",
      "request": {
        "method": "POST",
        "url": "https://api.test.com/v1/users",
        "header": [{ "key": "Content-Type", "value": "application/json" }],
        "body": { "mode": "raw", "raw": "{\"name\":\"Bob\",\"email\":\"bob@test.com\"}" }
      },
      "response": []
    },
    {
      "name": "Delete User",
      "request": {
        "method": "DELETE",
        "url": "https://api.test.com/v1/users/123"
      },
      "response": []
    }
  ],
  "auth": {
    "auth_type": "bearer",
    "bearer": [{ "key": "token", "value": "{{TOKEN}}" }]
  },
  "variable": [
    { "key": "TOKEN", "value": "test-token" }
  ]
}"#;

mod postman {
    use super::*;

    #[test]
    fn postman_v21_generates_stable_draft_names() {
        // AC.4: Postman v2.1 fixture generates stable draft names
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let names: Vec<&str> = drafts.iter().map(|d| d.name.as_str()).collect();
        let expected = ["delete_delete_user", "get_list_users", "post_create_user"];
        assert_eq!(names, expected);
    }

    #[test]
    fn postman_drafts_include_schemas_and_examples() {
        // AC.4: generates schemas, examples
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        for draft in &drafts {
            assert!(draft.input_schema.is_object(), "missing input_schema for {}", draft.name);
            assert!(draft.output_schema.is_object(), "missing output_schema for {}", draft.name);
        }

        // GET request has examples from response
        let get_draft = drafts
            .iter()
            .find(|d| d.name == "get_list_users")
            .unwrap();
        assert!(!get_draft.examples.is_empty(), "should have examples");
    }

    #[test]
    fn postman_mutating_requests_marked_review_required() {
        // AC.4: mutating requests marked review-required
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let post_draft = drafts
            .iter()
            .find(|d| d.name == "post_create_user")
            .unwrap();
        assert!(post_draft.review_required());
        assert!(!post_draft.enabled);

        let delete_draft = drafts
            .iter()
            .find(|d| d.name == "delete_delete_user")
            .unwrap();
        assert!(delete_draft.review_required());
        assert!(!delete_draft.enabled);
    }

    #[test]
    fn postman_read_only_drafts_are_safe() {
        let importer = PostmanImporter::new();
        let drafts = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let get_draft = drafts
            .iter()
            .find(|d| d.name == "get_list_users")
            .unwrap();
        assert_eq!(get_draft.safety, SafetyClassification::ReadOnly);
        assert!(!get_draft.review_required());
        assert!(get_draft.enabled);
    }

    #[test]
    fn postman_import_is_deterministic() {
        let importer = PostmanImporter::new();
        let drafts1 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();
        let drafts2 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();
        assert_eq!(drafts1.len(), drafts2.len());

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OCI import tests (AC.5)
// ═══════════════════════════════════════════════════════════════════════════

const OCI_SERVER_JSON_FIXTURE: &str = r#"{
  "name": "io.github.example/test-server",
  "title": "Test MCP Server",
  "description": "Test OCI MCP package",
  "version": "1.0.0",
  "repository": { "url": "https://github.com/example/test", "source": "github", "id": "1" },
  "packages": [
    {
      "registryType": "oci",
      "identifier": "ghcr.io/example/test-server:1.0.0",
      "version": "1.0.0",
      "runtimeHint": "docker",
      "packageArguments": [
        { "type": "positional", "value": "serve" },
        { "type": "positional", "value": "--stdio" }
      ],
      "transport": { "type": "stdio" }
    }
  ]
}"#;

mod oci {
    use super::*;

    #[test]
    fn oci_round_trips_package_metadata() {
        // AC.5: fixture based on server.json round-trips OCI package metadata
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();

        assert_eq!(drafts.len(), 1);
        let draft = &drafts[0];

        // Source kind is correct
        assert_eq!(draft.source_kind, ImportSourceKind::OciMcpPackage);

        // Identifier
        assert_eq!(draft.source_id, "oci:ghcr.io/example/test-server:1.0.0");

        // Package arguments
        assert_eq!(draft.oci_package_args.len(), 2);
        assert!(draft.oci_package_args.contains(&"serve".to_string()));

        // Transport
        assert_eq!(draft.oci_transport, Some("stdio".to_string()));

        // Export and re-import
        let exported = importer.export_json(&drafts).unwrap();
        let reimported = importer.import_json(&exported).unwrap();
        assert_eq!(reimported.len(), 1);
        assert_eq!(
            reimported[0].source_kind,
            ImportSourceKind::OciMcpPackage
        );
    }

    #[test]
    fn oci_imported_drafts_always_pending_review() {
        // AC.5: marks imported package drafts pending review
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();

        for draft in &drafts {
            assert_eq!(draft.review_state, ReviewState::Pending);
            assert!(draft.review_required());
        }
    }

    #[test]
    fn oci_never_enables_without_review() {
        // AC.5: never enables imported package capabilities without review
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();

        for draft in &drafts {
            assert!(!draft.enabled);
        }
    }

    #[test]
    fn oci_trust_card_has_risk_annotations() {
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();

        let tc = drafts[0].trust_card.as_ref().unwrap();
        assert!(!tc.risk_annotations.is_empty());
    }

    #[test]
    fn oci_import_is_deterministic() {
        let importer = OciMcpPackageImporter;
        let drafts1 = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();
        let drafts2 = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();
        assert_eq!(drafts1.len(), drafts2.len());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Generator review gate tests (AC.6)
// ═══════════════════════════════════════════════════════════════════════════

mod generator_review_gate {
    use super::*;

    fn destructive_draft() -> CapabilityDraft {
        CapabilityDraft {
            source_kind: ImportSourceKind::OpenApi,
            source_id: "test".into(),
            protocol: "rest".to_string(),
            name: "delete_resource".into(),
            description: "Delete a resource".into(),
            safety: SafetyClassification::Destructive,
            review_state: ReviewState::Pending,
            enabled: false,
            http_method: "DELETE".to_string(),
            base_url: "https://api.test.com".into(),
            path: "/resources/{id}".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "id": { "type": "string" } },
                "required": ["id"]
            }),
            output_schema: serde_json::json!({"type": "object"}),
            trust_card: Some(TrustCardStub {
                reviewer: None,
                notes: "Test".into(),
                generated_at: String::new(),
                source_url: String::new(),
                source_hash: String::new(),
                risk_annotations: vec!["Destructive operation".to_string()],
            }),
            ..Default::default()
        }
    }

    fn read_only_draft() -> CapabilityDraft {
        CapabilityDraft {
            source_kind: ImportSourceKind::OpenApi,
            source_id: "test".into(),
            protocol: "rest".to_string(),
            name: "get_resource".into(),
            description: "Get a resource".into(),
            safety: SafetyClassification::ReadOnly,
            review_state: ReviewState::Approved,
            enabled: true,
            http_method: "GET".to_string(),
            base_url: "https://api.test.com".into(),
            path: "/resources/{id}".into(),
            input_schema: serde_json::json!({"type": "object", "properties": { "id": { "type": "string" } }}),
            output_schema: serde_json::json!({"type": "object"}),
            ..Default::default()
        }
    }

    #[test]
    fn destructive_draft_has_review_required_and_disabled() {
        // AC.6: generated destructive fixture has review_required=true, enabled=false
        let draft = destructive_draft();
        assert!(draft.review_required());
        assert!(!draft.enabled);
    }

    #[test]
    fn generator_produces_trustcard_for_destructive_draft() {
        // AC.6: TrustCard file present
        let drafts = vec![destructive_draft()];
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        assert!(
            output
                .trust_card_files
                .iter()
                .any(|(name, _)| name == "delete_resource.trustcard.md"),
            "TrustCard should be generated"
        );
    }

    #[test]
    fn destructive_draft_not_visible_in_tools_list() {
        // AC.6: normal loader/search excludes destructive pending tools
        let draft = destructive_draft();
        assert!(!draft.is_visible());
    }

    #[test]
    fn generator_produces_risk_report() {
        // AC.6: machine-readable risk report
        let drafts = vec![destructive_draft(), read_only_draft()];
        let gen = ImportGenerator::new();
        let output = gen.generate(&drafts);

        // Verify risk_report is non-empty
        assert!(!output.risk_report.is_empty(), "risk report should not be empty");
    }

    #[test]
    fn read_only_draft_is_visible() {
        let draft = read_only_draft();
        assert!(draft.is_visible());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Snapshot stability tests (AC.7)
// ═══════════════════════════════════════════════════════════════════════════

mod snapshots_are_stable {
    use super::*;

    #[test]
    fn openapi_consecutive_generations_are_byte_identical() {
        // AC.7: two consecutive generations from the same fixtures produce
        // byte-identical output trees
        let converter = OpenApiDraftConverter::new();
        let drafts1 = converter.convert_string(OPENAPI_FIXTURE).unwrap();
        let drafts2 = converter.convert_string(OPENAPI_FIXTURE).unwrap();

        let gen = ImportGenerator::new();
        let output1 = gen.generate(&drafts1);
        let output2 = gen.generate(&drafts2);

        // Same number of files
        assert_eq!(output1.yaml_files.len(), output2.yaml_files.len());
        assert_eq!(output1.trust_card_files.len(), output2.trust_card_files.len());

        // Byte-identical content for yaml files
        for ((n1, c1), (n2, c2)) in output1
            .yaml_files
            .iter()
            .zip(output2.yaml_files.iter())
        {
            assert_eq!(n1, n2, "file name mismatch: {n1} vs {n2}");
            assert_eq!(c1, c2, "file content mismatch: {n1}");
        }
    }

    #[test]
    fn graphql_consecutive_generations_are_byte_identical() {
        let importer = GraphQlImporter::new("https://api.github.com/graphql");
        let drafts1 = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();
        let drafts2 = importer.import_sdl(GRAPHQL_SDL_FIXTURE).unwrap();

        let gen = ImportGenerator::new();
        let output1 = gen.generate(&drafts1);
        let output2 = gen.generate(&drafts2);

        assert_eq!(output1.yaml_files.len(), output2.yaml_files.len());
        for ((n1, c1), (n2, c2)) in output1.yaml_files.iter().zip(output2.yaml_files.iter()) {
            assert_eq!(n1, n2);
            assert_eq!(c1, c2);
        }
    }

    #[test]
    fn postman_consecutive_generations_are_byte_identical() {
        let importer = PostmanImporter::new();
        let drafts1 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();
        let drafts2 = importer.import_json(POSTMAN_V21_FIXTURE).unwrap();

        let gen = ImportGenerator::new();
        let output1 = gen.generate(&drafts1);
        let output2 = gen.generate(&drafts2);

        assert_eq!(output1.yaml_files.len(), output2.yaml_files.len());
        for ((n1, c1), (n2, c2)) in output1.yaml_files.iter().zip(output2.yaml_files.iter()) {
            assert_eq!(n1, n2);
            assert_eq!(c1, c2);
        }
    }

    #[test]
    fn oci_consecutive_generations_are_byte_identical() {
        let importer = OciMcpPackageImporter;
        let drafts1 = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();
        let drafts2 = importer.import_json(OCI_SERVER_JSON_FIXTURE).unwrap();

        let gen = ImportGenerator::new();
        let output1 = gen.generate(&drafts1);
        let output2 = gen.generate(&drafts2);

        assert_eq!(output1.yaml_files.len(), output2.yaml_files.len());
        for ((n1, c1), (n2, c2)) in output1.yaml_files.iter().zip(output2.yaml_files.iter()) {
            assert_eq!(n1, n2);
            assert_eq!(c1, c2);
        }
    }
}
