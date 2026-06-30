//! Acceptance-criterion test stubs for MIK-6561.
//!
//! - AC.1: MIK-6561.AC.1 AC.1: A `CapabilityDraft` intermediate model exists and normalizes source kind, source identity, protocol, operation name, auth requirements, input/output JSON Schema, examples, safety classification, review state, and TrustCard metadata for OpenAPI, GraphQL, Postman, and OCI inputs. CHECK: file `src/capability/import/draft.rs` contains `pub struct CapabilityDraft` and `pub enum ImportSourceKind` with variants matching `OpenApi|GraphQl|Postman|OciMcpPackage`.
//! - AC.2: MIK-6561.AC.2 AC.2: OpenAPI import is refactored to produce `CapabilityDraft` values before YAML generation, preserving existing auth, parameter, request-body, response-schema, examples, and deterministic operation ordering behavior. CHECK: `cargo test --test openapi_import_tests --test protocol_import_tests openapi` exits 0 (expected: tests assert OpenAPI fixture drafts include auth, schemas, examples, generated YAML, TrustCard stub, and stable snapshot order).
//! - AC.3: MIK-6561.AC.3 AC.3: GraphQL import accepts SDL or introspection JSON and generates bounded query/mutation drafts with explicit max depth, max complexity, variable schema, response schema, and mutation review gates; arbitrary caller-supplied GraphQL query passthrough is disabled unless the draft is reviewed. CHECK: `cargo test --test protocol_import_tests graphql` exits 0 (expected: query fixture produces reviewed-safe read draft, mutation fixture produces `review_required=true`, and unbounded query passthrough is rejected).
//! - AC.4: MIK-6561.AC.4 AC.4: Postman collection import converts collection items, folders, auth, variables, request bodies, tests/examples, and HTTP methods into `CapabilityDraft` records with deterministic names and safety classifications. CHECK: `cargo test --test protocol_import_tests postman` exits 0 (expected: Postman v2.1 fixture generates stable draft names, schemas, examples, and mutating requests marked review-required).
//! - AC.5: MIK-6561.AC.5 AC.5: OCI MCP package import/export prototype reads and writes MCP `server.json` package metadata with `registryType: "oci"`, maps package arguments and transport into draft source metadata, and never enables imported package capabilities without review. CHECK: `cargo test --test protocol_import_tests oci` exits 0 (expected: fixture based on `server.json` round-trips OCI package metadata and marks imported package drafts pending review).
//! - AC.6: MIK-6561.AC.6 AC.6: The generator writes reviewable output containing disabled/pending-review capability YAML, generated test fixtures, examples, TrustCard stubs, and a machine-readable risk report; destructive, mutation, write, delete, or open-world broad tools are not visible to normal `tools/list` until reviewed. CHECK: `cargo test --test protocol_import_tests generator_review_gate` exits 0 (expected: generated destructive/open-world fixture has `review_required=true`, `enabled=false` or equivalent loader-enforced disabled state, TrustCard file present, and normal loader/search excludes it).
//! - AC.7: MIK-6561.AC.7 AC.7: Importer output is deterministic and snapshot-tested across OpenAPI, GraphQL, Postman, and OCI fixtures, including stable file names, YAML key order, sorted risk annotations, and stable TrustCard content. CHECK: `cargo test --test protocol_import_tests snapshots_are_stable` exits 0 (expected: two consecutive generations from the same fixtures produce byte-identical output trees).
//! - AC.8: MIK-6561.AC.8 AC.8: CLI and docs expose the workflow as a review-first import path, including preview/diff mode and explicit approve/apply semantics; legacy `cap import` behavior remains backward-compatible or is documented as a wrapper around the new draft flow. CHECK: file `docs/PROTOCOL_IMPORTS.md` contains `mcp-gateway cap import --format openapi`, `--review`, `--approve`, `TrustCard`, and `pending review`.
//! - AC.9: MIK-6561.AC.9 AC.deploy: Diff merged to main, release built+deployed, post-deploy telemetry confirms active. CHECK: `git log origin/main --grep 'MIK-6561' --oneline` exits 0

/// MIK-6561.AC.1 AC.1: A `CapabilityDraft` intermediate model exists and normalizes source kind, source identity, protocol, operation name, auth requirements, input/output JSON Schema, examples, safety classification, review state, and TrustCard metadata for OpenAPI, GraphQL, Postman, and OCI inputs. CHECK: file `src/capability/import/draft.rs` contains `pub struct CapabilityDraft` and `pub enum ImportSourceKind` with variants matching `OpenApi|GraphQl|Postman|OciMcpPackage`.
#[test]
fn ac_1_mik_6561_ac_1_ac_1_a_capabilitydraft_intermed() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.2 AC.2: OpenAPI import is refactored to produce `CapabilityDraft` values before YAML generation, preserving existing auth, parameter, request-body, response-schema, examples, and deterministic operation ordering behavior. CHECK: `cargo test --test openapi_import_tests --test protocol_import_tests openapi` exits 0 (expected: tests assert OpenAPI fixture drafts include auth, schemas, examples, generated YAML, TrustCard stub, and stable snapshot order).
#[test]
fn ac_2_mik_6561_ac_2_ac_2_openapi_import_is_refactored() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.3 AC.3: GraphQL import accepts SDL or introspection JSON and generates bounded query/mutation drafts with explicit max depth, max complexity, variable schema, response schema, and mutation review gates; arbitrary caller-supplied GraphQL query passthrough is disabled unless the draft is reviewed. CHECK: `cargo test --test protocol_import_tests graphql` exits 0 (expected: query fixture produces reviewed-safe read draft, mutation fixture produces `review_required=true`, and unbounded query passthrough is rejected).
#[test]
fn ac_3_mik_6561_ac_3_ac_3_graphql_import_accepts_sdl_o() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.4 AC.4: Postman collection import converts collection items, folders, auth, variables, request bodies, tests/examples, and HTTP methods into `CapabilityDraft` records with deterministic names and safety classifications. CHECK: `cargo test --test protocol_import_tests postman` exits 0 (expected: Postman v2.1 fixture generates stable draft names, schemas, examples, and mutating requests marked review-required).
#[test]
fn ac_4_mik_6561_ac_4_ac_4_postman_collection_import_co() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.5 AC.5: OCI MCP package import/export prototype reads and writes MCP `server.json` package metadata with `registryType: "oci"`, maps package arguments and transport into draft source metadata, and never enables imported package capabilities without review. CHECK: `cargo test --test protocol_import_tests oci` exits 0 (expected: fixture based on `server.json` round-trips OCI package metadata and marks imported package drafts pending review).
#[test]
fn ac_5_mik_6561_ac_5_ac_5_oci_mcp_package_import_expor() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.6 AC.6: The generator writes reviewable output containing disabled/pending-review capability YAML, generated test fixtures, examples, TrustCard stubs, and a machine-readable risk report; destructive, mutation, write, delete, or open-world broad tools are not visible to normal `tools/list` until reviewed. CHECK: `cargo test --test protocol_import_tests generator_review_gate` exits 0 (expected: generated destructive/open-world fixture has `review_required=true`, `enabled=false` or equivalent loader-enforced disabled state, TrustCard file present, and normal loader/search excludes it).
#[test]
fn ac_6_mik_6561_ac_6_ac_6_the_generator_writes_reviewa() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.7 AC.7: Importer output is deterministic and snapshot-tested across OpenAPI, GraphQL, Postman, and OCI fixtures, including stable file names, YAML key order, sorted risk annotations, and stable TrustCard content. CHECK: `cargo test --test protocol_import_tests snapshots_are_stable` exits 0 (expected: two consecutive generations from the same fixtures produce byte-identical output trees).
#[test]
fn ac_7_mik_6561_ac_7_ac_7_importer_output_is_determini() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.8 AC.8: CLI and docs expose the workflow as a review-first import path, including preview/diff mode and explicit approve/apply semantics; legacy `cap import` behavior remains backward-compatible or is documented as a wrapper around the new draft flow. CHECK: file `docs/PROTOCOL_IMPORTS.md` contains `mcp-gateway cap import --format openapi`, `--review`, `--approve`, `TrustCard`, and `pending review`.
#[test]
fn ac_8_mik_6561_ac_8_ac_8_cli_and_docs_expose_the_work() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

/// MIK-6561.AC.9 AC.deploy: Diff merged to main, release built+deployed, post-deploy telemetry confirms active. CHECK: `git log origin/main --grep 'MIK-6561' --oneline` exits 0
#[test]
fn ac_9_mik_6561_ac_9_ac_deploy_diff_merged_to_main_re() {
    panic!("MIK-6561: pre-seeded stub not implemented");
}

