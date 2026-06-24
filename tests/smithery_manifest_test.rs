//! Smithery manifest + directory distribution validation tests.
//!
//! AC.3: Smithery manifest added to repo if applicable
//! AC.2: Glama listing verified and updated
//! AC.1: mcp.so submission sent (draft text verified present in docs)

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(relative: &str) -> String {
    let path = repo_root().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

// ---------------------------------------------------------------------------
// Smithery manifest schema (subset we validate)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SmitheryManifest {
    #[serde(rename = "startCommand")]
    start_command: StartCommand,
}

#[derive(Debug, Deserialize)]
struct StartCommand {
    #[serde(rename = "type")]
    transport_type: String,
    #[serde(rename = "configSchema")]
    config_schema: serde_yaml::Value,
    #[serde(rename = "commandFunction")]
    command_function: String,
}

fn load_smithery_manifest() -> SmitheryManifest {
    let raw = read_repo_file("smithery.yaml");
    serde_yaml::from_str(&raw).expect("smithery.yaml should be valid YAML")
}

// ---------------------------------------------------------------------------
// AC.3: Smithery manifest added to repo if applicable
// ---------------------------------------------------------------------------

/// AC.3 (verbatim): "Smithery manifest added to repo if applicable"
/// Asserts: smithery.yaml exists at repo root and is a valid Smithery manifest
/// with all required fields populated correctly.
#[test]
fn ac3_smithery_manifest_exists_and_is_valid() {
    let manifest = load_smithery_manifest();

    // Transport must be stdio — the gateway speaks MCP JSON-RPC over stdin/stdout.
    assert_eq!(
        manifest.start_command.transport_type, "stdio",
        "startCommand.type must be 'stdio' for MCP stdio transport"
    );

    // configSchema must be a JSON Schema object with type: object.
    let schema = &manifest.start_command.config_schema;
    let schema_type = schema
        .get("type")
        .and_then(|v| v.as_str())
        .expect("configSchema.type must be present");
    assert_eq!(
        schema_type, "object",
        "configSchema.type must be 'object' per Smithery schema spec"
    );
}

/// AC.3 (continuation): The commandFunction must be a valid JS arrow function
/// string (not a YAML array), returning { command, args, env }.
#[test]
fn ac3_smithery_command_function_is_js_arrow() {
    let manifest = load_smithery_manifest();
    let func = &manifest.start_command.command_function;

    // Must be a JS arrow function, not a YAML array.
    assert!(
        func.contains("=>"),
        "commandFunction must be a JS arrow function string (got: {func:?})"
    );

    // Must reference the mcp-gateway binary.
    assert!(
        func.contains("mcp-gateway"),
        "commandFunction must reference 'mcp-gateway' binary"
    );

    // Must include --stdio flag for MCP stdio transport.
    assert!(
        func.contains("--stdio"),
        "commandFunction must pass --stdio for MCP stdio mode"
    );

    // Must return command, args, and env keys.
    assert!(
        func.contains("command") && func.contains("args") && func.contains("env"),
        "commandFunction must return {{ command, args, env }}"
    );
}

/// AC.3 (continuation): The configSchema exposes an optional configFile field
/// so users can point at their own gateway.yaml.
#[test]
fn ac3_smithery_config_schema_exposes_config_file() {
    let manifest = load_smithery_manifest();
    let schema = &manifest.start_command.config_schema;

    let properties = schema
        .get("properties")
        .and_then(|v| v.as_mapping())
        .expect("configSchema.properties must be a mapping");

    assert!(
        properties.contains_key(&serde_yaml::Value::String("configFile".into())),
        "configSchema.properties must include 'configFile' for gateway.yaml path"
    );

    let config_file = &properties[&serde_yaml::Value::String("configFile".into())];
    let cf_type = config_file
        .get("type")
        .and_then(|v| v.as_str())
        .expect("configFile must have a type");
    assert_eq!(cf_type, "string", "configFile type must be 'string'");
}

// ---------------------------------------------------------------------------
// AC.2: Glama listing verified and updated
// ---------------------------------------------------------------------------

/// AC.2 (verbatim): "Glama listing verified and updated"
/// Asserts: README.md contains valid Glama badges pointing to the correct
/// repository listing.
#[test]
fn ac2_glama_listing_verified_in_readme() {
    let readme = read_repo_file("README.md");

    // Glama server badge must be present and point to the correct listing.
    assert!(
        readme.contains("glama.ai/mcp/servers/MikkoParkkola/mcp-gateway"),
        "README must contain Glama listing link for MikkoParkkola/mcp-gateway"
    );

    // Quality score badge must also be present.
    assert!(
        readme.contains("glama.ai/mcp/servers/MikkoParkkola/mcp-gateway/badges/score"),
        "README must contain Glama quality score badge"
    );
}

/// AC.2 (continuation): README includes Smithery badge after Glama verification.
#[test]
fn ac2_smithery_badge_added_to_readme() {
    let readme = read_repo_file("README.md");

    assert!(
        readme.contains("smithery.ai/badge/mcp-gateway"),
        "README must contain Smithery badge for mcp-gateway"
    );
}

// ---------------------------------------------------------------------------
// AC.1: mcp.so submission sent
// ---------------------------------------------------------------------------

/// AC.1 (verbatim): "mcp.so submission sent"
/// Asserts: The docs/DISTRIBUTION.md file exists and contains the mcp.so
/// submission draft text ready for manual submission.
/// Note: The actual browser submission is a manual operator action; this test
/// verifies the draft text is present and complete in the repo.
#[test]
fn ac1_mcp_so_submission_draft_exists_in_docs() {
    let dist_docs = read_repo_file("docs/DISTRIBUTION.md");

    // Must contain the mcp.so section with submission draft.
    assert!(
        dist_docs.contains("mcp.so"),
        "docs/DISTRIBUTION.md must reference mcp.so directory"
    );

    // Must contain a draft with the required submission fields.
    assert!(
        dist_docs.contains("Server Name:") && dist_docs.contains("MCP Gateway"),
        "docs/DISTRIBUTION.md must contain mcp.so submission draft with Server Name"
    );

    assert!(
        dist_docs.contains("Repository:")
            && dist_docs.contains("github.com/MikkoParkkola/mcp-gateway"),
        "docs/DISTRIBUTION.md must contain mcp.so submission draft with Repository URL"
    );

    assert!(
        dist_docs.contains("Description:"),
        "docs/DISTRIBUTION.md must contain mcp.so submission draft with Description"
    );

    assert!(
        dist_docs.contains("Install:"),
        "docs/DISTRIBUTION.md must contain mcp.so submission draft with Install instructions"
    );
}

/// AC.1 (continuation): Distribution docs cover all three directories.
#[test]
fn ac1_distribution_docs_cover_all_directories() {
    let dist_docs = read_repo_file("docs/DISTRIBUTION.md");

    for directory in &["Smithery", "Glama", "mcp.so"] {
        assert!(
            dist_docs.contains(directory),
            "docs/DISTRIBUTION.md must document the {directory} directory"
        );
    }
}
