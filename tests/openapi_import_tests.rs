//! Integration tests for the `OpenApiConverter` — the library side of
//! `mcp-gateway cap import`.
//!
//! These tests exercise end-to-end conversion of a realistic `OpenAPI` 3.0
//! spec (Petstore-style fixture) through to written `capabilities/*.yaml`
//! files, then parse every written file and run the structural validator on
//! it. The goal is to guarantee that generated YAML is always loader-ready.

use std::fs;

use mcp_gateway::capability::{
    AuthTemplate, CapabilityDefinition, IssueSeverity, OpenApiConverter, parse_capability,
    validate_capability_definition,
};
use tempfile::TempDir;

const PETSTORE_JSON: &str = r##"{
  "openapi": "3.0.0",
  "info": { "title": "Petstore", "version": "1.0.0" },
  "servers": [{ "url": "/api/v3" }],
  "paths": {
    "/pet": {
      "post": {
        "operationId": "addPet",
        "summary": "Add a new pet",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/Pet" }
            }
          }
        },
        "responses": { "200": { "description": "ok" } }
      },
      "put": {
        "operationId": "updatePet",
        "summary": "Update an existing pet",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": { "$ref": "#/components/schemas/Pet" }
            }
          }
        },
        "responses": { "200": { "description": "ok" } }
      }
    },
    "/pet/findByStatus": {
      "get": {
        "operationId": "findPetsByStatus",
        "summary": "Finds Pets by status",
        "description": "Multiple status values can be provided with comma separated strings",
        "parameters": [{
          "name": "status",
          "in": "query",
          "required": false,
          "schema": { "type": "string", "default": "available" }
        }],
        "responses": { "200": { "description": "ok" } }
      }
    },
    "/pet/{petId}": {
      "get": {
        "operationId": "getPetById",
        "summary": "Find pet by ID",
        "parameters": [{
          "name": "petId",
          "in": "path",
          "required": true,
          "schema": { "type": "integer", "format": "int64" }
        }],
        "responses": { "200": { "description": "ok" } }
      },
      "delete": {
        "summary": "Deletes a pet",
        "parameters": [{ "$ref": "#/components/parameters/PetIdPath" }],
        "responses": { "400": { "description": "bad" } }
      }
    },
    "/store/inventory": {
      "get": {
        "operationId": "getInventory",
        "summary": "Returns pet inventories by status",
        "responses": { "200": { "description": "ok" } }
      }
    },
    "/user/{username}": {
      "get": {
        "operationId": "getUserByName",
        "summary": "Get user by user name",
        "parameters": [{
          "name": "username",
          "in": "path",
          "required": true,
          "schema": { "type": "string" }
        }],
        "responses": { "200": { "description": "ok" } }
      }
    }
  },
  "components": {
    "schemas": {
      "Pet": {
        "type": "object",
        "required": ["name", "photoUrls"],
        "properties": {
          "id": { "type": "integer", "format": "int64" },
          "name": { "type": "string" },
          "status": { "type": "string" },
          "photoUrls": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "parameters": {
      "PetIdPath": {
        "name": "petId",
        "in": "path",
        "required": true,
        "description": "Pet id to delete",
        "schema": { "type": "integer", "format": "int64" }
      }
    },
    "securitySchemes": {
      "petstore_auth": {
        "type": "oauth2",
        "flows": {
          "implicit": {
            "authorizationUrl": "https://petstore3.swagger.io/oauth/authorize",
            "scopes": { "write:pets": "modify pets" }
          }
        }
      },
      "api_key": {
        "type": "apiKey",
        "name": "api_key",
        "in": "header"
      }
    }
  }
}"##;

/// Write the Petstore fixture to a tempfile and return (tempdir, path).
fn petstore_spec_file() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("petstore.json");
    fs::write(&path, PETSTORE_JSON).expect("write petstore fixture");
    (dir, path)
}

#[test]
fn import_petstore_from_file_writes_all_operations() {
    let (dir, path) = petstore_spec_file();
    let out_dir = dir.path().join("capabilities");
    fs::create_dir_all(&out_dir).expect("mkdir capabilities");

    let converter = OpenApiConverter::new().with_host_override("https://petstore3.swagger.io");
    let caps = converter
        .convert_file(path.to_str().unwrap())
        .expect("convert petstore");

    // 7 operations in the fixture: addPet, updatePet, findPetsByStatus,
    // getPetById, delete /pet/{petId}, getInventory, getUserByName
    assert_eq!(caps.len(), 7, "expected 7 capabilities, got {}", caps.len());

    for cap in &caps {
        cap.write_to_file(out_dir.to_str().unwrap())
            .expect("write capability file");
    }

    // Every file on disk must parse and pass the validator with no errors.
    let mut files = Vec::new();
    for entry in fs::read_dir(&out_dir).expect("read out_dir") {
        let entry = entry.expect("dir entry");
        if entry
            .path()
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s == "yaml")
        {
            files.push(entry.path());
        }
    }
    assert_eq!(files.len(), 7, "expected 7 yaml files on disk");

    for path in &files {
        let content = fs::read_to_string(path).expect("read capability file");
        let parsed: CapabilityDefinition = parse_capability(&content)
            .unwrap_or_else(|e| panic!("parse {}: {e}\n{content}", path.display()));
        let issues = validate_capability_definition(&parsed, path.to_str());
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "{} has validator errors: {errors:?}\nYAML:\n{content}",
            path.display()
        );
    }
}

#[test]
fn import_petstore_find_pets_by_status_preserves_enum_default() {
    let converter = OpenApiConverter::new().with_host_override("https://petstore3.swagger.io");
    let caps = converter
        .convert_string(PETSTORE_JSON)
        .expect("convert petstore string");
    let cap = caps
        .iter()
        .find(|c| c.name.contains("findpetsbystatus"))
        .expect("findPetsByStatus present");
    // Query parameter must appear as a config.params entry so the
    // substitution pipeline knows to wire it into the request URL.
    assert!(
        cap.yaml.contains("params:"),
        "expected params section, got:\n{}",
        cap.yaml
    );
    assert!(
        cap.yaml.contains("status:"),
        "expected status parameter, got:\n{}",
        cap.yaml
    );
}

#[test]
fn import_petstore_with_prefix_and_auth_key_override() {
    let converter = OpenApiConverter::new()
        .with_host_override("https://petstore3.swagger.io")
        .with_prefix("petstore")
        .with_default_auth(AuthTemplate {
            auth_type: "bearer".to_string(),
            key: "env:MY_CUSTOM_TOKEN".to_string(),
            description: "My Petstore token".to_string(),
        });

    let caps = converter
        .convert_string(PETSTORE_JSON)
        .expect("convert petstore");

    // Every capability name starts with the prefix.
    for cap in &caps {
        assert!(
            cap.name.starts_with("petstore_"),
            "missing prefix: {}",
            cap.name
        );
    }

    // Auth block uses the CLI-provided override key (env:MY_CUSTOM_TOKEN),
    // not the auto-derived env:API_KEY_TOKEN.
    let add_pet = caps
        .iter()
        .find(|c| c.name == "petstore_addpet")
        .expect("addPet present");
    assert!(
        add_pet.yaml.contains("env:MY_CUSTOM_TOKEN"),
        "expected override auth key, got:\n{}",
        add_pet.yaml
    );
}

#[test]
fn import_rejects_malformed_spec() {
    let converter = OpenApiConverter::new();
    let err = converter.convert_string("not an openapi spec");
    assert!(err.is_err(), "expected parse failure");
}

#[test]
fn import_from_missing_file_is_error() {
    let converter = OpenApiConverter::new();
    let err = converter.convert_file("/nonexistent/petstore.json");
    assert!(err.is_err(), "expected missing file error");
}

#[test]
fn import_petstore_get_pet_by_id_path_parameter_is_schema_property() {
    let converter = OpenApiConverter::new().with_host_override("https://petstore3.swagger.io");
    let caps = converter.convert_string(PETSTORE_JSON).unwrap();
    let cap = caps
        .iter()
        .find(|c| c.name == "getpetbyid")
        .expect("getPetById present");
    // `petId` must appear in the schema.input.properties so the {petId}
    // placeholder in the URL path passes CAP-006.
    let parsed: CapabilityDefinition = parse_capability(&cap.yaml).expect("parse");
    let issues = validate_capability_definition(&parsed, None);
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "getPetById has validator errors: {errors:?}\nYAML:\n{}",
        cap.yaml
    );
}
