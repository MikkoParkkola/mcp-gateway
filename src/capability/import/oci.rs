//! OCI MCP package import/export prototype — reads and writes MCP
//! `server.json` package metadata with `registryType: "oci"`, maps
//! package arguments and transport into draft source metadata, and
//! never enables imported package capabilities without review.

use std::collections::HashMap;

use crate::{Error, Result};

use super::draft::{
    CapabilityDraft, DraftAuth, ImportSourceKind, ReviewState, SafetyClassification, TrustCardStub,
};

/// Importer/Exporter for OCI MCP packages (`server.json`).
pub struct OciMcpPackageImporter;

/// Parsed OCI MCP package metadata from `server.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciPackageMetadata {
    /// Package name (e.g. `io.github.MikkoParkkola/mcp-gateway`).
    #[serde(default)]
    pub name: String,
    /// Human-readable title.
    #[serde(default)]
    pub title: String,
    /// Description.
    #[serde(default)]
    pub description: String,
    /// Version string.
    #[serde(default)]
    pub version: String,
    /// Packages array.
    #[serde(default)]
    pub packages: Vec<OciPackageEntry>,
    /// Repository URL.
    #[serde(default)]
    pub repository_url: Option<String>,
}

/// A single OCI package entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciPackageEntry {
    /// Registry type (e.g. "oci").
    #[serde(default)]
    pub registry_type: String,
    /// Package identifier (e.g. `ghcr.io/...`).
    #[serde(default)]
    pub identifier: String,
    /// Version of this package.
    #[serde(default)]
    pub version: String,
    /// Runtime hint (e.g. "docker").
    #[serde(default)]
    pub runtime_hint: Option<String>,
    /// Package arguments.
    #[serde(default)]
    pub package_arguments: Vec<OciPackageArgument>,
    /// Transport configuration.
    #[serde(default)]
    pub transport: Option<OciTransport>,
}

/// A package argument.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciPackageArgument {
    /// Argument type (positional, named, env).
    #[serde(default)]
    pub arg_type: String,
    /// Argument value.
    #[serde(default)]
    pub value: String,
}

/// Transport configuration for an OCI package.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciTransport {
    /// Transport type (stdio, sse, streamable).
    #[serde(default)]
    pub transport_type: String,
    /// Additional transport configuration.
    #[serde(default)]
    pub config: HashMap<String, String>,
}

impl OciMcpPackageImporter {
    /// Import OCI MCP package metadata from a `server.json` string.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON cannot be parsed.
    pub fn import_json(&self, json: &str) -> Result<Vec<CapabilityDraft>> {
        let metadata: OciPackageMetadata = serde_json::from_str(json).map_err(|e| {
            Error::Config(format!("Failed to parse server.json: {e}"))
        })?;

        let mut drafts = Vec::new();

        for package in &metadata.packages {
            if package.registry_type != "oci" {
                continue;
            }

            let source_id = format!("oci:{}", package.identifier);

            // Build package arguments as strings
            let pkg_args: Vec<String> = package
                .package_arguments
                .iter()
                .map(|a| {
                    if a.arg_type == "positional" {
                        a.value.clone()
                    } else {
                        format!("--{}={}", a.arg_type, a.value)
                    }
                })
                .collect();

            let transport_type = package
                .transport
                .as_ref()
                .map(|t| t.transport_type.clone());

            let description = format!(
                "OCI MCP package: {} v{} — {}. Review required before activation.",
                metadata.title,
                package.version,
                metadata.description
            );

            let trust_card = TrustCardStub {
                reviewer: None,
                notes: format!(
                    "Auto-generated from OCI MCP package manifest.\nIdentifier: {}\nRegistry: oci\nRuntime: {}",
                    package.identifier,
                    package.runtime_hint.as_deref().unwrap_or("unknown")
                ),
                generated_at: String::new(),
                source_url: metadata
                    .repository_url
                    .clone()
                    .unwrap_or_else(|| package.identifier.clone()),
                source_hash: String::new(),
                risk_annotations: vec![
                    "OCI MCP package import — ALWAYS requires review before activation"
                        .to_string(),
                    format!("Transport: {}", transport_type.as_deref().unwrap_or("unknown")),
                    format!("Runtime: {}", package.runtime_hint.as_deref().unwrap_or("unknown")),
                ],
            };

            let draft = CapabilityDraft {
                source_kind: ImportSourceKind::OciMcpPackage,
                source_id,
                protocol: "rest".to_string(),
                name: sanitize_name(&metadata.name),
                description,
                auth: DraftAuth::default(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: serde_json::json!({"type": "object"}),
                examples: Vec::new(),
                safety: SafetyClassification::OpenWorld,
                // AC.5: never enables imported package capabilities without review
                review_state: ReviewState::Pending,
                enabled: false,
                trust_card: Some(trust_card),
                base_url: package.identifier.clone(),
                path: String::new(),
                auth_required: false,
                oci_package_args: pkg_args,
                oci_transport: transport_type,
                tags: vec!["oci-mcp-package".to_string(), "imported".to_string()],
                ..Default::default()
            };

            drafts.push(draft);
        }

        // Stable sort by name
        drafts.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(drafts)
    }

    /// Export a `CapabilityDraft` back to OCI package metadata JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the draft is not an OCI MCP package draft.
    pub fn export_json(&self, drafts: &[CapabilityDraft]) -> Result<String> {
        let mut packages = Vec::new();

        for draft in drafts {
            if draft.source_kind != ImportSourceKind::OciMcpPackage {
                continue;
            }

            let mut pkg_args = Vec::new();
            for arg in &draft.oci_package_args {
                pkg_args.push(OciPackageArgument {
                    arg_type: "positional".to_string(),
                    value: arg.clone(),
                });
            }

            let transport = draft.oci_transport.as_ref().map(|t| OciTransport {
                transport_type: t.clone(),
                config: HashMap::new(),
            });

            packages.push(OciPackageEntry {
                registry_type: "oci".to_string(),
                identifier: draft.base_url.clone(),
                version: "1.0.0".to_string(),
                runtime_hint: Some("docker".to_string()),
                package_arguments: pkg_args,
                transport,
            });
        }

        let metadata = OciPackageMetadata {
            name: "exported-package".to_string(),
            title: "Exported OCI MCP Package".to_string(),
            description: "Exported from mcp-gateway".to_string(),
            version: "1.0.0".to_string(),
            packages,
            repository_url: None,
        };

        serde_json::to_string_pretty(&metadata)
            .map_err(|e| Error::Config(format!("Failed to serialize OCI metadata: {e}")))
    }
}

/// Sanitize a name for use as a capability name.
fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_JSON_FIXTURE: &str = r#"{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.github.example/test-server",
  "title": "Test MCP Server",
  "description": "A test MCP server for OCI import testing",
  "repository": {
    "url": "https://github.com/example/test-server",
    "source": "github",
    "id": "123456"
  },
  "websiteUrl": "https://github.com/example/test-server#readme",
  "version": "1.0.0",
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
      "transport": {
        "type": "stdio"
      }
    }
  ]
}"#;

    #[test]
    fn import_oci_package_metadata() {
        // AC.5: fixture based on server.json round-trips OCI package metadata
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(SERVER_JSON_FIXTURE).unwrap();

        assert_eq!(drafts.len(), 1);
        let draft = &drafts[0];

        assert_eq!(draft.source_kind, ImportSourceKind::OciMcpPackage);
        assert_eq!(draft.source_id, "oci:ghcr.io/example/test-server:1.0.0");
        assert_eq!(draft.safety, SafetyClassification::OpenWorld);
        // AC.5: marks imported package drafts pending review
        assert_eq!(draft.review_state, ReviewState::Pending);
        assert!(!draft.enabled);
        assert!(draft.review_required());

        // Package arguments are mapped
        assert_eq!(draft.oci_package_args.len(), 2);
        assert!(draft.oci_package_args.contains(&"serve".to_string()));
        assert!(draft.oci_package_args.contains(&"--stdio".to_string()));

        // Transport is mapped
        assert_eq!(draft.oci_transport, Some("stdio".to_string()));

        // TrustCard exists
        assert!(draft.trust_card.is_some());
    }

    #[test]
    fn oci_draft_never_enabled_without_review() {
        // AC.5: never enables imported package capabilities without review
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(SERVER_JSON_FIXTURE).unwrap();

        for draft in &drafts {
            assert!(
                !draft.enabled,
                "OCI draft '{}' must not be enabled without review",
                draft.name
            );
            assert!(draft.review_required());
        }
    }

    #[test]
    fn import_non_oci_packages_are_skipped() {
        let json = r#"{
          "name": "test",
          "title": "Test",
          "description": "Test",
          "version": "1.0.0",
          "packages": [
            { "registryType": "npm", "identifier": "test-pkg", "version": "1.0.0", "packageArguments": [], "transport": { "type": "stdio" } },
            { "registryType": "oci", "identifier": "ghcr.io/test:1.0.0", "version": "1.0.0", "packageArguments": [], "transport": { "type": "stdio" } }
          ]
        }"#;

        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(json).unwrap();

        // Only the OCI package should be imported
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].source_kind, ImportSourceKind::OciMcpPackage);
    }

    #[test]
    fn oci_round_trip_export_import() {
        // AC.5: round-trips OCI package metadata
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(SERVER_JSON_FIXTURE).unwrap();

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
    fn oci_import_is_deterministic() {
        let importer = OciMcpPackageImporter;
        let drafts1 = importer.import_json(SERVER_JSON_FIXTURE).unwrap();
        let drafts2 = importer.import_json(SERVER_JSON_FIXTURE).unwrap();

        let names1: Vec<&str> = drafts1.iter().map(|d| d.name.as_str()).collect();
        let names2: Vec<&str> = drafts2.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names1, names2);
    }

    #[test]
    fn oci_trust_card_has_risk_annotations() {
        let importer = OciMcpPackageImporter;
        let drafts = importer.import_json(SERVER_JSON_FIXTURE).unwrap();

        let tc = drafts[0].trust_card.as_ref().unwrap();
        assert!(
            !tc.risk_annotations.is_empty(),
            "TrustCard must have risk annotations"
        );
        assert!(
            tc.risk_annotations
                .iter()
                .any(|r| r.contains("ALWAYS requires review")),
            "Must warn about review requirement"
        );
    }
}
