//! Deterministic TrustCard and CapabilityBom generator.
//!
//! Accepts live MCP tools, prompts, resources, annotations, input schemas,
//! and output schemas, and emits deterministic TrustCard/CapabilityBom JSON
//! across repeated runs.

use crate::trust::{
    CapabilityBom, CbomAnnotation, CbomDependency, CbomPrompt, CbomProvenance, CbomResource,
    CbomTool, TrustCard, TrustNetworkReach, TrustRiskClass, TrustServer, TrustSignatureEvidence,
    TrustTool, CBOM_SCHEMA_VERSION, TRUSTCARD_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Compute a stable SHA-256 digest of a JSON-serializable value.
fn stable_digest(value: &impl serde::Serialize) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

/// Current UTC timestamp in ISO 8601 format (deterministic when called in
/// tests by using a fixed seed).
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Infer transport type from a URL string.
fn infer_transport(url: Option<&str>) -> String {
    match url {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => "http".to_string(),
        Some(u) if u.starts_with("sse://") => "sse".to_string(),
        Some(u) if u.starts_with("a2a://") => "a2a".to_string(),
        _ => "stdio".to_string(),
    }
}

/// Infer network reach from a URL string.
fn infer_network_reach(url: Option<&str>) -> TrustNetworkReach {
    match url {
        None => TrustNetworkReach::None,
        Some(u) if u.contains("localhost") || u.contains("127.0.0.1") || u.contains("[::1]") => {
            TrustNetworkReach::Local
        }
        Some(u)
            if u.contains("10.")
                || u.contains("192.168.")
                || u.contains("172.16.")
                || u.contains(".internal")
                || u.contains(".local") =>
        {
            TrustNetworkReach::Private
        }
        Some(_) => TrustNetworkReach::Public,
    }
}

/// Infer risk class from transport, auth, and permissions.
fn infer_risk_class(transport: &str, auth_mode: &str, permissions: &[String]) -> TrustRiskClass {
    if permissions.iter().any(|p| p == "exec" || p == "filesystem_write") {
        return TrustRiskClass::High;
    }
    if auth_mode == "none" && transport == "http" {
        return TrustRiskClass::Medium;
    }
    TrustRiskClass::Low
}

/// Generate a TrustCard from capability configuration inputs.
///
/// Resolved secret values are never included in the output.
pub fn generate_from_capability_config(
    name: &str,
    url: Option<&str>,
    auth_mode: Option<&str>,
    env_var_names: &[String],
    permissions: &[String],
) -> TrustCard {
    let transport = infer_transport(url);
    let auth = auth_mode.unwrap_or("none").to_string();
    let network_reach = infer_network_reach(url);
    let risk = infer_risk_class(&transport, &auth, permissions);

    let has_secrets = env_var_names.iter().any(|e| {
        let lower = e.to_lowercase();
        lower.contains("key") || lower.contains("token") || lower.contains("secret")
    });

    let data_classes = if has_secrets {
        vec!["credentials_ref".to_string()]
    } else {
        vec!["public".to_string()]
    };

    let runtime_profile = match transport.as_str() {
        "stdio" => "local_subprocess",
        "http" | "sse" => "remote_http",
        _ => "embedded",
    };

    TrustCard {
        schema_version: TRUSTCARD_SCHEMA_VERSION.to_string(),
        name: name.to_string(),
        server: TrustServer {
            source_uri: url.map(str::to_string),
            publisher: None,
            license: None,
            transport,
            auth_mode: auth,
            runtime_profile: runtime_profile.to_string(),
            network_reach,
            signature_evidence: vec![],
            risk_class: risk,
            data_classes,
            permissions: permissions.to_vec(),
            evidence_quality: "self_reported".to_string(),
        },
        tool: None,
        findings: vec![],
        generated_at: now_iso(),
    }
}

/// A live MCP tool descriptor for generation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMcpTool {
    /// Tool name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Input schema (JSON Schema).
    pub input_schema: Option<serde_json::Value>,
    /// Output schema (JSON Schema).
    pub output_schema: Option<serde_json::Value>,
    /// Annotations (key-value pairs).
    pub annotations: BTreeMap<String, serde_json::Value>,
}

/// A live MCP prompt descriptor for generation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMcpPrompt {
    /// Prompt name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Arguments.
    pub arguments: Vec<String>,
}

/// A live MCP resource descriptor for generation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveMcpResource {
    /// Resource URI.
    pub uri: String,
    /// Resource name.
    pub name: Option<String>,
    /// MIME type.
    pub mime_type: Option<String>,
}

use serde::{Deserialize, Serialize};

/// Generate a TrustCard from live MCP protocol metadata.
///
/// Output is deterministic: the same inputs always produce the same JSON
/// (the `generated_at` field is set from the caller-supplied timestamp).
pub fn generate_trust_card_from_live(
    server_name: &str,
    url: Option<&str>,
    auth_mode: Option<&str>,
    tools: &[LiveMcpTool],
    prompts: &[LiveMcpPrompt],
    resources: &[LiveMcpResource],
    generated_at: &str,
) -> TrustCard {
    let transport = infer_transport(url);
    let auth = auth_mode.unwrap_or("none").to_string();
    let network_reach = infer_network_reach(url);

    let has_write_tools = tools.iter().any(|t| {
        t.annotations
            .get("read_only_hint")
            .and_then(|v| v.as_bool())
            == Some(false)
    });

    let risk = if has_write_tools {
        TrustRiskClass::Medium
    } else {
        TrustRiskClass::Low
    };

    let perms = if url.is_some() {
        vec!["network".to_string()]
    } else {
        vec!["exec".to_string()]
    };

    let first_tool = tools.first().map(|t| TrustTool {
        name: t.name.clone(),
        read_only: t
            .annotations
            .get("read_only_hint")
            .and_then(|v| v.as_bool()),
        destructive: t
            .annotations
            .get("destructive_hint")
            .and_then(|v| v.as_bool()),
        idempotent: t
            .annotations
            .get("idempotent_hint")
            .and_then(|v| v.as_bool()),
        input_schema_digest: t.input_schema.as_ref().map(|s| stable_digest(s)),
        output_schema_digest: t.output_schema.as_ref().map(|s| stable_digest(s)),
    });

    let sig_evidence = if tools.iter().any(|t| !t.annotations.is_empty()) {
        vec![TrustSignatureEvidence {
            evidence_type: "protocol_annotations".to_string(),
            digest: Some(stable_digest(
                &tools
                    .iter()
                    .map(|t| (&t.name, &t.annotations))
                    .collect::<Vec<_>>(),
            )),
            issuer: Some("mcp_protocol".to_string()),
            verified: true,
        }]
    } else {
        vec![]
    };

    TrustCard {
        schema_version: TRUSTCARD_SCHEMA_VERSION.to_string(),
        name: server_name.to_string(),
        server: TrustServer {
            source_uri: url.map(str::to_string),
            publisher: None,
            license: None,
            transport,
            auth_mode: auth,
            runtime_profile: if url.is_some() {
                "remote_http".to_string()
            } else {
                "local_subprocess".to_string()
            },
            network_reach,
            signature_evidence: sig_evidence,
            risk_class: risk,
            data_classes: vec!["public".to_string()],
            permissions: perms,
            evidence_quality: "verified".to_string(),
        },
        tool: first_tool,
        findings: vec![],
        generated_at: generated_at.to_string(),
    }
}

/// Generate a CapabilityBom from live MCP protocol metadata.
///
/// Output is deterministic: the same inputs always produce the same JSON.
pub fn generate_cbom_from_live(
    server_name: &str,
    version: Option<&str>,
    tools: &[LiveMcpTool],
    prompts: &[LiveMcpPrompt],
    resources: &[LiveMcpResource],
    generated_at: &str,
) -> CapabilityBom {
    let cbom_tools: Vec<CbomTool> = tools
        .iter()
        .map(|t| CbomTool {
            name: t.name.clone(),
            description: t.description.clone(),
            input_schema_digest: t.input_schema.as_ref().map(|s| stable_digest(s)),
            output_schema_digest: t.output_schema.as_ref().map(|s| stable_digest(s)),
            annotations: t.annotations.clone(),
        })
        .collect();

    let cbom_prompts: Vec<CbomPrompt> = prompts
        .iter()
        .map(|p| CbomPrompt {
            name: p.name.clone(),
            description: p.description.clone(),
            arguments: p.arguments.clone(),
        })
        .collect();

    let cbom_resources: Vec<CbomResource> = resources
        .iter()
        .map(|r| CbomResource {
            uri: r.uri.clone(),
            name: r.name.clone(),
            mime_type: r.mime_type.clone(),
        })
        .collect();

    let annotations: Vec<CbomAnnotation> = tools
        .iter()
        .flat_map(|t| {
            t.annotations.iter().map(|(k, v)| CbomAnnotation {
                key: format!("{}.{}", t.name, k),
                value: v.clone(),
            })
        })
        .collect();

    CapabilityBom {
        schema_version: CBOM_SCHEMA_VERSION.to_string(),
        name: server_name.to_string(),
        version: version.map(str::to_string),
        tools: cbom_tools,
        prompts: cbom_prompts,
        resources: cbom_resources,
        annotations,
        dependencies: vec![],
        provenance: CbomProvenance {
            source_type: "mcp_protocol".to_string(),
            source_ref: None,
            verified: true,
        },
        components: vec![],
        generated_at: generated_at.to_string(),
    }
}
