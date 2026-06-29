use std::collections::BTreeMap;

use serde_json::Value;

use crate::config::{BackendConfig, Config, TransportConfig};
use crate::protocol::{Prompt, Resource, Tool};
use crate::registry::server_registry;

use super::schema::*;

pub fn generate_trust_card(
    backend_name: &str,
    backend: &BackendConfig,
    config: &Config,
) -> TrustCard {
    let registry_entry = server_registry::lookup(backend_name);
    let transport = build_transport_info(backend, registry_entry);
    let source = build_source_info(backend_name, registry_entry);
    let owner = build_owner_info(registry_entry);
    let license = LicenseInfo {
        spdx: None,
        url: None,
    };
    let runtime = build_runtime_info(registry_entry);
    let permissions = build_permissions(backend);
    let data_classes = Vec::new();
    let credential_needs = build_credential_needs(backend, registry_entry);
    let network_reach = build_network_reach(backend);
    let signature = build_signature_evidence(backend_name, config);
    let provenance = build_provenance_evidence(backend_name, config);
    let findings = Vec::new();
    let risk_verdict = RiskVerdict {
        level: "unknown".to_string(),
        findings,
        policy_allows: true,
    };

    TrustCard {
        schema_version: TRUST_SCHEMA_VERSION.to_string(),
        subject: TrustSubject {
            name: backend_name.to_string(),
            kind: "mcp-server".to_string(),
            version: None,
            description: backend.description.clone(),
        },
        source,
        owner,
        license,
        transport,
        runtime,
        permissions,
        data_classes,
        credential_needs,
        network_reach,
        signature,
        provenance,
        risk_verdict,
    }
}

pub fn generate_cbom(
    backend_name: &str,
    backend: &BackendConfig,
    config: &Config,
    tools: &[Tool],
    prompts: &[Prompt],
    resources: &[Resource],
) -> Cbom {
    let registry_entry = server_registry::lookup(backend_name);
    let cbom_tools: Vec<CbomTool> = tools
        .iter()
        .map(|t| CbomTool {
            name: t.name.clone(),
            title: t.title.clone(),
            description: t.description.clone(),
            input_schema: t.input_schema.clone(),
            output_schema: t.output_schema.clone(),
            annotations: t.annotations.as_ref().map(|a| {
                serde_json::to_value(a).unwrap_or_default()
            }),
            role: t.role.as_ref().map(|r| format!("{r:?}")),
        })
        .collect();

    let cbom_prompts: Vec<CbomPrompt> = prompts
        .iter()
        .map(|p| CbomPrompt {
            name: p.name.clone(),
            title: p.title.clone(),
            description: p.description.clone(),
            arguments: p
                .arguments
                .iter()
                .map(|a| CbomPromptArgument {
                    name: a.name.clone(),
                    description: a.description.clone(),
                    required: a.required,
                })
                .collect(),
        })
        .collect();

    let cbom_resources: Vec<CbomResource> = resources
        .iter()
        .map(|r| CbomResource {
            uri: r.uri.clone(),
            name: r.name.clone(),
            title: r.title.clone(),
            description: r.description.clone(),
            mime_type: r.mime_type.clone(),
        })
        .collect();

    let permissions = build_permissions(backend);
    let provenance = build_provenance_evidence(backend_name, config);
    let signature = build_signature_evidence(backend_name, config);

    Cbom {
        schema_version: TRUST_SCHEMA_VERSION.to_string(),
        subject: TrustSubject {
            name: backend_name.to_string(),
            kind: "mcp-server".to_string(),
            version: None,
            description: backend.description.clone(),
        },
        tools: cbom_tools,
        prompts: cbom_prompts,
        resources: cbom_resources,
        annotations: BTreeMap::new(),
        dependencies: build_dependencies(registry_entry),
        permissions,
        provenance,
        signature,
    }
}

fn build_transport_info(
    backend: &BackendConfig,
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> TransportInfo {
    let (protocol, url, command, env_var_names) = match &backend.transport {
        TransportConfig::Stdio {
            command,
            cwd: _,
            protocol_version: _,
        } => {
            let env_names: Vec<String> = backend.env.keys().cloned().collect();
            ("stdio".to_string(), None, Some(command.clone()), env_names)
        }
        TransportConfig::Http {
            http_url,
            protocol_version: _,
        } => ("http".to_string(), Some(http_url.clone()), None, {
            backend.env.keys().cloned().collect()
        }),
        #[cfg(feature = "a2a")]
        TransportConfig::A2a {
            a2a_url,
            protocol_version: _,
        } => ("a2a".to_string(), Some(a2a_url.clone()), None, {
            backend.env.keys().cloned().collect()
        }),
    };

    let env_var_names = if env_var_names.is_empty() {
        registry_entry
            .map(|e| {
                e.required_env
                    .iter()
                    .chain(e.optional_env.iter())
                    .map(|s| (*s).to_string())
                    .collect()
            })
            .unwrap_or_default()
    } else {
        env_var_names
    };

    TransportInfo {
        protocol,
        url,
        command,
        env_var_names,
    }
}

fn build_source_info(
    backend_name: &str,
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> SourceInfo {
    let (origin, registry) = if registry_entry.is_some() {
        ("registry".to_string(), Some("built-in".to_string()))
    } else {
        ("config".to_string(), None)
    };

    SourceInfo {
        origin,
        registry,
        config_path: None,
        manual_override: registry_entry.is_none(),
    }
}

fn build_owner_info(
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> OwnerInfo {
    registry_entry.map_or(
        OwnerInfo {
            name: None,
            contact: None,
            homepage: None,
        },
        |e| OwnerInfo {
            name: None,
            contact: None,
            homepage: Some(e.homepage.to_string()),
        },
    )
}

fn build_runtime_info(
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> RuntimeInfo {
    let (language, runtime, package_manager) = registry_entry.map_or(
        (None, None, None),
        |e| {
            if e.command.contains("npx") || e.command.contains("node") {
                (
                    Some("javascript".to_string()),
                    Some("node".to_string()),
                    Some("npm".to_string()),
                )
            } else if e.command.contains("uvx") || e.command.contains("python") {
                (
                    Some("python".to_string()),
                    Some("python".to_string()),
                    Some("pip".to_string()),
                )
            } else {
                (None, None, None)
            }
        },
    );

    RuntimeInfo {
        language,
        runtime,
        container_image: None,
        package_manager,
    }
}

fn build_permissions(backend: &BackendConfig) -> Vec<CapabilityPermission> {
    let mut perms = Vec::new();
    perms.push(CapabilityPermission {
        name: "tool_execution".to_string(),
        description: Some("Can execute tools on this backend".to_string()),
        read_only: None,
        destructive: None,
    });
    if backend.oauth.is_some() {
        perms.push(CapabilityPermission {
            name: "oauth".to_string(),
            description: Some("Requires OAuth authorization".to_string()),
            read_only: None,
            destructive: None,
        });
    }
    perms
}

fn build_credential_needs(
    backend: &BackendConfig,
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> Vec<CredentialNeed> {
    let mut needs = Vec::new();

    if let Some(entry) = registry_entry {
        for env_name in entry.required_env {
            needs.push(CredentialNeed {
                name: (*env_name).to_string(),
                required: true,
                description: Some(format!("Required environment variable: {env_name}")),
            });
        }
        for env_name in entry.optional_env {
            needs.push(CredentialNeed {
                name: (*env_name).to_string(),
                required: false,
                description: Some(format!("Optional environment variable: {env_name}")),
            });
        }
    }

    for key in backend.env.keys() {
        if !needs.iter().any(|n| n.name == *key) {
            needs.push(CredentialNeed {
                name: key.clone(),
                required: true,
                description: Some(format!("Configured environment variable: {key}")),
            });
        }
    }

    needs
}

fn build_network_reach(backend: &BackendConfig) -> NetworkReach {
    match &backend.transport {
        TransportConfig::Http { http_url, .. } => {
            let domain = http_url
                .strip_prefix("https://")
                .or_else(|| http_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.split(':').next())
                .map(String::from);

            NetworkReach {
                domains: domain.into_iter().collect(),
                ports: vec![],
                protocols: vec!["https".to_string()],
            }
        }
        #[cfg(feature = "a2a")]
        TransportConfig::A2a { a2a_url, .. } => {
            let domain = a2a_url
                .strip_prefix("https://")
                .or_else(|| a2a_url.strip_prefix("http://"))
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.split(':').next())
                .map(String::from);

            NetworkReach {
                domains: domain.into_iter().collect(),
                ports: vec![],
                protocols: vec!["https".to_string()],
            }
        }
        _ => NetworkReach {
            domains: vec![],
            ports: vec![],
            protocols: vec![],
        },
    }
}

fn build_signature_evidence(backend_name: &str, config: &Config) -> Option<SignatureEvidence> {
    let signing = &config.security.remote_server_signing;
    let backend_prov = signing.backends.get(backend_name)?;
    let key = signing.trusted_keys.get(&backend_prov.key_id)?;

    Some(SignatureEvidence {
        algorithm: format!("{:?}", key.algorithm).to_lowercase(),
        key_id: backend_prov.key_id.clone(),
        signature: backend_prov.signature.clone(),
        verified: false,
    })
}

fn build_provenance_evidence(
    backend_name: &str,
    config: &Config,
) -> Option<ProvenanceEvidence> {
    let signing = &config.security.remote_server_signing;
    let backend_prov = signing.backends.get(backend_name)?;

    Some(ProvenanceEvidence {
        issuer: Some(backend_prov.issuer.clone()),
        issued_at: Some(backend_prov.issued_at.clone()),
        subject: Some(backend_prov.subject.clone()),
        verified: false,
    })
}

fn build_dependencies(
    registry_entry: Option<crate::registry::server_registry::RegistryEntry>,
) -> Vec<CbomDependency> {
    let mut deps = Vec::new();
    if let Some(entry) = registry_entry {
        if let Some(pkg) = extract_npm_package(entry.command) {
            deps.push(CbomDependency {
                name: pkg,
                version: None,
                kind: "npm".to_string(),
                url: Some(entry.homepage.to_string()),
            });
        }
    }
    deps
}

fn extract_npm_package(command: &str) -> Option<String> {
    if let Some(rest) = command.strip_prefix("npx -y ") {
        Some(rest.to_string())
    } else if let Some(rest) = command.strip_prefix("npx ") {
        Some(rest.to_string())
    } else {
        None
    }
}
