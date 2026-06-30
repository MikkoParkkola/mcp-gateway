use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

use crate::config::TransportConfig;

use super::{
    ShadowActionGroup, ShadowAsset, ShadowAuthExposure, ShadowConfidence, ShadowDataRisk,
    ShadowOwnership, ShadowRemediation, ShadowRemediationAction, ShadowRiskSeverity,
    ShadowTransport,
};
use crate::discovery::{DiscoveredServer, DiscoverySource};

const HIGH_PRIVILEGE_KEYWORDS: &[&str] = &[
    "shell",
    "terminal",
    "exec",
    "filesystem",
    "file-system",
    "browser",
    "vault",
    "keychain",
];

const SENSITIVE_KEYWORDS: &[&str] = &[
    "gmail", "google", "drive", "calendar", "slack", "notion", "github", "linear", "stripe",
    "bank", "finance", "health", "medical", "email",
];

pub(super) fn classify_ownership(server: &DiscoveredServer) -> ShadowOwnership {
    if server.metadata.config_path.is_some() {
        ShadowOwnership::ClientConfig
    } else if server.metadata.pid.is_some() {
        ShadowOwnership::LocalProcess
    } else if server.source == DiscoverySource::Environment {
        ShadowOwnership::Environment
    } else {
        ShadowOwnership::Unknown
    }
}

pub(super) fn classify_data_risk(server: &DiscoveredServer) -> ShadowDataRisk {
    let mut haystack = format!("{} {}", server.name, server.description).to_ascii_lowercase();
    if let Some(command) = &server.metadata.command {
        haystack.push(' ');
        haystack.push_str(&command.to_ascii_lowercase());
    }

    if HIGH_PRIVILEGE_KEYWORDS
        .iter()
        .any(|needle| haystack.contains(needle))
    {
        ShadowDataRisk::HighPrivilege
    } else if SENSITIVE_KEYWORDS
        .iter()
        .any(|needle| haystack.contains(needle))
    {
        ShadowDataRisk::SensitiveData
    } else {
        ShadowDataRisk::Unknown
    }
}

pub(super) fn classify_severity(
    auth_exposure: &ShadowAuthExposure,
    data_risk: &ShadowDataRisk,
) -> ShadowRiskSeverity {
    let network_exposed = *auth_exposure == ShadowAuthExposure::NetworkHttpNoAuthMetadata;
    let sensitive = matches!(
        data_risk,
        ShadowDataRisk::SensitiveData | ShadowDataRisk::HighPrivilege
    );

    if network_exposed && sensitive {
        ShadowRiskSeverity::Critical
    } else if network_exposed || sensitive {
        ShadowRiskSeverity::High
    } else {
        ShadowRiskSeverity::Medium
    }
}

pub(super) fn classify_remediation(
    server: &DiscoveredServer,
    auth_exposure: &ShadowAuthExposure,
    data_risk: &ShadowDataRisk,
    ownership: &ShadowOwnership,
    gateway_config: Option<&str>,
) -> ShadowRemediation {
    let dry_run_command = Some(format_shadow_command(gateway_config, false));
    let verification_step = format_shadow_command(gateway_config, false);
    let rollback_step =
        "Remove the inserted backend entry or restore the previous gateway.yaml from VCS/backup."
            .to_string();

    if *auth_exposure == ShadowAuthExposure::NetworkHttpNoAuthMetadata {
        return ShadowRemediation {
            action: ShadowRemediationAction::Quarantine,
            confidence: ShadowConfidence::High,
            confirmation_required: true,
            active_probe_required: false,
            verification_step,
            rollback_step,
            dry_run_command,
            apply_command: None,
        };
    }

    if matches!(
        data_risk,
        ShadowDataRisk::SensitiveData | ShadowDataRisk::HighPrivilege
    ) {
        return ShadowRemediation {
            action: ShadowRemediationAction::RequestOwner,
            confidence: ShadowConfidence::Medium,
            confirmation_required: true,
            active_probe_required: false,
            verification_step,
            rollback_step,
            dry_run_command,
            apply_command: None,
        };
    }

    if matches!(
        ownership,
        ShadowOwnership::ClientConfig | ShadowOwnership::Environment
    ) || matches!(server.transport, TransportConfig::Stdio { .. })
    {
        return ShadowRemediation {
            action: ShadowRemediationAction::AdoptIntoGateway,
            confidence: ShadowConfidence::High,
            confirmation_required: true,
            active_probe_required: false,
            verification_step,
            rollback_step,
            dry_run_command,
            apply_command: Some(format_shadow_command(gateway_config, true)),
        };
    }

    ShadowRemediation {
        action: ShadowRemediationAction::RequestOwner,
        confidence: ShadowConfidence::Medium,
        confirmation_required: true,
        active_probe_required: false,
        verification_step,
        rollback_step,
        dry_run_command,
        apply_command: None,
    }
}

pub(super) fn risk_reasons(
    server: &DiscoveredServer,
    auth_exposure: &ShadowAuthExposure,
    data_risk: &ShadowDataRisk,
    ownership: &ShadowOwnership,
) -> Vec<String> {
    let mut reasons = vec![
        "unmanaged_server".to_string(),
        "not_registered_in_gateway_config".to_string(),
        "missing_trust_metadata".to_string(),
    ];
    match auth_exposure {
        ShadowAuthExposure::StdioProcess => reasons.push("local_stdio_process".to_string()),
        ShadowAuthExposure::LocalHttpNoAuthMetadata => {
            reasons.push("local_http_without_auth_metadata".to_string());
            reasons.push("unauthenticated_http_endpoint".to_string());
        }
        ShadowAuthExposure::NetworkHttpNoAuthMetadata => {
            reasons.push("network_http_without_auth_metadata".to_string());
            reasons.push("unauthenticated_http_endpoint".to_string());
        }
        ShadowAuthExposure::Unknown => reasons.push("unknown_transport_auth".to_string()),
    }
    match data_risk {
        ShadowDataRisk::SensitiveData => reasons.push("sensitive_data_domain".to_string()),
        ShadowDataRisk::HighPrivilege => reasons.push("high_privilege_domain".to_string()),
        ShadowDataRisk::Unknown => {}
    }
    match ownership {
        ShadowOwnership::ClientConfig => reasons.push("source_client_config".to_string()),
        ShadowOwnership::LocalProcess => reasons.push("source_local_process".to_string()),
        ShadowOwnership::Environment => reasons.push("source_environment".to_string()),
        ShadowOwnership::Unknown => {
            reasons.push("unknown_owner".to_string());
            reasons.push("unknown_provenance".to_string());
        }
    }
    if server.metadata.command.is_some() {
        reasons.push("command_arguments_redacted".to_string());
    }
    if has_personal_access_reference(server) {
        reasons.push("personal_access_reference".to_string());
    }
    if has_stale_binary_reference(server) {
        reasons.push("stale_binary".to_string());
    }
    reasons
}

fn has_personal_access_reference(server: &DiscoveredServer) -> bool {
    let mut haystack = format!("{} {}", server.name, server.description).to_ascii_lowercase();
    if let Some(command) = &server.metadata.command {
        haystack.push(' ');
        haystack.push_str(&command.to_ascii_lowercase());
    }
    ["token", "key", "password", "oauth", "bearer", "private"]
        .iter()
        .any(|needle| haystack.contains(needle))
}

fn has_stale_binary_reference(server: &DiscoveredServer) -> bool {
    let mut haystack = format!("{} {}", server.name, server.description).to_ascii_lowercase();
    if let Some(command) = &server.metadata.command {
        haystack.push(' ');
        haystack.push_str(&command.to_ascii_lowercase());
    }
    ["stale", "legacy", "deprecated"]
        .iter()
        .any(|needle| haystack.contains(needle))
}

pub(super) fn evidence_refs(asset: &ShadowAsset) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(config_path) = &asset.evidence.config_path {
        refs.push(format!("config_path:{config_path}"));
    }
    if let Some(pid) = asset.evidence.pid {
        refs.push(format!("pid:{pid}"));
    }
    if let Some(port) = asset.evidence.port {
        refs.push(format!("port:{port}"));
    }
    if let Some(executable) = &asset.evidence.executable {
        refs.push(format!("executable:{executable}"));
    }
    if let Some(endpoint) = &asset.evidence.endpoint {
        refs.push(format!("endpoint:{endpoint}"));
    }
    if refs.is_empty() {
        refs.push(format!("source:{:?}", asset.source));
    }
    refs
}

pub(super) fn build_action_groups(assets: &[ShadowAsset]) -> Vec<ShadowActionGroup> {
    let mut groups: BTreeMap<ShadowRemediationAction, Vec<String>> = BTreeMap::new();
    for asset in assets {
        groups
            .entry(asset.remediation.action.clone())
            .or_default()
            .push(asset.id.clone());
    }

    groups
        .into_iter()
        .map(|(action, asset_ids)| ShadowActionGroup {
            action,
            count: asset_ids.len(),
            asset_ids,
        })
        .collect()
}

pub(super) fn ensure_unique_ids(assets: &mut [ShadowAsset]) {
    let mut seen = HashMap::<String, usize>::new();
    for asset in assets {
        let base = asset.id.clone();
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            asset.id = format!("{base}-{count}");
        }
    }
}

pub(super) fn stable_shadow_id(server: &DiscoveredServer, transport: &ShadowTransport) -> String {
    let mut parts = vec![
        "shadow".to_string(),
        slug(&format!("{:?}", server.source)),
        slug(&server.name),
    ];

    if let Some(endpoint) = &transport.endpoint {
        parts.push(slug(endpoint));
    } else if let Some(port) = server.metadata.port {
        parts.push(format!("port-{port}"));
    } else if let Some(command) = &server.metadata.command
        && let Some(executable) = executable_name(command)
    {
        parts.push(slug(&executable));
    }

    parts.join(":")
}

fn format_shadow_command(gateway_config: Option<&str>, apply: bool) -> String {
    let mut command = "mcp-gateway cap discover --shadow".to_string();
    if let Some(path) = gateway_config {
        command.push_str(" --gateway-config ");
        command.push_str(&shell_word(path));
    }
    if apply {
        command.push_str(" --write-config");
    } else {
        command.push_str(" --format json");
    }
    command
}

fn shell_word(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

pub(super) fn sanitize_url(raw: &str) -> Option<String> {
    if let Ok(mut parsed) = url::Url::parse(raw) {
        let _ = parsed.set_username("");
        let _ = parsed.set_password(None);
        parsed.set_query(None);
        parsed.set_fragment(None);
        Some(parsed.to_string())
    } else if raw.is_empty() {
        None
    } else {
        Some(raw.split(['?', '#']).next().unwrap_or(raw).to_string())
    }
}

pub(super) fn is_loopback_url(raw: &str) -> bool {
    let Ok(parsed) = url::Url::parse(raw) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

pub(super) fn executable_name(command: &str) -> Option<String> {
    let first = command.split_whitespace().next()?;
    let name = Path::new(first)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(first);
    Some(name.to_string())
}

fn slug(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 96 {
            break;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}
