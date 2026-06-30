use crate::{capability::CapabilityDefinition, protocol::Tool};

use super::{
    TrustDataClass, TrustPermission, TrustRiskClass, TrustToolAnnotations, TrustTransport,
};

pub(super) fn transport_from_capability(capability: &CapabilityDefinition) -> TrustTransport {
    capability
        .providers
        .named
        .values()
        .next()
        .or_else(|| capability.providers.fallback.first())
        .map_or(TrustTransport::Unknown, |provider| {
            match provider.service.as_str() {
                "rest" | "graphql" | "jsonrpc" | "" => TrustTransport::Http,
                _ => TrustTransport::Unknown,
            }
        })
}

pub(super) fn source_uri_from_capability(capability: &CapabilityDefinition) -> Option<String> {
    capability
        .providers
        .named
        .values()
        .next()
        .or_else(|| capability.providers.fallback.first())
        .and_then(|provider| {
            let endpoint = provider.config.effective_base_url();
            if endpoint.is_empty() {
                None
            } else {
                Some(endpoint.to_string())
            }
        })
}

pub(super) fn infer_permissions(
    tool: &Tool,
    annotations: &TrustToolAnnotations,
) -> Vec<TrustPermission> {
    let mut permissions = Vec::new();
    if annotations.read_only == Some(true) {
        permissions.push(TrustPermission::Read);
    }
    if annotations.destructive == Some(true) {
        permissions.push(TrustPermission::Write);
    }
    if annotations.open_world == Some(true) {
        permissions.push(TrustPermission::Network);
    }

    let haystack = tool_haystack(tool);
    for (needle, permission) in [
        ("file", TrustPermission::Filesystem),
        ("filesystem", TrustPermission::Filesystem),
        ("browser", TrustPermission::Browser),
        ("sql", TrustPermission::Database),
        ("database", TrustPermission::Database),
        ("exec", TrustPermission::Execute),
        ("shell", TrustPermission::Execute),
        ("message", TrustPermission::Messaging),
        ("payment", TrustPermission::Payment),
    ] {
        if haystack.contains(needle) && !permissions.contains(&permission) {
            permissions.push(permission);
        }
    }

    if permissions.is_empty() {
        permissions.push(TrustPermission::Unknown);
    }
    permissions.sort_unstable();
    permissions.dedup();
    permissions
}

pub(super) fn infer_data_classes(tool: &Tool) -> Vec<TrustDataClass> {
    let haystack = tool_haystack(tool);
    let mut data_classes = Vec::new();
    for (needle, data_class) in [
        ("email", TrustDataClass::Personal),
        ("gmail", TrustDataClass::Personal),
        ("calendar", TrustDataClass::Personal),
        ("drive", TrustDataClass::Personal),
        ("bank", TrustDataClass::Financial),
        ("finance", TrustDataClass::Financial),
        ("health", TrustDataClass::Health),
        ("medical", TrustDataClass::Health),
        ("github", TrustDataClass::SourceCode),
        ("code", TrustDataClass::SourceCode),
        ("file", TrustDataClass::SystemAccess),
        ("shell", TrustDataClass::SystemAccess),
        ("browser", TrustDataClass::SystemAccess),
    ] {
        if haystack.contains(needle) && !data_classes.contains(&data_class) {
            data_classes.push(data_class);
        }
    }

    if data_classes.is_empty() {
        data_classes.push(TrustDataClass::Unknown);
    }
    data_classes.sort_unstable();
    data_classes.dedup();
    data_classes
}

pub(super) fn infer_risk_class(
    permissions: &[TrustPermission],
    data_classes: &[TrustDataClass],
    annotations: &TrustToolAnnotations,
) -> TrustRiskClass {
    if permissions.contains(&TrustPermission::Execute)
        || data_classes.contains(&TrustDataClass::SystemAccess)
    {
        TrustRiskClass::High
    } else if annotations.destructive == Some(true)
        || permissions.contains(&TrustPermission::Write)
        || data_classes.iter().any(|data_class| {
            matches!(
                data_class,
                TrustDataClass::Personal | TrustDataClass::Financial | TrustDataClass::Health
            )
        })
    {
        TrustRiskClass::Medium
    } else if permissions.contains(&TrustPermission::Unknown)
        || data_classes.contains(&TrustDataClass::Unknown)
    {
        TrustRiskClass::Unknown
    } else {
        TrustRiskClass::Low
    }
}

fn tool_haystack(tool: &Tool) -> String {
    format!(
        "{} {}",
        tool.name,
        tool.description.as_deref().unwrap_or_default()
    )
    .to_ascii_lowercase()
}
