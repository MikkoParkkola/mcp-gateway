use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use crate::hashing::sha256_hex;

use super::{
    CapabilityDraft, DraftPolicyDefaults, DraftRoute, ImportReviewGate, ImportReviewGateKind,
    ImportRisk, ImportRiskKind, ImportRiskLevel, ImportSafeDefaults, ImportSource,
    ImportSourceKind, ReviewAction,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PostmanRequest {
    pub(super) name: String,
    pub(super) method: String,
    pub(super) url: String,
    pub(super) query_params: Vec<String>,
}

pub(super) fn digest_for(kind: ImportSourceKind, content: &[u8]) -> String {
    let prefix = source_kind_slug(kind);
    let mut bytes = Vec::with_capacity(prefix.len() + 1 + content.len());
    bytes.extend_from_slice(prefix.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(content);
    sha256_hex(&bytes)
}

pub(super) fn plan_digest(
    source: &ImportSource,
    source_digest_sha256: &str,
    drafts: &[CapabilityDraft],
) -> String {
    let draft_projection = drafts
        .iter()
        .map(|draft| {
            json!({
                "id": &draft.id,
                "route": &draft.route,
                "risks": &draft.risks,
                "gates": &draft.review_gates,
                "policy": &draft.policy_defaults,
                "trust_digest": &draft.trust_card.draft_digest_sha256,
            })
        })
        .collect::<Vec<_>>();
    let payload = serde_json::to_vec(&json!({
        "source": source,
        "source_digest_sha256": source_digest_sha256,
        "drafts": draft_projection,
    }))
    .unwrap_or_default();
    sha256_hex(&payload)
}

pub(super) fn empty_object_schema() -> Value {
    json!({
        "type": "object",
        "properties": {}
    })
}

pub(super) fn source_kind_slug(kind: ImportSourceKind) -> &'static str {
    match kind {
        ImportSourceKind::OpenApi => "openapi",
        ImportSourceKind::Graphql => "graphql",
        ImportSourceKind::Postman => "postman",
        ImportSourceKind::OciMcpPackage => "oci_mcp_package",
    }
}

pub(super) fn is_safe_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "QUERY"
    )
}

pub(super) fn classify_route_risks(
    route: &DraftRoute,
    input_schema: &Value,
    auth_required: bool,
    read_only: bool,
    description: &str,
) -> Vec<ImportRisk> {
    let mut risks = classify_schema_risks(input_schema);

    if !read_only {
        risks.push(ImportRisk {
            kind: ImportRiskKind::DestructiveOperation,
            level: ImportRiskLevel::High,
            reason: "Operation may mutate remote state and starts confirm-gated".to_string(),
            field: route.method.clone(),
        });
    }

    if !auth_required && !read_only {
        risks.push(ImportRisk {
            kind: ImportRiskKind::AuthAmbiguity,
            level: ImportRiskLevel::High,
            reason: "Mutating operation does not declare unambiguous auth requirements".to_string(),
            field: route.operation.clone(),
        });
    }

    if route
        .endpoint
        .as_deref()
        .is_some_and(|endpoint| endpoint.starts_with("http://") || endpoint.starts_with("https://"))
    {
        risks.push(ImportRisk {
            kind: ImportRiskKind::ExternalNetwork,
            level: ImportRiskLevel::Low,
            reason: "Draft calls an external network endpoint".to_string(),
            field: route.endpoint.clone(),
        });
    }

    let broad_text = format!(
        "{} {} {}",
        route.operation.as_deref().unwrap_or_default(),
        route.method.as_deref().unwrap_or_default(),
        description
    )
    .to_ascii_lowercase();
    if broad_text.contains("delete all")
        || broad_text.contains("bulk")
        || broad_text.contains("admin")
        || broad_text.contains("wildcard")
    {
        risks.push(ImportRisk {
            kind: ImportRiskKind::BroadScope,
            level: ImportRiskLevel::High,
            reason: "Operation name or description implies broad scope".to_string(),
            field: route.operation.clone(),
        });
    }

    risks
}

pub(super) fn classify_schema_risks(schema: &Value) -> Vec<ImportRisk> {
    let mut field_names = BTreeSet::new();
    collect_schema_field_names(schema, &mut field_names);

    let sensitive = field_names
        .iter()
        .find(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("email")
                || lower.contains("phone")
                || lower.contains("address")
                || lower.contains("ssn")
                || lower.contains("card")
                || lower.contains("password")
                || lower.contains("api_key")
                || lower.contains("session")
        })
        .cloned();

    sensitive.map_or_else(Vec::new, |field| {
        vec![ImportRisk {
            kind: ImportRiskKind::SensitiveDataSurface,
            level: ImportRiskLevel::Medium,
            reason: "Schema includes fields that may carry sensitive or regulated data".to_string(),
            field: Some(field),
        }]
    })
}

fn collect_schema_field_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if key != "properties" && key != "required" && key != "items" {
                    names.insert(key.clone());
                }
                collect_schema_field_names(nested, names);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_schema_field_names(nested, names);
            }
        }
        _ => {}
    }
}

pub(super) fn lacks_graphql_bounds(query: &str, variables_schema: &Value) -> bool {
    let lower = query.to_ascii_lowercase();
    let has_query_bounds = ["first:", "last:", "limit:", "after:", "before:"]
        .iter()
        .any(|needle| lower.contains(needle));
    let mut variable_names = BTreeSet::new();
    collect_schema_field_names(variables_schema, &mut variable_names);
    let has_variable_bounds = variable_names.iter().any(|name| {
        let lower = name.to_ascii_lowercase();
        matches!(
            lower.as_str(),
            "first" | "last" | "limit" | "page" | "cursor" | "after" | "before"
        )
    });
    !has_query_bounds && !has_variable_bounds
}

pub(super) fn gates_for_risks(risks: &[ImportRisk]) -> Vec<ImportReviewGate> {
    let mut gates = Vec::new();
    for risk in risks {
        match risk.kind {
            ImportRiskKind::DestructiveOperation | ImportRiskKind::BroadScope => {
                gates.push(ImportReviewGate {
                    kind: ImportReviewGateKind::DestructiveAction,
                    level: risk.level,
                    reason: risk.reason.clone(),
                    non_inferable: true,
                    can_auto_resolve: false,
                });
            }
            ImportRiskKind::AuthAmbiguity => gates.push(ImportReviewGate {
                kind: ImportReviewGateKind::AuthDecision,
                level: risk.level,
                reason: risk.reason.clone(),
                non_inferable: true,
                can_auto_resolve: false,
            }),
            ImportRiskKind::ExternalNetwork => gates.push(ImportReviewGate {
                kind: ImportReviewGateKind::NetworkScope,
                level: risk.level,
                reason: risk.reason.clone(),
                non_inferable: false,
                can_auto_resolve: true,
            }),
            ImportRiskKind::LicenseUnknown => gates.push(ImportReviewGate {
                kind: ImportReviewGateKind::LicenseReview,
                level: risk.level,
                reason: risk.reason.clone(),
                non_inferable: true,
                can_auto_resolve: false,
            }),
            ImportRiskKind::SupplyChainProvenance => gates.push(ImportReviewGate {
                kind: ImportReviewGateKind::ProvenanceVerification,
                level: risk.level,
                reason: risk.reason.clone(),
                non_inferable: false,
                can_auto_resolve: true,
            }),
            ImportRiskKind::UnboundedQuery => gates.push(ImportReviewGate {
                kind: ImportReviewGateKind::QueryBoundaries,
                level: risk.level,
                reason: risk.reason.clone(),
                non_inferable: true,
                can_auto_resolve: false,
            }),
            ImportRiskKind::SensitiveDataSurface => {}
        }
    }

    dedupe_gates(gates)
}

pub(super) fn aggregate_gates(drafts: &[CapabilityDraft]) -> Vec<ImportReviewGate> {
    let gates = drafts
        .iter()
        .flat_map(|draft| draft.review_gates.iter().cloned())
        .collect::<Vec<_>>();
    dedupe_gates(gates)
}

fn dedupe_gates(gates: Vec<ImportReviewGate>) -> Vec<ImportReviewGate> {
    let mut by_key: BTreeMap<(ImportReviewGateKind, String), ImportReviewGate> = BTreeMap::new();
    for gate in gates {
        let key = (gate.kind, gate.reason.clone());
        by_key
            .entry(key)
            .and_modify(|existing| {
                if gate.level > existing.level {
                    existing.level = gate.level;
                }
                existing.non_inferable |= gate.non_inferable;
                existing.can_auto_resolve &= gate.can_auto_resolve;
            })
            .or_insert(gate);
    }
    by_key.into_values().collect()
}

pub(super) fn policy_for_gates(
    safe_defaults: &ImportSafeDefaults,
    context_integrity_profile: &str,
    gates: &[ImportReviewGate],
) -> DraftPolicyDefaults {
    let activation = if gates
        .iter()
        .any(|gate| gate.kind == ImportReviewGateKind::DestructiveAction)
    {
        safe_defaults.destructive_action
    } else {
        ReviewAction::ManualReview
    };
    let auth = if gates
        .iter()
        .any(|gate| gate.kind == ImportReviewGateKind::AuthDecision)
    {
        safe_defaults.ambiguous_auth
    } else {
        ReviewAction::Allow
    };
    let network_egress = if gates
        .iter()
        .any(|gate| gate.kind == ImportReviewGateKind::NetworkScope)
    {
        safe_defaults.broad_network_egress
    } else {
        ReviewAction::Allow
    };

    DraftPolicyDefaults {
        activation,
        auth,
        network_egress,
        context_integrity_profile: context_integrity_profile.to_string(),
        audit_required: true,
        rollback_required: safe_defaults.rollback_required,
    }
}

pub(super) fn collect_postman_requests(value: &Value, requests: &mut Vec<PostmanRequest>) {
    if let Some(items) = value.get("item").and_then(Value::as_array) {
        for item in items {
            collect_postman_requests(item, requests);
        }
    }

    let Some(request) = value.get("request") else {
        return;
    };
    let Some(name) = value.get("name").and_then(Value::as_str) else {
        return;
    };
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return;
    };
    let Some(url) = postman_url(request.get("url")) else {
        return;
    };
    let query_params = request
        .pointer("/url/query")
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .filter_map(|param| param.get("key").and_then(Value::as_str))
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();

    requests.push(PostmanRequest {
        name: name.to_string(),
        method: method.to_ascii_uppercase(),
        url,
        query_params,
    });
}

fn postman_url(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(raw)) => Some(raw.clone()),
        Some(Value::Object(map)) => map
            .get("raw")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                let host = map.get("host").and_then(Value::as_array)?;
                let path = map.get("path").and_then(Value::as_array);
                let host = host
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(".");
                let path = path
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("/");
                Some(format!("https://{host}/{path}"))
            }),
        _ => None,
    }
}

pub(super) fn postman_input_schema(query_params: &[String]) -> Value {
    let properties = query_params
        .iter()
        .map(|param| (param.clone(), json!({ "type": "string" })))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(
        [
            ("type".to_string(), json!("object")),
            ("properties".to_string(), Value::Object(properties)),
        ]
        .into_iter()
        .collect(),
    )
}

pub(super) fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut prev_sep = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_sep = false;
        } else if !prev_sep {
            out.push('_');
            prev_sep = true;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "imported_tool".to_string()
    } else {
        trimmed
    }
}

pub(super) fn human_title(value: &str) -> String {
    let slug = slugify(value);
    let words = slug
        .split('_')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
            })
        })
        .collect::<Vec<_>>();
    if words.is_empty() {
        "Imported Tool".to_string()
    } else {
        words.join(" ")
    }
}
