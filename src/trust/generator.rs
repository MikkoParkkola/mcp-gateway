// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `TrustCard` generation facade.
//!
//! Generation currently reuses the canonical `TrustCard` constructors. The
//! facade keeps CLI, docs, tests, and future registry/live metadata adapters on
//! one import path instead of binding them to constructor placement.

use serde::Serialize;
use serde_json::Value;

use crate::{
    capability::CapabilityDefinition,
    hashing::canonical_json_sha256,
    protocol::{Prompt, Resource, Tool},
};

use super::{
    CBOM_SCHEMA_VERSION, CapabilityBom, CbomAnnotation, CbomComponent, CbomComponentKind,
    CbomPrompt, CbomProvenance, CbomResource, CbomSubjectKind, CbomTool, TRUST_CARD_SCHEMA_VERSION,
    TrustAuthMode, TrustCard, TrustDataClass, TrustEvaluationStatus, TrustEvidenceKind,
    TrustPermission, TrustRiskClass, TrustServer, TrustSignatureEvidence, TrustSignatureStatus,
    TrustTool, TrustTransport,
};

/// Generate a `TrustCard` from a live or fixture MCP tool descriptor.
#[must_use]
pub fn trust_card_from_tool(server_name: impl Into<String>, tool: &Tool) -> TrustCard {
    TrustCard::from_tool(server_name, tool)
}

/// Generate a `TrustCard` from a local capability definition.
#[must_use]
pub fn trust_card_from_capability(capability: &CapabilityDefinition) -> TrustCard {
    TrustCard::from_capability(capability)
}

/// Generate a `TrustCard` from live or discovered MCP metadata.
#[must_use]
pub fn trust_card_from_live_metadata(
    server_name: impl Into<String>,
    tools: &[Tool],
    prompts: &[Prompt],
    resources: &[Resource],
) -> TrustCard {
    let server_name = server_name.into();
    let trust_tools = sorted_trust_tools(tools);
    let cbom_tools = sorted_cbom_tools(&trust_tools);
    let annotations = sorted_annotations(&trust_tools);
    let cbom_prompts = sorted_prompts(prompts);
    let cbom_resources = sorted_resources(resources);
    let components = sorted_components(&server_name, trust_tools, &cbom_prompts, &cbom_resources);
    let provenance = sorted_provenance(&cbom_tools, &cbom_prompts, &cbom_resources);

    let permissions = unique_sorted(
        cbom_tools
            .iter()
            .flat_map(|tool| tool.permissions.iter().copied()),
    );
    let data_classes = unique_sorted(
        cbom_tools
            .iter()
            .flat_map(|tool| tool.data_classes.iter().copied()),
    );
    let risk_class = cbom_tools
        .iter()
        .map(|tool| tool.risk_class)
        .max()
        .unwrap_or(TrustRiskClass::Unknown);

    TrustCard {
        schema_version: TRUST_CARD_SCHEMA_VERSION.to_string(),
        server: TrustServer {
            name: server_name,
            publisher: None,
            version: None,
            license: None,
            source_uri: None,
            transport: TrustTransport::Unknown,
            auth_mode: TrustAuthMode::Unknown,
            runtime_profile: None,
            network_reach: Vec::new(),
            signature_evidence: vec![TrustSignatureEvidence {
                subject: "live-descriptor".to_string(),
                kind: "protocol_metadata".to_string(),
                status: TrustSignatureStatus::Unknown,
                evidence: TrustEvidenceKind::Observed,
            }],
            risk_class,
            data_classes,
            permissions,
            evidence: TrustEvidenceKind::Observed,
        },
        cbom: CapabilityBom {
            schema_version: CBOM_SCHEMA_VERSION.to_string(),
            tools: cbom_tools,
            prompts: cbom_prompts,
            resources: cbom_resources,
            annotations,
            dependencies: Vec::new(),
            provenance,
            components,
        },
        evaluation_status: TrustEvaluationStatus::NotEvaluated,
        findings: Vec::new(),
    }
}

fn sorted_trust_tools(tools: &[Tool]) -> Vec<TrustTool> {
    let mut trust_tools = tools.iter().map(TrustTool::from_tool).collect::<Vec<_>>();
    trust_tools.sort_by(|left, right| left.name.cmp(&right.name));
    trust_tools
}

fn sorted_cbom_tools(trust_tools: &[TrustTool]) -> Vec<CbomTool> {
    let mut cbom_tools = trust_tools
        .iter()
        .map(CbomTool::from_trust_tool)
        .collect::<Vec<_>>();
    cbom_tools.sort_by(|left, right| left.name.cmp(&right.name));
    cbom_tools
}

fn sorted_annotations(trust_tools: &[TrustTool]) -> Vec<CbomAnnotation> {
    let mut annotations = trust_tools
        .iter()
        .map(CbomAnnotation::from_trust_tool)
        .collect::<Vec<_>>();
    annotations.sort_by(|left, right| left.subject_name.cmp(&right.subject_name));
    annotations
}

fn sorted_prompts(prompts: &[Prompt]) -> Vec<CbomPrompt> {
    let mut cbom_prompts = prompts
        .iter()
        .map(cbom_prompt_from_prompt)
        .collect::<Vec<_>>();
    cbom_prompts.sort_by(|left, right| left.name.cmp(&right.name));
    cbom_prompts
}

fn sorted_resources(resources: &[Resource]) -> Vec<CbomResource> {
    let mut cbom_resources = resources
        .iter()
        .map(cbom_resource_from_resource)
        .collect::<Vec<_>>();
    cbom_resources.sort_by(|left, right| left.uri.cmp(&right.uri));
    cbom_resources
}

fn sorted_components(
    server_name: &str,
    trust_tools: Vec<TrustTool>,
    prompts: &[CbomPrompt],
    resources: &[CbomResource],
) -> Vec<CbomComponent> {
    let mut components = trust_tools
        .into_iter()
        .map(|tool| tool.into_component(server_name))
        .collect::<Vec<_>>();
    components.extend(
        prompts
            .iter()
            .map(|prompt| prompt_component(server_name, prompt)),
    );
    components.extend(
        resources
            .iter()
            .map(|resource| resource_component(server_name, resource)),
    );
    components.sort_by(|left, right| {
        component_kind_rank(left.kind)
            .cmp(&component_kind_rank(right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });
    components
}

fn sorted_provenance(
    tools: &[CbomTool],
    prompts: &[CbomPrompt],
    resources: &[CbomResource],
) -> Vec<CbomProvenance> {
    let mut provenance = Vec::new();
    provenance.extend(tools.iter().map(|tool| {
        CbomProvenance::observed(
            CbomSubjectKind::Tool,
            tool.name.clone(),
            "protocol.tools/list",
        )
    }));
    provenance.extend(prompts.iter().map(|prompt| {
        CbomProvenance::observed(
            CbomSubjectKind::Prompt,
            prompt.name.clone(),
            "protocol.prompts/list",
        )
    }));
    provenance.extend(resources.iter().map(|resource| {
        CbomProvenance::observed(
            CbomSubjectKind::Resource,
            resource.uri.clone(),
            "protocol.resources/list",
        )
    }));
    provenance.sort_by(|left, right| {
        subject_kind_rank(left.subject_kind)
            .cmp(&subject_kind_rank(right.subject_kind))
            .then_with(|| left.subject_name.cmp(&right.subject_name))
            .then_with(|| left.source_uri.cmp(&right.source_uri))
    });
    provenance
}

fn cbom_prompt_from_prompt(prompt: &Prompt) -> CbomPrompt {
    CbomPrompt {
        name: prompt.name.clone(),
        description: prompt.description.clone().or_else(|| prompt.title.clone()),
        digest_sha256: descriptor_digest(prompt),
        evidence: TrustEvidenceKind::Observed,
    }
}

fn cbom_resource_from_resource(resource: &Resource) -> CbomResource {
    CbomResource {
        uri: resource.uri.clone(),
        name: Some(resource.name.clone()),
        mime_type: resource.mime_type.clone(),
        digest_sha256: descriptor_digest(resource),
        evidence: TrustEvidenceKind::Observed,
    }
}

fn prompt_component(server_name: &str, prompt: &CbomPrompt) -> CbomComponent {
    CbomComponent {
        name: format!("{server_name}:prompt:{}", prompt.name),
        kind: CbomComponentKind::Prompt,
        version: None,
        source_uri: None,
        digest_sha256: prompt.digest_sha256.clone(),
        license: None,
        permissions: Vec::new(),
        data_classes: Vec::new(),
        evidence: prompt.evidence,
    }
}

fn resource_component(server_name: &str, resource: &CbomResource) -> CbomComponent {
    CbomComponent {
        name: format!("{server_name}:resource:{}", resource.uri),
        kind: CbomComponentKind::Resource,
        version: None,
        source_uri: Some(resource.uri.clone()),
        digest_sha256: resource.digest_sha256.clone(),
        license: None,
        permissions: vec![TrustPermission::Read],
        data_classes: vec![TrustDataClass::Unknown],
        evidence: resource.evidence,
    }
}

fn descriptor_digest<T: Serialize>(value: &T) -> Option<String> {
    let value: Value = serde_json::to_value(value).ok()?;
    Some(canonical_json_sha256(&value))
}

fn unique_sorted<T>(values: impl IntoIterator<Item = T>) -> Vec<T>
where
    T: Ord,
{
    values
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn component_kind_rank(kind: CbomComponentKind) -> u8 {
    match kind {
        CbomComponentKind::Server => 0,
        CbomComponentKind::Tool => 1,
        CbomComponentKind::Prompt => 2,
        CbomComponentKind::Resource => 3,
        CbomComponentKind::Runtime => 4,
        CbomComponentKind::Dependency => 5,
    }
}

fn subject_kind_rank(kind: CbomSubjectKind) -> u8 {
    match kind {
        CbomSubjectKind::Server => 0,
        CbomSubjectKind::Tool => 1,
        CbomSubjectKind::Prompt => 2,
        CbomSubjectKind::Resource => 3,
        CbomSubjectKind::Runtime => 4,
        CbomSubjectKind::Dependency => 5,
    }
}
