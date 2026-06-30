//! Sensitive-data-free Kubernetes reconciliation evidence export contract.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{KubernetesPlanStatus, KubernetesReconcilePlan};

/// Schema version emitted by Kubernetes evidence export payloads.
pub const KUBERNETES_EVIDENCE_EXPORT_SCHEMA: &str = "kubernetes.evidence_export.v1";

/// Build evidence exports for a reconcile plan.
pub fn plan_evidence_exports(plan: &KubernetesReconcilePlan) -> Vec<KubernetesEvidenceExport> {
    let payload = KubernetesEvidencePayload::from_plan(plan);
    let gateway_name = gateway_name(plan);

    vec![
        status_export(plan, &gateway_name, &payload),
        event_export(plan, &gateway_name, &payload),
        otel_export(&payload),
        siem_export(payload),
    ]
}

fn status_export(
    plan: &KubernetesReconcilePlan,
    gateway_name: &str,
    payload: &KubernetesEvidencePayload,
) -> KubernetesEvidenceExport {
    KubernetesEvidenceExport {
        schema_version: KUBERNETES_EVIDENCE_EXPORT_SCHEMA.to_string(),
        sink: KubernetesEvidenceSink::StatusSubresource,
        target: format!("Gateway/{gateway_name}/status"),
        payload: payload.clone(),
        delivery: KubernetesEvidenceDelivery {
            transport: KubernetesEvidenceTransport::KubernetesStatusPatch,
            command: vec![
                "kubectl".to_string(),
                "patch".to_string(),
                "gateway".to_string(),
                gateway_name.to_string(),
                "-n".to_string(),
                plan.namespace.clone(),
                "--subresource=status".to_string(),
                "--type=merge".to_string(),
                "-p".to_string(),
                "<generated-status-evidence-payload>".to_string(),
            ],
            modifies_cluster: true,
            retry_safe: true,
            description: "Publish observed reconcile evidence to the Gateway status subresource"
                .to_string(),
        },
        redaction: KubernetesEvidenceRedaction::default(),
        contains_sensitive_material: false,
        requires_enterprise_license: true,
        rollback:
            "Next reconcile replaces status evidence; rollback uses the previous custom-resource generation"
                .to_string(),
    }
}

fn event_export(
    plan: &KubernetesReconcilePlan,
    gateway_name: &str,
    payload: &KubernetesEvidencePayload,
) -> KubernetesEvidenceExport {
    KubernetesEvidenceExport {
        schema_version: KUBERNETES_EVIDENCE_EXPORT_SCHEMA.to_string(),
        sink: KubernetesEvidenceSink::KubernetesEvent,
        target: format!("Event/{gateway_name}-reconcile-plan"),
        payload: payload.clone(),
        delivery: KubernetesEvidenceDelivery {
            transport: KubernetesEvidenceTransport::KubernetesEvent,
            command: vec![
                "kubectl".to_string(),
                "apply".to_string(),
                "-n".to_string(),
                plan.namespace.clone(),
                "-f".to_string(),
                "<generated-reconcile-event.yaml>".to_string(),
            ],
            modifies_cluster: true,
            retry_safe: true,
            description: "Emit a short Kubernetes Event for operators watching rollout progress"
                .to_string(),
        },
        redaction: KubernetesEvidenceRedaction::default(),
        contains_sensitive_material: false,
        requires_enterprise_license: true,
        rollback: "Events age out naturally; disable event export in the next reconcile"
            .to_string(),
    }
}

fn otel_export(payload: &KubernetesEvidencePayload) -> KubernetesEvidenceExport {
    KubernetesEvidenceExport {
        schema_version: KUBERNETES_EVIDENCE_EXPORT_SCHEMA.to_string(),
        sink: KubernetesEvidenceSink::OpenTelemetry,
        target: "otel.collector".to_string(),
        payload: payload.clone(),
        delivery: adapter_delivery(
            KubernetesEvidenceTransport::Otlp,
            "Forward reconcile attributes through the configured OpenTelemetry exporter",
        ),
        redaction: KubernetesEvidenceRedaction::default(),
        contains_sensitive_material: false,
        requires_enterprise_license: true,
        rollback: "Disable the OTel evidence sink or remove the collector endpoint reference"
            .to_string(),
    }
}

fn siem_export(payload: KubernetesEvidencePayload) -> KubernetesEvidenceExport {
    KubernetesEvidenceExport {
        schema_version: KUBERNETES_EVIDENCE_EXPORT_SCHEMA.to_string(),
        sink: KubernetesEvidenceSink::SiemWebhook,
        target: "siem.webhook".to_string(),
        payload,
        delivery: adapter_delivery(
            KubernetesEvidenceTransport::Webhook,
            "Forward reconcile evidence to the configured SIEM webhook adapter",
        ),
        redaction: KubernetesEvidenceRedaction::default(),
        contains_sensitive_material: false,
        requires_enterprise_license: true,
        rollback: "Disable the SIEM evidence sink or rotate the webhook reference".to_string(),
    }
}

fn adapter_delivery(
    transport: KubernetesEvidenceTransport,
    description: &str,
) -> KubernetesEvidenceDelivery {
    KubernetesEvidenceDelivery {
        transport,
        command: Vec::new(),
        modifies_cluster: false,
        retry_safe: true,
        description: description.to_string(),
    }
}

/// One evidence export target generated from a Kubernetes reconcile plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesEvidenceExport {
    /// Evidence export schema version.
    pub schema_version: String,
    /// Destination sink.
    pub sink: KubernetesEvidenceSink,
    /// Destination resource, collector, or adapter reference.
    pub target: String,
    /// Sensitive-data-free payload shared across sinks.
    pub payload: KubernetesEvidencePayload,
    /// Delivery method and command metadata.
    pub delivery: KubernetesEvidenceDelivery,
    /// Redaction guarantees applied to the payload.
    pub redaction: KubernetesEvidenceRedaction,
    /// Whether the payload contains sensitive material.
    pub contains_sensitive_material: bool,
    /// Whether this sink is enterprise-only.
    pub requires_enterprise_license: bool,
    /// Rollback or disablement path for this sink.
    pub rollback: String,
}

/// Evidence sink.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesEvidenceSink {
    /// Gateway status subresource.
    StatusSubresource,
    /// Kubernetes Event object.
    KubernetesEvent,
    /// OpenTelemetry collector/exporter path.
    OpenTelemetry,
    /// SIEM webhook adapter path.
    SiemWebhook,
}

/// Transport used to deliver evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KubernetesEvidenceTransport {
    /// kubectl status subresource patch.
    KubernetesStatusPatch,
    /// Kubernetes Event manifest apply.
    KubernetesEvent,
    /// OpenTelemetry Protocol exporter.
    Otlp,
    /// Webhook adapter.
    Webhook,
}

/// Delivery metadata for one evidence export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesEvidenceDelivery {
    /// Transport family.
    pub transport: KubernetesEvidenceTransport,
    /// Optional command preview. Empty when delivery is handled by an adapter.
    pub command: Vec<String>,
    /// Whether executing the delivery mutates the cluster.
    pub modifies_cluster: bool,
    /// Whether duplicate delivery is safe.
    pub retry_safe: bool,
    /// Human-readable delivery purpose.
    pub description: String,
}

/// Sensitive-data-free payload exported to evidence sinks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesEvidencePayload {
    /// Target namespace.
    pub namespace: String,
    /// Source manifest path or label.
    pub source: String,
    /// Reconcile plan status.
    pub plan_status: KubernetesPlanStatus,
    /// Number of parsed resources.
    pub resource_count: usize,
    /// Number of planned actions.
    pub action_count: usize,
    /// Number of status conditions.
    pub condition_count: usize,
    /// Stable reason codes from actions and conditions.
    pub reason_codes: Vec<String>,
    /// Low-cardinality attributes for `OTel` and SIEM sinks.
    pub attributes: BTreeMap<String, String>,
}

impl KubernetesEvidencePayload {
    fn from_plan(plan: &KubernetesReconcilePlan) -> Self {
        let reason_codes = reason_codes(plan);
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "mcp_gateway.schema".to_string(),
            KUBERNETES_EVIDENCE_EXPORT_SCHEMA.to_string(),
        );
        attributes.insert("mcp_gateway.namespace".to_string(), plan.namespace.clone());
        attributes.insert("mcp_gateway.source".to_string(), plan.source.clone());
        attributes.insert(
            "mcp_gateway.status".to_string(),
            status_label(plan.status).to_string(),
        );
        attributes.insert(
            "mcp_gateway.resource_count".to_string(),
            plan.resource_count.to_string(),
        );
        attributes.insert(
            "mcp_gateway.action_count".to_string(),
            plan.actions.len().to_string(),
        );
        attributes.insert(
            "mcp_gateway.condition_count".to_string(),
            plan.conditions.len().to_string(),
        );
        attributes.insert(
            "mcp_gateway.dry_run_modifies_cluster".to_string(),
            plan.server_side_dry_run.modifies_cluster.to_string(),
        );
        attributes.insert(
            "mcp_gateway.rollback_requires_confirmation".to_string(),
            plan.rollback.requires_human_confirmation.to_string(),
        );

        Self {
            namespace: plan.namespace.clone(),
            source: plan.source.clone(),
            plan_status: plan.status,
            resource_count: plan.resource_count,
            action_count: plan.actions.len(),
            condition_count: plan.conditions.len(),
            reason_codes,
            attributes,
        }
    }
}

/// Redaction guarantees for an evidence payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KubernetesEvidenceRedaction {
    /// Raw Kubernetes manifests are not included.
    pub raw_manifests_included: bool,
    /// Sensitive values are not included.
    pub sensitive_values_included: bool,
    /// Protected-value material is not included.
    pub protected_values_included: bool,
}

fn reason_codes(plan: &KubernetesReconcilePlan) -> Vec<String> {
    let mut codes = BTreeSet::new();
    for action in &plan.actions {
        codes.insert(action.reason_code.clone());
    }
    for condition in &plan.conditions {
        codes.insert(condition.reason.clone());
    }
    codes.into_iter().collect()
}

fn gateway_name(plan: &KubernetesReconcilePlan) -> String {
    plan.actions
        .iter()
        .find(|action| action.resource_kind == "Gateway")
        .map_or_else(
            || "mcp-gateway".to_string(),
            |action| action.resource_name.clone(),
        )
}

fn status_label(status: KubernetesPlanStatus) -> &'static str {
    match status {
        KubernetesPlanStatus::Ready => "ready",
        KubernetesPlanStatus::Blocked => "blocked",
    }
}
