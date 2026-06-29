use serde::Deserialize;
use serde_yaml::Value;

const CRDS: &str = include_str!("../deploy/kubernetes/enterprise-alpha/crds/mcpgateway.io.yaml");
const RBAC: &str = include_str!("../deploy/kubernetes/enterprise-alpha/base/rbac.yaml");
const NETWORK_POLICY: &str =
    include_str!("../deploy/kubernetes/enterprise-alpha/base/networkpolicy.yaml");
const DEPLOYMENT: &str = include_str!("../deploy/kubernetes/enterprise-alpha/base/deployment.yaml");
const VALUES: &str =
    include_str!("../deploy/kubernetes/enterprise-alpha/values.enterprise.example.yaml");
const PREFLIGHT: &str = include_str!("../deploy/kubernetes/enterprise-alpha/scripts/preflight.sh");
const SERVER_DRY_RUN: &str =
    include_str!("../deploy/kubernetes/enterprise-alpha/scripts/server-dry-run.sh");
const KIND_SMOKE: &str =
    include_str!("../deploy/kubernetes/enterprise-alpha/scripts/kind-smoke.sh");

fn docs(input: &str) -> Vec<Value> {
    serde_yaml::Deserializer::from_str(input)
        .map(Value::deserialize)
        .collect::<Result<Vec<_>, _>>()
        .expect("kubernetes yaml must parse")
}

fn str_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key).expect("path key exists");
    }
    cursor.as_str().expect("path value is string")
}

#[test]
fn crds_cover_gateway_server_policy_trustcard_and_runtime_profile() {
    let kinds: Vec<String> = docs(CRDS)
        .iter()
        .map(|doc| str_at(doc, &["spec", "names", "kind"]).to_string())
        .collect();

    assert!(kinds.contains(&"Gateway".to_string()));
    assert!(kinds.contains(&"MCPServer".to_string()));
    assert!(kinds.contains(&"Policy".to_string()));
    assert!(kinds.contains(&"RuntimeProfile".to_string()));
    assert!(kinds.contains(&"TrustCardReference".to_string()));
}

#[test]
fn deployment_defaults_are_ha_safe_probe_backed_and_restricted() {
    let deployment = docs(DEPLOYMENT).remove(0);
    assert_eq!(str_at(&deployment, &["kind"]), "Deployment");
    assert_eq!(deployment["spec"]["replicas"].as_i64(), Some(2));
    assert_eq!(
        deployment["spec"]["strategy"]["rollingUpdate"]["maxUnavailable"].as_i64(),
        Some(0)
    );

    let container = &deployment["spec"]["template"]["spec"]["containers"][0];
    assert!(container.get("readinessProbe").is_some());
    assert!(container.get("livenessProbe").is_some());
    assert!(container.get("startupProbe").is_some());
    assert_eq!(
        container["securityContext"]["allowPrivilegeEscalation"].as_bool(),
        Some(false)
    );
    assert_eq!(
        container["securityContext"]["readOnlyRootFilesystem"].as_bool(),
        Some(true)
    );
}

#[test]
fn rbac_is_namespaced_and_avoids_wildcard_permissions() {
    for doc in docs(RBAC) {
        let kind = str_at(&doc, &["kind"]);
        assert_ne!(kind, "ClusterRole");
        assert_ne!(kind, "ClusterRoleBinding");

        if kind == "Role" {
            for rule in doc["rules"].as_sequence().expect("role rules") {
                let verbs = rule["verbs"].as_sequence().expect("verbs");
                let resources = rule["resources"].as_sequence().expect("resources");
                assert!(!verbs.iter().any(|verb| verb.as_str() == Some("*")));
                assert!(
                    !resources
                        .iter()
                        .any(|resource| resource.as_str() == Some("*"))
                );
            }
        }
    }
}

#[test]
fn network_policy_has_ingress_and_egress_defaults() {
    let network_policy = docs(NETWORK_POLICY).remove(0);
    assert_eq!(str_at(&network_policy, &["kind"]), "NetworkPolicy");
    let policy_types = network_policy["spec"]["policyTypes"]
        .as_sequence()
        .expect("policy types");
    assert!(
        policy_types
            .iter()
            .any(|item| item.as_str() == Some("Ingress"))
    );
    assert!(
        policy_types
            .iter()
            .any(|item| item.as_str() == Some("Egress"))
    );
    assert!(
        !network_policy["spec"]["egress"]
            .as_sequence()
            .expect("egress")
            .is_empty()
    );
}

#[test]
fn values_expose_enterprise_boundary_human_gates_and_protected_value_provider() {
    let values: Value = serde_yaml::from_str(VALUES).expect("values parse");
    assert_eq!(values["licenseTier"].as_str(), Some("enterprise"));
    assert_eq!(values["replicaCount"].as_i64(), Some(2));
    assert_eq!(values["policy"]["networkEgress"].as_str(), Some("deny_all"));
    assert_eq!(
        values["protectedValues"]["provider"].as_str(),
        Some("kubernetes")
    );

    for gate in values["humanGates"]
        .as_mapping()
        .expect("human gates")
        .values()
    {
        assert_eq!(gate.as_bool(), Some(true));
    }
}

#[test]
fn preflight_is_read_only_and_reports_required_capabilities() {
    assert!(PREFLIGHT.contains("auth can-i"));
    assert!(PREFLIGHT.contains("api-resources"));
    assert!(PREFLIGHT.contains("networking.k8s.io"));
    assert!(!PREFLIGHT.contains(" apply "));
    assert!(!PREFLIGHT.contains(" delete "));
}

#[test]
fn reconcile_plan_resolves_example_resources_and_keeps_dry_run_non_mutating() {
    let plan = mcp_gateway::kubernetes::plan_reconciliation(
        "mcp-gateway",
        "example-gateway.yaml",
        include_str!("../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"),
    )
    .expect("example resources should plan");

    assert_eq!(
        plan.status,
        mcp_gateway::kubernetes::KubernetesPlanStatus::Ready
    );
    assert!(
        plan.server_side_dry_run
            .command
            .contains(&"--dry-run=server".to_string())
    );
    assert!(!plan.server_side_dry_run.modifies_cluster);
    assert!(
        plan.actions
            .iter()
            .any(|action| action.reason_code == "K8S_MCP_SERVER_RECONCILE")
    );
    assert!(
        plan.conditions
            .iter()
            .all(|condition| condition.reason != "K8S_REFERENCE_MISSING")
    );
}

#[test]
fn reconcile_plan_emits_sensitive_free_enterprise_evidence_exports() {
    use mcp_gateway::kubernetes::{KubernetesEvidenceSink, KubernetesEvidenceTransport};

    let plan = mcp_gateway::kubernetes::plan_reconciliation(
        "mcp-gateway",
        "example-gateway.yaml",
        include_str!("../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"),
    )
    .expect("example resources should plan");

    let sinks: Vec<KubernetesEvidenceSink> = plan
        .evidence_exports
        .iter()
        .map(|export| export.sink)
        .collect();
    assert!(sinks.contains(&KubernetesEvidenceSink::StatusSubresource));
    assert!(sinks.contains(&KubernetesEvidenceSink::KubernetesEvent));
    assert!(sinks.contains(&KubernetesEvidenceSink::OpenTelemetry));
    assert!(sinks.contains(&KubernetesEvidenceSink::SiemWebhook));

    assert!(
        plan.evidence_exports
            .iter()
            .all(|export| export.requires_enterprise_license)
    );
    assert!(
        plan.evidence_exports
            .iter()
            .all(|export| !export.contains_sensitive_material)
    );
    assert!(plan.evidence_exports.iter().all(|export| {
        !export.redaction.raw_manifests_included
            && !export.redaction.sensitive_values_included
            && !export.redaction.protected_values_included
    }));

    let status_export = plan
        .evidence_exports
        .iter()
        .find(|export| export.sink == KubernetesEvidenceSink::StatusSubresource)
        .expect("status export");
    assert_eq!(
        status_export.delivery.transport,
        KubernetesEvidenceTransport::KubernetesStatusPatch
    );
    assert!(status_export.delivery.modifies_cluster);
    assert!(
        status_export
            .delivery
            .command
            .contains(&"--subresource=status".to_string())
    );

    let otel_export = plan
        .evidence_exports
        .iter()
        .find(|export| export.sink == KubernetesEvidenceSink::OpenTelemetry)
        .expect("otel export");
    assert_eq!(
        otel_export.delivery.transport,
        KubernetesEvidenceTransport::Otlp
    );
    assert!(!otel_export.delivery.modifies_cluster);
    assert!(otel_export.delivery.command.is_empty());
    assert!(
        otel_export
            .payload
            .reason_codes
            .contains(&"K8S_MCP_SERVER_RECONCILE".to_string())
    );
}

#[test]
fn controller_report_summarizes_reconcile_cycles_and_evidence_exports() {
    use mcp_gateway::kubernetes::{
        KUBERNETES_CONTROLLER_REPORT_SCHEMA, KubernetesControllerOptions,
        KubernetesControllerShutdownReason, KubernetesPlanStatus,
    };

    let report = mcp_gateway::kubernetes::plan_controller_report(
        KubernetesControllerOptions::bounded(
            "mcp-gateway",
            "deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml",
            30,
            2,
        ),
        include_str!("../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml"),
    )
    .expect("controller report should plan");

    assert_eq!(report.schema_version, KUBERNETES_CONTROLLER_REPORT_SCHEMA);
    assert_eq!(report.completed_cycles, 2);
    assert_eq!(report.status, KubernetesPlanStatus::Ready);
    assert_eq!(
        report.shutdown_reason,
        KubernetesControllerShutdownReason::CycleLimitReached
    );
    assert_eq!(report.last_plan.evidence_exports.len(), 4);
    assert!(
        report
            .cycles
            .iter()
            .all(|cycle| cycle.evidence_export_count == 4)
    );
}

#[test]
fn dry_run_and_kind_scripts_are_gated_and_reversible() {
    assert!(SERVER_DRY_RUN.contains("--server-side --dry-run=server"));
    assert!(SERVER_DRY_RUN.contains("preflight.sh"));
    assert!(SERVER_DRY_RUN.contains("mcpgateway.io"));
    assert!(KIND_SMOKE.contains("create cluster --name"));
    assert!(KIND_SMOKE.contains("trap cleanup EXIT"));
    assert!(KIND_SMOKE.contains("MCP_GATEWAY_KIND_KEEP"));
    assert!(KIND_SMOKE.contains("server-dry-run.sh"));
}
