// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

const EXAMPLE: &str =
    include_str!("../deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml");

#[test]
fn valid_k8s_object_names_accepted() {
    for name in [
        "mcp-gateway",
        "gw1",
        "a",
        "my.svc-2",
        "x".repeat(253).as_str(),
    ] {
        assert!(is_valid_k8s_object_name(name), "should accept {name:?}");
    }
}

#[test]
fn flag_shaped_and_malformed_names_rejected() {
    for name in [
        "--all",
        "-l",
        "-n",
        "",
        "UPPER",
        "trailing-",
        ".leading",
        "a b",
        &"x".repeat(254),
    ] {
        assert!(!is_valid_k8s_object_name(name), "should reject {name:?}");
    }
}

#[test]
fn parse_rejects_flag_shaped_resource_name() {
    // A manifest whose metadata.name is `--all` must be rejected before it
    // can reach a kubectl command vector as a positional argument.
    let manifest =
        "apiVersion: mcpgateway.io/v1alpha1\nkind: Gateway\nmetadata:\n  name: --all\nspec: {}\n";
    let err = parse_resources(manifest).expect_err("flag-shaped name must be rejected");
    assert!(
        matches!(err, KubernetesPlanError::InvalidName { .. }),
        "got {err:?}"
    );
}

#[test]
fn reconcile_plan_resolves_example_custom_resources() {
    let plan = plan_reconciliation("mcp-gateway", "example-gateway.yaml", EXAMPLE).unwrap();

    assert_eq!(plan.status, KubernetesPlanStatus::Ready);
    assert_eq!(plan.resource_count, 5);
    assert!(
        plan.server_side_dry_run
            .command
            .contains(&"--dry-run=server".to_string())
    );
    assert!(!plan.server_side_dry_run.modifies_cluster);
    assert!(
        plan.actions
            .iter()
            .any(|action| action.action == KubernetesReconcileActionKind::ReconcileMcpServer)
    );
    assert!(
        plan.conditions
            .iter()
            .any(|condition| condition.reason == "K8S_REFERENCE_RESOLVED")
    );
    assert!(
        plan.evidence_exports
            .iter()
            .any(|export| export.sink == KubernetesEvidenceSink::OpenTelemetry)
    );
    assert!(
        plan.evidence_exports
            .iter()
            .all(|export| !export.contains_sensitive_material)
    );
}

#[test]
fn reconcile_plan_blocks_missing_policy_reference() {
    let broken = EXAMPLE.replace("policyRef: default-policy", "policyRef: missing-policy");
    let plan = plan_reconciliation("mcp-gateway", "broken.yaml", &broken).unwrap();

    assert_eq!(plan.status, KubernetesPlanStatus::Blocked);
    assert!(
        plan.conditions
            .iter()
            .any(|condition| condition.reason == "K8S_REFERENCE_MISSING")
    );
}

/// MIK-8425 MIG.1c: the stream read stops at the first malformed document and
/// reports it as a parse error, before and after routing through the adapter.
#[test]
fn parse_refuses_a_malformed_later_document() {
    let manifest = "apiVersion: v1\nkind: Gateway\nmetadata:\n  name: gw\n---\nkind: [unclosed\n---\napiVersion: v1\nkind: Gateway\nmetadata:\n  name: later\n";
    let err = parse_resources(manifest).expect_err("a malformed later document must refuse");
    assert!(matches!(err, KubernetesPlanError::Parse(_)), "got {err:?}");
}

/// MIK-8425 MIG.1c: documents are checked in order, so an earlier document's
/// validation failure is reported before a later document's parse error.
#[test]
fn an_earlier_invalid_document_is_reported_before_a_later_parse_error() {
    let manifest =
        "apiVersion: v1\nkind: Gateway\nmetadata:\n  name: --all\n---\nkind: [unclosed\n";
    let err = parse_resources(manifest).expect_err("the first document is invalid");
    assert!(
        matches!(err, KubernetesPlanError::InvalidName { .. }),
        "got {err:?}"
    );
}

/// MIK-8425 MIG.1c: an empty document is skipped but still counts towards the
/// index reported for a later document's missing field.
#[test]
fn an_empty_document_keeps_later_document_indices() {
    let manifest =
        "apiVersion: v1\nkind: Gateway\nmetadata:\n  name: gw\n---\n---\nkind: Gateway\n";
    let err = parse_resources(manifest).expect_err("the third document has no name");
    assert!(
        matches!(
            err,
            KubernetesPlanError::MissingField {
                document: 2,
                field: "metadata.name"
            }
        ),
        "got {err:?}"
    );
}
