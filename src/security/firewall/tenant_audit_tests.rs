// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: the firewall's `request` audit line names the request's
//! tenants, hashed, allowed or refused (test plan T1-T3).

use serde_json::{Value, json};

use super::tenant_guard::TenantGuardConfig;
use super::{Firewall, FirewallConfig, ScanType};
use crate::security::hash_argument;

fn h(id: &str) -> String {
    hash_argument(&json!(id))
}

fn firewall(dir: &tempfile::TempDir, tenant_guard: TenantGuardConfig) -> Firewall {
    Firewall::from_config(
        FirewallConfig {
            audit_log: Some(dir.path().join("fw.ndjson")),
            tenant_guard,
            ..FirewallConfig::default()
        },
        None,
    )
}

fn request_lines(dir: &tempfile::TempDir) -> Vec<Value> {
    std::fs::read_to_string(dir.path().join("fw.ndjson"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["event"] == "request")
        .collect()
}

fn keyed(enabled: bool, max: usize) -> TenantGuardConfig {
    TenantGuardConfig {
        enabled,
        max_tenants_per_window: max,
        arg_keys: vec!["customer_id".to_string()],
        ..TenantGuardConfig::default()
    }
}

/// T1. With the guard off, an allowed request's line names its tenant as a
/// hash; the raw id is never written.
#[test]
fn allowed_request_line_names_hashed_tenants() {
    let dir = tempfile::tempdir().unwrap();
    let fw = firewall(&dir, keyed(false, 1));
    let args = json!({"filter": {"customer_id": "cust-1"}});
    let verdict = fw.check_request("s1", "alpha", "read", &args, "ci", "p1");
    assert!(verdict.allowed);

    let lines = request_lines(&dir);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["tenants"], json!([h("cust-1")]));
    let raw = std::fs::read_to_string(dir.path().join("fw.ndjson")).unwrap();
    assert!(!raw.contains("cust-1"), "raw tenant id written: {raw}");
}

/// T2 (firewall half). A tenant-guard refusal's line names the tenant it
/// refused.
#[test]
fn refused_request_line_names_the_refused_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let fw = firewall(&dir, keyed(true, 1));
    let first = fw.check_request(
        "s1",
        "alpha",
        "read",
        &json!({"customer_id": "cust-1"}),
        "ci",
        "p1",
    );
    assert!(first.allowed);
    let second = fw.check_request(
        "s1",
        "alpha",
        "read",
        &json!({"customer_id": "cust-2"}),
        "ci",
        "p1",
    );
    assert!(!second.allowed);
    assert!(
        second
            .findings
            .iter()
            .any(|f| f.scan_type == ScanType::CrossTenantReach)
    );

    let lines = request_lines(&dir);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["tenants"], json!([h("cust-2")]));
}

/// T3. Without `arg_keys` the line has no `tenants` key: default deployments
/// keep their schema.
#[test]
fn line_has_no_tenants_key_without_arg_keys() {
    let dir = tempfile::tempdir().unwrap();
    let fw = firewall(&dir, TenantGuardConfig::default());
    fw.check_request(
        "s1",
        "alpha",
        "read",
        &json!({"customer_id": "cust-1"}),
        "ci",
        "p1",
    );
    let lines = request_lines(&dir);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].get("tenants").is_none());
}
