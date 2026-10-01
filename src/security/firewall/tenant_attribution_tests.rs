// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: the tenant extractors behind attribution (test plan T4-T6).

use std::collections::BTreeSet;

use serde_json::json;

use super::{TenantGuard, TenantGuardConfig, TenantVerdict};

fn guard(enabled: bool, max: usize) -> TenantGuard {
    TenantGuard::new(TenantGuardConfig {
        enabled,
        max_tenants_per_window: max,
        arg_keys: vec!["customer_id".to_string()],
        ..TenantGuardConfig::default()
    })
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_string()).collect()
}

/// T4. Extraction never records: after both extractors saw `cust-2`, a
/// principal limited to one tenant may still reach `cust-1`.
#[test]
fn extraction_does_not_count_against_the_guard() {
    let g = guard(true, 1);
    let names_cust_2 = json!({"filter": {"customer_id": "cust-2"}});
    let _ = g.request_tenants(&names_cust_2);
    let _ = g.response_tenants(&json!({"structuredContent": names_cust_2}));
    assert_eq!(
        g.check(Some("p1"), &json!({"customer_id": "cust-1"})),
        TenantVerdict::Allowed
    );
}

/// The request walk is the guard's walk, at any depth, with the guard off.
#[test]
fn request_tenants_walks_nested_arguments_with_the_guard_off() {
    let g = guard(false, 1);
    let args = json!({"filter": {"customer_id": "cust-1"}, "rows": [{"customer_id": 7}]});
    assert_eq!(g.request_tenants(&args), set(&["cust-1", "7"]));
}

/// T5. Most backends return JSON as text; `structuredContent` is walked too.
#[test]
fn response_tenants_reads_text_json_and_structured_content() {
    let g = guard(false, 1);
    let text = json!({"content": [{
        "type": "text",
        "text": r#"{"rows":[{"customer_id":"cust-9"}]}"#
    }]});
    assert_eq!(g.response_tenants(&text), set(&["cust-9"]));
    let structured = json!({"structuredContent": {"customer_id": 7}});
    assert_eq!(g.response_tenants(&structured), set(&["7"]));
}

/// Plain prose in a text block names no tenant and is not an error.
#[test]
fn response_tenants_ignores_non_json_text() {
    let g = guard(false, 1);
    let prose = json!({"content": [{"type": "text", "text": "customer_id cust-9"}]});
    assert!(g.response_tenants(&prose).is_empty());
}

/// T6 (re-pinned, MIN.1 gap 2). A text block over 1 MiB is not parsed, even
/// when it is valid JSON naming a tenant (the DoS bound holds), and the
/// result says so: its tenants were not read, which is not the same as none.
#[test]
fn response_tenants_skips_text_over_one_mib() {
    let g = guard(false, 1);
    let padding = "x".repeat(1024 * 1024);
    let big = format!(r#"{{"customer_id":"cust-9","pad":"{padding}"}}"#);
    let result = json!({"content": [{"type": "text", "text": big}]});
    assert!(g.response_tenants(&result).is_empty());
    assert!(
        g.response_uninspected(&result),
        "an over-bound block is uninspected"
    );
    let small = json!({"content": [{"type": "text", "text": "{\"customer_id\":\"cust-9\"}"}]});
    assert!(
        !g.response_uninspected(&small),
        "a parsed block is inspected"
    );
    let off = TenantGuard::new(TenantGuardConfig::default());
    assert!(
        !off.response_uninspected(&result),
        "no arg_keys, no attribution"
    );
}
