// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7116.TENANT.1 — the cross-tenant
//! data-minimisation guard keys on the authenticated principal.
//!
//! The ticket specified its own mechanism in terms of sessions: *"blocks
//! accessing sensitive data about multiple customers within one session"*.
//! This release deletes the session, so the guard is rebound to the principal.
//! A guard still keyed on a session would not fail — it would allow every
//! request, because every stateless request is a new session with one tenant
//! in it. Each case below therefore asserts a refusal.

use serde_json::json;

use mcp_gateway::security::firewall::tenant_guard::{
    TenantGuard, TenantGuardConfig, TenantVerdict,
};

fn guard(max_tenants: usize) -> TenantGuard {
    TenantGuard::new(TenantGuardConfig {
        enabled: true,
        max_tenants_per_window: max_tenants,
        window_secs: 3600,
        arg_keys: vec!["customer_id".to_string(), "tenant_id".to_string()],
    })
}

#[test]
fn ac_tenant_1_one_principal_reaching_across_the_limit_is_refused() {
    let guard = guard(2);
    let principal = Some("principal:a");

    guard.check(principal, &json!({ "customer_id": "cust-1" }));
    guard.check(principal, &json!({ "customer_id": "cust-2" }));

    assert!(
        matches!(
            guard.check(principal, &json!({ "customer_id": "cust-3" })),
            TenantVerdict::Refused { .. }
        ),
        "a third distinct customer inside the window exceeds a limit of two \
         and must be refused, not merely counted"
    );
}

#[test]
fn ac_tenant_1_repeating_one_tenant_is_not_reaching_across_tenants() {
    // Data minimisation restricts breadth, not volume. A caller working one
    // customer's records all day is doing its job.
    let guard = guard(2);
    let principal = Some("principal:a");

    for _ in 0..10 {
        assert!(matches!(
            guard.check(principal, &json!({ "customer_id": "cust-1" })),
            TenantVerdict::Allowed
        ));
    }
}

#[test]
fn ac_tenant_1_the_guard_keys_on_the_principal_not_on_the_request() {
    // The defect the rebinding exists to close. Keyed per request — which is
    // what a session key degrades to under statelessness — each call carries
    // one tenant, no call ever exceeds the limit, and the guard passes
    // everything while appearing to work.
    let guard = guard(1);

    assert!(matches!(
        guard.check(Some("principal:a"), &json!({ "tenant_id": "t-1" })),
        TenantVerdict::Allowed
    ));
    assert!(
        matches!(
            guard.check(Some("principal:a"), &json!({ "tenant_id": "t-2" })),
            TenantVerdict::Refused { .. }
        ),
        "the second tenant is reached by the same principal across two \
         requests; a guard that cannot see across requests sees nothing"
    );
}

#[test]
fn ac_tenant_1_separate_principals_have_separate_breadth() {
    let guard = guard(1);

    assert!(matches!(
        guard.check(Some("principal:a"), &json!({ "tenant_id": "t-1" })),
        TenantVerdict::Allowed
    ));
    assert!(
        matches!(
            guard.check(Some("principal:b"), &json!({ "tenant_id": "t-2" })),
            TenantVerdict::Allowed
        ),
        "one principal's breadth must not exhaust another's"
    );
}

#[test]
fn ac_tenant_1_tenant_scoped_arguments_without_a_principal_are_refused() {
    // The unobservable case, and the reason it cannot be an allow. A call
    // carrying a customer identifier with no authenticated principal is a call
    // the guard cannot attribute, so it cannot enforce breadth on it at all.
    let guard = guard(2);

    assert!(
        matches!(
            guard.check(None, &json!({ "customer_id": "cust-1" })),
            TenantVerdict::Unattributable
        ),
        "no principal means no breadth can be measured; the guard must say so \
         rather than allow the call unmeasured"
    );
}

#[test]
fn ac_tenant_1_a_call_carrying_no_tenant_is_not_the_guards_business() {
    // Scope discipline. This guard restricts cross-tenant breadth; a call with
    // no tenant identifier in it does not widen breadth and must not be
    // refused for lacking a principal.
    let guard = guard(2);

    assert!(matches!(
        guard.check(None, &json!({ "query": "select 1" })),
        TenantVerdict::Allowed
    ));
}

#[test]
fn ac_tenant_1_nested_arguments_are_inspected() {
    // Tenant identifiers arrive nested as often as they arrive flat; a guard
    // that only reads the top level is trivially evaded by an object wrapper.
    let guard = guard(1);
    let principal = Some("principal:a");

    guard.check(principal, &json!({ "filter": { "customer_id": "cust-1" } }));

    assert!(matches!(
        guard.check(principal, &json!({ "filter": { "customer_id": "cust-2" } })),
        TenantVerdict::Refused { .. }
    ));
}

#[test]
fn ac_tenant_1_a_disabled_guard_allows_everything() {
    let guard = TenantGuard::new(TenantGuardConfig::default());
    assert!(matches!(
        guard.check(None, &json!({ "customer_id": "cust-1" })),
        TenantVerdict::Allowed
    ));
}

// ─── Wiring: the guard must actually sit on the request path ────────────────
//
// Every case above exercises `TenantGuard` directly — proof the unit is
// correct, not proof anything calls it. `Firewall::check_request` is the
// production consumer (`src/gateway/router/handlers.rs`,
// `src/gateway/router/backend_handlers.rs`); these cases go through it.

use mcp_gateway::security::firewall::{Firewall, FirewallConfig};

fn wired_firewall(max_tenants: usize) -> Firewall {
    let mut config = FirewallConfig {
        enabled: true,
        scan_requests: true,
        ..FirewallConfig::default()
    };
    config.tenant_guard = TenantGuardConfig {
        enabled: true,
        max_tenants_per_window: max_tenants,
        window_secs: 3600,
        arg_keys: vec!["customer_id".to_string()],
    };
    Firewall::from_config(config, None)
}

#[test]
fn ac_tenant_1_firewall_refuses_a_principal_reaching_across_tenants() {
    let fw = wired_firewall(2);
    let principal = "principal:a";

    for cust in ["cust-1", "cust-2"] {
        let verdict = fw.check_request(
            "irrelevant-session",
            "srv",
            "tool",
            &json!({ "customer_id": cust }),
            "caller",
            principal,
        );
        assert!(verdict.allowed, "first two distinct tenants stay allowed");
    }

    let verdict = fw.check_request(
        "irrelevant-session",
        "srv",
        "tool",
        &json!({ "customer_id": "cust-3" }),
        "caller",
        principal,
    );
    assert!(
        !verdict.allowed,
        "a third distinct tenant for the same principal must be refused \
         at the firewall entry point, not just inside the unit"
    );
}

#[test]
fn ac_tenant_1_firewall_allows_one_tenant_worked_repeatedly() {
    let fw = wired_firewall(2);

    for _ in 0..5 {
        let verdict = fw.check_request(
            "irrelevant-session",
            "srv",
            "tool",
            &json!({ "customer_id": "cust-1" }),
            "caller",
            "principal:a",
        );
        assert!(verdict.allowed);
    }
}

#[test]
fn ac_tenant_1_firewall_refuses_tenant_data_with_no_principal() {
    let fw = wired_firewall(2);

    let verdict = fw.check_request(
        "irrelevant-session",
        "srv",
        "tool",
        &json!({ "customer_id": "cust-1" }),
        "caller",
        "",
    );
    assert!(
        !verdict.allowed,
        "an unattributable tenant-scoped call must be refused, not passed \
         through unmeasured"
    );
}
