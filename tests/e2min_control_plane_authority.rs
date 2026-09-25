// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E2-min (MIK 7570.ADMINGRANT.1): a grant or policy edit made in the admin
//! panel is refused with 409, never accepted and then ignored.
//!
//! Dispatch enforces grants from `security.identity_grants.path` and policies
//! from `security.sanitize_input` / `security.ssrf_protection`. The
//! control-plane store is read by nothing but the page, so a write to it is
//! refused after RBAC and before any store or audit write, and the page stops
//! calling itself mutating. The view half is in
//! `src/gateway/ui/control_plane_authority_tests.rs`.

mod common;
use common::*;

use axum::http::Method;
use mcp_gateway::control_plane::{
    AuditFilter, ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan,
    ControlPlaneStore, InMemoryControlPlaneStore,
};

const ADMIN: &str = "e2min-admin-token";
const AUDITOR: &str = "e2min-auditor-key";
const GRANTS_KEY: &str = "security.identity_grants.path";

/// A gateway with auth on, an admin bearer, a non-admin key, and an open store.
async fn gateway() -> (Arc<AppState>, Arc<dyn ControlPlaneStore>, tempfile::TempDir) {
    let (mut app, tasks) = state(Fixture {
        auth: auth_with(vec![api_key(AUDITOR, 1000, None)], Some(ADMIN)),
        ..Fixture::default()
    })
    .await;
    let store: Arc<dyn ControlPlaneStore> = Arc::new(InMemoryControlPlaneStore::new());
    Arc::get_mut(&mut app).unwrap().control_plane_store = Some(Arc::clone(&store));
    (app, store, tasks)
}

async fn send(
    app: &Arc<AppState>,
    token: &str,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let response = create_router(Arc::clone(app))
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn rollback() -> Value {
    json!({ "summary": "revert", "step": "restore the prior row" })
}

/// The four admin-panel writes, each with the reason code and the config key
/// its 409 must name.
fn writes() -> Vec<(&'static str, Value, &'static str, &'static [&'static str])> {
    let grants = (
        "grants_managed_in_identity_grants_file",
        &[GRANTS_KEY, "mcp-gateway identity grants"][..],
    );
    let policies = (
        "policies_managed_in_gateway_config",
        &["security.sanitize_input", "security.ssrf_protection"][..],
    );
    vec![
        (
            "/ui/api/control-plane/grants",
            json!({
                "grant": {
                    "grant_id": "grant-1", "subject_id": "user-1",
                    "server_id": "srv-1", "tool_id": null, "status": "approved",
                },
                "reason": "MIK-1", "rollback": rollback(),
            }),
            grants.0,
            grants.1,
        ),
        (
            "/ui/api/control-plane/policies",
            json!({
                "policy": { "policy_id": "local:ssrf_protection", "name": "SSRF", "enforced": false },
                "reason": "MIK-1", "rollback": rollback(),
            }),
            policies.0,
            policies.1,
        ),
        (
            "/ui/api/control-plane/decisions",
            json!({
                "target_kind": "grant", "target_id": "grant-1", "decision": "deny",
                "reason": "MIK-1", "rollback": rollback(),
            }),
            grants.0,
            grants.1,
        ),
        (
            "/ui/api/control-plane/decisions",
            json!({
                "target_kind": "policy", "target_id": "local:ssrf_protection",
                "decision": "deny", "reason": "MIK-1", "rollback": rollback(),
            }),
            policies.0,
            policies.1,
        ),
    ]
}

fn audit_count(store: &Arc<dyn ControlPlaneStore>) -> usize {
    store
        .read_audit(&AuditFilter::new(50))
        .unwrap()
        .events
        .len()
}

#[tokio::test]
async fn admin_grant_and_policy_writes_are_refused_and_point_at_config() {
    let (app, store, _tasks) = gateway().await;

    for (uri, body, code, keys) in writes() {
        let (status, resp) = send(&app, ADMIN, Method::POST, uri, Some(body)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{uri}: {resp}");
        assert_eq!(resp["ok"], false, "{uri}: {resp}");
        assert_eq!(resp["reason_code"], code, "{uri}: {resp}");
        let reason = resp["reason"].as_str().unwrap_or_default();
        for key in keys {
            assert!(
                reason.contains(key),
                "{uri}: the 409 must name {key}: {reason}"
            );
        }
        assert!(
            !reason.contains('/'),
            "{uri}: the 409 names config keys, never a filesystem path: {reason}"
        );
    }

    assert!(
        store.list_grants().unwrap().is_empty(),
        "no grant row persists"
    );
    assert!(
        store.list_policies().unwrap().is_empty(),
        "no policy row persists"
    );
    assert_eq!(audit_count(&store), 0, "a refused write is not audited");
}

/// Positive control: the refusal sits after RBAC. A non-admin still gets
/// RBAC's own 403, not the 409.
#[tokio::test]
async fn a_non_admin_write_is_still_refused_by_rbac() {
    let (app, store, _tasks) = gateway().await;

    for (uri, body, _, _) in writes() {
        let (status, resp) = send(&app, AUDITOR, Method::POST, uri, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {resp}");
        assert_eq!(
            resp["reason_code"], "CONTROL_RBAC_MUTATION_DENIED",
            "{uri}: {resp}"
        );
    }
    assert!(store.list_grants().unwrap().is_empty());
    assert_eq!(audit_count(&store), 0);
}

#[tokio::test]
async fn the_snapshot_does_not_advertise_mutation() {
    let (app, store, _tasks) = gateway().await;
    // The store still holds the audit log, which the page keeps showing.
    store
        .append_audit(&ControlPlaneAuditEvent {
            event_id: "e1".to_string(),
            actor_id: "alice".to_string(),
            action: ControlPlaneAction::MutateGrant,
            target_id: "g1".to_string(),
            reason: "MIK-1".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "revert".to_string(),
                step: "restore".to_string(),
            },
        })
        .unwrap();

    let (status, body) = send(&app, ADMIN, Method::GET, "/ui/api/control-plane", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(body["route"]["read_only"], true, "{body}");
    assert_eq!(body["route"]["mutation_endpoint"], false, "{body}");
    let governance = body["features"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["feature"] == "governance_mutation")
        .unwrap_or_else(|| panic!("governance_mutation entitlement listed: {body}"));
    assert_eq!(governance["available_in_this_route"], false, "{body}");
    assert_eq!(body["authority"]["grants"], GRANTS_KEY, "{body}");
    assert_eq!(
        body["authority"]["policies"], "security.sanitize_input, security.ssrf_protection",
        "{body}"
    );
    let limits: Vec<&str> = body["current_limits"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(limits.contains(&"no_mutation_endpoint"), "{limits:?}");
    assert!(
        !limits.contains(&"no_persistence"),
        "the store is open and holds the audit log: {limits:?}"
    );
    assert_eq!(
        body["view"]["audit_events"][0]["event_id"], "e1",
        "the store stays wired for the audit log: {body}"
    );
}
