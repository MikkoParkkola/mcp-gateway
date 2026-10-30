// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use serde_json::{Value, json};

use super::*;
use crate::test_log_capture::capture_warnings as warns;

fn note(method: &str, params: Value) -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: Some(params),
    }
}

fn backend() -> Origin {
    Origin::Backend("b1".into())
}

/// The scoped members a backend may not put on a protocol notification.
fn scoped() -> Value {
    json!({"taskId": "t", "ttlMs": 1, "requestState": "s", "cacheScope": "c", "own": 1})
}

/// NOTIFY.5, Strip side: a protocol notification outside the in-call pair
/// (the listen acknowledgement) loses every scoped member at its root.
#[test]
fn a_protocol_notification_loses_its_scoped_members() {
    let mut n = note("notifications/subscriptions/acknowledged", scoped());
    assert_eq!(ingress_notification(&backend(), &mut n), Ingress::Deliver);
    assert_eq!(n.params, Some(json!({"own": 1})));
}

/// NOTIFY.5, Keep side: a vendor's method under `notifications/` keeps its
/// own fields of those names, and still loses the gateway-only ones.
#[test]
fn a_vendor_notification_keeps_its_own_fields() {
    let mut params = scoped();
    params["_security_findings"] = json!(["FORGED-1"]);
    let mut n = note("notifications/acme/status", params);
    assert_eq!(ingress_notification(&backend(), &mut n), Ingress::Deliver);
    assert_eq!(n.params, Some(scoped()));
}

/// The two `_meta` tags no notification may carry are removed; a vendor
/// `_meta` entry and the progress token stay.
#[test]
fn a_chain_and_a_listen_tag_are_removed() {
    let mut n = note(
        "notifications/progress",
        json!({"progressToken": "p", "_meta": {
            "io.mcp-gateway/signature-chain": "FORGED",
            "io.modelcontextprotocol/subscriptionId": 4,
            "vendor.example/x": 1,
        }}),
    );
    assert_eq!(ingress_notification(&backend(), &mut n), Ingress::Deliver);
    assert_eq!(
        n.params,
        Some(json!({"progressToken": "p", "_meta": {"vendor.example/x": 1}}))
    );
}

/// Root only: a `notifications/message` whose `data` nests a scoped or a
/// gateway-only name passes unchanged.
#[test]
fn a_nested_name_in_a_payload_is_not_touched() {
    let params = json!({"level": "info", "data": {"taskId": "t", "_security_findings": [1]}});
    let mut n = note("notifications/message", params.clone());
    assert_eq!(ingress_notification(&backend(), &mut n), Ingress::Deliver);
    assert_eq!(n.params, Some(params));
}

/// Both task notifications a backend raises are withheld.
#[test]
fn a_backend_task_notification_is_dropped() {
    for method in ["notifications/tasks", "notifications/tasks/status"] {
        let mut n = note(method, json!({"taskId": "t"}));
        assert!(matches!(
            ingress_notification(&backend(), &mut n),
            Ingress::Drop(_)
        ));
    }
}

/// A notification with no sender is withheld with exactly one warn naming
/// the method.
#[test]
fn a_missing_sender_is_dropped_with_one_warn() {
    let mut n = note("notifications/progress", json!({"progressToken": "p"}));
    let (decided, logged) = warns(|| ingress_notification(&Origin::Missing, &mut n));
    assert_eq!(decided, Ingress::Drop("no sender"));
    assert_eq!(logged.lines().count(), 1, "{logged}");
    assert!(logged.contains("notifications/progress"), "{logged}");
}

/// The warn names the backend, the method and the removed paths, never a
/// value.
#[test]
fn the_warn_names_paths_never_values() {
    let mut n = note(
        "notifications/progress",
        json!({"progressToken": "p", "_security_findings": ["CANARY-VALUE"], "taskId": "CANARY-TASK"}),
    );
    let (_, logged) = warns(|| ingress_notification(&backend(), &mut n));
    assert_eq!(logged.lines().count(), 1, "{logged}");
    for named in [
        "b1",
        "notifications/progress",
        "_security_findings",
        "taskId",
    ] {
        assert!(logged.contains(named), "{named} missing: {logged}");
    }
    assert!(
        !logged.contains("CANARY"),
        "a value reached the log: {logged}"
    );
}

/// A gateway log line outside any backend call is the gateway's and is
/// delivered unchanged; inside one it names that backend.
#[tokio::test]
async fn a_gateway_line_takes_the_ambient_backend() {
    assert!(matches!(Origin::gateway_line(), Origin::Gateway));
    assert!(matches!(Origin::ambient(), Origin::Missing));
    let params = json!({"level": "info", "logger": "gateway.invoke", "data": {"tool": "t"}});
    let mut n = note("notifications/message", params.clone());
    assert_eq!(
        ingress_notification(&Origin::gateway_line(), &mut n),
        Ingress::Deliver
    );
    assert_eq!(n.params, Some(params));
    in_backend("b2".into(), async {
        assert!(matches!(Origin::gateway_line(), Origin::Backend(b) if &*b == "b2"));
    })
    .await;
}

/// Two backend calls in one request each name their own backend, the inner
/// one while it runs.
#[tokio::test]
async fn nested_and_sibling_calls_name_their_own_backend() {
    let name = || match Origin::ambient() {
        Origin::Backend(b) => b.to_string(),
        other => format!("{other:?}"),
    };
    in_backend("outer".into(), async {
        assert_eq!(name(), "outer");
        in_backend("inner".into(), async { assert_eq!(name(), "inner") }).await;
        assert_eq!(name(), "outer");
    })
    .await;
    in_backend("sibling".into(), async { assert_eq!(name(), "sibling") }).await;
}
