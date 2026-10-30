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

/// The strip asks nothing of the sender: a gateway line and a notification
/// with no sender lose a planted member as a backend's does.
#[test]
fn a_gateway_or_missing_sender_is_still_stripped() {
    for origin in [Origin::Gateway, Origin::Missing] {
        let mut n = note(
            "notifications/progress",
            json!({"progressToken": "p", "_security_findings": ["FORGED-1"]}),
        );
        let _ = ingress_notification(&origin, &mut n);
        assert_eq!(
            n.params,
            Some(json!({"progressToken": "p"})),
            "{origin:?} skipped the strip"
        );
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

/// Every way into the sink outside the sink module, by file and count. A
/// transport's is a backend's notification and runs inside that backend's
/// scope (`Backend::send_in_scope`, the catalogue fill and drain); the
/// gateway's own is `emit_log`, whose lines carry only gateway config, the
/// caller's request and gateway ids, never backend text. A new site fails
/// here until it is classified: inside a backend's scope, or a gateway line
/// with no backend text in it.
const SINK_ENTRIES: &[(&str, &str, usize)] = &[
    // Backend: an SSE frame read on the caller's task.
    (
        "src/transport/http/sse_decoder.rs",
        "notification_sink::publish",
        1,
    ),
    // Backend: captured on the caller's task, delivered by the reader.
    ("src/transport/stdio.rs", "DeliveryHandle::capture(", 1),
    (
        "src/transport/websocket_progress.rs",
        "DeliveryHandle::capture(",
        1,
    ),
    // Gateway: a refusal and "tool invoked", both before the backend call.
    (
        "src/gateway/meta_mcp/invoke/pre_dispatch.rs",
        "emit_log(",
        2,
    ),
];

const NEEDLES: &[&str] = &[
    "notification_sink::publish",
    "publish_as(",
    "DeliveryHandle::capture(",
    "emit_log(",
];

#[test]
fn every_way_into_the_sink_is_classified() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a source dir") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk(&root.join("src"), &mut files);
    let mut found = std::collections::BTreeMap::new();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // The sink and the ingress define these; tests and test fixtures
        // publish as a backend's call would.
        if name.contains("test")
            || name.contains("fixture")
            || rel.ends_with("transport/notification_sink.rs")
            || rel.ends_with("transport/notify_ingress.rs")
        {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
            for needle in NEEDLES {
                let n = line.matches(needle).count();
                if n > 0 {
                    *found.entry((rel.clone(), *needle)).or_insert(0usize) += n;
                }
            }
        }
    }
    let want: std::collections::BTreeMap<(String, &str), usize> = SINK_ENTRIES
        .iter()
        .map(|(file, needle, n)| (((*file).to_owned(), *needle), *n))
        .collect();
    assert_eq!(
        found, want,
        "a way into the sink changed; classify it above"
    );
}
