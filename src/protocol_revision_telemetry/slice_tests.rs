// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! U1 v2: per-transport slices, the agent breakdown and the seal check.
//! Each row counts into its own registry, never the process-wide one.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::json;

use super::observe::{HttpCaller, observe_into};
use super::{Registry, Transport};

#[test]
fn a_stdio_request_never_appears_in_the_http_slice() {
    let mut registry = Registry::new();
    for _ in 0..3 {
        registry.observe_request_from(Some("2025-11-25"), "claude", Transport::Http, None);
    }
    registry.observe_request_from(Some("2025-06-18"), "codex", Transport::Stdio, None);
    registry.observe_request_from(None, "codex", Transport::Internal, None);

    let http = registry.transport_snapshot(Transport::Http);
    assert_eq!(http.total, 3);
    assert_eq!(http.by_revision.get("2025-11-25"), Some(&3));
    assert_eq!(http.by_transport.get("http"), Some(&3));
    assert!(!http.by_transport.contains_key("stdio"));
    assert!(!http.by_transport.contains_key("internal"));

    let stdio = registry.transport_snapshot(Transport::Stdio);
    assert_eq!(stdio.total, 1);
    assert_eq!(stdio.by_revision.get("2025-06-18"), Some(&1));
    // The merged public view is unchanged.
    assert_eq!(registry.snapshot().total, 5);
}

#[test]
fn a_missing_revision_is_broken_down_by_bounded_caller() {
    let mut registry = Registry::new();
    registry.observe_request_from(None, "unattributed", Transport::Http, Some("curl/8.4.0"));
    registry.observe_request_from(None, "my-script", Transport::Http, Some("curl/8.0"));
    registry.observe_request_from(None, "Claude Code", Transport::Http, Some("node"));
    registry.observe_request_from(Some("2025-11-25"), "x", Transport::Http, Some("curl/8"));

    let agents = registry.missing_revision_agents(Transport::Http);
    assert_eq!(agents.get("curl"), Some(&2));
    assert_eq!(agents.get("claude"), Some(&1));
    assert_eq!(
        agents.values().sum::<u64>(),
        2 + 1,
        "a declared revision is not broken down"
    );
    assert!(
        agents.keys().all(|key| !key.contains('/')),
        "a raw agent reached the map: {agents:?}"
    );
}

fn observe(registry: &Mutex<Registry>, method: &str, sealed: &AtomicBool) -> bool {
    observe_into(
        registry,
        &json!({"jsonrpc": "2.0", "id": 7, "method": method}),
        None,
        method,
        Some("2025-11-25"),
        None,
        Transport::Http,
        Some(HttpCaller {
            user_agent: Some("curl/8.4.0"),
            sealed,
        }),
    )
}

#[test]
fn a_sealed_gateway_refuses_and_does_not_count() {
    let registry = Mutex::new(Registry::new());
    let sealed = AtomicBool::new(false);
    assert!(observe(&registry, "tools/list", &sealed));
    sealed.store(true, Ordering::SeqCst);
    assert!(
        !observe(&registry, "tools/list", &sealed),
        "a request after the seal must be refused"
    );
    let registry = registry.into_inner().expect("not poisoned");
    assert_eq!(registry.transport_snapshot(Transport::Http).total, 1);
    assert_eq!(
        registry.snapshot().total,
        1,
        "a refused request is not counted"
    );
}

#[test]
fn a_notification_is_never_refused_or_counted() {
    let registry = Mutex::new(Registry::new());
    let sealed = AtomicBool::new(true);
    assert!(observe(&registry, "notifications/initialized", &sealed));
    assert_eq!(
        registry
            .into_inner()
            .expect("not poisoned")
            .snapshot()
            .total,
        0
    );
}

#[test]
fn stdio_is_never_refused() {
    let registry = Mutex::new(Registry::new());
    let served = observe_into(
        &registry,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        None,
        "ping",
        None,
        None,
        Transport::Stdio,
        None,
    );
    assert!(served);
    let registry = registry.into_inner().expect("not poisoned");
    assert_eq!(registry.transport_snapshot(Transport::Stdio).total, 1);
}

#[test]
fn the_missing_revision_breakdown_is_kept_per_transport() {
    // An HTTP segment writes only HTTP callers, and stdio only stdio's.
    let mut registry = Registry::new();
    registry.observe_request_from(None, "other", Transport::Http, Some("curl/8.4.0"));
    registry.observe_request_from(None, "other", Transport::Stdio, Some("node"));
    registry.observe_request_from(None, "other", Transport::Internal, Some("xh/0.22"));
    let http = registry.missing_revision_agents(Transport::Http);
    assert_eq!(http.len(), 1, "{http:?}");
    assert_eq!(http.get("curl"), Some(&1));
    let stdio = registry.missing_revision_agents(Transport::Stdio);
    assert_eq!(stdio.get("node"), Some(&1));
    assert!(
        !stdio.contains_key("curl") && !stdio.contains_key("xh"),
        "{stdio:?}"
    );
}
