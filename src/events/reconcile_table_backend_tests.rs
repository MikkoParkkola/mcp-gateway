// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6): the backend
//! rows that need no upstream fixture. Each test is one row with the worker
//! sweep never run: rows (R) and started keys (K) are asserted; upstream work
//! (U) is asserted by the rows built on the upstream listener fixture.
//! Rows fail on base at their own assertions until the reconcile step lands.
//!
//! First pass by evsources; evcore corrects the backend and upstream rows.
//!
//! Rows still to write, each with its anchor and assertion:
//! - T02 re-add: rows of a removed backend come back; K started and the
//!   parked upstream task woken within 1 s, not by its 30 s timer
//!   (`upstream_session.rs:154-165`). Upstream fixture.
//! - T03 hot-add during the startup reconcile: the new backend's row is kept
//!   and started (F3; `backend_source.rs:172-184`). Needs the R1 pass pause.
//! - T04 publish order: the listen handle is visible whenever the transport
//!   is (`repin.rs:20` against `lifecycle.rs:527`). Upstream fixture.
//! - T05/T06 snapshot: after a replace, or after the last URI interest leaves,
//!   `authorize_uri` reads live, not the old snapshot
//!   (`upstream_listener.rs:361-391`). Upstream fixture.
//! - T07 a re-subscribe that commits between a removal pass's judgement and
//!   its delete survives (G3 generation check). Needs the R1 pass pause.
//! - T08 debug-build lock-order assert on every deleting path. R1 only.
//! - T09 startup withdraw: absent-backend rows never start K or U
//!   (`runtime.rs:118` order). Hub start fixture.
//! - T10 expiry releases K at the expiry tick, without a sweep. Needs the
//!   worker tick running (L5).
//! - T13 ineligible with no live task: the three upstream kinds are
//!   withdrawn, `tools_changed` kept (`upstream_session.rs:116`). Upstream fixture.
//! - T14 an eligibility flip waits for the pass's gate. Needs the R1 pause.
//! - T15 a flavour flip published at the worker's `before_send` pause
//!   (`worker.rs:378`) is refused at admit; nothing delivered. R2.
//! - T16 (PIN) a send in progress does not block detection. R2.
//! - T27 a burst of 100 causes before the first pass costs 1 pass, and one
//!   cause during it exactly 1 more. Needs the R1 pass counter.

use super::*;

/// Every backend event kind for backend `x`.
const KINDS: [&str; 4] = [
    "tools_changed",
    "resources_changed",
    "resource_updated",
    "prompts_changed",
];

/// Admit `p`'s row for `backend.x.<kind>`.
fn admit_kind(hub: &EventsHub, kind: &str) {
    admit_on(hub, "x", kind);
}

/// Admit `p`'s row for `backend.<backend>.<kind>`.
fn admit_on(hub: &EventsHub, backend: &str, kind: &str) {
    let config = crate::config::EventsConfig::default();
    let row: records::Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": format!("sub_{backend}_{kind}"), "principal": "p", "url": "https://h/x",
        "name": format!("backend.{backend}.{kind}"), "arguments": {}, "secret": "whsec_x",
        "previous_secret": null, "previous_until": null,
        "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    hub.store
        .admit(
            row,
            true,
            store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            chrono::Utc::now(),
            tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
}

/// T01 (MIK-7897 LIFE.1, design r3 D1a): a backend absent from a complete
/// view withdraws every one of its kinds and releases their keys, with no
/// sweep.
#[tokio::test]
async fn t01_a_removed_backend_withdraws_every_kind_and_its_keys() {
    let (hub, _dir) = hub();
    let names = Arc::new(parking_lot::Mutex::new(vec!["x".to_owned()]));
    let live = Arc::clone(&names);
    hub.install_backend_source(Arc::new(move || live.lock().clone()));
    for kind in KINDS {
        admit_kind(&hub, kind);
    }
    hub.replay_starts().await;
    assert!(
        !hub.lifecycle.lock().await.is_empty(),
        "premise: keys started"
    );
    names.lock().clear();
    hub.backend_tools_changed("x");
    tokio::task::yield_now().await;
    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert!(left.is_empty(), "withdrawn with the backend: {left:?}");
    assert!(hub.lifecycle.lock().await.is_empty(), "their keys released");
}

/// A registered backend `b` that never answers.
fn silent_backend() -> Arc<crate::backend::Backend> {
    let config = crate::config::BackendConfig {
        transport: crate::config::TransportConfig::Http {
            http_url: "http://127.0.0.1:9/mcp".to_owned(),
            streamable_http: Some(true),
            protocol_version: None,
        },
        timeout: std::time::Duration::from_secs(1),
        ..crate::config::BackendConfig::default()
    };
    Arc::new(crate::backend::Backend::new(
        "b",
        config,
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

/// T02 (MIK-7897 LIFE.2, design r3 L2, finding #7): a held row of a backend
/// that was not registered gets its upstream listener within a second of the
/// backend's registration announce, not at the 30 s revive sweep.
#[tokio::test(start_paused = true)]
async fn t02_a_re_added_backend_is_listened_to_at_once() {
    let (hub, _dir) = hub();
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let none: backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["b".to_owned()]),
        Arc::clone(&registry),
        none,
    );
    admit_on(&hub, "b", "resources_changed");
    hub.replay_starts().await;
    let source = hub
        .source(types::SourceKind::BackendNotification)
        .expect("source");
    assert_eq!(source.upstream_starts(), 0, "premise: b is not registered");
    assert!(registry.register(silent_backend()));
    // What the registry's announce drives (tools_changed.rs drain).
    hub.backend_tools_changed("b");
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        source.upstream_starts(),
        1,
        "listened to within a second of the re-add"
    );
}
