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
    admit_on_at(hub, backend, kind, chrono::Utc::now());
}

/// [`admit_on`] granted at `at` (the store grants at the later of `at` and
/// its clock, so a future `at` fixes the grant time).
fn admit_on_at(hub: &EventsHub, backend: &str, kind: &str, at: chrono::DateTime<chrono::Utc>) {
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
            at,
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

/// T13 (MIK-8180 INELIG.1, design r3 D3, finding #4): a backend that turns
/// ineligible while no listener task runs for it loses its three
/// upstream-kind rows at the announce; `tools_changed` stays.
#[tokio::test(start_paused = true)]
async fn t13_an_ineligible_backend_with_no_task_loses_its_upstream_rows() {
    let (hub, _dir) = hub();
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&refused);
    let ineligible: backend_source::Ineligible = Arc::new(move || {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            std::iter::once("b".to_owned()).collect()
        } else {
            std::collections::BTreeSet::new()
        }
    });
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["b".to_owned()]),
        Arc::clone(&registry),
        ineligible,
    );
    for kind in KINDS {
        admit_on(&hub, "b", kind);
    }
    // No listener task: the rows were stored while b was unregistered.
    assert!(registry.register(silent_backend()));
    refused.store(true, std::sync::atomic::Ordering::SeqCst);
    hub.backend_tools_changed("b");
    tokio::task::yield_now().await;
    let mut left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["backend.b.tools_changed".to_owned()],
        "upstream kinds withdrawn, tools_changed kept"
    );
}

/// T07 (MIK-8178 WRECHECK.1, design r3 G3, finding #2): a withdraw deletes
/// only the rows it judged. A client that unsubscribes and subscribes again
/// meanwhile (the same id, a new row) keeps its new subscription.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_a_row_re_made_during_a_withdraw_survives() {
    let (hub, _dir) = hub();
    hub.install_backend_source(Arc::new(|| vec!["x".to_owned()]));
    admit_kind(&hub, "tools_changed");
    let (reached, release) = hub.before_withdraw.arm();
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.withdraw(&["backend.x.tools_changed".to_owned()])
    });
    crate::test_pause::within("the withdraw judging", reached.notified()).await;
    let tail = tail_policy(&hub.config);
    hub.store
        .remove("sub_x_tools_changed", chrono::Utc::now(), tail)
        .expect("unsubscribed");
    admit_kind(&hub, "tools_changed");
    release.notify_one();
    crate::test_pause::within("the withdraw", pass)
        .await
        .expect("join");
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "the re-made row survives the stale withdraw"
    );
}

/// T09 PIN (MIK-8179 STARTED.2, design r3 L1, findings #5/#6): at startup a
/// row of a backend absent from the configuration starts no key and no
/// listener, before or after the startup reconcile withdraws it. Holds on
/// base because an absent backend's names are not offered; R1 moves replay
/// after the reconcile and must keep it so.
#[tokio::test(start_paused = true)]
async fn t09_an_absent_backends_row_never_starts_at_startup() {
    let (hub, _dir) = hub();
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let none: backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.install_backend_source_with_upstream(Arc::new(Vec::new), registry, none);
    admit_on(&hub, "x", "resources_changed");
    hub.replay_starts().await;
    assert!(
        hub.reconcile_catalogue(fanout::CatalogueScan::Complete),
        "startup reconcile done"
    );
    tokio::task::yield_now().await;
    let source = hub
        .source(types::SourceKind::BackendNotification)
        .expect("source");
    assert_eq!(source.upstream_starts(), 0, "no listener for x");
    assert!(hub.lifecycle.lock().await.is_empty(), "no key for x");
    assert!(hub.store.subscriptions().is_empty(), "x's row withdrawn");
}

/// T07, second half (R1a review HIGH): a delivery status written between a
/// withdraw's judgement and its delete is the same subscription, so it
/// still goes rather than being skipped with no retry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_a_row_touched_during_a_withdraw_still_goes() {
    let (hub, _dir) = hub();
    hub.install_backend_source(Arc::new(|| vec!["x".to_owned()]));
    admit_kind(&hub, "tools_changed");
    let (reached, release) = hub.before_withdraw.arm();
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.withdraw(&["backend.x.tools_changed".to_owned()])
    });
    crate::test_pause::within("the withdraw judging", reached.notified()).await;
    hub.store
        .suspend("sub_x_tools_changed")
        .expect("status written");
    release.notify_one();
    crate::test_pause::within("the withdraw", pass)
        .await
        .expect("join");
    assert!(
        hub.store.subscriptions().is_empty(),
        "the touched row is withdrawn"
    );
}

/// T02, parked-key half (R1a review MEDIUM): a `tools_changed` key started
/// while its backend was unregistered is parked in the listeners; the
/// backend's registration wakes it within a second, not at the sweep.
#[tokio::test(start_paused = true)]
async fn t02_a_parked_tools_key_is_listened_to_at_registration() {
    let (hub, _dir) = hub();
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let none: backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["b".to_owned()]),
        Arc::clone(&registry),
        none,
    );
    admit_on(&hub, "b", "tools_changed");
    hub.replay_starts().await;
    assert!(
        !hub.lifecycle.lock().await.is_empty(),
        "premise: the tools key started, parked"
    );
    let source = hub
        .source(types::SourceKind::BackendNotification)
        .expect("source");
    assert_eq!(source.upstream_starts(), 0, "premise: no task yet");
    assert!(registry.register(silent_backend()));
    hub.backend_tools_changed("b");
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(source.upstream_starts(), 1, "listened to at registration");
}

/// T10, removal half (R1a review MEDIUM): any removed row counts, so the
/// worker tick releases its key whichever path removed it.
#[test]
fn t10_every_row_removal_is_counted_for_the_tick() {
    let (hub, _dir) = hub();
    admit_kind(&hub, "tools_changed");
    let now = chrono::Utc::now();
    let (_, before) = hub.store.lapses(now, now);
    let tail = tail_policy(&hub.config);
    assert!(
        hub.store
            .remove("sub_x_tools_changed", now, tail)
            .expect("removed")
    );
    let (_, after) = hub.store.lapses(now, now);
    assert_eq!(after, before + 1, "the removal is counted");
}

/// T07, same-tick half (lead ruling on the R1a review): a re-grant whose
/// grant time equals the judged row's is still a new incarnation, so the
/// stale withdraw leaves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_a_re_grant_in_the_same_tick_survives() {
    let (hub, _dir) = hub();
    hub.install_backend_source(Arc::new(|| vec!["x".to_owned()]));
    let tick = chrono::Utc::now() + chrono::Duration::hours(1);
    admit_on_at(&hub, "x", "tools_changed", tick);
    let (reached, release) = hub.before_withdraw.arm();
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.withdraw(&["backend.x.tools_changed".to_owned()])
    });
    crate::test_pause::within("the withdraw judging", reached.notified()).await;
    let tail = tail_policy(&hub.config);
    hub.store
        .remove("sub_x_tools_changed", chrono::Utc::now(), tail)
        .expect("unsubscribed");
    admit_on_at(&hub, "x", "tools_changed", tick);
    let regranted = hub.store.subscriptions();
    assert_eq!(
        regranted[0].granted_at, tick,
        "premise: the same grant time"
    );
    release.notify_one();
    crate::test_pause::within("the withdraw", pass)
        .await
        .expect("join");
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "the re-grant survives the stale withdraw"
    );
}

/// T07, restart half (lead ruling): the generation counter is seeded from
/// the highest persisted generation (store.rs `Store::open`), so a grant
/// after a restart never reuses a persisted row's incarnation, and a stale
/// withdraw leaves the re-grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t07_a_re_grant_after_a_restart_survives() {
    let (hub, dir) = hub();
    admit_kind(&hub, "tools_changed");
    let before = hub.store.subscriptions()[0].incarnation;
    drop(hub);
    let hub =
        EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("reopened");
    hub.install_backend_source(Arc::new(|| vec!["x".to_owned()]));
    assert_eq!(
        hub.store.subscriptions()[0].incarnation,
        before,
        "premise: the persisted incarnation"
    );
    let (reached, release) = hub.before_withdraw.arm();
    let pass = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        move || hub.withdraw(&["backend.x.tools_changed".to_owned()])
    });
    crate::test_pause::within("the withdraw judging", reached.notified()).await;
    let tail = tail_policy(&hub.config);
    hub.store
        .remove("sub_x_tools_changed", chrono::Utc::now(), tail)
        .expect("unsubscribed");
    admit_kind(&hub, "tools_changed");
    assert!(
        hub.store.subscriptions()[0].incarnation > before,
        "the re-grant is a new incarnation"
    );
    release.notify_one();
    crate::test_pause::within("the withdraw", pass)
        .await
        .expect("join");
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "the re-grant survives the stale withdraw"
    );
}

/// T06, revocation half (R1a d1 review CRITICAL): a catalogue read revokes
/// only rows granted before it began; a grant after it is not judged by it.
#[tokio::test]
async fn t06_a_read_revokes_only_grants_it_covered() {
    let (hub, _dir) = hub();
    let config = crate::config::EventsConfig::default();
    let row: records::Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": "sub_uri", "principal": "p", "url": "https://h/x",
        "name": "backend.b.resource_updated", "arguments": {"uri": "file:///x"},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
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
    let granted = hub.store.subscriptions()[0].incarnation;
    let listed = std::collections::HashSet::new();
    hub.revoke_absent_uris("b", &listed, granted - 1).await;
    assert_eq!(
        hub.store.subscriptions().len(),
        1,
        "a grant after the read began is kept"
    );
    hub.revoke_absent_uris("b", &listed, granted).await;
    assert!(
        hub.store.subscriptions().is_empty(),
        "a grant the read covered and that is absent goes"
    );
}
