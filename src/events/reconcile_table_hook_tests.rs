// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Reconcile table (Family-fix MIK-7940, design r3 section 6): the webhook
//! hold rows. Each test is one row: an initial state, a change, and the
//! asserted rows (R), started keys (K) and hold stamps (H), with the worker
//! sweep never run. Rows marked PIN hold on base and must stay green; the
//! rest fail on base at their own assertions until the reconcile step lands.
//!
//! Rows here: T11 (non-watch half, red), T28 (webhook half, PIN), and the
//! hold-write rows (R2, design r3 section 4):
//! - T17 (red): fan-out finishes while a hold's stamp write is paused.
//! - T18 (PIN): a crash before a first hold's row write delays its end by at
//!   most the downtime plus one pass.
//! - T19 (red, retry half): a failed stamp write is retried with no reload;
//!   its in-memory half is pinned by
//!   `a_failed_stamp_write_still_bounds_the_row`.
//! - T20 (PIN until the write leaves the store lock): a delayed stamp write
//!   never revives an unsubscribed row or overwrites a newer one.

use std::time::Duration;

use serde_json::json;

use super::*;
use crate::events::types::SourceKind;

/// The webhook keys started now.
async fn webhook_keys(hub: &EventsHub) -> Vec<String> {
    hub.lifecycle
        .lock()
        .await
        .iter()
        .filter(|(kind, _)| *kind == SourceKind::Webhook)
        .map(|(_, key)| key.clone())
        .collect()
}

/// Whether the webhook keys reach `count` within 50 scheduler turns.
async fn keys_settle(hub: &EventsHub, count: usize) -> bool {
    for _ in 0..50 {
        if webhook_keys(hub).await.len() == count {
            return true;
        }
        tokio::task::yield_now().await;
    }
    false
}

/// T11, non-watch half (MIK-8179 STARTED.1, design r3 K rule): a held
/// webhook row keeps no started key, without waiting for a sweep; the route
/// coming back starts it again.
#[tokio::test]
async fn t11_a_held_webhook_row_releases_its_key() {
    let (_dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    assert_eq!(webhook_keys(&hub).await.len(), 1, "premise: started");
    refresh(&hub, &registry, "");
    assert!(hub.store.held(&id).is_some(), "premise: held");
    // Turns for the posted key reconcile, bounded; no sweep runs.
    assert!(keys_settle(&hub, 0).await, "a held row keeps no key");
    refresh(&hub, &registry, &full());
    assert!(hub.store.held(&id).is_none(), "premise: resumed");
    assert!(keys_settle(&hub, 1).await, "started again");
}

/// T28, webhook half (PIN, #3488): a complete catalogue without the route
/// holds the subscription and deletes nothing; the route coming back
/// resumes it with no subscriber action.
#[tokio::test]
async fn t28_a_dropped_route_holds_the_row_then_resumes() {
    let (_dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    refresh(&hub, &registry, "");
    assert!(hub.store.get(&id).is_some(), "the row is kept");
    assert!(hub.store.held(&id).is_some(), "held");
    refresh(&hub, &registry, &full());
    assert!(hub.store.held(&id).is_none(), "resumed");
}

/// T11, still-offered half (R1a mutants): a row held because the route does
/// not serve its filter, while its type is offered, keeps no key either (the
/// held check in `live_keys`, not the type's absence).
#[tokio::test]
async fn t11_a_row_held_by_a_narrowed_route_releases_its_key() {
    let (_dir, hub, _registry) = restarted(json!({"ref": "main"}), &narrower()).await;
    let answer = subscribe(&hub, json!({"ref": "main"})).await.expect("held");
    assert_eq!(
        answer["held"]["key"], "ref",
        "premise: held, type offered: {answer}"
    );
    assert!(keys_settle(&hub, 0).await, "a held row keeps no key");
}

/// Admit `count` more held-type rows for `q`, straight into the store, each
/// with its own `sha` filter.
fn admit_rows(hub: &EventsHub, count: usize) {
    let config = crate::config::EventsConfig::default();
    for i in 0..count {
        let arguments = json!({"sha": i.to_string()});
        let url = "https://h/q";
        let row: crate::events::records::Subscription = serde_json::from_value(json!({
            "v": 1, "principal": "q",
            "id": crate::events::rpc::subscription_id("q", url, TYPE, &arguments),
            "url": url, "name": TYPE, "arguments": arguments,
            "secret": "whsec_x", "previous_secret": null, "previous_until": null,
            "granted_at": chrono::Utc::now(), "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null,
            "api_key": {"name": "key-q", "principal": "0123456789ab"},
            "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::None)
                .expect("kind"),
        }))
        .expect("row");
        hub.store
            .admit(
                row,
                true,
                crate::events::store::Caps {
                    per_principal: count,
                    global: count + 10,
                },
                chrono::Duration::zero(),
                chrono::Utc::now(),
                crate::events::tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
}

/// An occurrence no subscription matches: fan-out only reads the rows.
fn unrelated() -> crate::events::fanout::SourceEvent {
    crate::events::fanout::SourceEvent {
        kind: SourceKind::Webhook,
        name: "webhook.other.thing".into(),
        backend: "other".into(),
        scope: crate::events::types::Visibility::Backend("other".into()),
        owner: None,
        upstream_id: "u1".into(),
        occurred_at: chrono::Utc::now(),
        data: json!({}),
        lifecycle_key: None,
    }
}

/// T17 (MIK-8133 AC2, design r3 P3): a reload holds 1,000 rows and their
/// first stamp write is paused; fan-out of an occurrence meanwhile still
/// finishes, because no stamp I/O runs under the catalogue gate or the
/// store lock. Red on base: the write runs under both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t17_fan_out_proceeds_while_hold_writes_are_paused() {
    let (_dir, hub, registry) = restarted(json!({}), &full()).await;
    admit_rows(&hub, 999);
    let (reached, release) = hub.store.before_hold_write.arm();
    let hold = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        let registry = Arc::clone(&registry);
        move || refresh(&hub, &registry, "")
    });
    crate::test_pause::within("the first stamp write", reached.notified()).await;
    let fan = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move { hub.fan_out(&services(), &unrelated()).await }
    });
    // Bounded from here, then released, so a blocked fan-out unwinds
    // before the assertion.
    let finished = tokio::time::timeout(Duration::from_secs(5), fan).await;
    release.notify_one();
    crate::test_pause::within("the hold", hold)
        .await
        .expect("join");
    assert!(finished.is_ok(), "fan-out waited for a paused stamp write");
}

/// T19, retry half (MIK-8133 AC3, design r3 P1): a stamp write that failed
/// is retried by the reconcile step itself once the store is writable
/// again, with no further reload and no worker sweep (none runs here). Its
/// in-memory half is pinned by `a_failed_stamp_write_still_bounds_the_row`.
#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn t19_a_failed_stamp_write_is_retried_without_a_reload() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, hub, registry) = restarted(json!({}), &full()).await;
    let _ = subscribe(&hub, json!({})).await.expect("refresh");
    let subs = dir.path().join("subs");
    let mode = |m| std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(m));
    mode(0o500).expect("read-only");
    refresh(&hub, &registry, "");
    mode(0o700).expect("writable");
    assert!(!stamped(dir.path()), "premise: the write failed");
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert!(stamped(dir.path()), "retried with no reload");
}

/// T18 (PIN, MIK-8133 AC1, design r3 P2): a crash after a first hold is
/// applied and before its row is written re-stamps the row at restart, so
/// the hold ends no later than its original end plus the downtime plus one
/// pass. A row held durably before that pass keeps its deadline.
#[cfg(unix)]
#[tokio::test]
async fn t18_a_crash_before_the_stamp_write_delays_the_hold_end_by_the_downtime() {
    use std::os::unix::fs::PermissionsExt;
    // Held durably first, at a restart whose route no longer serves `ref`
    // (a live reload that narrows a type is refused, T52).
    let (dir, hub, registry) = restarted(json!({"ref": "main"}), &narrower()).await;
    let early = id_of(
        &subscribe(&hub, json!({"ref": "main"}))
            .await
            .expect("refresh"),
    );
    let early_until = hub.store.get(&early).and_then(|r| r.held_until);
    assert!(early_until.is_some(), "premise: stamped");
    // Granted under the narrower route, so that route does not hold it.
    let late = id_of(
        &subscribe(&hub, json!({"sha": "x"}))
            .await
            .expect("subscribe"),
    );
    assert!(hub.store.held(&late).is_none(), "premise: served");
    // The crashed pass: the type goes, the late row's stamp is not written.
    let subs = dir.path().join("subs");
    let mode = |m| std::fs::set_permissions(&subs, std::fs::Permissions::from_mode(m));
    mode(0o500).expect("read-only");
    refresh(&hub, &registry, "");
    let late_until = hub.store.get(&late).and_then(|r| r.held_until);
    let crashed = chrono::Utc::now();
    drop(hub);
    mode(0o700).expect("writable");
    let config = crate::config::EventsConfig::default();
    let (hub, _registry) = hub_with(dir.path(), "", &config);
    let downtime = chrono::Utc::now() - crashed;
    let one_pass = chrono::Duration::seconds(5);
    let restamped = hub.store.get(&late).and_then(|r| r.held_until);
    let (Some(late_until), Some(restamped)) = (late_until, restamped) else {
        panic!("held before and after the restart: {late_until:?}, {restamped:?}");
    };
    assert!(
        restamped <= late_until + downtime + one_pass,
        "{restamped} past {late_until} + downtime + one pass"
    );
    assert_eq!(
        hub.store.get(&early).and_then(|r| r.held_until),
        early_until,
        "a row held before the crashed pass keeps its deadline"
    );
}

/// The stored copy of row `id`, or `None` when its file is gone.
fn on_disk(dir: &std::path::Path, id: &str) -> Option<serde_json::Value> {
    let bytes = std::fs::read(dir.join("subs").join(format!("{id}.json"))).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// A hold of beta's rows whose first stamp write pauses; returns once it
/// is paused, with its release and its handle.
async fn paused_hold(
    hub: &Arc<EventsHub>,
    registry: &Registry,
) -> (Arc<tokio::sync::Notify>, tokio::task::JoinHandle<()>) {
    let (reached, release) = hub.store.before_hold_write.arm();
    let hold = tokio::task::spawn_blocking({
        let hub = Arc::clone(hub);
        let registry = Arc::clone(registry);
        move || refresh(&hub, &registry, "")
    });
    crate::test_pause::within("the stamp write", reached.notified()).await;
    (release, hold)
}

/// T20, unsubscribe half (PIN, MIK-8133 P1, design r3 G3): an unsubscribe
/// that lands while a hold's stamp write is paused stays done: the delayed
/// write never revives the row. On base the write runs under the store
/// lock, so the unsubscribe waits for it; the row bites once the write
/// leaves the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t20_a_delayed_stamp_write_never_revives_an_unsubscribed_row() {
    let (dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    let (release, hold) = paused_hold(&hub, &registry).await;
    // Spawned, never awaited while paused: on base it waits for the lock.
    let gone = tokio::task::spawn_blocking({
        let hub = Arc::clone(&hub);
        let id = id.clone();
        move || {
            let tail = crate::events::tail_policy(&hub.config);
            hub.store.remove(&id, chrono::Utc::now(), tail)
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();
    crate::test_pause::within("the hold", hold)
        .await
        .expect("join");
    let removed = crate::test_pause::within("the unsubscribe", gone)
        .await
        .expect("join");
    assert!(removed.expect("io"), "premise: unsubscribed");
    assert!(hub.store.get(&id).is_none(), "deleted stays deleted");
    assert!(on_disk(dir.path(), &id).is_none(), "and stays off disk");
}

/// T20, newer-row half (PIN, MIK-8133 P1, design r3 G3): a refresh that
/// commits while a hold's stamp write is paused is the row kept, in memory
/// and on disk; the delayed write never overwrites it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t20_a_delayed_stamp_write_never_overwrites_a_newer_row() {
    let (dir, hub, registry) = restarted(json!({}), &full()).await;
    let id = id_of(&subscribe(&hub, json!({})).await.expect("refresh"));
    let (release, hold) = paused_hold(&hub, &registry).await;
    let newer = tokio::spawn({
        let hub = Arc::clone(&hub);
        async move { subscribe(&hub, json!({})).await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    release.notify_one();
    crate::test_pause::within("the hold", hold)
        .await
        .expect("join");
    let answer = crate::test_pause::within("the refresh", newer)
        .await
        .expect("join");
    assert!(answer.is_ok(), "premise: refreshed: {answer:?}");
    let kept = hub.store.get(&id).expect("the row is kept");
    let stored = on_disk(dir.path(), &id).expect("the row is on disk");
    assert_eq!(
        stored["generation"],
        json!(kept.generation),
        "the disk holds the newest row, not the delayed write"
    );
}
