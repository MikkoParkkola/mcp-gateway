// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8498: the `WatchClass` to `Charge` mapping, pinned before its
//! copies were merged: the charge a keyed poller starts under, the
//! spellings of the mapping, and the inverse a poller records on a row.

use std::sync::Arc;

use serde_json::json;

use super::*;

/// MIK-8498 pin (P3.8b): the Keyed arm of `on_first_subscriber` starts
/// its poller charged to the holder, not to the global budget. Unlike
/// `watch_polls_are_charged_by_sharing`, which builds its poller through
/// the `run` helper, this drives the product start path and reads the
/// charge the spawned poller polls under.
#[tokio::test]
async fn a_keyed_watch_started_by_first_subscriber_polls_charged_to_its_holder() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("crm", true, CredentialUse::Keyed)]);
    let name = "watch.crm.changed";
    admit(&hub, "p", name, &json!({}));
    host.answers.lock().push_back(json!({"x": 1}));
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let arguments = json!({});
    let key = source.lifecycle_key("p", name, &arguments, now());
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("started");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while host.calls.lock().is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let calls = host.calls.lock().clone();
    assert_eq!(
        calls,
        [("p".to_owned(), Charge::Holder)],
        "a keyed poller polls charged to its holder"
    );
    source.on_last_subscriber(&key).await;
}

/// MIK-8498 (P3.8 guard): the `WatchClass` to `Charge` mapping is
/// one-to-one, and its three spellings agree: `Charge::of` (hold.rs),
/// the inline `if shared` that `on_first_subscriber` spelled before
/// MIK-8498 merged it into `Charge::of` (kept below as written then),
/// and the inverse in `judge_rows` (hold.rs). The class-keyed
/// "principal only when Keyed" also agrees with the Charge-keyed one
/// in `Run::key_of` (watch_source.rs:425).
#[test]
fn every_watch_class_maps_to_one_charge_and_back() {
    // Every variant, written out. The exhaustive match in the loop has
    // no wildcard arm, so a new `WatchClass` variant fails to compile
    // here until it is added to this list and asserted below.
    let classes = [WatchClass::Free, WatchClass::Keyed];
    let principal = "principal";
    for class in classes {
        let () = match class {
            WatchClass::Free => (),
            WatchClass::Keyed => (),
        };
        // (1) `Charge::of`, watch_source/hold.rs:14-22, which
        // `on_first_subscriber` calls (watch_source.rs:334).
        let charge = Charge::of(class);
        // (2) The inline expression `on_first_subscriber` used before
        // MIK-8498, exactly as it was written: `let shared = class ==
        // WatchClass::Free;` feeding `if shared { Charge::Global } else
        // { Charge::Holder }`. It checks that the merge kept the mapping.
        let shared = class == WatchClass::Free;
        let inline_charge = if shared {
            Charge::Global
        } else {
            Charge::Holder
        };
        assert_eq!(
            charge, inline_charge,
            "Charge::of and the inline expression agree for {class:?}"
        );
        // (3) The inverse has no callable form to invoke: it is a local
        // `let class = match self.charge { ... }` inside `Run::judge_rows`
        // (watch_source/hold.rs:65-68), re-stated here exactly.
        let back = match charge {
            Charge::Global => WatchClass::Free,
            Charge::Holder => WatchClass::Keyed,
        };
        assert_eq!(back, class, "the inverse maps back for {class:?}");
        // "Principal only when Keyed": `WatchClass::principal_for`
        // (watch_source.rs:91, called at :271 and :282) against
        // `(self.charge == Charge::Holder).then_some(...)` with this
        // class's charge (watch_source.rs:425).
        let by_class = class.principal_for(principal);
        let by_charge = (charge == Charge::Holder).then_some(principal);
        assert_eq!(
            by_class, by_charge,
            "principal only when Keyed agrees for {class:?}"
        );
    }
}

/// Pins the charge -> class inverse inside `Run::judge_rows`
/// (watch_source/hold.rs:65-68) through its public effect: a poller
/// whose capability is watchable records its own class, derived from
/// its charge, on a live row of its type that has none.
#[tokio::test]
async fn a_poller_records_its_own_class_on_a_row_without_one() {
    {
        let dir = tempfile::tempdir().expect("dir");
        let hub = hub(dir.path());
        let host = fake(vec![target("weather", true, CredentialUse::Free)]);
        admit(&hub, "p", "watch.weather.changed", &json!({}));
        assert_eq!(hub.store.subscriptions()[0].watch_class, None);
        let poller = run(&hub, &host, "p", "watch.weather.changed", &json!({}));
        assert_eq!(poller.charge, Charge::Global);
        poller.once(&hub, &mut None).await;
        assert_eq!(
            hub.store.subscriptions()[0].watch_class,
            Some(WatchClass::Free)
        );
    }
    {
        let dir = tempfile::tempdir().expect("dir");
        let hub = hub(dir.path());
        let host = fake(vec![target("weather", true, CredentialUse::Keyed)]);
        admit(&hub, "p", "watch.weather.changed", &json!({}));
        assert_eq!(hub.store.subscriptions()[0].watch_class, None);
        let poller = run(&hub, &host, "p", "watch.weather.changed", &json!({}));
        assert_eq!(poller.charge, Charge::Holder);
        poller.once(&hub, &mut None).await;
        assert_eq!(
            hub.store.subscriptions()[0].watch_class,
            Some(WatchClass::Keyed)
        );
    }
}
