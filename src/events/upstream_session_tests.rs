// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener's frame routing that need no peer.

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::events::upstream_need::{Interest, Need, Snapshot, WINDOW};

fn shared() -> Arc<Shared> {
    shared_with(Arc::new(std::collections::BTreeSet::new))
}

fn shared_with(ineligible: crate::events::backend_source::Ineligible) -> Arc<Shared> {
    Arc::new(Shared {
        name: "b".to_owned(),
        need: Mutex::new(Need::default()),
        snapshot: Mutex::new(Snapshot::default()),
        wake: watch::channel(0).0,
        stop: CancellationToken::new(),
        gate: Arc::default(),
        ineligible,
    })
}

/// A graceful end of the current stream ends the session (so it reconnects);
/// the end of a replacement still being opened ends nothing.
#[test]
fn a_graceful_end_ends_only_the_current_stream() {
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    assert!(state.note(UpstreamNote::End, false));
    assert!(!state.note(UpstreamNote::End, true));
}

/// A watched URI the catalogue snapshot lacks is never emitted; once the
/// snapshot lists it, it is.
#[tokio::test]
async fn emission_waits_for_the_snapshot_to_list_the_uri() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ResourceUpdated("file:///a".to_owned()))
        .expect("room");
    let mut state = State::new(&shared, Era::Modern);
    let changed = || UpstreamNote::Notice {
        kind: NoteKind::ResourceUpdated,
        uri: Some("file:///a".to_owned()),
    };
    shared
        .snapshot
        .lock()
        .read(std::collections::HashSet::new(), true);
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(
        intake.try_recv().is_err(),
        "absent from the snapshot: silent"
    );
    shared
        .snapshot
        .lock()
        .read(["file:///a".to_owned()].into(), true);
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(intake.try_recv().is_ok(), "listed: one event");
}

/// MIK-7894: a backend the live config makes ineligible after its listener
/// started delivers nothing more, and its task is stopped. Control: the same
/// listener emits while the backend is still eligible.
#[tokio::test]
async fn a_backend_made_ineligible_after_start_emits_nothing_and_stops() {
    let refused = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&refused);
    let shared = shared_with(Arc::new(move || {
        if flag.load(std::sync::atomic::Ordering::SeqCst) {
            std::iter::once("b".to_owned()).collect()
        } else {
            std::collections::BTreeSet::new()
        }
    }));
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    // The backend's listener-only subscription and the one the gateway also
    // announces itself.
    let (config, now) = (crate::config::EventsConfig::default(), chrono::Utc::now());
    for name in ["backend.b.resources_changed", "backend.b.tools_changed"] {
        let sub: crate::events::records::Subscription = serde_json::from_value(json!({
            "v": 1, "id": format!("sub_{name}"), "principal": "p", "url": "https://h/x",
            "name": name, "arguments": {}, "secret": "whsec_x", "previous_secret": null,
            "previous_until": null, "granted_at": now, "expires_at": null, "active": true,
            "failed_since": null, "last_delivery_at": null, "last_error": null
        }))
        .expect("subscription");
        hub.store
            .admit(
                sub,
                true,
                crate::events::store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                now,
                crate::events::tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    let mut state = State::new(&shared, Era::Modern);
    let changed = || UpstreamNote::Notice {
        kind: NoteKind::ResourcesChanged,
        uri: None,
    };
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(intake.try_recv().is_ok(), "control: eligible, one event");
    assert_eq!(hub.store.subscriptions().len(), 2, "control: both held");
    assert!(!shared.stop.is_cancelled());

    refused.store(true, std::sync::atomic::Ordering::SeqCst);
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(
        intake.try_recv().is_err(),
        "an ineligible backend still delivered"
    );
    assert!(shared.stop.is_cancelled(), "its listener was not stopped");
    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(
        left,
        ["backend.b.tools_changed"],
        "the listener-only subscription outlived the backend's eligibility"
    );
}

/// MIK-7894: a listener whose backend is ineligible when it (re)connects ends
/// at the head of its loop instead of connecting.
#[tokio::test]
async fn a_listener_for_an_ineligible_backend_ends_at_the_loop_head() {
    let shared = shared_with(Arc::new(|| std::iter::once("b".to_owned()).collect()));
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    tokio::time::timeout(
        Duration::from_secs(5),
        run(Arc::clone(&shared), registry, Arc::downgrade(&hub)),
    )
    .await
    .expect("the task ended instead of parking or connecting");
    assert!(shared.stop.is_cancelled());
}
