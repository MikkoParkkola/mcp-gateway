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
        ledger: Mutex::new(Arc::default()),
        resolve: Box::new(|| None),
        recycle: RECYCLE,
        snapshot: Mutex::new(Snapshot::default()),
        wake: watch::channel(0).0,
        stop: CancellationToken::new(),
        gate: Arc::default(),
        ineligible,
        tools: Mutex::default(),
        before_park: Arc::default(),
        before_backoff: Arc::default(),
        ran_interactive: Mutex::default(),
    })
}

/// Admit `backend.b.resources_changed` (listener-only) and
/// `backend.b.tools_changed` (the gateway announces it itself).
fn admit_both(hub: &EventsHub) {
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
}

/// The subscription names left once a withdrawal removed one of the two.
async fn after_withdrawal(hub: &EventsHub) -> Vec<String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let left: Vec<String> = hub
                .store
                .subscriptions()
                .into_iter()
                .map(|s| s.name)
                .collect();
            if left.len() < 2 {
                return left;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the withdrawal ran")
}

/// A gateway config file and the reload pipeline the watcher and admin API
/// run over it, starting from an empty running config.
struct Reload {
    path: std::path::PathBuf,
    ctx: crate::config_reload::ReloadContext,
    live: Arc<crate::config_reload::LiveConfig>,
    registry: Arc<BackendRegistry>,
}

impl Reload {
    fn new(dir: &std::path::Path) -> Self {
        let path = dir.join("gateway.yaml");
        let live = Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        ));
        let registry = Arc::new(BackendRegistry::new());
        let ctx = crate::config_reload::ReloadContext::new(
            path.clone(),
            Arc::clone(&live),
            Arc::clone(&registry),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("context");
        Self {
            path,
            ctx,
            live,
            registry,
        }
    }

    /// Rewrite the file with backend `b` (Streamable HTTP or not), then reload.
    async fn to(&self, streamable: bool) {
        crate::gateway::test_helpers::write_owner_only(
            &self.path,
            format!(
                "backends:\n  b:\n    http_url: \"http://127.0.0.1:9/mcp\"\n    \
                 streamable_http: {streamable}\n"
            ),
        )
        .expect("write");
        self.ctx.reload_outcome().await.expect("reload");
    }
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
    let mut state = State::new(&shared, Era::Legacy);
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
    admit_both(&hub);
    let mut state = State::new(&shared, Era::Legacy);
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

    // T19 (MIK-7969): eligibility returns before the withdrawal gets the
    // lifecycle lock (a subscribe holds it). Nothing pending is sent, nothing
    // is withdrawn, and the listener keeps running and delivering.
    let held = hub.lifecycle.lock().await;
    refused.store(true, std::sync::atomic::Ordering::SeqCst);
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    assert!(state.flush(&weak), "the flush saw the backend ineligible");
    assert!(
        intake.try_recv().is_err(),
        "an ineligible backend still delivered"
    );
    let ending = tokio::spawn({
        let (shared, weak) = (Arc::clone(&shared), weak.clone());
        async move { super::end_ineligible(&shared, &weak).await }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !shared.stop.is_cancelled(),
        "stopped before the locked recheck"
    );
    refused.store(false, std::sync::atomic::Ordering::SeqCst);
    drop(held);
    assert!(
        !ending.await.expect("task"),
        "a restored backend's listener was ended"
    );
    assert!(
        !shared.stop.is_cancelled(),
        "a restored listener was stopped"
    );
    assert_eq!(
        hub.store.subscriptions().len(),
        2,
        "a withdrawal outlived the restore and deleted subscriptions"
    );
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    assert!(!state.flush(&weak));
    assert!(intake.try_recv().is_ok(), "delivery resumes once restored");

    // Still ineligible when the lock is had: the listener stops and the
    // listener-only subscription goes.
    refused.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(super::end_ineligible(&shared, &weak).await);
    assert!(shared.stop.is_cancelled(), "its listener was not stopped");
    let left = after_withdrawal(&hub).await;
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

/// MIK-7894 ELIG.4: a real config reload (the file rewritten, then
/// `ReloadContext::reload_outcome`, as the watcher and admin API run it) that
/// makes a running listener's backend ineligible. The live predicate the
/// gateway wires refuses authorization, the listener task ends on its own,
/// nothing more reaches intake, and only the listener-only subscription goes.
#[tokio::test]
async fn a_real_reload_making_the_backend_ineligible_stops_its_listener() {
    use crate::events::EventSource as _;
    use crate::events::backend_source::{BackendSource, Upstream};

    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    let registry = Arc::clone(&reload.registry);
    let ineligible =
        crate::events::upstream_live_ineligible(Arc::clone(&reload.live), Arc::clone(&registry));

    // Reload 1 adds `b`, eligible (Streamable HTTP).
    reload.to(true).await;
    assert!(registry.get("b").is_some(), "reload 1 did not register b");
    assert!(ineligible().is_empty(), "b must start eligible");

    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    admit_both(&hub);
    let source = BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: Some(Upstream {
            listeners: crate::events::upstream_listener::UpstreamListeners::new(
                Arc::clone(&registry),
                weak.clone(),
                Arc::clone(&ineligible),
            ),
            ineligible: Arc::clone(&ineligible),
        }),
    };
    let shared = shared_with(Arc::clone(&ineligible));
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    let task = tokio::spawn(run(
        Arc::clone(&shared),
        Arc::clone(&registry),
        weak.clone(),
    ));

    // Control: past one failed connect and its backoff, the loop head
    // re-checked an eligible backend and kept going; it emits and authorizes.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    assert!(!task.is_finished(), "control: an eligible listener ended");
    assert!(!shared.stop.is_cancelled());
    let mut state = State::new(&shared, Era::Legacy);
    let changed = || UpstreamNote::Notice {
        kind: NoteKind::ResourcesChanged,
        uri: None,
    };
    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(intake.try_recv().is_ok(), "control: eligible, one event");
    assert!(
        source
            .authorize("p", "backend.b.resources_changed", &json!({}))
            .await
            .is_ok()
    );

    // Reload 2: the file drops Streamable HTTP, so `b` is ineligible.
    reload.to(false).await;
    assert!(
        ineligible().contains("b"),
        "reload 2 did not reach the live predicate"
    );

    let refused = source
        .authorize("p", "backend.b.resources_changed", &json!({}))
        .await
        .expect_err("an ineligible backend was authorized after the reload");
    assert_eq!(refused.code, -32012);

    // The task ends by itself (no flush drives it), at its loop head.
    tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("the listener kept running after the reload")
        .expect("task");
    assert!(shared.stop.is_cancelled(), "the listener was not stopped");

    state.note(changed(), false);
    tokio::time::sleep(WINDOW + Duration::from_millis(100)).await;
    state.flush(&weak);
    assert!(
        intake.try_recv().is_err(),
        "an ineligible backend still delivered"
    );

    let left = after_withdrawal(&hub).await;
    assert_eq!(left, ["backend.b.tools_changed"]);
}

/// MIK-7969 H2: every arm of the tick decision. Only a live read of the SSE
/// handshake that the shared predicate confirms ends the listener; the
/// predicate is not read otherwise.
#[test]
fn a_tick_ends_the_listener_only_on_a_confirmed_switch_to_sse() {
    use super::{OnTick, on_tick};
    let unread = || -> bool { panic!("the predicate was read for a non-SSE transport") };
    assert_eq!(on_tick(Some(true), unread), OnTick::Keep, "streamable");
    assert_eq!(
        on_tick(None, unread),
        OnTick::Keep,
        "undetected is not refused"
    );
    assert_eq!(on_tick(Some(false), || true), OnTick::EndIneligible);
    assert_eq!(
        on_tick(Some(false), || false),
        OnTick::Keep,
        "eligible again by the time it is asked"
    );
}

/// MIK-7969 H2 + T11: a session recovery that switches the installed
/// transport in place is seen by the next tick, through the backend's live
/// read, with no notification on the stream.
#[test]
fn a_tick_sees_an_in_place_switch_through_the_live_read() {
    use super::{OnTick, on_tick};
    let backend = crate::backend::Backend::new(
        "b",
        serde_yaml::from_str("http_url: http://127.0.0.1:9/mcp").expect("config"),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    let transport = crate::transport::HttpTransport::new(
        "http://127.0.0.1:9/mcp",
        std::collections::HashMap::new(),
        Duration::from_secs(1),
        true,
    )
    .expect("transport");
    backend.install_http_for_test(&transport);
    transport.set_detected(Some(true));
    assert_eq!(
        on_tick(backend.connected_streamable(), || true),
        OnTick::Keep
    );
    transport.set_detected(Some(false));
    assert_eq!(
        on_tick(backend.connected_streamable(), || true),
        OnTick::EndIneligible
    );
}

/// MIK-7950 FIX.3: the default catalogue cache TTL, which the session now
/// re-reads at, is the 300 s the fixed interval was; a zero TTL re-reads at
/// most once a second and a huge one at least daily, without overflow.
#[test]
fn the_snapshot_interval_follows_the_cache_ttl_within_bounds() {
    let default = crate::config::MetaMcpConfig::default().cache_ttl;
    assert_eq!(snapshot_interval(default), Duration::from_secs(300));
    assert_eq!(
        snapshot_interval(Duration::from_secs(2)),
        Duration::from_secs(2)
    );
    assert_eq!(snapshot_interval(Duration::ZERO), Duration::from_secs(1));
    let huge = Duration::from_secs(10_000 * 365 * 24 * 3600);
    assert_eq!(snapshot_interval(huge), Duration::from_secs(24 * 3600));
    let _ = Instant::now() + snapshot_interval(huge);
}

/// MIK-7951 REFILLFU.6: the session's end path, which a replaced transport
/// takes, waits for a refill in flight and announces the tools change.
#[tokio::test]
async fn a_refill_in_flight_at_the_session_end_is_announced() {
    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    reload.to(true).await;
    let backend = reload.registry.get("b").expect("b registered");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    hub.register_source(Arc::new(crate::events::backend_source::BackendSource {
        names: Arc::new(|| vec!["b".to_owned()]),
        upstream: None,
    }));
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    // The refill serves a notice the hub has not heard of.
    state.refill_announces = true;
    let (release, released) = tokio::sync::oneshot::channel::<()>();
    let refill: Refill = Box::pin(async move {
        let _ = released.await;
        true
    });
    let ending = finish_refill(
        &mut state,
        &shared,
        &backend,
        &weak,
        Some(refill),
        Instant::now(),
    );
    tokio::pin!(ending);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut ending)
            .await
            .is_err(),
        "the end waits for the refill"
    );
    release.send(()).expect("release");
    tokio::time::timeout(Duration::from_secs(5), ending)
        .await
        .expect("the session end finished once the refill did");
    // Announced after the hub's own quiet period.
    let announced = tokio::time::timeout(Duration::from_secs(5), intake.recv()).await;
    assert!(
        matches!(announced, Ok(Some(_))),
        "the tools change was announced"
    );
}

/// MIK-7950: a session that started with no URI watched, while the shared
/// snapshot is known from an earlier session, reads the catalogue as soon as
/// a URI is watched, not after a fixed 300 s.
#[tokio::test]
async fn a_uri_watched_after_the_session_started_is_read_at_once() {
    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    reload.to(true).await;
    let backend = reload.registry.get("b").expect("b registered");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    shared
        .snapshot
        .lock()
        .read(["file:///a".to_owned()].into(), true);
    let mut state = State::new(&shared, Era::Modern);
    let started = Instant::now();
    shared
        .need
        .lock()
        .add(&Interest::ResourceUpdated("file:///b".to_owned()))
        .expect("room");
    // No transport: only the catalogue read is of interest here.
    let handle: Weak<dyn UpstreamListen> = Weak::<crate::transport::HttpTransport>::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        state.maintain(&backend, &weak, &handle, true),
    )
    .await
    .expect("maintain finished");
    // The backend is unreachable, so the read failed and set its retry time:
    // proof that it ran.
    assert!(
        state.snapshot_retry_at > started,
        "the newly watched URI's catalogue was not read"
    );
}

#[path = "upstream_session_debt_tests.rs"]
mod debt;

fn changed(kind: NoteKind) -> UpstreamNote {
    UpstreamNote::Notice { kind, uri: None }
}

/// MIK-7898 SESS.1: a notice still inside its coalescing window when the
/// session ends is delivered, not dropped with the session's state.
#[tokio::test]
async fn a_coalesced_notice_is_delivered_when_the_session_ends() {
    let dir = tempfile::tempdir().expect("dir");
    let reload = Reload::new(dir.path());
    reload.to(true).await;
    let backend = reload.registry.get("b").expect("b registered");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    let mut state = State::new(&shared, Era::Legacy);
    state.note(changed(NoteKind::ResourcesChanged), false);
    let _ = finish_refill(&mut state, &shared, &backend, &weak, None, Instant::now()).await;
    assert!(
        intake.try_recv().is_ok(),
        "the notice in its window was dropped with the session"
    );
}

/// MIK-7898 SESS.3: a notice of a kind the peer's acknowledgement did not
/// honour is not delivered. Control: the honoured kind is.
#[tokio::test]
async fn a_kind_the_acknowledgement_did_not_honour_is_not_delivered() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    for interest in [Interest::ResourcesChanged, Interest::PromptsChanged] {
        shared.need.lock().add(&interest).expect("room");
    }
    let mut state = State::new(&shared, Era::Modern);
    let honoured = KindSet {
        resources_changed: true,
        ..KindSet::default()
    };
    state.note(
        UpstreamNote::Ack {
            kinds: honoured,
            uris: Vec::new(),
        },
        false,
    );
    state.note(changed(NoteKind::PromptsChanged), false);
    state.flush_at(&weak, Instant::now() + WINDOW);
    assert!(
        intake.try_recv().is_err(),
        "a kind the peer did not acknowledge was delivered"
    );
    state.note(changed(NoteKind::ResourcesChanged), false);
    state.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "control: the honoured kind");
}

/// MIK-7899 CLASS.1: a listen the peer answers with `-32601` ends the session
/// as `Unsupported` (the long backoff); a refused replacement ends nothing.
#[test]
fn a_refused_listen_ends_the_session_as_unsupported() {
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    assert!(!state.note(UpstreamNote::Unsupported, true));
    assert!(matches!(state.ended(Instant::now()), Outcome::Ended { .. }));
    assert!(state.note(UpstreamNote::Unsupported, false));
    assert!(matches!(state.ended(Instant::now()), Outcome::Unsupported));
}

/// MIK-7898 SESS.3: a `resources/updated` for a URI the acknowledgement did
/// not list is not delivered. Control: a listed URI is.
#[tokio::test]
async fn a_uri_the_acknowledgement_did_not_list_is_not_delivered() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    let (a, b) = ("file:///a".to_owned(), "file:///b".to_owned());
    for uri in [&a, &b] {
        shared
            .need
            .lock()
            .add(&Interest::ResourceUpdated(uri.clone()))
            .expect("room");
    }
    shared
        .snapshot
        .lock()
        .read([a.clone(), b.clone()].into(), true);
    let mut state = State::new(&shared, Era::Modern);
    state.note(
        UpstreamNote::Ack {
            kinds: KindSet::default(),
            uris: vec![a.clone()],
        },
        false,
    );
    let updated = |uri: &str| UpstreamNote::Notice {
        kind: NoteKind::ResourceUpdated,
        uri: Some(uri.to_owned()),
    };
    state.note(updated(&b), false);
    state.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_err(), "an unlisted URI was delivered");
    state.note(updated(&a), false);
    state.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "control: the listed URI");
}

/// MIK-7898 SESS.3: on a modern stream a notice before the acknowledgement,
/// the first listen's or a replacement's, is not delivered; a legacy stream,
/// which has none, is not gated.
#[tokio::test]
async fn a_notice_before_the_acknowledgement_is_not_delivered() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    let mut modern = State::new(&shared, Era::Modern);
    modern.note(changed(NoteKind::ResourcesChanged), false);
    modern.flush_at(&weak, Instant::now() + WINDOW);
    assert!(
        intake.try_recv().is_err(),
        "before the first acknowledgement"
    );
    let all = KindSet {
        resources_changed: true,
        ..KindSet::default()
    };
    modern.note(
        UpstreamNote::Ack {
            kinds: all,
            uris: Vec::new(),
        },
        false,
    );
    modern.note(changed(NoteKind::ResourcesChanged), true);
    modern.flush_at(&weak, Instant::now() + WINDOW);
    assert!(
        intake.try_recv().is_err(),
        "a replacement before its acknowledgement"
    );
    // Its acknowledgement makes the replacement current: its notices count.
    modern.note(
        UpstreamNote::Ack {
            kinds: all,
            uris: Vec::new(),
        },
        true,
    );
    modern.note(changed(NoteKind::ResourcesChanged), false);
    modern.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "the promoted replacement");
    let mut legacy = State::new(&shared, Era::Legacy);
    legacy.note(changed(NoteKind::ResourcesChanged), false);
    legacy.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "control: a legacy stream");
}

#[path = "upstream_session_backoff_tests.rs"]
mod backoff;

#[path = "snapshot_renewal_tests.rs"]
mod snapshot_renewal;

#[path = "upstream_session_wake_tests.rs"]
mod wake;
