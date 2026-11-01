// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Which upstream notices a session delivers: those still coalescing when it
//! ends, and only the kinds and URIs the peer's acknowledgement named.

use super::*;

/// A notice still inside its coalescing window when the
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
    let mut state = State::new(&shared, PeerEra::Legacy);
    state.note(changed(NoteKind::ResourcesChanged), false);
    let _ = finish_refill(&mut state, &shared, &backend, &weak, None, Instant::now()).await;
    assert!(
        intake.try_recv().is_ok(),
        "the notice in its window was dropped with the session"
    );
}

/// A notice of a kind the peer's acknowledgement did not
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
    let mut state = State::new(&shared, PeerEra::Modern);
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

/// A listen the peer answers with `-32601` ends the session
/// as `Unsupported` (the long backoff); a refused replacement ends nothing.
#[test]
fn a_refused_listen_ends_the_session_as_unsupported() {
    let shared = shared();
    let mut state = State::new(&shared, PeerEra::Modern);
    assert!(!state.note(UpstreamNote::Unsupported, true));
    assert!(matches!(state.ended(Instant::now()), Outcome::Ended { .. }));
    assert!(state.note(UpstreamNote::Unsupported, false));
    assert!(matches!(state.ended(Instant::now()), Outcome::Unsupported));
}

/// A `resources/updated` for a URI the acknowledgement did
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
    let mut state = State::new(&shared, PeerEra::Modern);
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

/// On a modern stream a notice before the acknowledgement,
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
    let mut modern = State::new(&shared, PeerEra::Modern);
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
    let mut legacy = State::new(&shared, PeerEra::Legacy);
    legacy.note(changed(NoteKind::ResourcesChanged), false);
    legacy.flush_at(&weak, Instant::now() + WINDOW);
    assert!(intake.try_recv().is_ok(), "control: a legacy stream");
}
