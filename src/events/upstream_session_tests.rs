// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener's frame routing that need no peer.

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::events::upstream_need::{Interest, Need, Snapshot, WINDOW};

fn shared() -> Arc<Shared> {
    Arc::new(Shared {
        name: "b".to_owned(),
        need: Mutex::new(Need::default()),
        snapshot: Mutex::new(Snapshot::default()),
        wake: watch::channel(0).0,
        stop: CancellationToken::new(),
        gate: Arc::default(),
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
