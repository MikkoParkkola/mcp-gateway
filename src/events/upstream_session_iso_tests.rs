// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T4a: two subscribers of one per-user backend share no listener state.
//! Overlapping tools notices inside one coalescing window give two
//! emissions, each under its own subscriber's key. A listener map or a
//! coalescer keyed by backend alone would merge them into one.

use std::sync::Arc;

use super::*;
use crate::events::upstream_listener::ListenerKey;
use crate::events::upstream_need::{Interest, WINDOW};

fn as_user(obs: &str) -> ListenerKey {
    ListenerKey {
        backend: "b".into(),
        obs: Some(obs.into()),
    }
}

#[tokio::test]
async fn iso_t4a_overlapping_tools_notices_emit_once_per_subscriber_key() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let mut intake = hub.runtime.intake.lock().take().expect("intake");
    let weak = Arc::downgrade(&hub);
    let keys = [as_user("obs-p"), as_user("obs-q")];
    let shared: Vec<_> = keys
        .iter()
        .map(|key| {
            let shared =
                super::tests::shared_keyed(key.clone(), Arc::new(std::collections::BTreeSet::new));
            shared
                .need
                .lock()
                .add(&Interest::ToolsChanged)
                .expect("room");
            shared
        })
        .collect();
    let at = std::time::Instant::now() + WINDOW;
    let mut states: Vec<_> = shared
        .iter()
        .map(|s| State::new(s, PeerEra::Legacy))
        .collect();
    for state in &mut states {
        state.note(
            UpstreamNote::Notice {
                kind: NoteKind::ToolsChanged,
                uri: None,
            },
            false,
        );
    }
    // A tools notice emits after its refill: each listener owes its own,
    // which is then made due and served before the flush.
    for (state, shared) in states.iter_mut().zip(&shared) {
        assert!(
            shared.tools.lock().unannounced,
            "each listener owes its own"
        );
        shared.tools.lock().due = Some(std::time::Instant::now());
        assert!(state.take_due_refill(), "the refill is due");
        state.refill_ended(true);
        state.flush_at(&weak, at);
    }
    let mut emitted = Vec::new();
    while let Ok(event) = intake.try_recv() {
        emitted.push(event.lifecycle_key);
    }
    let want: Vec<_> = keys
        .iter()
        .map(|key| {
            crate::events::backend_source::backend_key(
                key.obs.as_deref(),
                "backend.b.tools_changed",
                &serde_json::json!({}),
            )
        })
        .collect();
    assert_eq!(emitted.len(), 2, "one emission per subscriber: {emitted:?}");
    for key in &want {
        assert!(key.is_some(), "a per-user key");
        assert!(emitted.contains(key), "{key:?} emitted: {emitted:?}");
    }
    assert_ne!(want[0], want[1], "the two subscribers' keys differ");
}
