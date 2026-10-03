// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the listener's frame routing that need no peer.

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::events::upstream_need::{Need, Snapshot};

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
