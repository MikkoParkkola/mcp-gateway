// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Listener session rows for listen backoff (MIK-7898 SESS.2a), the hourly
//! recycle (MIK-7899 CLASS.3b) and the legacy pass cursor (D5).

use super::*;

/// A backend `maintain` can be handed without any network: its listen
/// handle is dead, so an open fails at once.
fn offline() -> (Backend, Weak<dyn UpstreamListen>) {
    let backend = Backend::new(
        "b",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(60),
    );
    let handle: Weak<dyn UpstreamListen> = Weak::<crate::transport::StdioTransport>::new();
    (backend, handle)
}

fn stream() -> FrameStream {
    FrameStream::new(tokio::sync::mpsc::channel(1).1)
}

/// The wait before the next open, as `unacked` last set it.
fn next_open_in(state: &State<'_>) -> Duration {
    state
        .retry_open_at
        .saturating_duration_since(Instant::now())
}

/// MIK-7898 SESS.2a: each unacknowledged end waits one step longer, and the
/// ±25 % jitter intervals [0.75, 1.25] / [1.5, 2.5] / [3, 5] s are disjoint,
/// so the strict growth cannot flake. An acknowledgement resets the steps.
#[test]
fn unacknowledged_ends_back_off_and_an_ack_resets() {
    let shared = shared();
    let mut state = State::new(&shared, Era::Modern);
    let mut gaps = Vec::new();
    for _ in 0..3 {
        state.pending_ended();
        gaps.push(next_open_in(&state));
    }
    assert!(gaps[0] <= Duration::from_millis(1250), "{gaps:?}");
    assert!(gaps[1] > Duration::from_millis(1400), "{gaps:?}");
    assert!(gaps[2] > Duration::from_millis(2900), "{gaps:?}");
    state.on_ack(KindSet::default(), &[], false);
    state.pending_ended();
    assert!(
        next_open_in(&state) <= Duration::from_millis(1250),
        "reset by the ack"
    );
}

/// SESS.2a: a replacement past its acknowledgement deadline backs off.
#[tokio::test]
async fn a_replacement_past_its_ack_deadline_backs_off() {
    let (shared, (backend, handle)) = (shared(), offline());
    let mut state = State::new(&shared, Era::Modern);
    state.pending = Some(Pending {
        stream: stream(),
        requested: Requested::default(),
        since: Instant::now() - ACK_DEADLINE * 2,
    });
    state.maintain(&backend, &Weak::new(), &handle, true).await;
    assert!(state.pending.is_none());
    assert_eq!(state.open_failures, 1);
    assert!(next_open_in(&state) > Duration::from_millis(500));
}

/// SESS.2a: a first listen never acknowledged backs off, once, not per tick.
#[tokio::test]
async fn an_unacknowledged_first_listen_backs_off_once() {
    let (shared, (backend, handle)) = (shared(), offline());
    let mut state = State::new(&shared, Era::Modern);
    state.current = Some((stream(), Requested::default()));
    state.opened = Instant::now() - ACK_DEADLINE * 2;
    for _ in 0..3 {
        state.maintain(&backend, &Weak::new(), &handle, true).await;
    }
    assert!(state.current.is_none());
    assert_eq!(state.open_failures, 1);
}

/// SESS.2a: an open that fails backs off, and is not retried at once.
#[tokio::test]
async fn a_failed_open_backs_off() {
    let (shared, (backend, handle)) = (shared(), offline());
    let mut state = State::new(&shared, Era::Modern);
    shared
        .need
        .lock()
        .add(&Interest::ResourcesChanged)
        .expect("room");
    for _ in 0..3 {
        state.maintain(&backend, &Weak::new(), &handle, true).await;
        if let Some(opening) = state.opening.take() {
            let (opened, requested) = opening.await;
            state.on_opened(opened, requested);
        }
    }
    assert_eq!(state.open_failures, 1, "the second and third waited");
    assert!(next_open_in(&state) > Duration::from_millis(500));
}

/// D5 (r1 HIGH): a pass resumes after the URI the last one reached, so a
/// hanging prefix cannot starve the URIs ordered after it.
#[test]
fn a_legacy_pass_resumes_after_the_last_uri_reached() {
    let sorted = || -> Vec<(String, bool)> {
        ["a", "b", "c"]
            .iter()
            .map(|u| ((*u).to_owned(), true))
            .collect()
    };
    let order = |last: Option<&str>| {
        let mut due = sorted();
        super::super::legacy::resume_after(&mut due, last);
        due.into_iter().map(|(u, _)| u).collect::<Vec<_>>()
    };
    assert_eq!(order(Some("a")), ["b", "c", "a"]);
    assert_eq!(order(Some("c")), ["a", "b", "c"], "past the end wraps");
    assert_eq!(order(None), ["a", "b", "c"]);
}

/// MIK-7899 CLASS.3b (D2): an acknowledged stream past `recycle` gets a
/// replacement with the same filter, and `maintain` does not wait for it.
#[tokio::test]
async fn an_aged_stream_is_replaced_make_before_break() {
    let (backend, handle) = offline();
    let mut shared = shared();
    Arc::get_mut(&mut shared).expect("sole owner").recycle = Duration::ZERO;
    let mut state = State::new(&shared, Era::Modern);
    state.current = Some((stream(), Requested::default()));
    state.acked = Some(Instant::now());
    state.maintain(&backend, &Weak::new(), &handle, true).await;
    assert!(state.opening.is_some(), "a replacement is opening");
    assert!(
        state.current.is_some(),
        "the current stream stays meanwhile"
    );
}

/// D2: at the replacement's acknowledgement, what the old stream had already
/// queued is routed under the old filter, then the old stream is closed.
#[test]
fn the_old_streams_queued_notes_are_delivered_at_the_cutover() {
    let shared = shared();
    shared
        .need
        .lock()
        .add(&Interest::PromptsChanged)
        .expect("room");
    let mut state = State::new(&shared, Era::Modern);
    let (old_tx, old_rx) = tokio::sync::mpsc::channel(4);
    state.current = Some((FrameStream::new(old_rx), Requested::default()));
    let old = KindSet {
        prompts_changed: true,
        ..KindSet::default()
    };
    state.honoured = Some((old, Vec::new()));
    state.acked = Some(Instant::now());
    old_tx
        .try_send(UpstreamNote::Notice {
            kind: NoteKind::PromptsChanged,
            uri: None,
        })
        .expect("queued");
    state.pending = Some(Pending {
        stream: stream(),
        requested: Requested::default(),
        since: Instant::now(),
    });
    state.note(
        UpstreamNote::Ack {
            kinds: KindSet::default(),
            uris: Vec::new(),
        },
        true,
    );
    assert!(
        state.coalescer.next().is_some(),
        "the queued notice was routed"
    );
    assert!(old_tx.is_closed(), "the old stream takes no more frames");
    assert!(state.pending.is_none());
}
