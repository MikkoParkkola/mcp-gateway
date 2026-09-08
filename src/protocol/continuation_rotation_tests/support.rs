// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! Private observation and rendezvous adapters; all acceptance cases remain in the parent.

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub(super) minting_kid: u8,
    // Metadata only. Never copy key bytes into an observation or failure log.
    pub(super) entries: Vec<(u8, Option<u64>, Option<u64>)>,
    pub(super) minted: u64,
    pub(super) remaining: u64,
}

// Observe one coherent state without recursively acquiring its read guard.
// Only representation access changed when RingState replaced the baseline;
// acceptance assertions in the parent remain unchanged.
pub(super) fn snapshot(ring: &Keyring) -> Snapshot {
    let state = ring.state.read();
    let minted = state
        .key(state.minting_kid)
        .unwrap()
        .key
        .minted
        .load(Ordering::Relaxed);
    Snapshot {
        minting_kid: state.minting_kid,
        entries: state
            .keys
            .iter()
            .map(|entry| (entry.kid, entry.created_at, entry.retired_at))
            .collect(),
        minted,
        remaining: ring.mint_budget.saturating_sub(minted),
    }
}

pub(super) fn force_counter(ring: &Keyring, value: u64) {
    let state = ring.state.read();
    state
        .key(state.minting_kid)
        .unwrap()
        .key
        .minted
        .store(value, Ordering::Relaxed);
}

// Only ROTATE.2 uses raw sealing: it stages a last old-key envelope at retirement
// equality without adding a production bypass of the mint-side age check.
pub(super) fn seal_under_current(ring: &Keyring, payload: &Payload) -> String {
    let state = ring.state.read();
    let key = &state.key(state.minting_kid).unwrap().key.cipher;
    let header = [VERSION, state.minting_kid];
    let mut nonce = [0; NONCE_LEN];
    ring.rng.fill(&mut nonce).unwrap();
    let mut body = serde_json::to_vec(payload).unwrap();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(header),
        &mut body,
    )
    .unwrap();
    let mut wire = header.to_vec();
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&body);
    B64.encode(wire)
}

pub(super) fn set_hooks(ring: &Keyring, hooks: KeyringTestHooks) {
    *ring.test_hooks.lock() = hooks;
}

pub(super) fn ring() -> Keyring {
    Keyring::new(&[(1, KEY)]).unwrap()
}

pub(super) fn payload(now: u64) -> Payload {
    Payload::mint(
        "rotation-backend".into(),
        Some("private-backend-state".into()),
        "verified-rotation-caller".into(),
        "original-request-digest".into(),
        "rotation-replica".into(),
        "held-exchange".into(),
        now,
    )
}

pub(super) fn kid(token: &str) -> u8 {
    B64.decode(token).unwrap()[1]
}

pub(super) fn assert_opens(ring: &Keyring, token: &str, original: &Payload, now: u64) {
    assert_eq!(&ring.open(token, now).unwrap(), original);
}

pub(super) fn concurrent_mints(
    ring: &Arc<Keyring>,
    now: u64,
    count: usize,
) -> Vec<(Payload, Result<String, ContinuationError>)> {
    let barrier = Arc::new(Barrier::new(count + 1));
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::new();
    for _ in 0..count {
        let ring = Arc::clone(ring);
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        threads.push(std::thread::spawn(move || {
            let value = payload(now);
            barrier.wait();
            let result = ring.mint(&value);
            let _ = sender.send((value, result));
        }));
    }
    drop(sender);
    barrier.wait();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let results = (0..count)
        .map(|_| {
            receiver
                .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
                .expect("rotation minter deadlock watchdog: a worker did not return")
        })
        .collect();
    // Only completed workers are joined. A timeout panics before any join,
    // so a deliberately deadlocked implementation cannot hang the test runner.
    for thread in threads {
        thread.join().unwrap();
    }
    results
}

pub(super) type EventFields = std::collections::BTreeMap<String, serde_json::Value>;

#[derive(Default)]
struct FieldVisitor(EventFields);

impl tracing::field::Visit for FieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
}

#[derive(Clone)]
struct EventCapture(Arc<std::sync::Mutex<Vec<EventFields>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target().contains("protocol::continuation") {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
    }
}

pub(super) fn capture_events<T>(run: impl FnOnce() -> T) -> (T, Vec<EventFields>) {
    use tracing_subscriber::prelude::*;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(EventCapture(Arc::clone(&events)));
    let dispatch = tracing::Dispatch::new(subscriber);
    let result = tracing::dispatcher::with_default(&dispatch, run);
    let collected = events.lock().unwrap().clone();
    (result, collected)
}
