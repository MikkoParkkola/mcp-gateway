// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 test support: a metric recorder scoped to one thread, and a gate
//! that can stop a real publication mid-flight so a caller can witness what the
//! publishing thread still holds.
//!
//! Crate-visible on purpose. The nonce store's telemetry is observed here and at
//! the `gateway_invoke` signing boundary, and those two live in different module
//! trees; a second copy of the recorder would drift from this one.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use telemetry_metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit, with_local_recorder,
};

use super::NonceStore;
use crate::gateway::auth::QuotaPrincipal;
use crate::{Error, Result};

/// Aggregate live-entry occupancy. No labels, by design: a per-principal series
/// would republish the identity the store deliberately keeps opaque.
pub(crate) const OCCUPANCY: &str = "mcp_message_signing_nonce_entries";
/// Bounded refusal counter. `reason` is its only label.
pub(crate) const REJECTIONS: &str = "mcp_message_signing_nonce_rejections_total";
/// Proves the scoped recorder is actually receiving events, so an empty event
/// list means "production emitted nothing", never "the harness was not wired".
const CANARY: &str = "signing_nonce_test_recorder_canary_total";

/// Upper bound on a rendezvous a correct implementation completes at once. A
/// failure bound, not a synchronization primitive — every assertion is driven
/// by a signal, never by elapsed time.
const GATE_BOUND: Duration = Duration::from_secs(5);

pub(crate) const REPLAY_REFUSAL: &str = "Nonce replay detected";
pub(crate) const CAPACITY_REFUSAL: &str = "Signing nonce capacity exceeded";
pub(crate) const INVALID_REFUSAL: &str = "Invalid signing nonce";

// ── Observed events ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Observed {
    GaugeSet(String, Vec<(String, String)>, f64),
    /// A gauge moved by a delta rather than set to a value. Recorded separately
    /// because a bulk reclamation cannot be expressed as a delta the reader can
    /// reconcile.
    GaugeDelta(String, f64),
    CounterAdd(String, Vec<(String, String)>, u64),
}

impl Observed {
    fn name(&self) -> &str {
        match self {
            Self::GaugeSet(name, _, _)
            | Self::GaugeDelta(name, _)
            | Self::CounterAdd(name, _, _) => name,
        }
    }
}

#[derive(Default)]
struct Ledger(Mutex<Vec<Observed>>);

impl Ledger {
    fn push(&self, event: Observed) {
        self.0.lock().expect("event ledger").push(event);
    }

    fn snapshot(&self) -> Vec<Observed> {
        self.0.lock().expect("event ledger").clone()
    }
}

// ── The recorder ─────────────────────────────────────────────────────────────

/// Blocks the FIRST publication of one named metric, inside the recorder
/// callback, so the caller can probe what the emitting thread still holds.
struct PublishGate {
    metric: &'static str,
    armed: AtomicBool,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl PublishGate {
    fn new(metric: &'static str) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::SyncSender<()>) {
        let (entered, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release) = mpsc::sync_channel(1);
        let gate = Arc::new(Self {
            metric,
            armed: AtomicBool::new(true),
            entered,
            release: Mutex::new(release),
        });
        (gate, entered_rx, release_tx)
    }

    fn trip(&self, name: &str) {
        if name == self.metric && self.armed.swap(false, Ordering::AcqRel) {
            self.entered.send(()).expect("publication observer");
            self.release
                .lock()
                .expect("gate")
                .recv_timeout(GATE_BOUND)
                .expect("gate release");
        }
    }
}

struct TestRecorder {
    ledger: Arc<Ledger>,
    gate: Option<Arc<PublishGate>>,
}

fn labels_of(key: &Key) -> Vec<(String, String)> {
    key.labels()
        .map(|label| (label.key().to_owned(), label.value().to_owned()))
        .collect()
}

struct RecordedCounter {
    name: String,
    labels: Vec<(String, String)>,
    ledger: Arc<Ledger>,
}

impl CounterFn for RecordedCounter {
    fn increment(&self, value: u64) {
        self.ledger.push(Observed::CounterAdd(
            self.name.clone(),
            self.labels.clone(),
            value,
        ));
    }

    fn absolute(&self, value: u64) {
        self.ledger.push(Observed::CounterAdd(
            self.name.clone(),
            self.labels.clone(),
            value,
        ));
    }
}

struct RecordedGauge {
    name: String,
    labels: Vec<(String, String)>,
    ledger: Arc<Ledger>,
    gate: Option<Arc<PublishGate>>,
}

impl GaugeFn for RecordedGauge {
    fn set(&self, value: f64) {
        self.ledger.push(Observed::GaugeSet(
            self.name.clone(),
            self.labels.clone(),
            value,
        ));
        if let Some(gate) = &self.gate {
            gate.trip(&self.name);
        }
    }

    fn increment(&self, value: f64) {
        self.ledger
            .push(Observed::GaugeDelta(self.name.clone(), value));
    }

    fn decrement(&self, value: f64) {
        self.ledger
            .push(Observed::GaugeDelta(self.name.clone(), -value));
    }
}

struct DiscardedHistogram;

impl HistogramFn for DiscardedHistogram {
    fn record(&self, _value: f64) {}
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(RecordedCounter {
            name: key.name().to_owned(),
            labels: labels_of(key),
            ledger: Arc::clone(&self.ledger),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(RecordedGauge {
            name: key.name().to_owned(),
            labels: labels_of(key),
            ledger: Arc::clone(&self.ledger),
            gate: self.gate.clone(),
        }))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(DiscardedHistogram))
    }
}

// ── Observation entry points ─────────────────────────────────────────────────

/// Run `f` with a recorder scoped to this thread and return what it observed.
pub(crate) fn observe<T>(f: impl FnOnce() -> T) -> (T, Vec<Observed>) {
    let ledger = Arc::new(Ledger::default());
    let recorder = TestRecorder {
        ledger: Arc::clone(&ledger),
        gate: None,
    };
    let out = with_local_recorder(&recorder, || {
        telemetry_metrics::counter!(CANARY).increment(1);
        f()
    });
    let events = ledger.snapshot();
    assert!(
        events.iter().any(|event| event.name() == CANARY),
        "scoped metric recorder is required; the harness saw nothing at all"
    );
    (out, events)
}

/// What a gated run witnessed.
pub(crate) struct GuardWitness {
    /// Whether the store's own guard was unavailable at the moment of publication.
    pub(crate) guard_held: bool,
    pub(crate) events: Vec<Observed>,
}

/// Run `operation` on a worker thread whose recorder blocks the first
/// [`OCCUPANCY`] publication, and probe the store's own guard at that instant.
///
/// The probe is `NonceStore::state.try_lock` — the SAME guard admission,
/// reclamation and eviction take. No second mutex is introduced, because a
/// second mutex would prove a fact about the fixture rather than the store.
pub(crate) fn witness_publication_under_guard<F, R>(
    store: &NonceStore,
    operation: F,
) -> (R, GuardWitness)
where
    F: FnOnce() -> R + Send,
    R: Send,
{
    let ledger = Arc::new(Ledger::default());
    let (gate, entered, release) = PublishGate::new(OCCUPANCY);
    std::thread::scope(|scope| {
        let worker_ledger = Arc::clone(&ledger);
        let worker_gate = Arc::clone(&gate);
        let worker = scope.spawn(move || {
            // `with_local_recorder` is thread-local: the worker installs its own.
            let recorder = TestRecorder {
                ledger: worker_ledger,
                gate: Some(worker_gate),
            };
            with_local_recorder(&recorder, operation)
        });
        // Drop this thread's gate handle so a panicking worker disconnects the
        // channel at once instead of parking the wait for the full bound.
        drop(gate);
        entered
            .recv_timeout(GATE_BOUND)
            .expect("the occupancy gauge must be published from inside the operation");
        // Capture the witness, then ALWAYS release: asserting here would panic
        // with the gate shut and bury the finding under the worker's timeout.
        let guard_held = store.state.try_lock().is_none();
        release.send(()).expect("release the paused publication");
        let out = worker.join().expect("gated worker thread");
        (
            out,
            GuardWitness {
                guard_held,
                events: ledger.snapshot(),
            },
        )
    })
}

// ── Assertions over observed events ──────────────────────────────────────────

fn gauge_sets<'a>(events: &'a [Observed], name: &str) -> Vec<(&'a [(String, String)], f64)> {
    events
        .iter()
        .filter_map(|event| match event {
            Observed::GaugeSet(gauge, labels, value) if gauge == name => {
                Some((labels.as_slice(), *value))
            }
            _ => None,
        })
        .collect()
}

/// The last published occupancy must be label-free and equal `expected`.
pub(crate) fn assert_occupancy(events: &[Observed], expected: u32) {
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, Observed::GaugeDelta(name, _) if name == OCCUPANCY)),
        "occupancy is an absolute aggregate; a delta cannot express bulk reclamation"
    );
    let sets = gauge_sets(events, OCCUPANCY);
    let (labels, value) = *sets
        .last()
        .unwrap_or_else(|| panic!("no {OCCUPANCY} publication observed; events: {events:?}"));
    assert!(labels.is_empty(), "occupancy gauge must carry no labels");
    assert!(
        (value - f64::from(expected)).abs() < 0.5,
        "occupancy gauge {value} should report {expected}"
    );
}

pub(crate) fn assert_no_occupancy(events: &[Observed]) {
    assert!(
        gauge_sets(events, OCCUPANCY).is_empty(),
        "no occupancy publication may happen for a refusal decided before the lock"
    );
}

/// Every rejection counted by this batch, as `(reason, increment)` pairs.
pub(crate) fn rejections(events: &[Observed]) -> Vec<(String, u64)> {
    events
        .iter()
        .filter_map(|event| match event {
            Observed::CounterAdd(name, labels, value) if name == REJECTIONS => {
                assert_eq!(
                    labels.len(),
                    1,
                    "reason is the only permitted label on {REJECTIONS}: {labels:?}"
                );
                assert_eq!(labels[0].0, "reason", "unexpected label key: {labels:?}");
                Some((labels[0].1.clone(), *value))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn assert_single_rejection(events: &[Observed], reason: &str) {
    assert_eq!(
        rejections(events),
        vec![(reason.to_owned(), 1)],
        "expected exactly one {reason} rejection; events: {events:?}"
    );
}

pub(crate) fn assert_no_rejections(events: &[Observed]) {
    assert!(
        rejections(events).is_empty(),
        "no nonce rejection may be counted here; events: {events:?}"
    );
}

/// Local copy of the refusal-shape check: `message_signing_nonce_tests`' own is
/// module-private, and this slice must not edit that file.
pub(crate) fn assert_refusal(result: Result<()>, code: i32, expected: &str) {
    match result.expect_err("the operation must refuse") {
        Error::JsonRpc {
            code: actual,
            message,
            data,
        } => {
            assert_eq!(actual, code);
            assert_eq!(message, expected);
            assert!(data.is_none());
        }
        other => panic!("typed refusal required: {other:?}"),
    }
}

/// A real validated-credential bucket key, not a display label.
pub(crate) fn principal_key(secret: &str) -> String {
    QuotaPrincipal::api_key(secret).as_store_key().to_owned()
}
