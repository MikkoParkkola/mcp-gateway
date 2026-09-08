// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T6 of the `MIK-7215.CONTROL.4` test plan
//! (`docs/design/2026-09-08-control4-session-lifecycle-test-plan.md:57`).
//!
//! The sweep log carries the COUNT of what it reclaimed, and is ABSENT on an
//! empty sweep. The negative half is the hard half, and it is why D7 of the
//! design emits a `trace!` marker on every sweep in addition to the conditional
//! `info!`: an empty sweep and a sweep that never ran are the same silence, so
//! without a completion signal "no `info!` was emitted" is green when nothing
//! ran at all.
//!
//! The marker is emitted LAST, after the conditional `info!`. That order is
//! what makes markers sweep boundaries: every `info!` falls before its own
//! sweep's marker, so "no `info!` between marker N and marker N+1" is a
//! statement about exactly one sweep. This case consumes the count-2 sweep's
//! marker, blocks on the next one — which can only come from a later sweep, by
//! which time the map is empty — and asserts nothing was logged between them.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::StreamingConfig;
use mcp_gateway::gateway::session_lifecycle::{SessionLifecycle, now_unix};
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use tracing::field::{Field, Visit};
use tracing::subscriber::set_global_default;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::Registry;

/// One captured event, reduced to what this case discriminates on.
#[derive(Clone, Debug)]
struct Record {
    message: String,
    reclaimed: Option<String>,
}

fn captured() -> &'static Mutex<Vec<Record>> {
    static BUFFER: OnceLock<Mutex<Vec<Record>>> = OnceLock::new();
    BUFFER.get_or_init(|| Mutex::new(Vec::new()))
}

struct Collector;

impl<S: tracing::Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut visitor = FieldVisitor {
            message: String::new(),
            reclaimed: None,
        };
        event.record(&mut visitor);
        captured().lock().expect("buffer").push(Record {
            message: visitor.message,
            reclaimed: visitor.reclaimed,
        });
    }
}

struct FieldVisitor {
    message: String,
    reclaimed: Option<String>,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "reclaimed" {
            self.reclaimed = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            "reclaimed" => self.reclaimed = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

const SWEEP_MARKER: &str = "Session lifecycle sweep complete";
const RECLAIM_LOG: &str = "Session lifecycle reaper completed";

fn snapshot() -> Vec<Record> {
    captured().lock().expect("buffer").clone()
}

/// Index of the `n`-th marker in the captured log, if it has arrived.
fn nth_marker(records: &[Record], n: usize) -> Option<usize> {
    records
        .iter()
        .enumerate()
        .filter(|(_, r)| r.message == SWEEP_MARKER)
        .map(|(i, _)| i)
        .nth(n)
}

/// Poll until `f` returns `Some`, or fail the case. A bounded wait, because a
/// marker that never arrives must fail this test rather than hang it.
async fn wait_for<T>(what: &str, mut f: impl FnMut(&[Record]) -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(found) = f(&snapshot()) {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}; captured: {:#?}", snapshot());
}

#[tokio::test]
async fn the_sweep_log_carries_its_count_and_is_absent_on_an_empty_sweep() {
    let subscriber = Registry::default()
        .with(tracing_subscriber::filter::LevelFilter::TRACE)
        .with(Collector);
    set_global_default(subscriber).expect("no other global subscriber in this test binary");

    // GIVEN two identities whose deadlines have already passed, so the first
    // sweep that observes them reclaims both — one sweep, count 2, not two
    // sweeps of one.
    let lifecycle = Arc::new(SessionLifecycle::new());
    lifecycle.register("noop", |_key| {});
    let past = now_unix().saturating_sub(60);
    lifecycle.track("identity-a", past);
    lifecycle.track("identity-b", past);

    let config = StreamingConfig {
        session_ttl: Duration::from_millis(50),
        session_reaper_interval: Duration::from_millis(20),
        ..StreamingConfig::default()
    };
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::new(BackendRegistry::new()),
        config,
    ));

    // WHEN the host tick runs
    multiplexer.spawn_reaper_on(Arc::clone(&lifecycle));

    // THEN exactly one event carries the count of what that sweep reclaimed.
    let reclaim_at = wait_for("the reclaim log", |records| {
        records
            .iter()
            .position(|r| r.message == RECLAIM_LOG && r.reclaimed.as_deref() == Some("2"))
    })
    .await;

    // The count-2 sweep's own marker follows its `info!` — consume it, so the
    // next marker can only belong to a later sweep.
    let first_marker = wait_for("the marker closing the reclaiming sweep", |records| {
        nth_marker(records, 0)
    })
    .await;
    assert!(
        first_marker > reclaim_at,
        "the marker must be emitted LAST: a marker before its own sweep's count \
         cannot bound that sweep (marker at {first_marker}, count at {reclaim_at})"
    );

    // Block on the NEXT marker. The map is empty by now, so that marker IS the
    // acknowledgement that an empty sweep completed.
    let second_marker = wait_for("the marker closing an empty sweep", |records| {
        nth_marker(records, 1)
    })
    .await;

    // Nothing was logged in between — an unconditional `info!` fails here, and
    // so does one that fires once per key.
    let records = snapshot();
    let between: Vec<&Record> = records[first_marker + 1..second_marker]
        .iter()
        .filter(|r| r.message != SWEEP_MARKER)
        .collect();
    assert!(
        between.is_empty(),
        "a sweep that reclaimed nothing must log nothing, but it logged: {between:#?}"
    );
}
