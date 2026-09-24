// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Error-budget accounting for GH #475: a throttled backend must not be
//! recorded as either a success or a failure in the budget windows.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{BudgetOutcome, MetaMcp};
use crate::Error;
use crate::backend::BackendRegistry;

/// GH475.RL.1 / GH475.RL.2 — a rate-limited dispatch records no sample in
/// either budget. Both windows must stay empty, not merely stay under
/// threshold: a suppressed call recorded as a success would mask a genuine
/// failure rate just as effectively as one recorded as a failure.
#[test]
fn rate_limited_dispatch_records_no_budget_sample() {
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("srv", "tool", BudgetOutcome::IgnoredRateLimit);
    assert_eq!(
        m.kill_switch.window_counts("srv"),
        (0, 0),
        "a throttled backend is neither a failing backend nor a healthy sample"
    );
    assert_eq!(
        m.kill_switch.capability_window_counts("srv", "tool"),
        (0, 0),
        "the per-capability budget must be untouched too"
    );
}

/// GH475.RL.7 — an ordinary failure still counts at the meta-MCP recorder,
/// so the exclusion cannot be mistaken for the budget having stopped
/// working altogether. `ordinary_dispatch_failure_still_counts` in
/// `src/backend/tests.rs` asserts the same property at the breaker and the
/// transport-health counters; the two call sites decide independently.
#[test]
fn ordinary_dispatch_failure_still_counts_against_both_budgets() {
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("srv", "tool", BudgetOutcome::Failure);
    assert_eq!(m.kill_switch.window_counts("srv"), (0, 1));
    assert_eq!(
        m.kill_switch.capability_window_counts("srv", "tool"),
        (0, 1)
    );
}

/// GH475.RL.8 — a success is still recorded as a success, at both budgets.
/// Nothing else pins that arm: RL.1 wants empty windows and RL.7 pins only
/// the failure one, so a `Success` that reached the recorders as a failure,
/// or never reached them at all, would go unnoticed. The falsifier probe
/// run against this case was the first of those — the `Success` arm of the
/// outcome predicate forced false — and it failed here, `(0, 1)` against
/// the expected `(1, 0)`.
#[test]
fn ordinary_dispatch_success_still_counts_as_a_success_sample() {
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("srv", "tool", BudgetOutcome::Success);
    assert_eq!(
        m.kill_switch.window_counts("srv"),
        (1, 0),
        "a healthy call is a healthy sample, not a skipped one"
    );
    assert_eq!(
        m.kill_switch.capability_window_counts("srv", "tool"),
        (1, 0),
        "the per-capability budget records the same success"
    );
}

/// GH475.RL.4-RL.6 — the outcome mapping is driven by the shared predicate,
/// so a request id that merely contains `429` inside a `500` is a failure.
#[test]
fn budget_outcome_classifies_only_unambiguous_rate_limits() {
    assert_eq!(
        BudgetOutcome::of(&Ok::<_, Error>(json!({"content": []}))),
        BudgetOutcome::Success
    );
    for text in [
        "API returned 429 Too Many Requests",
        "backend replied: rate limit exceeded",
        "RESOURCE_EXHAUSTED: quota",
    ] {
        assert_eq!(
            BudgetOutcome::of(&Err::<Value, _>(Error::Protocol(text.to_string()))),
            BudgetOutcome::IgnoredRateLimit,
            "{text} must be excluded"
        );
    }
    assert_eq!(
        BudgetOutcome::of(&Err::<Value, _>(Error::Protocol(
            "500 internal server error (request 4291a)".to_string()
        ))),
        BudgetOutcome::Failure,
        "a 429 inside a request id is not a rate limit"
    );
}

/// GH475.RL.14 — a backend that reports its 429 the MCP way, as a
/// successful response carrying `isError: true`, is excluded too.
///
/// Classifying on the `Result` shape alone sampled this as a healthy call:
/// not ill-health, but still a sample, and RL.1 asks for none.
#[test]
fn an_is_error_rate_limit_envelope_records_no_sample() {
    let throttled = json!({
        "isError": true,
        "content": [{"type": "text", "text": "429 Too Many Requests"}],
    });
    assert_eq!(
        BudgetOutcome::of(&Ok::<_, Error>(throttled)),
        BudgetOutcome::IgnoredRateLimit
    );

    // The same text in a SUCCESSFUL envelope is ordinary payload — a tool
    // that returns documentation about rate limits is not being throttled.
    let payload = json!({
        "isError": false,
        "content": [{"type": "text", "text": "429 Too Many Requests"}],
    });
    assert_eq!(
        BudgetOutcome::of(&Ok::<_, Error>(payload)),
        BudgetOutcome::Success
    );

    // An `isError` envelope that is not a rate limit still counts.
    let broken = json!({
        "isError": true,
        "content": [{"type": "text", "text": "500 internal server error"}],
    });
    assert_eq!(
        BudgetOutcome::of(&Ok::<_, Error>(broken)),
        BudgetOutcome::Success
    );
}

/// GH475.OBS.2 — the suppression debug event is emitted. Captured under a
/// scoped `tracing` subscriber rather than asserted from reading the
/// source: a debug statement that never fires (wrong log level enabled,
/// removed by a later refactor) reads identically to one that does until
/// something actually listens for it.
///
/// PROD GAP, recorded rather than fixed (out of scope for this test-only
/// change; tracked at #481): the event carries `server` and `tool` —
/// which call was excluded — not which `BudgetOutcome` variant excluded
/// it. `record_error_budget` today has exactly one exclusion arm
/// (`IgnoredRateLimit`), so the criterion's "each exclusion is
/// observable" holds by there being only one to observe. A second
/// exclusion reason added later would emit textually identical fields
/// except for the hardcoded message string, and nothing in the event
/// itself would let a consumer tell the two apart.
#[test]
fn rate_limited_exclusion_emits_a_debug_event() {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    #[derive(Default)]
    struct Fields(HashMap<String, String>);

    impl Visit for Fields {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    struct Collector(Arc<Mutex<Vec<Fields>>>);

    impl<S: tracing::Subscriber> Layer<S> for Collector {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            if fields.0.get("message").map(String::as_str)
                == Some("Rate-limited response excluded from error budget accounting")
            {
                self.0.lock().expect("collector lock").push(fields);
            }
        }
    }

    // `tracing` caches each callsite's interest process-wide.
    // `rate_limited_dispatch_records_no_budget_sample` above calls
    // `record_error_budget(.., IgnoredRateLimit)` with no subscriber
    // installed, which caches this `debug!` callsite's interest as
    // `never`; whichever test runs first decides the cache for the rest
    // of the process, and every later capture on any thread is then
    // skipped. A global subscriber that is interested keeps the cached
    // interest live so the thread-local subscriber below decides each
    // event instead. Same fix shape as
    // `gateway::server::mod::tests::stdio_observation::records_for_session`,
    // for the analogous problem at a different callsite.
    static INTEREST: std::sync::Once = std::sync::Once::new();
    INTEREST.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            Registry::default().with(tracing::level_filters::LevelFilter::DEBUG),
        );
    });

    let events: Arc<Mutex<Vec<Fields>>> = Arc::new(Mutex::new(Vec::new()));

    let subscriber = Registry::default()
        .with(Collector(events.clone()))
        .with(tracing::level_filters::LevelFilter::DEBUG);
    tracing::subscriber::with_default(subscriber, || {
        let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
        m.record_error_budget("srv", "tool", BudgetOutcome::IgnoredRateLimit);
    });

    let captured = events.lock().expect("collector lock");
    assert_eq!(
        captured.len(),
        1,
        "exactly one suppression debug event must fire per exclusion"
    );
    assert_eq!(captured[0].0.get("server").map(String::as_str), Some("srv"));
    assert_eq!(captured[0].0.get("tool").map(String::as_str), Some("tool"));
}

/// GH475.OBS.1 — each exclusion arm of `record_error_budget` is
/// independently observable via a metrics scrape, not only through the
/// OBS.2 debug event. The population under test is derived from
/// `BudgetOutcome` itself (`Success`, `Failure`, `IgnoredRateLimit`) —
/// exactly one arm excludes today — rather than from a codebase grep, so
/// a future exclusion variant grows this criterion's population by
/// definition instead of needing a new search. Scoped to
/// `#[cfg(feature = "metrics")]` because both the recorder install and
/// the render call live behind that feature (`src/metrics.rs`); the
/// counter itself (`telemetry_metrics::counter!` in
/// `record_error_budget`) fires unconditionally — a no-op recorder just
/// swallows it when the feature is off.
///
/// Each case uses a server label unique to that test function: the
/// Prometheus recorder installed by `crate::metrics::install()` is
/// process-global (`OnceLock`), so two tests sharing a label would let
/// one test's increment leak into another's scrape under parallel
/// `cargo test` execution.
#[cfg(feature = "metrics")]
fn suppressed_counter_value_for(text: &str, server: &str) -> Option<u64> {
    text.lines()
        .find(|line| {
            line.starts_with("mcp_error_budget_suppressed_total")
                && line.contains(&format!("server=\"{server}\""))
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|n| n.parse::<u64>().ok())
}

#[cfg(feature = "metrics")]
#[test]
fn ignored_rate_limit_increments_the_suppressed_counter_exactly_once() {
    crate::metrics::install();
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("obs1-ignored-rl", "tool", BudgetOutcome::IgnoredRateLimit);
    let text = crate::metrics::render();
    assert_eq!(
        suppressed_counter_value_for(&text, "obs1-ignored-rl"),
        Some(1),
        "the one exclusion arm must increment the suppression counter exactly once: {text}"
    );
}

#[cfg(feature = "metrics")]
#[test]
fn success_outcome_does_not_increment_the_suppressed_counter() {
    crate::metrics::install();
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("obs1-success", "tool", BudgetOutcome::Success);
    let text = crate::metrics::render();
    assert_eq!(
        suppressed_counter_value_for(&text, "obs1-success"),
        None,
        "a success sample must not appear under the suppression counter: {text}"
    );
}

#[cfg(feature = "metrics")]
#[test]
fn ordinary_failure_does_not_increment_the_suppressed_counter() {
    crate::metrics::install();
    let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
    m.record_error_budget("obs1-failure", "tool", BudgetOutcome::Failure);
    let text = crate::metrics::render();
    assert_eq!(
        suppressed_counter_value_for(&text, "obs1-failure"),
        None,
        "an ordinary failure sample must not appear under the suppression counter: {text}"
    );
}
