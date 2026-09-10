// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Proves the in-flight table's silent eviction reaches the scrape output
//! (`MIK-7212.NFR.OBS.4`).
//!
//! A continuation's expiry is observable twice: the client presents a stale
//! envelope and is refused (counted at `src/gateway/meta_mcp/invoke.rs:535`),
//! and the hold ages out of the table when a later reader passes a `now` past
//! its deadline. The second left no trace at all, which is the one an operator
//! cannot reconstruct from anywhere else -- a client that walks away never
//! makes a failed call to be seen in.
//!
//! Isolated in its own integration-test binary on purpose, for the same reason
//! `tests/metrics_export_test.rs` is: `PrometheusBuilder::install_recorder`
//! installs a PROCESS-GLOBAL recorder behind a `OnceLock` (`src/metrics.rs`),
//! so a second test in this binary calling `install()`/`render()` would share
//! and race on that state. Run only this binary:
//!   `cargo test --features metrics --test continuation_expiry_metric_test`

#![cfg(feature = "metrics")]

use mcp_gateway::protocol::continuation::InFlight;

/// Whether the scrape output carries EXACTLY this sample.
///
/// A substring test would be satisfied by `} 20` and `} 200`, so an increment
/// that fired once per read rather than once per eviction would pass while
/// reporting an order of magnitude too many expiries. The exposition format
/// puts one sample per line, so line equality is the exact check.
fn rendered_sample(scrape: &str, reason: &str, value: u64) -> bool {
    let want = format!("continuation_expiry_total{{reason=\"{reason}\"}} {value}");
    scrape.lines().any(|line| line.trim() == want)
}

/// Drives real reclamation rather than reissuing the macro.
///
/// Reissuing `counter!` with the same name would prove the exporter carries
/// the label shape and nothing about `reclaim_abandoned`, so deleting the
/// production increment would leave this green. Every assertion below is
/// reached through `InFlight`'s public surface, and `guard` -- the only caller
/// of `reclaim_abandoned` -- runs on every one of those reads.
#[tokio::test]
async fn an_evicted_hold_is_counted_with_its_reason() {
    mcp_gateway::metrics::install();

    let table = InFlight::new("replica-a", 8);
    let held_until = 1_000_u64;

    // Baseline: absent before anything expires, so the assertion after cannot
    // pass for a reason unrelated to the eviction.
    let before = mcp_gateway::metrics::render();
    assert!(
        !before.contains("continuation_expiry_total"),
        "metric present before any hold expired; the test would prove \
         nothing. Rendered:\n{before}"
    );

    let a = table.hold("backend-1", held_until, 0).await.unwrap();
    let b = table.hold("backend-2", held_until, 0).await.unwrap();
    assert_eq!(table.len(0).await, 2, "premise: both holds are live at t=0");

    // The retain is `now <= deadline`, so a read AT the deadline evicts
    // nothing -- the same boundary `MIK-7212.MRTR.8b` settled. A count here
    // would mean the eviction fires a tick early for every continuation.
    assert_eq!(
        table.len(held_until).await,
        2,
        "a hold is live at its own deadline"
    );
    let at_deadline = mcp_gateway::metrics::render();
    assert!(
        !at_deadline.contains("continuation_expiry_total"),
        "nothing was evicted at the deadline, so nothing may be counted. \
         Rendered:\n{at_deadline}"
    );

    // One tick past both deadlines: `guard` reclaims both before `len` reads.
    assert_eq!(table.len(held_until + 1).await, 0, "both holds aged out");

    let after = mcp_gateway::metrics::render();
    assert!(
        rendered_sample(&after, "hold_evicted", 2),
        "two evictions must be counted under their own reason, separably \
         from the `deadline_passed` refusal. Rendered:\n{after}"
    );

    // Reading again adds nothing: the entries are gone, not merely stale. A
    // count that grew here would report one abandoned continuation once per
    // subsequent request for the life of the process.
    assert_eq!(table.len(held_until + 2).await, 0);
    let repeated = mcp_gateway::metrics::render();
    assert!(
        rendered_sample(&repeated, "hold_evicted", 2),
        "an eviction is counted once, not once per later read. \
         Rendered:\n{repeated}"
    );

    // A hold completed before it expired is not an eviction. Without this,
    // an increment placed on removal rather than on expiry would pass every
    // assertion above.
    let c = table.hold("backend-3", held_until * 3, 0).await.unwrap();
    assert!(
        table.complete(&c, 0).await,
        "premise: the hold was completed"
    );
    let completed = mcp_gateway::metrics::render();
    assert!(
        rendered_sample(&completed, "hold_evicted", 2),
        "completing a live hold is not an expiry. Rendered:\n{completed}"
    );

    // Keys are unused beyond the holds they name; naming them documents that
    // two distinct exchanges were evicted rather than one counted twice.
    assert_ne!(a, b, "premise: two distinct exchanges");
}
