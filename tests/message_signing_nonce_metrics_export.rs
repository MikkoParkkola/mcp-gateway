// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! SIGNING.5 export half: proves the nonce occupancy gauge and the bounded
//! rejection counter emitted by `security::message_signing::NonceStore` reach
//! the Prometheus text output `mcp_gateway::metrics::render()` produces.
//!
//! The unit half (`src/security/message_signing_nonce_metrics_tests.rs`) proves
//! WHAT the production path emits and that it publishes under the store guard.
//! This half proves the hook-to-scrape chain exists at all. Neither is the
//! other; together they are the claim the capacity alerts rest on.
//!
//! Isolated in its own integration binary on purpose:
//! `metrics_exporter_prometheus::PrometheusBuilder::install_recorder` installs a
//! PROCESS-GLOBAL recorder behind a `OnceLock` (src/metrics.rs `HANDLE`), so a
//! second test in the same binary would race on it. Run only this binary:
//!   `cargo test --features metrics --test message_signing_nonce_metrics_export`
//!
//! Scope, stated so the name cannot drift from what is proven: `NonceStore`'s
//! limits (100_000 global, 10_000 per principal) are not settable through the
//! public API, so the `principal_capacity` and `global_capacity` reasons are
//! covered by the unit half only. This binary drives admission, replay and
//! invalid through the real public entry point — no hand-emitted product
//! metrics.

#![cfg(feature = "metrics")]

use std::time::Duration;

use mcp_gateway::security::message_signing::NonceStore;

const OCCUPANCY: &str = "mcp_message_signing_nonce_entries";
const REJECTIONS: &str = "mcp_message_signing_nonce_rejections_total";

#[test]
fn nonce_occupancy_and_rejection_reasons_survive_render() {
    mcp_gateway::metrics::install();

    // Independent canary: proves the installed recorder is live, so a missing
    // nonce metric below means production emitted nothing — not that the
    // exporter was never installed.
    telemetry_metrics::counter!("signing_nonce_export_canary_total").increment(1);

    let before = mcp_gateway::metrics::render();
    assert!(
        before.contains("signing_nonce_export_canary_total"),
        "global recorder is not exporting at all:\n{before}"
    );
    assert!(
        !before.contains(OCCUPANCY) && !before.contains(REJECTIONS),
        "nonce metrics present before anything drove them; the assertions below \
         would pass for an unrelated reason:\n{before}"
    );

    let store = NonceStore::new(Duration::from_secs(300));
    store
        .check_and_register("export-nonce-1")
        .expect("first admission");
    store
        .check_and_register("export-nonce-2")
        .expect("second admission");
    store
        .check_and_register("export-nonce-1")
        .expect_err("replay must be refused");
    store
        .check_and_register("")
        .expect_err("empty nonce must be refused");

    let after = mcp_gateway::metrics::render();

    assert_eq!(
        gauge_value(&after, OCCUPANCY),
        Some(2.0),
        "expected the live-entry aggregate in scrape output:\n{after}"
    );
    assert_eq!(
        counter_value(&after, REJECTIONS, "replay"),
        Some(1),
        "expected one replay rejection in scrape output:\n{after}"
    );
    assert_eq!(
        counter_value(&after, REJECTIONS, "invalid"),
        Some(1),
        "expected one invalid-nonce rejection in scrape output:\n{after}"
    );

    for line in nonce_metric_lines(&after) {
        assert!(
            !line.contains("nonce=") && !line.contains("principal="),
            "nonce telemetry must carry neither the nonce nor the identity: {line}"
        );
        assert!(
            !line.contains("export-nonce-"),
            "the nonce value itself reached scrape output: {line}"
        );
    }
}

/// Sample lines (not `# HELP`/`# TYPE`) for the two nonce metric families.
fn nonce_metric_lines(rendered: &str) -> impl Iterator<Item = &str> {
    rendered.lines().filter(|line| {
        !line.starts_with('#') && (line.starts_with(OCCUPANCY) || line.starts_with(REJECTIONS))
    })
}

fn gauge_value(rendered: &str, name: &str) -> Option<f64> {
    let line = nonce_metric_lines(rendered).find(|line| line.starts_with(name))?;
    let (label_part, value) = line.rsplit_once(' ')?;
    assert_eq!(
        label_part, name,
        "the occupancy gauge must be a label-free aggregate: {line}"
    );
    value.parse().ok()
}

fn counter_value(rendered: &str, name: &str, reason: &str) -> Option<u64> {
    let wanted = format!("{name}{{reason=\"{reason}\"}}");
    let line = nonce_metric_lines(rendered).find(|line| line.starts_with(&wanted))?;
    let (labelled, value) = line.rsplit_once(' ')?;
    assert_eq!(
        labelled, wanted,
        "reason is the only permitted label on {name}: {line}"
    );
    value.parse().ok()
}
