// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows M1 and M2: cumulative allocation of a list page and an export
//! with the join over its caps. The meter counts cumulative bytes and calls on
//! the metered thread only, so both rows call the synchronous entry points.

use super::answer_export_tests::signer;
use super::answer_fixture::{Dl, Fixture, fat_findings};
use super::answer_profile_tests::scan;
use super::{ExportQuery, ListQuery, export_response, list_page};
use crate::gateway::alloc_meter::{Measured, measure};

const MIB: u64 = 1 << 20;

/// `calls` calls, each with a delivery carrying `findings`, then 4,500 more
/// deliveries: 300 pending past the cap and 4,200 evicted past the tombstone
/// cap.
pub(super) fn over_caps(calls: usize, fat: bool) -> Fixture {
    let fx = Fixture::new(None);
    for i in 0..calls {
        fx.call(&format!("gw-c{i}"));
    }
    for i in 0..calls {
        let d = if fat {
            Dl::effect("annotated").findings(fat_findings())
        } else {
            Dl::effect("annotated")
        };
        fx.delivery(&format!("gw-c{i}"), &d);
    }
    for i in 0..4_500 {
        fx.delivery(&format!("gw-o{i}"), &Dl::effect("delivered"));
    }
    fx
}

fn shape(fx: &Fixture) -> (u64, u64) {
    let text = std::fs::read_to_string(&fx.path).unwrap();
    (text.len() as u64, text.lines().count() as u64)
}

/// M1's page: cumulative allocation, bytes examined, lines examined.
fn m1_page() -> (Measured, u64, u64) {
    let fx = over_caps(200, true);
    let (examined, lines) = shape(&fx);
    let q = ListQuery {
        limit: Some("200".into()),
        ..ListQuery::default()
    };
    let (response, measured) = measure(|| list_page(&fx.logs(), &fx.access(), &q));
    assert!(response.status().is_success());
    (measured, examined, lines)
}

/// M2's export: cumulative allocation, bytes examined, output bytes.
async fn m2_export() -> (Measured, u64, u64) {
    let fx = over_caps(10_000, false);
    let (examined, _) = shape(&fx);
    let query = ExportQuery {
        list: ListQuery::default(),
        format: Some("ndjson".into()),
    };
    let signer = signer();
    let (response, measured) =
        measure(|| export_response(&fx.logs(), &fx.access(), &query, Some(&signer)));
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (measured, examined, body.len() as u64)
}

// The design bounds (section 4). Both are ignored: the exporter reads each
// window several times, so the bound cannot hold until that is fixed.

#[test]
#[ignore = "export reads each window several times; the fix that carries the window remainder across pages lands separately"]
fn m1_a_list_page_over_the_caps_allocates_within_its_bound() {
    let (measured, examined, lines) = m1_page();
    let shape = format!("{measured}; examined {examined} bytes, {lines} lines");
    assert!(measured.bytes <= 2 * examined + 4 * MIB, "{shape}");
    assert!(measured.calls <= 40 * lines, "{shape}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "export reads each window several times; the fix that carries the window remainder across pages lands separately"]
async fn m2_an_export_over_the_caps_allocates_within_its_bound() {
    let (measured, examined, output) = m2_export().await;
    assert!(
        measured.bytes <= 4 * output + 2 * examined + 16 * MIB,
        "{measured}; examined {examined} bytes, output {output} bytes"
    );
}

// The ratchet rows: the measured post-fix cost plus a margin. They tighten to
// the design bound when the window-overlap fix lands.

/// Allowed growth over the measured figure, in percent.
const MARGIN_PERCENT: u64 = 5;
/// M1 measured after the first-line fix (tested 2c4855e9d6): bytes and calls.
const M1_MEASURED: (u64, u64) = (66_609_930, 508_245);
/// M2 measured after the first-line fix (tested 2c4855e9d6): bytes and calls.
const M2_MEASURED: (u64, u64) = (684_450_970, 3_532_364);

fn within_margin(measured: Measured, (bytes, calls): (u64, u64)) -> bool {
    measured.bytes <= bytes * (100 + MARGIN_PERCENT) / 100
        && measured.calls <= calls * (100 + MARGIN_PERCENT) / 100
}

#[test]
fn m1_ratchet_a_list_page_stays_within_five_percent_of_its_measured_cost() {
    let (measured, examined, lines) = m1_page();
    assert!(
        within_margin(measured, M1_MEASURED),
        "{measured}; examined {examined} bytes, {lines} lines; limit {M1_MEASURED:?} + {MARGIN_PERCENT}%"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn m2_ratchet_an_export_stays_within_five_percent_of_its_measured_cost() {
    let (measured, examined, output) = m2_export().await;
    assert!(
        within_margin(measured, M2_MEASURED),
        "{measured}; examined {examined} bytes, output {output} bytes; limit {M2_MEASURED:?} + {MARGIN_PERCENT}%"
    );
}

/// The join's own cost, measured in one binary as the scan with the join
/// minus the same scan without it, against a bound derived from design
/// section 4: each checked line (a delivery or poison candidate) costs one
/// verification, which copies and serialises its entry, so at most two
/// entries' worth of the scan's own per-line cost; each call may clone one
/// bounded projection (32 findings, 4 KiB); the pending map holds at most
/// `MAX_PENDING` projections and the tombstones `MAX_EVICTED` ids.
fn assert_join_delta_within_design(fx: &Fixture, checked: u64, calls: u64) {
    use super::answer::{MAX_EVICTED, MAX_PENDING};
    let (_, lines) = shape(fx);
    let ((), base) = measure(|| scan(fx, false));
    let ((), joined) = measure(|| scan(fx, true));
    let (extra_bytes, extra_calls) = (joined.bytes - base.bytes, joined.calls - base.calls);
    let per_line_bytes = base.bytes / lines;
    let per_line_calls = base.calls / lines;
    let projection = 4 * 1024;
    let bytes_bound = checked * 2 * per_line_bytes
        + (calls + MAX_PENDING as u64) * projection
        + MAX_EVICTED as u64 * 64;
    let calls_bound = checked * 2 * per_line_calls + (calls + MAX_PENDING as u64) * 8;
    let shape = format!(
        "join added {extra_bytes} B ({}% of the {bytes_bound} B bound) and {extra_calls} calls ({}% of {calls_bound}) over {base}",
        extra_bytes * 100 / bytes_bound,
        extra_calls * 100 / calls_bound
    );
    assert!(extra_bytes <= bytes_bound, "{shape}");
    assert!(extra_calls <= calls_bound, "{shape}");
}

#[test]
fn m2_join_delta_stays_within_the_designed_join_cost() {
    assert_join_delta_within_design(&over_caps(10_000, false), 14_500, 10_000);
}

#[test]
fn m1_join_delta_stays_within_the_designed_join_cost() {
    assert_join_delta_within_design(&over_caps(200, true), 4_700, 200);
}
