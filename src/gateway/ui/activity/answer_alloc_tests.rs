// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 rows M1 and M2: cumulative allocation of a list page and an export
//! with the join over its caps. The meter counts cumulative bytes and calls on
//! the metered thread only, so both rows call the synchronous entry points.

use super::answer_export_tests::signer;
use super::answer_fixture::{Dl, Fixture, fat_findings};
use super::{ExportQuery, ListQuery, export_response, list_page};
use crate::gateway::alloc_meter::measure;

const MIB: u64 = 1 << 20;

/// `calls` calls, each with a delivery carrying `findings`, then 4,500 more
/// deliveries: 300 pending past the cap and 4,200 evicted past the tombstone
/// cap.
fn over_caps(calls: usize, fat: bool) -> Fixture {
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

#[test]
fn m1_a_list_page_over_the_caps_allocates_within_its_bound() {
    let fx = over_caps(200, true);
    let (examined, lines) = shape(&fx);
    let q = ListQuery {
        limit: Some("200".into()),
        ..ListQuery::default()
    };
    let (response, measured) = measure(|| list_page(&fx.logs(), &fx.access(), &q));
    assert!(response.status().is_success());
    let shape = format!("{measured}; examined {examined} bytes, {lines} lines");
    assert!(measured.bytes <= 2 * examined + 4 * MIB, "{shape}");
    assert!(measured.calls <= 40 * lines, "{shape}");
}

#[tokio::test(flavor = "current_thread")]
async fn m2_an_export_over_the_caps_allocates_within_its_bound() {
    let fx = over_caps(10_000, false);
    let (examined, _) = shape(&fx);
    let query = ExportQuery {
        list: ListQuery::default(),
        format: Some("ndjson".into()),
    };
    let signer = signer();
    let (response, measured) =
        measure(|| export_response(&fx.logs(), &fx.access(), &query, Some(&signer)));
    let output = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .len() as u64;
    assert!(
        measured.bytes <= 4 * output + 2 * examined + 16 * MIB,
        "{measured}; examined {examined} bytes, output {output} bytes"
    );
}
