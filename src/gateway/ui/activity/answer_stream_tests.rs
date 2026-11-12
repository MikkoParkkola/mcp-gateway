// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 stream rows R15, R23, R24: a frame is the list row as of its
//! append; a delivery record raises no frame.

use super::access::Access;
use super::answer_fixture::{Dl, Fixture};
use super::answer_list_tests::{get, row_of};
use super::forward::{Limits, Log, Search, StreamKind, frame, head, rows_after};

fn log_of(fx: &Fixture) -> Log<'_> {
    Log {
        path: &fx.path,
        kind: StreamKind::Activity,
        generation: 0,
        secret: None,
    }
}

fn call_entry(fx: &Fixture, trace: &str) -> serde_json::Value {
    fx.lines()
        .into_iter()
        .find(|l| l["trace_id"] == trace && l.get("request_hash").is_some())
        .unwrap()
}

#[tokio::test]
async fn r15_a_frame_is_the_list_row_as_of_its_append() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    let served = frame(&log_of(&fx), &Access::All, &call_entry(&fx, "gw-t")).unwrap();
    let (_, page) = get(&fx, &[]).await;
    assert_eq!(served.row["effect"], "no_record");
    assert_eq!(served.row, *row_of(&page, "gw-t"));
}

#[test]
fn r23_a_frame_drained_after_its_delivery_still_reads_no_record() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    let entry = call_entry(&fx, "gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let served = frame(&log_of(&fx), &Access::All, &entry).unwrap();
    assert_eq!(served.row["effect"], "no_record");
}

#[test]
fn r24_a_replay_reads_the_snapshot_and_the_delivery_raises_no_frame() {
    let fx = Fixture::new(None);
    fx.call("gw-t");
    fx.delivery("gw-t", &Dl::effect("refused"));
    let log = log_of(&fx);
    let stop = head(&log).unwrap();
    let wide = Limits {
        matches: 200,
        bytes: 8 << 20,
    };
    let page = rows_after(
        &log,
        None,
        stop.as_ref(),
        &Access::All,
        wide,
        &mut Search::default(),
    )
    .unwrap();
    let calls: Vec<_> = page
        .rows
        .iter()
        .filter(|s| s.row["kind"] == "call")
        .collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].row["effect"], "no_record");
    assert!(
        page.rows
            .iter()
            .all(|s| s.row.get("response_stage").is_none())
    );
    assert!(page.rows.len() <= 1, "{:?}", page.rows.len());
}
