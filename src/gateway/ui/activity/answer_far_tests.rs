// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! API2.10 row R37 (beyond-window case, design 12a): a delivery 300 KiB after
//! its call breaks the writer contract and the reader cannot see it. The call
//! reads `no_record`, nothing is counted, and the look-above stops at its
//! 256 KiB bound without reading further.

use std::cell::Cell;

use super::answer::LOOK_ABOVE;
use super::answer_fixture::{Dl, Fixture, fat_findings};
use super::answer_list_tests::{get, row_of};
use super::reader::{Limits, Line, Look, read_page_joined};

/// C1 and C2 early; about 300 KiB of fat records; then C1's delivery.
async fn far_layout() -> (Fixture, String) {
    let fx = Fixture::rotating(None, 4096);
    fx.call("gw-c1");
    fx.call("gw-c2");
    for i in 0..90 {
        fx.delivery(
            &format!("gw-f{i}"),
            &Dl::effect("annotated").findings(fat_findings()),
        );
    }
    fx.delivery("gw-c1", &Dl::effect("delivered"));
    let (_, first) = get(&fx, &[("limit", "1")]).await;
    let token = first["next_cursor"].as_str().unwrap().to_string();
    (fx, token)
}

#[tokio::test]
async fn r37_a_delivery_beyond_the_window_reads_no_record_and_counts_nothing() {
    let (fx, token) = far_layout().await;
    let (_, second) = get(&fx, &[("limit", "1"), ("cursor", &token)]).await;
    assert_eq!(row_of(&second, "gw-c1")["effect"], "no_record");
    assert_eq!(second["join_incomplete"], 0);
}

#[tokio::test]
async fn r37_the_look_above_stops_at_its_bound_and_never_reads_the_far_record() {
    let (fx, token) = far_layout().await;
    let cursor = super::cursor::decode(&token).expect("a cursor");
    let folded = Cell::new(0_u64);
    let far_read = Cell::new(false);
    let mut fold = |line: &Line| {
        folded.set(folded.get() + line.entry.to_string().len() as u64 + 1);
        let e = &line.entry;
        far_read.set(
            far_read.get()
                || (e["trace_id"] == "gw-c1" && e["event"] == "response_delivery_attempt"),
        );
    };
    let limits = Limits {
        matches: 200,
        bytes: 8 << 20,
    };
    read_page_joined(
        &fx.path,
        None,
        Some(&cursor),
        limits,
        Look::Fold(&mut fold),
        |_, _| false,
    )
    .unwrap();
    assert!(folded.get() <= LOOK_ABOVE, "{} bytes folded", folded.get());
    assert!(
        folded.get() + 8 * 1024 >= LOOK_ABOVE,
        "stopped early at {}",
        folded.get()
    );
    assert!(!far_read.get(), "the record past the window was read");
}
