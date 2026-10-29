// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The merge loop against a fake log source with the agreed signatures.

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::sync::broadcast;
use tokio::time::Instant;

use super::id::{LogCursor, LogName, LogPart};
use super::merge::{Appended, LAG_WINDOW, LagWindow, LogMerge, LogSource, Out, PAGE, Page, Row};

const HASH: &str = "0123456789abcdef";

fn part(n: u64) -> LogPart {
    LogPart {
        counter: n,
        hash16: HASH.to_owned(),
    }
}

fn row(n: u64, hidden: bool) -> Row {
    Row {
        log: LogName::Invocation,
        part: part(n),
        data: json!({"id": format!("{n}-{HASH}"), "hidden": hidden}),
    }
}

/// One invocation log; row `n` sits at index `n - 1`.
struct Fake {
    rows: Mutex<Vec<Row>>,
    tx: broadcast::Sender<Appended>,
    biggest_page: Mutex<usize>,
    reads: Mutex<usize>,
    generation: Mutex<u64>,
    heads: Mutex<usize>,
    append_on_read: Mutex<bool>,
}

impl Fake {
    fn new(existing: u64, capacity: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(capacity);
        Arc::new(Self {
            rows: Mutex::new((1..=existing).map(|n| row(n, false)).collect()),
            tx,
            biggest_page: Mutex::new(0),
            reads: Mutex::new(0),
            generation: Mutex::new(0),
            heads: Mutex::new(0),
            append_on_read: Mutex::new(false),
        })
    }

    /// Swap the whole log for `count` rows carrying `hash`.
    fn replace(&self, count: u64, hash: &str) {
        let swapped = (1..=count)
            .map(|n| Row {
                part: LogPart {
                    counter: n,
                    hash16: hash.to_owned(),
                },
                ..row(n, false)
            })
            .collect();
        *self.rows.lock().unwrap() = swapped;
        *self.generation.lock().unwrap() += 1;
    }

    fn append(&self, hidden: bool) -> u64 {
        let mut rows = self.rows.lock().unwrap();
        let n = rows.len() as u64 + 1;
        let r = row(n, hidden);
        rows.push(r.clone());
        let _ = self.tx.send(Appended {
            log: LogName::Invocation,
            part: r.part.clone(),
            generation: *self.generation.lock().unwrap(),
            entry: Arc::new(r.data),
        });
        n
    }
}

impl LogSource for Fake {
    type Access = ();

    fn subscribe(&self) -> broadcast::Receiver<Appended> {
        self.tx.subscribe()
    }

    fn head(&self, (): &()) -> impl Future<Output = LogCursor> + Send {
        *self.heads.lock().unwrap() += 1;
        let n = self.rows.lock().unwrap().len() as u64;
        std::future::ready(LogCursor {
            inv: (n > 0).then(|| part(n)),
            gov: None,
        })
    }

    fn rows_after(
        &self,
        cursor: &LogCursor,
        (): &(),
        limit: usize,
    ) -> impl Future<Output = Page> + Send {
        std::future::ready(self.page(cursor, limit))
    }

    fn frame(&self, (): &(), a: &Appended) -> Option<Row> {
        let n: u64 = a.entry["id"].as_str()?.split('-').next()?.parse().ok()?;
        (a.entry["hidden"] == false).then(|| row(n, false))
    }
}

impl Fake {
    fn page(&self, cursor: &LogCursor, limit: usize) -> Page {
        *self.reads.lock().unwrap() += 1;
        let grow = *self.append_on_read.lock().unwrap();
        let page = self.read_page(cursor, limit);
        if grow {
            self.append(false);
        }
        page
    }

    fn read_page(&self, cursor: &LogCursor, limit: usize) -> Page {
        let rows = self.rows.lock().unwrap();
        let mut b = self.biggest_page.lock().unwrap();
        *b = (*b).max(limit);
        let known = cursor.inv.as_ref().map(|p| p.counter);
        let reset = known.is_some_and(|n| {
            n > 0
                && rows
                    .get(usize::try_from(n).unwrap() - 1)
                    .is_none_or(|r| r.part != cursor.inv.clone().unwrap())
        });
        let start = if reset {
            0
        } else {
            usize::try_from(known.unwrap_or(0)).unwrap()
        };
        let end = (start + limit).min(rows.len());
        let slice = &rows[start..end];
        Page {
            rows: slice
                .iter()
                .filter(|r| r.data["hidden"] == false)
                .cloned()
                .collect(),
            next: LogCursor {
                inv: slice.last().map(|r| r.part.clone()).or(cursor.inv.clone()),
                gov: None,
            },
            more: end < rows.len(),
            reset,
        }
    }
}

fn ids(out: &[Out]) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Out::Row(r) => Some(r.part.counter),
            Out::Reset => None,
        })
        .collect()
}

/// Drain `merge` until `want` rows came out, or 50 empty rounds pass.
async fn collect(merge: &mut LogMerge<Fake>, want: usize) -> Vec<Out> {
    let mut all = Vec::new();
    for _ in 0..50 {
        if ids(&all).len() >= want {
            break;
        }
        let batch = tokio::time::timeout(std::time::Duration::from_secs(30), merge.next())
            .await
            .unwrap_or_default();
        for out in &batch {
            merge.ack(out);
        }
        all.extend(batch);
    }
    all
}

fn from(n: u64) -> LogCursor {
    LogCursor {
        inv: Some(part(n)),
        gov: None,
    }
}

#[tokio::test(start_paused = true)]
async fn resume_across_the_subscribe_then_read_race_has_no_gap_or_duplicate() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(from(2))).await;
    fake.append(false); // lands after subscribe, before the catch-up reads
    let out = collect(&mut merge, 4).await;
    assert_eq!(ids(&out), vec![3, 4, 5, 6]);
    fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![7]);
}

#[tokio::test(start_paused = true)]
async fn a_fresh_connect_starts_at_the_head() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![6]);
}

#[tokio::test(start_paused = true)]
async fn a_cursor_whose_row_is_gone_resets_then_replays_from_the_oldest() {
    let fake = Fake::new(3, 64);
    let stale = LogCursor {
        inv: Some(LogPart {
            counter: 2,
            hash16: "ffffffffffffffff".to_owned(),
        }),
        gov: None,
    };
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(stale)).await;
    let out = collect(&mut merge, 3).await;
    assert_eq!(out.first(), Some(&Out::Reset));
    assert_eq!(ids(&out), vec![1, 2, 3]);
}

#[tokio::test(start_paused = true)]
async fn a_long_backlog_pages_through_in_chunks_and_loses_nothing() {
    let fake = Fake::new(2_450, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    let out = collect(&mut merge, 2_450).await;
    assert_eq!(ids(&out), (1..=2_450).collect::<Vec<_>>());
    assert!(
        !out.contains(&Out::Reset),
        "a long backlog is never a reset"
    );
    assert_eq!(*fake.biggest_page.lock().unwrap(), PAGE);
}

#[tokio::test(start_paused = true)]
async fn a_lagged_receiver_catches_up_from_its_own_cursor() {
    let fake = Fake::new(0, 4);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    for _ in 0..20 {
        fake.append(false);
    }
    let out = collect(&mut merge, 20).await;
    assert_eq!(ids(&out), (1..=20).collect::<Vec<_>>());
    fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![21]);
    assert!(merge.lag_recoveries() >= 1);
}

#[tokio::test(start_paused = true)]
async fn a_page_of_only_invisible_rows_moves_forward_and_ends() {
    let fake = Fake::new(0, 64);
    for _ in 0..450 {
        fake.append(true);
    }
    fake.append(false);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![451]);
}

#[tokio::test(start_paused = true)]
async fn a_slow_client_closed_and_resumed_over_cycles_loses_no_row() {
    let fake = Fake::new(0, 8);
    let mut cursor = Some(LogCursor::default());
    let (mut produced, mut delivered) = (0usize, Vec::new());
    for cycle in 0..6 {
        let mut merge = LogMerge::connect(Arc::clone(&fake), (), cursor.clone()).await;
        for _ in 0..(37 + cycle * 11) {
            fake.append(false);
            produced += 1;
        }
        // The client reads only part of what is ready, then is closed.
        let out = collect(&mut merge, 25).await;
        delivered.extend(ids(&out));
        cursor = Some(merge.delivered().clone());
    }
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), cursor).await;
    delivered.extend(ids(&collect(&mut merge, produced - delivered.len()).await));
    assert_eq!(delivered.len(), produced);
    assert_eq!(delivered, (1..=produced as u64).collect::<Vec<_>>());
}

#[test]
fn more_than_three_recoveries_in_a_minute_is_too_many() {
    let t0 = Instant::now();
    let mut w = LagWindow::default();
    let step = std::time::Duration::from_secs(10);
    assert!(!w.record(t0));
    assert!(!w.record(t0 + step));
    assert!(!w.record(t0 + step * 2));
    assert!(w.record(t0 + step * 3));
}

#[test]
fn recoveries_older_than_the_window_do_not_count() {
    let t0 = Instant::now();
    let mut w = LagWindow::default();
    for i in 0..3 {
        assert!(!w.record(t0 + std::time::Duration::from_secs(i)));
    }
    assert!(!w.record(t0 + LAG_WINDOW + std::time::Duration::from_secs(5)));
}

#[tokio::test(start_paused = true)]
async fn a_disconnect_partway_through_a_page_loses_and_repeats_no_row() {
    let fake = Fake::new(450, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    let page = merge.next().await;
    assert!(page.len() > 3, "the first page holds many rows");
    for out in &page[..3] {
        merge.ack(out);
    }
    let cursor = merge.delivered().clone();
    assert_eq!(cursor, from(3), "only written rows move the position");
    let mut resumed = LogMerge::connect(Arc::clone(&fake), (), Some(cursor)).await;
    let rest = collect(&mut resumed, 447).await;
    assert_eq!(ids(&rest), (4..=450).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn a_replaced_log_under_a_live_stream_resets_then_sends_the_new_rows() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    fake.replace(8, "fedcba9876543210");
    fake.append(false);
    let out = collect(&mut merge, 9).await;
    assert_eq!(out.first(), Some(&Out::Reset));
    assert_eq!(ids(&out), (1..=9).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn catch_up_stops_at_the_head_captured_when_it_began() {
    let fake = Fake::new(400, 1_024);
    *fake.append_on_read.lock().unwrap() = true;
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    let out = collect(&mut merge, 402).await;
    assert_eq!(ids(&out), (1..=402).collect::<Vec<_>>());
    assert_eq!(*fake.reads.lock().unwrap(), 2, "two pages reach the head");
}

#[tokio::test(start_paused = true)]
async fn the_fourth_lag_recovery_inside_a_minute_closes_the_view() {
    let fake = Fake::new(0, 2);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    for round in 0..4 {
        for _ in 0..6 {
            fake.append(false);
        }
        let out = tokio::time::timeout(std::time::Duration::from_secs(30), merge.next())
            .await
            .expect("a recovery or the close arrives");
        assert_eq!(out.is_empty(), round == 3, "round {round}");
    }
    assert!(merge.is_too_slow());
    assert_eq!(merge.lag_recoveries(), 4);
}

#[tokio::test(start_paused = true)]
async fn rows_hidden_from_the_viewer_do_not_cost_a_scan_per_visible_row() {
    let fake = Fake::new(0, 1_024);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    let (mut visible, mut got) = (Vec::new(), Vec::new());
    for i in 0..400 {
        let n = fake.append(i % 2 == 0);
        if i % 2 == 1 {
            visible.push(n);
            got.extend(ids(&collect(&mut merge, 1).await));
        }
    }
    assert_eq!(got, visible, "exactly the visible rows, in order");
    let scans = *fake.reads.lock().unwrap() + *fake.heads.lock().unwrap() - 1;
    assert!(scans <= 400_usize.div_ceil(PAGE) + 1, "{scans} scans");
}

#[tokio::test(start_paused = true)]
async fn a_log_rewritten_in_place_resets_even_when_the_next_counter_follows() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    fake.replace(5, "fedcba9876543210");
    fake.append(false);
    let out = collect(&mut merge, 6).await;
    assert_eq!(out.first(), Some(&Out::Reset));
    assert_eq!(ids(&out), (1..=6).collect::<Vec<_>>());
}

#[tokio::test(start_paused = true)]
async fn a_truncated_log_whose_counter_restarts_resets_and_drops_no_row() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    fake.replace(0, "fedcba9876543210");
    for _ in 0..3 {
        fake.append(false);
    }
    let out = collect(&mut merge, 3).await;
    assert_eq!(out.first(), Some(&Out::Reset));
    assert_eq!(ids(&out), vec![1, 2, 3]);
}

#[tokio::test(start_paused = true)]
async fn a_continuation_under_the_same_generation_is_not_a_reset() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    let (heads, reads) = (*fake.heads.lock().unwrap(), *fake.reads.lock().unwrap());
    fake.append(false);
    fake.append(false);
    let out = collect(&mut merge, 2).await;
    assert!(!out.contains(&Out::Reset));
    assert_eq!(ids(&out), vec![6, 7]);
    assert_eq!(*fake.heads.lock().unwrap(), heads, "no head read");
    assert_eq!(
        *fake.reads.lock().unwrap(),
        reads,
        "no page read: no rescan"
    );
}

#[tokio::test(start_paused = true)]
async fn lag_recoveries_do_not_rescan_hidden_rows_they_already_passed() {
    let fake = Fake::new(0, 4);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    for _ in 0..400 {
        fake.append(true);
    }
    // The first recovery pages through 400 rows nobody can see.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), merge.next()).await;
    for _ in 0..400 {
        fake.append(true);
    }
    let visible = fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![visible]);
    assert!(merge.lag_recoveries() >= 2);
    let reads = *fake.reads.lock().unwrap();
    let pages = usize::try_from(visible)
        .expect("a test row count fits in usize")
        .div_ceil(PAGE);
    assert!(reads <= pages + 1, "{reads} page reads for {pages} pages");
}

#[tokio::test(start_paused = true)]
async fn rows_past_the_captured_head_then_a_lag_recovery_are_neither_lost_nor_repeated() {
    let fake = Fake::new(0, 4);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(LogCursor::default())).await;
    // All six land after the head was captured, so the first catch-up page
    // holds only rows past it; the live receiver then lags and recovers.
    for _ in 0..6 {
        fake.append(false);
    }
    let out = collect(&mut merge, 6).await;
    assert_eq!(ids(&out), (1..=6).collect::<Vec<_>>());
    assert!(merge.lag_recoveries() >= 1);
}

#[tokio::test(start_paused = true)]
async fn a_replaced_log_rescans_from_the_delivered_row_not_the_old_recovery_position() {
    let fake = Fake::new(2, 4);
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), None).await;
    for _ in 0..300 {
        fake.append(true);
    }
    // A lag recovery pages past the hidden rows and moves the recovery
    // position to row 302; the delivered row stays at 2.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), merge.next()).await;
    // The log is replaced; rows 3 to 302 of the new log were never sent.
    fake.replace(400, HASH);
    fake.append(false);
    let out = collect(&mut merge, 399).await;
    assert_eq!(ids(&out), (3..=401).collect::<Vec<_>>());
    assert!(!out.contains(&Out::Reset));
}
