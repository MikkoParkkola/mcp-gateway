// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The merge loop against a fake log source with the agreed signatures.

use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::sync::broadcast;
use tokio::time::Instant;

use super::id::{LogCursor, LogName, LogPart};
use super::merge::{Appended, LAG_WINDOW, LagWindow, LogMerge, LogSource, Out, PAGE, Page, Row};

const HASH: &str = "0123456789abcdef";

fn part(n: u64) -> LogPart {
    LogPart {
        n,
        hash: HASH.to_owned(),
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
}

impl Fake {
    fn new(existing: u64, capacity: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(capacity);
        Arc::new(Self {
            rows: Mutex::new((1..=existing).map(|n| row(n, false)).collect()),
            tx,
            biggest_page: Mutex::new(0),
        })
    }

    fn append(&self, hidden: bool) -> u64 {
        let mut rows = self.rows.lock().unwrap();
        let n = rows.len() as u64 + 1;
        let r = row(n, hidden);
        rows.push(r.clone());
        let _ = self.tx.send(Appended {
            log: LogName::Invocation,
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

    async fn head(&self, _: &()) -> LogCursor {
        let n = self.rows.lock().unwrap().len() as u64;
        LogCursor {
            inv: (n > 0).then(|| part(n)),
            gov: None,
        }
    }

    async fn rows_after(&self, cursor: &LogCursor, _: &(), limit: usize) -> Page {
        let rows = self.rows.lock().unwrap();
        let mut b = self.biggest_page.lock().unwrap();
        *b = (*b).max(limit);
        let known = cursor.inv.as_ref().map(|p| p.n);
        let reset = known.is_some_and(|n| {
            n > 0
                && rows
                    .get(n as usize - 1)
                    .is_none_or(|r| r.part != cursor.inv.clone().unwrap())
        });
        let start = if reset {
            0
        } else {
            known.unwrap_or(0) as usize
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

    fn frame(&self, _: &(), a: &Appended) -> Option<Row> {
        let n: u64 = a.entry["id"].as_str()?.split('-').next()?.parse().ok()?;
        (a.entry["hidden"] == false).then(|| row(n, false))
    }
}

fn ids(out: &[Out]) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Out::Row(r) => Some(r.part.n),
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
        all.extend(
            tokio::time::timeout(std::time::Duration::from_secs(30), merge.next())
                .await
                .unwrap_or_default(),
        );
    }
    all
}

fn from(n: u64) -> Option<LogCursor> {
    Some(LogCursor {
        inv: Some(part(n)),
        gov: None,
    })
}

#[tokio::test]
async fn resume_across_the_subscribe_then_read_race_has_no_gap_or_duplicate() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::new(Arc::clone(&fake), (), from(2));
    fake.append(false); // lands after subscribe, before the catch-up reads
    let out = collect(&mut merge, 4).await;
    assert_eq!(ids(&out), vec![3, 4, 5, 6]);
    fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![7]);
}

#[tokio::test]
async fn a_fresh_connect_starts_at_the_head() {
    let fake = Fake::new(5, 64);
    let mut merge = LogMerge::new(Arc::clone(&fake), (), None);
    fake.append(false);
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![6]);
}

#[tokio::test]
async fn a_cursor_whose_row_is_gone_resets_then_replays_from_the_oldest() {
    let fake = Fake::new(3, 64);
    let stale = LogCursor {
        inv: Some(LogPart {
            n: 2,
            hash: "ffffffffffffffff".to_owned(),
        }),
        gov: None,
    };
    let mut merge = LogMerge::new(Arc::clone(&fake), (), Some(stale));
    let out = collect(&mut merge, 3).await;
    assert_eq!(out.first(), Some(&Out::Reset));
    assert_eq!(ids(&out), vec![1, 2, 3]);
}

#[tokio::test]
async fn a_long_backlog_pages_through_in_chunks_and_loses_nothing() {
    let fake = Fake::new(2_450, 64);
    let mut merge = LogMerge::new(Arc::clone(&fake), (), Some(LogCursor::default()));
    let out = collect(&mut merge, 2_450).await;
    assert_eq!(ids(&out), (1..=2_450).collect::<Vec<_>>());
    assert!(
        !out.contains(&Out::Reset),
        "a long backlog is never a reset"
    );
    assert_eq!(*fake.biggest_page.lock().unwrap(), PAGE);
}

#[tokio::test]
async fn a_lagged_receiver_catches_up_from_its_own_cursor() {
    let fake = Fake::new(0, 4);
    let mut merge = LogMerge::new(Arc::clone(&fake), (), Some(LogCursor::default()));
    for _ in 0..20 {
        fake.append(false);
    }
    let out = collect(&mut merge, 20).await;
    assert_eq!(ids(&out), (1..=20).collect::<Vec<_>>());
    assert!(merge.lag_recoveries() >= 1);
}

#[tokio::test]
async fn a_page_of_only_invisible_rows_moves_forward_and_ends() {
    let fake = Fake::new(0, 64);
    for _ in 0..450 {
        fake.append(true);
    }
    fake.append(false);
    let mut merge = LogMerge::new(Arc::clone(&fake), (), Some(LogCursor::default()));
    assert_eq!(ids(&collect(&mut merge, 1).await), vec![451]);
}

#[tokio::test]
async fn a_slow_client_closed_and_resumed_over_cycles_loses_no_row() {
    let fake = Fake::new(0, 8);
    let mut cursor = Some(LogCursor::default());
    let (mut produced, mut delivered) = (0usize, Vec::new());
    for cycle in 0..6 {
        let mut merge = LogMerge::new(Arc::clone(&fake), (), cursor.clone());
        for _ in 0..(37 + cycle * 11) {
            fake.append(false);
            produced += 1;
        }
        // The client reads only part of what is ready, then is closed.
        let out = collect(&mut merge, 25).await;
        delivered.extend(ids(&out));
        cursor = Some(merge.delivered().clone());
    }
    let mut merge = LogMerge::new(Arc::clone(&fake), (), cursor);
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
