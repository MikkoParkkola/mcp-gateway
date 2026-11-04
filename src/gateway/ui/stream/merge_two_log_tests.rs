// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The merge loop over two logs with a fake that honours `stop`: catch-up
//! ends only when both logs reach their head, a log still searching for its
//! cursor is not at its head, and one log's reset leaves the other's half.

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::sync::broadcast;

use super::id::{LogCursor, LogName, Mark};
use super::merge::{Appended, LogMerge, LogSource, Out, Page, Reset, Row};

const HASH: &str = "0123456789abcdef";

fn part(n: u64) -> Mark {
    Mark {
        counter: n,
        hash16: HASH.to_owned(),
    }
}

/// One fake log: rows numbered `1..=len`, and how its search behaves.
#[derive(Default)]
struct OneLog {
    len: u64,
    /// Calls that still answer "searching" before the cursor is found.
    searching_calls: usize,
    /// The next call finds the cursor gone.
    /// The call (1-based) on which this log finds its cursor gone.
    reset_on_call: Option<usize>,
    calls: usize,
}

/// One log's half of a page.
#[derive(Default)]
struct Half {
    rows: Vec<Row>,
    next: Option<Mark>,
    more: bool,
    reset: bool,
    searching: bool,
}

struct TwoLogs {
    logs: Mutex<[OneLog; 2]>,
    tx: broadcast::Sender<Appended>,
    /// Rows per log per call.
    per_call: u64,
}

impl TwoLogs {
    fn new(inv: OneLog, gov: OneLog, per_call: u64) -> Arc<Self> {
        let (tx, _) = broadcast::channel(16);
        Arc::new(Self {
            logs: Mutex::new([inv, gov]),
            tx,
            per_call,
        })
    }

    fn calls(&self, log: LogName) -> usize {
        self.logs.lock().unwrap()[log as usize].calls
    }

    /// One log's half of a page.
    fn half(&self, log: LogName, from: Option<&Mark>, stop: Option<&Mark>) -> Half {
        let mut logs = self.logs.lock().unwrap();
        let l = &mut logs[log as usize];
        let Some(stop) = stop else {
            return Half {
                next: from.cloned(),
                ..Half::default()
            };
        };
        l.calls += 1;
        if l.reset_on_call == Some(l.calls) {
            return Half {
                reset: true,
                ..Half::default()
            };
        }
        if l.searching_calls > 0 {
            l.searching_calls -= 1;
            return Half {
                next: from.cloned(),
                more: true,
                searching: true,
                ..Half::default()
            };
        }
        let start = from.map_or(0, |p| p.counter);
        let end = (start + self.per_call).min(stop.counter).min(l.len);
        let rows = (start + 1..=end)
            .map(|n| Row {
                log,
                part: part(n),
                data: json!({"n": n}),
            })
            .collect();
        let next = (end > start).then(|| part(end)).or_else(|| from.cloned());
        Half {
            rows,
            next,
            more: end < stop.counter,
            ..Half::default()
        }
    }
}

impl LogSource for TwoLogs {
    type Access = ();
    type Search = ();

    fn subscribe(&self) -> broadcast::Receiver<Appended> {
        self.tx.subscribe()
    }

    fn head(&self, (): &()) -> impl Future<Output = std::io::Result<LogCursor>> + Send {
        let logs = self.logs.lock().unwrap();
        let h = |l: &OneLog| (l.len > 0).then(|| part(l.len));
        std::future::ready(Ok(LogCursor {
            inv: h(&logs[0]),
            gov: h(&logs[1]),
        }))
    }

    fn rows_after(
        &self,
        cursor: &LogCursor,
        stop: &LogCursor,
        (): &(),
        _limit: usize,
        (): &mut (),
    ) -> impl Future<Output = std::io::Result<Page>> + Send {
        let inv = self.half(LogName::Invocation, cursor.inv.as_ref(), stop.inv.as_ref());
        let gov = self.half(LogName::Governance, cursor.gov.as_ref(), stop.gov.as_ref());
        std::future::ready(Ok(Page {
            rows: inv.rows.into_iter().chain(gov.rows).collect(),
            next: LogCursor {
                inv: inv.next,
                gov: gov.next,
            },
            more: inv.more || gov.more,
            reset: Reset {
                inv: inv.reset,
                gov: gov.reset,
            },
            searching: inv.searching || gov.searching,
        }))
    }

    fn frame(&self, (): &(), _: &Appended) -> Option<Row> {
        None
    }
}

/// Run catch-up to its end: batches until one comes back empty or 50 pass.
async fn catch_up(merge: &mut LogMerge<TwoLogs>) -> Vec<Out> {
    let mut all = Vec::new();
    for _ in 0..50 {
        let batch = tokio::time::timeout(std::time::Duration::from_millis(50), merge.next())
            .await
            .unwrap_or_default();
        if batch.is_empty() {
            break;
        }
        for out in &batch {
            merge.ack(out);
        }
        all.extend(batch);
    }
    all
}

fn counters(out: &[Out], log: LogName) -> Vec<u64> {
    out.iter()
        .filter_map(|o| match o {
            Out::Row(r) if r.log == log => Some(r.part.counter),
            _ => None,
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn f8_catch_up_continues_until_both_logs_reach_their_heads() {
    let fake = TwoLogs::new(
        OneLog {
            len: 2,
            ..OneLog::default()
        },
        OneLog {
            len: 9,
            ..OneLog::default()
        },
        2,
    );
    let resume = LogCursor {
        inv: Some(part(2)),
        gov: Some(part(1)),
    };
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(resume)).await;
    let out = catch_up(&mut merge).await;
    assert_eq!(
        counters(&out, LogName::Governance),
        (2..=9).collect::<Vec<_>>()
    );
}

#[tokio::test(start_paused = true)]
async fn f9_a_log_still_searching_is_not_counted_at_its_head() {
    // The governance cursor names the head's counter, but its search is not
    // finished: catch-up must keep calling until it is.
    let gov = OneLog {
        len: 5,
        searching_calls: 2,
        ..OneLog::default()
    };
    let fake = TwoLogs::new(
        OneLog {
            len: 3,
            ..OneLog::default()
        },
        gov,
        10,
    );
    let resume = LogCursor {
        inv: Some(part(3)),
        gov: Some(part(5)),
    };
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(resume)).await;
    catch_up(&mut merge).await;
    assert!(
        fake.calls(LogName::Governance) >= 3,
        "the suspended search was resumed to its end"
    );
}

#[tokio::test(start_paused = true)]
async fn f10b_one_log_resetting_keeps_the_other_logs_half() {
    // The invocation log reaches its head on the first page; the governance
    // log resets on the second, a page with no invocation rows to re-set it.
    let inv = OneLog {
        len: 3,
        ..OneLog::default()
    };
    let gov = OneLog {
        len: 8,
        reset_on_call: Some(2),
        ..OneLog::default()
    };
    let fake = TwoLogs::new(inv, gov, 2);
    let resume = LogCursor {
        inv: Some(part(1)),
        gov: Some(part(2)),
    };
    let mut merge = LogMerge::connect(Arc::clone(&fake), (), Some(resume)).await;
    let out = catch_up(&mut merge).await;
    assert!(
        out.contains(&Out::Reset),
        "the governance reset reaches the client"
    );
    assert_eq!(
        counters(&out, LogName::Invocation),
        vec![2, 3],
        "no replay, no drop"
    );
    assert_eq!(
        merge.delivered().inv,
        Some(part(3)),
        "the invocation half survives the reset"
    );
}
