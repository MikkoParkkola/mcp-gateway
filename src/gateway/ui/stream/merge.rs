// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The log-kind merge loop: one per connection and per log kind.
//!
//! Order of operations: subscribe, then page `rows_after` from the delivered
//! cursor until the head captured at the start, then drain the live receiver,
//! skipping anything at or below the delivered cursor. A `Lagged` receiver
//! pauses the drain and pages again from the delivered cursor. Nothing is
//! discarded: a stream that cannot keep up is closed by the slow-consumer rule
//! and its reconnect resumes from its own cursor.
//!
//! It is written against [`LogSource`], the signatures the Activity work
//! agreed for its append hook, `rows_after` and `visible`. No real source is
//! wired yet, so `hello` advertises no log kind.

use std::future::Future;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::broadcast;
use tokio::time::Instant;

use super::id::{LogCursor, LogName, LogPart};

/// Rows per catch-up page, the list's maximum page size.
pub(super) const PAGE: usize = 200;
/// `Lagged` recoveries tolerated inside [`LAG_WINDOW`].
pub(super) const MAX_LAG_RECOVERIES: usize = 3;
/// The window those recoveries are counted in.
pub(super) const LAG_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

/// A projected row with its position.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Row {
    pub(super) log: LogName,
    pub(super) part: LogPart,
    pub(super) data: Value,
}

/// A record the append hook announced: the exact chained line.
#[derive(Clone, Debug)]
pub(super) struct Appended {
    pub(super) log: LogName,
    pub(super) entry: Arc<Value>,
}

/// One page of `rows_after`.
#[derive(Clone, Debug, Default)]
pub(super) struct Page {
    pub(super) rows: Vec<Row>,
    /// A scan cursor: it moves past rows this caller cannot see.
    pub(super) next: LogCursor,
    pub(super) more: bool,
    /// A cursor half named a row that no longer exists.
    pub(super) reset: bool,
}

/// Where log rows come from.
pub(super) trait LogSource: Send + Sync + 'static {
    /// What scopes a caller's rows.
    type Access: Send + Sync;
    /// The append hook.
    fn subscribe(&self) -> broadcast::Receiver<Appended>;
    /// The newest position this caller can read.
    fn head(&self, access: &Self::Access) -> impl Future<Output = LogCursor> + Send;
    /// Rows after `cursor`, oldest first, at most `limit`.
    fn rows_after(
        &self,
        cursor: &LogCursor,
        access: &Self::Access,
        limit: usize,
    ) -> impl Future<Output = Page> + Send;
    /// The allowlisted row for an announced record, or `None` when the list
    /// would not show it to this caller.
    fn frame(&self, access: &Self::Access, appended: &Appended) -> Option<Row>;
}

/// What the merge loop hands the connection, in order.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Out {
    /// The cursor's row is gone; the list must be reloaded.
    Reset,
    Row(Row),
}

/// Counts `Lagged` recoveries and says when there are too many.
#[derive(Debug, Default)]
pub(super) struct LagWindow {
    at: Vec<Instant>,
}

impl LagWindow {
    /// Record a recovery; `true` when it is more than [`MAX_LAG_RECOVERIES`]
    /// inside [`LAG_WINDOW`].
    pub(super) fn record(&mut self, now: Instant) -> bool {
        self.at
            .retain(|t| now.saturating_duration_since(*t) < LAG_WINDOW);
        self.at.push(now);
        self.at.len() > MAX_LAG_RECOVERIES
    }
}

/// One connection's view of one log kind.
pub(super) struct LogMerge<S: LogSource> {
    source: Arc<S>,
    access: S::Access,
    rx: broadcast::Receiver<Appended>,
    delivered: LogCursor,
    lag_recoveries: usize,
    /// `Some` while paging: where the next page starts. Never cut short.
    scan: Option<LogCursor>,
}

impl<S: LogSource> LogMerge<S> {
    /// Subscribe, then (for a fresh connect) read the head, so a row appended
    /// after this returns is delivered. `resume` is the position a reconnect
    /// carried; `None` is a fresh connect, which starts at the head.
    pub(super) async fn connect(
        source: Arc<S>,
        access: S::Access,
        resume: Option<LogCursor>,
    ) -> Self {
        let rx = source.subscribe();
        let delivered = match &resume {
            Some(from) => from.clone(),
            None => source.head(&access).await,
        };
        Self {
            source,
            access,
            rx,
            delivered,
            lag_recoveries: 0,
            scan: resume,
        }
    }

    /// What this connection has delivered so far.
    pub(super) fn delivered(&self) -> &LogCursor {
        &self.delivered
    }

    /// `Lagged` recoveries so far.
    pub(super) fn lag_recoveries(&self) -> usize {
        self.lag_recoveries
    }

    /// The next batch, in order: catch-up pages first, then live rows. Empty
    /// only when the source is closed.
    pub(super) async fn next(&mut self) -> Vec<Out> {
        loop {
            if let Some(from) = self.scan.clone() {
                let out = self.page(&from).await;
                if !out.is_empty() {
                    return out;
                }
                continue;
            }
            match self.rx.recv().await {
                Ok(appended) => {
                    if let Some(row) = self.live(&appended) {
                        return vec![Out::Row(row)];
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    self.lag_recoveries += 1;
                    tracing::debug!(
                        missed,
                        "ui stream: lagged, catching up from its own position"
                    );
                    self.scan = Some(self.delivered.clone());
                }
                Err(broadcast::error::RecvError::Closed) => return Vec::new(),
            }
        }
    }

    /// One catch-up page from `from`, after yielding to the runtime.
    async fn page(&mut self, from: &LogCursor) -> Vec<Out> {
        tokio::task::yield_now().await;
        let page = self.source.rows_after(from, &self.access, PAGE).await;
        let mut out = Vec::with_capacity(page.rows.len() + 1);
        if page.reset {
            tracing::debug!("ui stream: the position's row is gone, resetting");
            self.delivered = LogCursor::default();
            out.push(Out::Reset);
        }
        for row in page.rows {
            if self.advance(&row) {
                out.push(Out::Row(row));
            }
        }
        tracing::debug!(
            rows = out.len(),
            more = page.more,
            "ui stream: catch-up page"
        );
        self.scan = page.more.then_some(page.next);
        out
    }

    /// A live row for the caller, unless already delivered.
    fn live(&mut self, appended: &Appended) -> Option<Row> {
        let row = self.source.frame(&self.access, appended)?;
        self.advance(&row).then_some(row)
    }

    /// Move the delivered position to `row`; `false` when it is at or below
    /// what was already delivered.
    fn advance(&mut self, row: &Row) -> bool {
        let slot = match row.log {
            LogName::Invocation => &mut self.delivered.inv,
            LogName::Governance => &mut self.delivered.gov,
        };
        if slot.as_ref().is_some_and(|d| row.part.n <= d.n) {
            return false;
        }
        *slot = Some(row.part.clone());
        true
    }
}
