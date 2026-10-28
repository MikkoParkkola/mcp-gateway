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
    pub(super) fn record(&mut self, _now: Instant) -> bool {
        false
    }
}

/// One connection's view of one log kind.
pub(super) struct LogMerge<S: LogSource> {
    source: Arc<S>,
    access: S::Access,
    rx: broadcast::Receiver<Appended>,
    delivered: LogCursor,
    lag_recoveries: usize,
    started: bool,
    resume: Option<LogCursor>,
}

impl<S: LogSource> LogMerge<S> {
    /// Subscribe now. `resume` is the cursor a reconnect carried; `None` is a
    /// fresh connect, which starts at the head.
    pub(super) fn new(source: Arc<S>, access: S::Access, resume: Option<LogCursor>) -> Self {
        let rx = source.subscribe();
        Self {
            source,
            access,
            rx,
            delivered: LogCursor::default(),
            lag_recoveries: 0,
            started: false,
            resume,
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

    /// The next batch, in order: the catch-up on the first call, then live
    /// rows. Empty only when the source is closed.
    pub(super) async fn next(&mut self) -> Vec<Out> {
        let _ = (
            &self.source,
            &self.access,
            &self.rx,
            self.started,
            &self.resume,
        );
        Vec::new()
    }
}
