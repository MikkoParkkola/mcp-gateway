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
use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::broadcast;
use tokio::time::Instant;

use super::id::{LogCursor, LogName, Mark};

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
    pub(super) part: Mark,
    pub(super) data: Value,
}

/// A record the append hook announced: the exact chained line.
#[derive(Clone, Debug)]
pub(super) struct Appended {
    pub(super) log: LogName,
    /// The announced row's position and hash; the announcing hook fills it,
    /// so a row hidden from this caller still moves the view's `seen` mark.
    pub(super) part: Mark,
    /// Per log, in memory, starting at 0, and comparable only within one
    /// subscription. The source raises it when the log gets a new file id,
    /// when the file shrinks below its last write, and when a resync's tail
    /// counter is lower than before. Rotation does not raise it.
    pub(super) generation: u64,
    pub(super) entry: Arc<Value>,
}

/// One page of `rows_after`.
#[derive(Clone, Debug, Default)]
pub(super) struct Page {
    pub(super) rows: Vec<Row>,
    /// A scan cursor: it moves past rows this caller cannot see.
    pub(super) next: LogCursor,
    pub(super) more: bool,
    /// Which cursor halves named a row that no longer exists.
    pub(super) reset: Reset,
    /// A log whose cursor row is not yet found: it is not at its head.
    pub(super) searching: bool,
}

/// Which logs' cursor halves are gone. Only those halves are cleared: the
/// other log's delivered position still holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Reset {
    pub(super) inv: bool,
    pub(super) gov: bool,
}

impl Reset {
    pub(super) fn any(self) -> bool {
        self.inv || self.gov
    }
}

/// Where log rows come from.
pub(super) trait LogSource: Send + Sync + 'static {
    /// What scopes a caller's rows.
    type Access: Send + Sync;
    /// One connection's place in the source for one catch-up: never shared
    /// and never sent to the client.
    type Search: Default + Send;
    /// The append hook.
    fn subscribe(&self) -> broadcast::Receiver<Appended>;
    /// The newest position this caller can read.
    fn head(&self, access: &Self::Access) -> impl Future<Output = io::Result<LogCursor>> + Send;
    /// Rows after `cursor` up to and including `stop`, oldest first, at
    /// most `limit`.
    fn rows_after(
        &self,
        cursor: &LogCursor,
        stop: &LogCursor,
        access: &Self::Access,
        limit: usize,
        search: &mut Self::Search,
    ) -> impl Future<Output = io::Result<Page>> + Send;
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
    /// The last announced row observed per log, hidden or not. "In order" is
    /// judged against it; resume ids come from `delivered`.
    seen: LogCursor,
    /// The last source generation seen per log (invocation, governance). An
    /// unseen log counts as 0, so a rewrite before the first announcement is
    /// still caught, at the cost of one extra check for a late subscriber.
    generations: [u64; 2],
    /// Where a lag recovery restarts: the last completed page's scan cursor,
    /// which moves past hidden rows. Used only once every row handed out
    /// before it is acknowledged; resume ids still come from `delivered`.
    recovery: Option<LogCursor>,
    /// A page's scan cursor, waiting for its rows to be acknowledged.
    hint: Option<LogCursor>,
    /// Rows handed out and not yet acknowledged.
    unacked: usize,
    lag_recoveries: usize,
    lag: LagWindow,
    too_slow: bool,
    /// `Some` while paging: where the next page starts.
    scan: Option<LogCursor>,
    /// The head captured when the current scan began; rows past it arrive
    /// through the live receiver, so a scan never chases a moving boundary.
    stop: LogCursor,
    /// The source's place for this catch-up.
    search: S::Search,
    /// Resets handed out and not yet acknowledged, oldest first.
    resets: std::collections::VecDeque<Reset>,
    /// A live announcement asked for a catch-up; its head is read at the
    /// start of the next step, never while racing the connection's timers.
    scan_wanted: bool,
    /// The source failed a read: the view ends, its delivered cursor kept.
    failed: bool,
    /// Resets met in the current catch-up: the first replays from the
    /// oldest record, a second goes live from the captured head instead of
    /// replaying forever.
    replays: u8,
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
        let (head, failed) = match source.head(&access).await {
            Ok(head) => (head, false),
            Err(e) => {
                tracing::debug!(error = %e, "ui stream: the log's head could not be read");
                (LogCursor::default(), true)
            }
        };
        let delivered = resume.clone().unwrap_or_else(|| head.clone());
        Self {
            source,
            access,
            rx,
            delivered,
            seen: head.clone(),
            generations: [0; 2],
            recovery: None,
            hint: None,
            unacked: 0,
            lag_recoveries: 0,
            lag: LagWindow::default(),
            too_slow: false,
            scan: resume,
            stop: head,
            search: S::Search::default(),
            resets: std::collections::VecDeque::new(),
            scan_wanted: false,
            failed,
            replays: 0,
        }
    }

    /// Whether the next step is a catch-up page: the connection reads it to
    /// the end, outside its timer race, after checking entitlement.
    pub(super) fn scanning(&self) -> bool {
        self.scan.is_some() || self.scan_wanted
    }

    /// What this connection has delivered so far.
    pub(super) fn delivered(&self) -> &LogCursor {
        &self.delivered
    }

    /// Record that `out` was written to the client: only now does the
    /// delivered position move.
    pub(super) fn ack(&mut self, out: &Out) {
        match out {
            Out::Reset => {
                let gone = self.resets.pop_front().unwrap_or(Reset {
                    inv: true,
                    gov: true,
                });
                // Not `None`, which an id reads as "not carried, start at the
                // head": the replay is owed until its first row is acked.
                if gone.inv {
                    self.delivered.inv = Some(super::id::replay_pending());
                }
                if gone.gov {
                    self.delivered.gov = Some(super::id::replay_pending());
                }
                self.recovery = None;
            }
            Out::Row(row) => *self.slot(row.log) = Some(row.part.clone()),
        }
        self.unacked = self.unacked.saturating_sub(1);
        self.promote_hint();
    }

    fn promote_hint(&mut self) {
        if self.unacked == 0
            && let Some(hint) = self.hint.take()
        {
            // Everything up to the hint is delivered or not this viewer's,
            // so a replay still marked owed is done that far: the id moves
            // on even when the replay showed this viewer no row. Only to a
            // real position: a reset page's hint has no half for its log.
            for (delivered, reached) in [
                (&mut self.delivered.inv, &hint.inv),
                (&mut self.delivered.gov, &hint.gov),
            ] {
                if delivered.as_ref().is_some_and(super::id::is_replay_pending)
                    && let Some(reached) = reached
                {
                    *delivered = Some(reached.clone());
                }
            }
            self.recovery = Some(hint);
        }
    }

    /// Where a scan starts: the delivered position, or the recovery position
    /// where that is further on in a log.
    fn scan_start(&self) -> LogCursor {
        let Some(r) = &self.recovery else {
            return self.delivered.clone();
        };
        let pick = |d: &Option<Mark>, r: &Option<Mark>| match (d, r) {
            (Some(d), Some(r)) if r.counter > d.counter => Some(r.clone()),
            (None, r) => r.clone(),
            (d, _) => d.clone(),
        };
        LogCursor {
            inv: pick(&self.delivered.inv, &r.inv),
            gov: pick(&self.delivered.gov, &r.gov),
        }
    }

    /// Whether the slow-consumer rule has closed this view.
    #[cfg(test)]
    pub(super) fn is_too_slow(&self) -> bool {
        self.too_slow
    }

    fn slot(&mut self, log: LogName) -> &mut Option<Mark> {
        match log {
            LogName::Invocation => &mut self.delivered.inv,
            LogName::Governance => &mut self.delivered.gov,
        }
    }

    /// `Lagged` recoveries so far.
    #[cfg(test)]
    pub(super) fn lag_recoveries(&self) -> usize {
        self.lag_recoveries
    }

    /// One step: a catch-up page (its rows, possibly none, when the caller
    /// may see none of them) or one live announcement's rows. `None` when the
    /// source closed or failed or the view is too slow; a reset's replay that
    /// resets again goes live from the captured head instead, with no second
    /// reset frame. The caller must `ack` every row it wrote before asking
    /// again. The live half awaits only the broadcast receive and is safe to
    /// cancel; a catch-up page must be awaited to its end.
    pub(super) async fn step(&mut self) -> Option<Vec<Out>> {
        if self.too_slow || self.failed {
            return None;
        }
        if self.scan_wanted && self.begin_scan().await.is_err() {
            self.failed = true;
            return None;
        }
        if let Some(from) = self.scan.clone() {
            return self.page(&from).await;
        }
        match self.rx.recv().await {
            Ok(appended) => Some(match self.live(&appended) {
                Some(row) => {
                    self.unacked += 1;
                    vec![Out::Row(row)]
                }
                None => Vec::new(),
            }),
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                self.lagged(missed);
                Some(Vec::new())
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }

    /// The next non-empty batch, in order: catch-up pages first, then live
    /// rows. Empty only when the view has ended (see [`Self::step`]). The
    /// connection drives [`Self::step`]; the merge loop's own rows use this.
    #[cfg(test)]
    pub(super) async fn next(&mut self) -> Vec<Out> {
        loop {
            match self.step().await {
                None => return Vec::new(),
                Some(out) if out.is_empty() => {}
                Some(out) => return out,
            }
        }
    }

    /// Count a `Lagged` recovery. The catch-up needs no request here: a lag
    /// drops the oldest announcements, all newer than the last one seen, so
    /// the next one received lies past a gap and `classify` asks for it.
    fn lagged(&mut self, missed: u64) {
        self.lag_recoveries += 1;
        self.too_slow = self.lag.record(Instant::now());
        tracing::debug!(
            missed,
            "ui stream: lagged, catching up from its own position"
        );
    }

    /// Start paging from the delivered position up to the head as of now.
    async fn begin_scan(&mut self) -> io::Result<()> {
        self.stop = self.source.head(&self.access).await?;
        self.seen = self.stop.clone();
        self.scan = Some(self.scan_start());
        self.search = S::Search::default();
        self.scan_wanted = false;
        self.replays = 0;
        Ok(())
    }

    /// One catch-up page from `from`, after yielding to the runtime. `None`
    /// when the read failed.
    async fn page(&mut self, from: &LogCursor) -> Option<Vec<Out>> {
        tokio::task::yield_now().await;
        let page = match self
            .source
            .rows_after(from, &self.stop, &self.access, PAGE, &mut self.search)
            .await
        {
            Ok(page) => page,
            Err(e) => {
                tracing::debug!(error = %e, "ui stream: a catch-up read failed");
                self.failed = true;
                return None;
            }
        };
        let mut out = Vec::with_capacity(page.rows.len() + 1);
        if page.reset.any() {
            self.replays += 1;
            if self.replays > 1 {
                // The replay from the oldest record met a gap that stays. The
                // client already holds the reset frame and reloads: the reset
                // log goes live from the head captured when this catch-up
                // began. Ending the view instead would leave the client's id
                // on the replay-pending marker, so every reconnect would
                // replay, reset twice and end, and the stream never go live.
                tracing::debug!("ui stream: the replay reset again, going live from the head");
                if page.reset.inv {
                    self.delivered.inv.clone_from(&self.stop.inv);
                }
                if page.reset.gov {
                    self.delivered.gov.clone_from(&self.stop.gov);
                }
                self.recovery = None;
                self.hint = None;
                self.scan = None;
                self.search = S::Search::default();
                return Some(Vec::new());
            }
            tracing::debug!("ui stream: the position's row is gone, resetting");
            out.push(Out::Reset);
            self.resets.push_back(page.reset);
        }
        out.extend(page.rows.into_iter().map(Out::Row));
        // A source returns no row past `stop`; a log still searching for its
        // cursor is not at its head, whatever counter the cursor names.
        let done = !page.searching && (!page.more || self.reached_head(&page.next));
        self.unacked += out.len();
        self.hint = Some(page.next.clone());
        self.promote_hint();
        self.scan = (!done).then_some(page.next);
        Some(out)
    }

    /// Whether a scan cursor has caught up with the captured head in both logs.
    fn reached_head(&self, next: &LogCursor) -> bool {
        let at = |head: &Option<Mark>, pos: &Option<Mark>| {
            head.as_ref()
                .is_none_or(|h| pos.as_ref().is_some_and(|p| p.counter >= h.counter))
        };
        at(&self.stop.inv, &next.inv) && at(&self.stop.gov, &next.gov)
    }

    /// A live row for the caller. An announcement that does not follow the
    /// last one seen exactly sends the view back to the source to be checked.
    fn live(&mut self, appended: &Appended) -> Option<Row> {
        let known = &mut self.generations[appended.log as usize];
        if std::mem::replace(known, appended.generation) != appended.generation {
            // The log was replaced or truncated: the source says where we are.
            // Positions in the old log mean nothing in the new one.
            self.recovery = None;
            self.hint = None;
            self.scan_wanted = true;
            return None;
        }
        let seen = match appended.log {
            LogName::Invocation => &mut self.seen.inv,
            LogName::Governance => &mut self.seen.gov,
        };
        match classify(seen.as_ref(), &appended.part) {
            Order::Skip => return None,
            Order::Gap => {
                self.scan_wanted = true;
                return None;
            }
            Order::Next => *seen = Some(appended.part.clone()),
        }
        self.source.frame(&self.access, appended)
    }
}

/// How an announced position relates to the last one seen.
enum Order {
    Skip,
    Next,
    Gap,
}

fn classify(seen: Option<&Mark>, part: &Mark) -> Order {
    match seen {
        Some(s)
            if part.counter < s.counter
                || (part.counter == s.counter && part.hash16 == s.hash16) =>
        {
            Order::Skip
        }
        Some(s) if part.counter == s.counter + 1 => Order::Next,
        None if part.counter == 1 => Order::Next,
        _ => Order::Gap,
    }
}
