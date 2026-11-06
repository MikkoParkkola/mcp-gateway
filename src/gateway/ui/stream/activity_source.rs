// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The live stream's activity and config sources: each reads one transparency
//! log forward through the Activity reader, and frames that log's announced
//! records with the same keep a read back gives.

use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use super::feed::LogFeed;
use super::id::{LogCursor, LogName, Mark};
use super::merge::{Appended, LogSource, Page, Reset, Row};
use crate::gateway::router::AppState;
use crate::gateway::ui::activity::access::Access;
use crate::gateway::ui::activity::forward::{self, Limits, Log, Search, StreamKind};
use crate::gateway::ui::activity::{StreamRead, stream_read};

/// One stream kind's rows, from its one log.
pub(super) struct ActivitySource {
    state: Arc<AppState>,
    kind: StreamKind,
    log: LogName,
    path: PathBuf,
    feed: Arc<LogFeed>,
    /// The verification key of the latest read, for framing announcements
    /// between reads. A connect reads the head first, so it is set before
    /// any announcement is framed.
    secret: Mutex<Option<Vec<u8>>>,
}

impl ActivitySource {
    /// The source for `kind`, reading `path`.
    pub(super) fn new(state: Arc<AppState>, kind: StreamKind, path: PathBuf) -> Self {
        let log = match kind {
            StreamKind::Activity => LogName::Invocation,
            StreamKind::Config => LogName::Governance,
        };
        let feed = Arc::clone(state.dashboard_bootstrap.stream_hub().feed(log));
        Self {
            state,
            kind,
            log,
            path,
            feed,
            secret: Mutex::new(None),
        }
    }

    /// This source's half of a cursor; the other half is never touched.
    fn half<'c>(&self, cursor: &'c LogCursor) -> Option<&'c Mark> {
        match self.log {
            LogName::Invocation => cursor.inv.as_ref(),
            LogName::Governance => cursor.gov.as_ref(),
        }
    }

    /// `base` with this source's half set to `part`.
    fn with_half(&self, base: &LogCursor, part: Option<Mark>) -> LogCursor {
        let mut out = base.clone();
        match self.log {
            LogName::Invocation => out.inv = part,
            LogName::Governance => out.gov = part,
        }
        out
    }

    fn reset_half(&self) -> Reset {
        Reset {
            inv: self.log == LogName::Invocation,
            gov: self.log == LogName::Governance,
        }
    }

    fn remember(&self, secret: Option<&Vec<u8>>) {
        if let Ok(mut held) = self.secret.lock() {
            held.clone_from(&secret.cloned());
        }
    }
}

impl LogSource for ActivitySource {
    type Access = Access;
    type Search = Search;

    fn subscribe(&self) -> broadcast::Receiver<Appended> {
        self.feed.subscribe()
    }

    fn head(&self, _access: &Access) -> impl Future<Output = io::Result<LogCursor>> + Send {
        let (path, kind, generation) = (self.path.clone(), self.kind, self.feed.generation());
        async move {
            let (secret, mark) = stream_read(&self.state, move |given: StreamRead| {
                let log = Log {
                    path: &path,
                    kind,
                    generation,
                    secret: given.secret.as_deref(),
                };
                Ok((given.secret.clone(), forward::head(&log)?))
            })
            .await?;
            self.remember(secret.as_ref());
            Ok(self.with_half(&LogCursor::default(), mark))
        }
    }

    fn rows_after(
        &self,
        cursor: &LogCursor,
        stop: &LogCursor,
        access: &Access,
        limit: usize,
        search: &mut Search,
    ) -> impl Future<Output = io::Result<Page>> + Send {
        // A pending replay reads from the oldest kept record: no cursor.
        let from = self
            .half(cursor)
            .filter(|m| !super::id::is_replay_pending(m))
            .cloned();
        let to = self.half(stop).cloned();
        let (path, kind, generation) = (self.path.clone(), self.kind, self.feed.generation());
        let access = access.clone();
        let mut owned = std::mem::take(search);
        let base = cursor.clone();
        async move {
            let (owned, secret, page) = stream_read(&self.state, move |given: StreamRead| {
                let log = Log {
                    path: &path,
                    kind,
                    generation,
                    secret: given.secret.as_deref(),
                };
                let budget = Limits {
                    matches: limit,
                    bytes: given.bytes,
                };
                let page = forward::rows_after(
                    &log,
                    from.as_ref(),
                    to.as_ref(),
                    &access,
                    budget,
                    &mut owned,
                );
                Ok((owned, given.secret.clone(), page))
            })
            .await?;
            *search = owned;
            self.remember(secret.as_ref());
            let page = page?;
            if page.reset {
                // The rows read before the reset are dropped: the replay from
                // the oldest kept record delivers each of them once.
                return Ok(Page {
                    rows: Vec::new(),
                    next: self.with_half(&base, None),
                    more: true,
                    reset: self.reset_half(),
                    searching: false,
                });
            }
            Ok(Page {
                rows: page
                    .rows
                    .into_iter()
                    .map(|served| Row {
                        log: self.log,
                        part: served.mark,
                        data: served.row,
                    })
                    .collect(),
                next: self.with_half(&base, page.next),
                more: page.more,
                reset: Reset::default(),
                searching: page.searching,
            })
        }
    }

    fn frame(&self, access: &Access, appended: &Appended) -> Option<Row> {
        if appended.log != self.log {
            return None;
        }
        let secret = self.secret.lock().ok()?.clone();
        let log = Log {
            path: &self.path,
            kind: self.kind,
            generation: appended.generation,
            secret: secret.as_deref(),
        };
        forward::frame(&log, access, &appended.entry).map(|served| Row {
            log: self.log,
            part: served.mark,
            data: served.row,
        })
    }
}
