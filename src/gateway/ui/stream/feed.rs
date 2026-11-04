// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One log's live feed: the transparency logger's all-records reader hands each
//! written record to a bounded broadcast, which every open stream of that kind
//! subscribes to.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::Value;
use tokio::sync::broadcast;

use super::id::LogName;
use super::merge::Appended;
use crate::gateway::ui::activity::forward::mark_of;
use crate::security::TransparencyLogger;

/// Announcements one log's broadcast holds for a stream that has not read
/// them yet. A stream that falls further behind gets `Lagged` and catches up
/// from the file.
pub(super) const BROADCAST: usize = 1024;

/// One log's feed.
pub(super) struct LogFeed {
    log: LogName,
    tx: broadcast::Sender<Appended>,
    /// The last rewrite generation the logger announced, 0 before any: the
    /// forward read is given it with every read.
    generation: AtomicU64,
    /// Whether a logger's reader is attached: once per process.
    attached: AtomicBool,
}

impl LogFeed {
    pub(super) fn new(log: LogName) -> Self {
        Self {
            log,
            tx: broadcast::channel(BROADCAST).0,
            generation: AtomicU64::new(0),
            attached: AtomicBool::new(false),
        }
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<Appended> {
        self.tx.subscribe()
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Whether a logger's reader is attached.
    pub(super) fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }

    /// Attach `logger`'s all-records reader, once: a second call does nothing
    /// and returns `false`. The reader runs under the log's lock: it only
    /// stores the generation and hands the record to the broadcast, whose
    /// `send` never waits.
    pub(super) fn attach(self: &Arc<Self>, logger: &TransparencyLogger) -> bool {
        if self.attached.swap(true, Ordering::AcqRel) {
            return false;
        }
        let feed = Arc::clone(self);
        logger.subscribe_all(Arc::new(
            move |record: &serde_json::Map<String, Value>, _counter: u64, generation: u64| {
                feed.generation.store(generation, Ordering::Release);
                if feed.tx.receiver_count() == 0 {
                    return;
                }
                let entry = Value::Object(record.clone());
                let Some(part) = mark_of(&entry) else {
                    return;
                };
                // No receiver now is not an error: the next stream catches up.
                let _ = feed.tx.send(Appended {
                    log: feed.log,
                    part,
                    generation,
                    entry: Arc::new(entry),
                });
            },
        ));
        true
    }
}
