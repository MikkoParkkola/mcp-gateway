// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `schedule.tick` (event-sources design §4). Stub: the rows in
//! `schedule_source_tests.rs` fail against it until the source lands.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::fanout::SourceEvent;
use super::types::{EventDescriptor, SourceKind};
use super::{EventSource, EventsHub};

#[allow(dead_code, reason = "stub until the source lands")]
pub(crate) const NAME: &str = "schedule.tick";

/// The `schedule.tick` source.
pub(crate) struct ScheduleSource {
    _hub: Weak<EventsHub>,
    _dir: PathBuf,
}

impl ScheduleSource {
    pub(crate) fn new(hub: &Arc<EventsHub>, dir: PathBuf) -> Self {
        Self {
            _hub: Arc::downgrade(hub),
            _dir: dir,
        }
    }

    #[allow(
        dead_code,
        clippy::unused_self,
        reason = "stub until the source lands"
    )]
    pub(crate) fn tick_at(&self, _now: DateTime<Utc>) {}
}

#[async_trait::async_trait]
impl EventSource for ScheduleSource {
    fn kind(&self) -> SourceKind {
        SourceKind::Schedule
    }

    fn descriptors(&self) -> Vec<EventDescriptor> {
        Vec::new()
    }

    fn matches(&self, _principal: &str, _arguments: &Value, _event: &SourceEvent) -> bool {
        false
    }
}

impl EventsHub {
    /// Offer `schedule.tick` (stub: offers nothing).
    pub(crate) fn install_schedule_source(self: &Arc<Self>, store_dir: &Path) {
        let source = Arc::new(ScheduleSource::new(self, store_dir.join("schedule")));
        self.register_source(source);
    }
}

#[cfg(test)]
#[path = "schedule_source_tests.rs"]
mod tests;
