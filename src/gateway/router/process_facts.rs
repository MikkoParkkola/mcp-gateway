// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What was fixed when this process started, held by [`super::AppState`] and
//! read by the web UI: when the process began, the version change this start
//! recorded, and what the gateway refused while starting.
//!
//! A value of the state, not a global: the start is set where server start
//! builds the state, a test builds the state with a start it chooses, and
//! nothing falls back to "the first request".

use std::sync::OnceLock;
use std::time::Instant;

use chrono::{DateTime, Utc};

use crate::config_reload::refusals::Refusal;
use crate::counters::VersionChange;

/// When this process started: the wall clock for display, the monotonic clock
/// for elapsed time, so a clock that steps never moves the uptime.
#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "read only by the web UI's routes")
)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessStart {
    /// `None` when the host clock could not be read.
    wall: Option<DateTime<Utc>>,
    mono: Instant,
}

#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "read only by the web UI's routes")
)]
impl ProcessStart {
    /// Now: server start calls this once, before anything else is built.
    pub(crate) fn now() -> Self {
        Self {
            wall: crate::clock::utc_now().ok(),
            mono: Instant::now(),
        }
    }

    /// A start a test chooses.
    #[cfg(test)]
    pub(crate) fn at(wall: Option<DateTime<Utc>>, mono: Instant) -> Self {
        Self { wall, mono }
    }
}

/// The facts of one run. See the module docs.
#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "read only by the web UI's routes")
)]
#[derive(Debug)]
pub struct ProcessFacts {
    start: ProcessStart,
    upgrade: Option<VersionChange>,
    /// This host's name, resolved once here rather than on every request.
    host_name: Option<String>,
    /// Set once, after the startup backend pass has finalised what the
    /// runtime policy denies. Later denials stay on `/ui/api/refusals`.
    refused_at_start: OnceLock<Vec<Refusal>>,
}

#[cfg_attr(
    not(feature = "webui"),
    allow(dead_code, reason = "read only by the web UI's routes")
)]
impl ProcessFacts {
    /// The facts of a start at `start` that recorded `upgrade`.
    pub(crate) fn new(start: ProcessStart, upgrade: Option<VersionChange>) -> Self {
        Self {
            start,
            upgrade,
            host_name: resolve_host_name(),
            refused_at_start: OnceLock::new(),
        }
    }

    /// Whole seconds since the process started.
    pub(crate) fn uptime_secs(&self) -> u64 {
        self.start.mono.elapsed().as_secs()
    }

    /// When the process started; `None` when the host clock could not be read.
    pub(crate) fn started_at(&self) -> Option<DateTime<Utc>> {
        self.start.wall
    }

    /// This host's name as resolved at start, when one could be read.
    pub(crate) fn host_name(&self) -> Option<&str> {
        self.host_name.as_deref()
    }

    /// The version change this start recorded, when there was one.
    pub(crate) fn upgrade(&self) -> Option<&VersionChange> {
        self.upgrade.as_ref()
    }

    /// Keep `refused` as what the gateway refused at start. The first call
    /// wins: the snapshot is taken once.
    pub(crate) fn record_refused_at_start(&self, refused: Vec<Refusal>) {
        let _ = self.refused_at_start.set(refused);
    }

    /// What the gateway refused at start; empty until the snapshot is taken.
    pub(crate) fn refused_at_start(&self) -> &[Refusal] {
        self.refused_at_start.get().map_or(&[], Vec::as_slice)
    }
}

/// This host's name, from the variable a container or shell sets, else the
/// kernel's node name. `None` when neither says.
fn resolve_host_name() -> Option<String> {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|key| {
            std::env::var(key)
                .ok()
                .filter(|name| !name.trim().is_empty())
        })
        .or_else(node_name)
}

/// The kernel's node name (`uname -n`).
#[cfg(unix)]
fn node_name() -> Option<String> {
    let name = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    (!name.trim().is_empty()).then_some(name)
}

/// No `uname` off Unix: the environment variables above are the source.
#[cfg(not(unix))]
fn node_name() -> Option<String> {
    None
}

/// A start at this moment with nothing recorded: for a state built without a
/// server start (embedders and tests), which have no earlier moment to count
/// from. Server start never uses it.
impl Default for ProcessFacts {
    fn default() -> Self {
        Self::new(ProcessStart::now(), None)
    }
}
