// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: the live rows a watch source reads. Liveness is judged on the
//! wall clock through `Subscription::live_now`, so a clock before 1970 reads
//! no row as live: a lease that cannot be dated holds nothing and admits
//! nothing, where chrono's 1969 date read every ended lease as live.

use serde_json::Value;

use super::{EventsHub, Run, Subscription, WatchSource};

impl WatchSource {
    /// Live rows of `principal` for `name` with these canonical `arguments`.
    /// A clock before 1970 reads none live (MIK-8202).
    pub(super) fn rows(
        hub: &EventsHub,
        principal: &str,
        name: &str,
        arguments: &Value,
    ) -> Vec<Subscription> {
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.live_now() && s.principal == principal && s.name == name)
            .filter(|s| s.arguments == *arguments)
            .collect()
    }
}

impl Run {
    /// The live rows that hold this poller's key.
    /// A clock before 1970 reads none live (MIK-8202).
    pub(super) fn holders(&self, hub: &EventsHub) -> Vec<Subscription> {
        hub.store
            .subscriptions()
            .into_iter()
            // Its own class only: a poller never holds, resumes or polls
            // for a row admitted under another class (MIK-8122).
            .filter(|s| s.live_now() && self.owns(s))
            .collect()
    }
}
