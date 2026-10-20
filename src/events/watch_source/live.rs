// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202: the live rows a watch source reads, and the holder each polls
//! as. Liveness is judged on the caller's one reading of the wall clock, and
//! only a reading that succeeded: a caller whose clock reads before 1970
//! refuses at its own read, so an undated lease never becomes an empty row
//! set that a holder check passes over.

use serde_json::Value;

use super::{EventsHub, Holder, Run, Subscription, Target, WatchSource};

impl WatchSource {
    /// Live rows of `principal` for `name` with these canonical `arguments`,
    /// at `now`, a reading that succeeded (MIK-8202).
    pub(super) fn rows(
        hub: &EventsHub,
        principal: &str,
        name: &str,
        arguments: &Value,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Subscription> {
        hub.store
            .subscriptions()
            .into_iter()
            .filter(|s| s.live(now) && s.principal == principal && s.name == name)
            .filter(|s| s.arguments == *arguments)
            .collect()
    }

    /// The holder a stored row polls as, when its credential still passes:
    /// an API key that is live and may invoke `target`.
    pub(super) fn holder(
        &self,
        row: &Subscription,
        target: &Target,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<Holder> {
        let holder = super::holder_of(row)?;
        self.host.may_invoke(&holder, target, now).then_some(holder)
    }
}

impl Run {
    /// The rows live at `now` that hold this poller's key. `now` is the
    /// poll's one reading of the clock, so a clock that fails during the scan
    /// cannot drop a live row and retire the poller (MIK-8202).
    pub(super) fn holders(
        &self,
        hub: &EventsHub,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Subscription> {
        hub.store
            .subscriptions()
            .into_iter()
            // Its own class only: a poller never holds, resumes or polls
            // for a row admitted under another class (MIK-8122).
            .filter(|s| s.live(now) && self.owns(s))
            .collect()
    }
}
