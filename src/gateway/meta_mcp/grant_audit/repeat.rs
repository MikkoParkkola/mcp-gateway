// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The repeat-suppression store for re-checked grant decisions:
//! the last decision written per task, caller and target, and the window an
//! unchanged one is not written again inside. See the parent module's docs.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long an unchanged re-check decision is not written again.
pub(in crate::gateway::meta_mcp) const REPEAT_WINDOW: Duration = Duration::from_secs(600);

/// Keys the store holds at most; a full store records every decision.
const REPEAT_CAP: usize = 4096;

/// The last written re-check decision per task, caller and target.
///
/// One async lock spans the repeat check, the append and the remember, so
/// the remembered decision is always the last one written: two concurrent
/// re-checks straddling a grant change cannot leave an older decision
/// remembered over a newer record. The append it waits on is bounded (F20).
// ponytail: one lock per gateway serializes re-check records only; per-key
// locks if polling a finished task ever becomes a throughput concern.
#[derive(Debug, Default)]
pub(crate) struct DecisionDedupe(pub(super) tokio::sync::Mutex<RepeatLedger>);

/// The suppression state [`DecisionDedupe`] guards.
#[derive(Debug, Default)]
pub(in crate::gateway::meta_mcp) struct RepeatLedger(HashMap<String, (String, Instant)>);

impl RepeatLedger {
    /// Whether `decision` is what was last written for `key`, inside the window.
    pub(in crate::gateway::meta_mcp) fn is_repeat(
        &self,
        key: &str,
        decision: &str,
        now: Instant,
    ) -> bool {
        self.0.get(key).is_some_and(|(last, at)| {
            last == decision && now.saturating_duration_since(*at) < REPEAT_WINDOW
        })
    }

    /// Record that `decision` was written for `key` at `now`.
    pub(in crate::gateway::meta_mcp) fn remember(
        &mut self,
        key: String,
        decision: String,
        now: Instant,
    ) {
        let map = &mut self.0;
        if map.len() >= REPEAT_CAP && !map.contains_key(&key) {
            map.retain(|_, (_, at)| now.saturating_duration_since(*at) < REPEAT_WINDOW);
            if map.len() >= REPEAT_CAP {
                // ponytail: a full store of live keys stops suppressing new
                // ones (fails toward recording); an LRU if that ever matters.
                return;
            }
        }
        map.insert(key, (decision, now));
    }
}
