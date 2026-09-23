// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-memory sliding rate windows (design §5.3). A restart forgets them: they
//! throttle, they do not protect state.

use std::collections::VecDeque;

use super::{GLOBAL_WINDOW, JourneyLimits, JourneyRefusal, PER_USER_WINDOW, START_RATE_WINDOW};

/// Events as `(principal_digest, at)`, oldest first.
// ponytail: linear scans; bounded by the rates themselves (at most
// `journeys_created_per_minute x 10` creations), index per principal if not.
#[derive(Debug, Default)]
pub(crate) struct Rates {
    creations: VecDeque<(String, u64)>,
    starts: VecDeque<(String, u64)>,
}

/// Seconds until enough in-window events leave for one more to fit, or
/// `None` while fewer than `limit` are inside `window`.
fn wait(times: &[u64], limit: u32, window: u64, now: u64) -> Option<u64> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let excess = times.len().checked_sub(limit)?;
    Some(times[excess].saturating_add(window).saturating_sub(now))
}

/// In-window times of `events`, optionally only one principal's, oldest first.
fn inside(events: &VecDeque<(String, u64)>, who: Option<&str>, window: u64, now: u64) -> Vec<u64> {
    events
        .iter()
        .filter(|(principal, at)| {
            now < at.saturating_add(window) && who.is_none_or(|w| w == principal)
        })
        .map(|(_, at)| *at)
        .collect()
}

fn prune(events: &mut VecDeque<(String, u64)>, window: u64, now: u64) {
    while events
        .front()
        .is_some_and(|(_, at)| now >= at.saturating_add(window))
    {
        events.pop_front();
    }
}

impl Rates {
    /// Per-principal creations (429) then global creations (503).
    pub(crate) fn admit_creation(
        &mut self,
        limits: &JourneyLimits,
        principal: &str,
        now: u64,
    ) -> Result<(), JourneyRefusal> {
        prune(&mut self.creations, PER_USER_WINDOW.max(GLOBAL_WINDOW), now);
        let mine = inside(&self.creations, Some(principal), PER_USER_WINDOW, now);
        if let Some(retry_after) = wait(&mine, limits.journeys_per_user, PER_USER_WINDOW, now) {
            return Err(JourneyRefusal::RateLimited { retry_after });
        }
        let all = inside(&self.creations, None, GLOBAL_WINDOW, now);
        match wait(&all, limits.journeys_created_per_minute, GLOBAL_WINDOW, now) {
            Some(retry_after) => Err(JourneyRefusal::CapacityExceeded { retry_after }),
            None => Ok(()),
        }
    }

    pub(crate) fn record_creation(&mut self, principal: &str, now: u64) {
        self.creations.push_back((principal.to_owned(), now));
    }

    /// `starts_per_minute_per_user`: first starts and re-arms alike (429).
    pub(crate) fn admit_start(
        &mut self,
        limits: &JourneyLimits,
        principal: &str,
        now: u64,
    ) -> Result<(), JourneyRefusal> {
        prune(&mut self.starts, START_RATE_WINDOW, now);
        let mine = inside(&self.starts, Some(principal), START_RATE_WINDOW, now);
        if let Some(retry_after) = wait(
            &mine,
            limits.starts_per_minute_per_user,
            START_RATE_WINDOW,
            now,
        ) {
            return Err(JourneyRefusal::RateLimited { retry_after });
        }
        self.starts.push_back((principal.to_owned(), now));
        Ok(())
    }
}
