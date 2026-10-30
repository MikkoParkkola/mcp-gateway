// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's UI sign-in in flight: who started it, where it stands, when it
//! ends, and the token it holds between the callback and the confirm. Memory
//! only: a restart drops it. The engine that drives it lives with the routes.

use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::Notify;
use tokio::time::Instant;

use super::Backend;
use crate::gateway::auth::AuthenticatedClient;
use crate::oauth::client::sign_in::PendingGrant;

/// Where a flow stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// The link is out; nobody has come back yet.
    AwaitingCallback,
    /// The callback landed; the person must confirm.
    AwaitingConfirm,
}

impl Phase {
    /// The word the status read shows.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::AwaitingCallback => "awaiting_callback",
            Self::AwaitingConfirm => "awaiting_confirm",
        }
    }
}

/// One sign-in in flight. Holds no link and no verifier.
pub(crate) struct Flow {
    /// The keyed digest of the starting session's handle.
    pub(crate) owner: String,
    /// Random; a confirm must present it.
    pub(crate) attempt_id: String,
    pub(crate) phase: Phase,
    /// When the flow ends if nobody acts: its current stage's end.
    pub(crate) until: Instant,
    /// `until` on the wall clock, for what a person reads.
    pub(crate) until_at: SystemTime,
    /// The token the callback bought, until a decision takes it.
    pub(crate) grant: Option<PendingGrant>,
    /// When the grant arrived, to shorten its lifetime by the time held.
    pub(crate) held_since: Option<Instant>,
    /// The slot's `auth_wait` generation when the callback landed.
    pub(crate) wait_generation: u64,
    /// The starting caller, for the records of the flow's later ends.
    pub(crate) caller: Option<AuthenticatedClient>,
    /// Woken when a decision has ended the flow, so its task lets go.
    pub(crate) ended: Arc<Notify>,
    /// The client the login ran on, which saves the grant on a confirm.
    pub(crate) client: Arc<crate::oauth::OAuthClient>,
}

impl Flow {
    /// Move the flow's end to `at`, `from_now` away.
    pub(crate) fn end_at(&mut self, at: Instant) {
        self.until_at = SystemTime::now() + at.saturating_duration_since(Instant::now());
        self.until = at;
    }

    /// Whole seconds left until the flow's end, rounded up.
    pub(crate) fn retry_after_secs(&self) -> u64 {
        let left = self.until.saturating_duration_since(Instant::now());
        left.as_secs() + u64::from(left.subsec_nanos() > 0)
    }
}

impl Backend {
    /// Run `f` on the flow slot under its lock.
    pub(crate) fn with_flow<R>(&self, f: impl FnOnce(&mut Option<Flow>) -> R) -> R {
        f(&mut self.sign_in_flow.lock())
    }

    /// Clear the slot's `auth_wait` unless a newer wait was recorded since the
    /// generation `seen`.
    // ponytail: check then store, not one atomic step; a wait recorded in
    // between is lost. Pack the flag and the generation into one word if it
    // ever matters.
    pub(crate) fn clear_auth_wait_if(&self, seen: u64) {
        let entry = self.shared_entry();
        if entry
            .auth_wait_gen
            .load(std::sync::atomic::Ordering::Relaxed)
            == seen
        {
            entry
                .auth_wait
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// The phase and wall-clock end of the flow in flight, for the status
    /// read: nothing else of it.
    pub(crate) fn sign_in_flow_view(&self) -> Option<(Phase, SystemTime)> {
        self.with_flow(|slot| slot.as_ref().map(|flow| (flow.phase, flow.until_at)))
    }
}
