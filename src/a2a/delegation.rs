// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who owns an agent's task while the bridge waits on it (MIK-8063 PR2).
//!
//! Two owners, never none: while a call is in flight a [`CancelGuard`] holds the
//! task, and while a question waits for the caller the [`Parked`] map does.
//! Whichever owns it when the wait is abandoned (the caller's future dropped,
//! the question expired, the backend closed) sends the agent one `CancelTask`,
//! so an abandoned delegation does not keep running at the agent.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::client::{A2aClient, Endpoint};

/// How long an unanswered question stays redeemable: the gateway's 300 s
/// continuation plus a margin, so a live sealed envelope never outlives its
/// token. With the sweep below, an abandoned question's task is canceled
/// within [`ABANDONED_CANCEL_BOUND`] (the promise A2A.9 and the release notes
/// make).
pub(crate) const PARKED_TTL: Duration = Duration::from_secs(315);
/// How often parked questions are checked for expiry.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_secs(15);
/// The latest an abandoned parked task is canceled, after it was asked.
pub(crate) const ABANDONED_CANCEL_BOUND: Duration = Duration::from_secs(330);

// Checked at build time: the token expires after the TTL and the sweep finds
// it at most one interval later, within the promised bound; and it outlives
// the gateway's 300 s continuation, so an answer in time is never refused.
const _: () = assert!(
    PARKED_TTL.as_secs() + SWEEP_EVERY.as_secs() <= ABANDONED_CANCEL_BOUND.as_secs()
        && PARKED_TTL.as_secs() > 300
);
/// The most questions one agent backend holds open at once.
pub(crate) const PARKED_CAP: usize = 1024;

/// An agent task waiting for the caller's answer.
pub(crate) struct Pending {
    pub task_id: String,
    pub context_id: Option<String>,
    /// The identity the question was asked of; only it may answer.
    identity: Option<String>,
    /// The request's own headers (a propagated credential), so a cancel sent
    /// on the caller's behalf authenticates as the caller did.
    pub headers: Vec<(String, String)>,
    expires: Instant,
}

/// Why a token was not redeemed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Never issued, already used, expired, or issued to someone else. One
    /// answer for all, so a caller cannot probe which.
    NotYours,
}

/// Why a question could not be parked; its task is then canceled instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkRefused {
    /// [`PARKED_CAP`] questions are already waiting.
    Full,
    /// The backend is closing: nothing would ever sweep the entry.
    Closed,
}

/// The parked entries, and whether the backend has closed. One lock for
/// both, so a park and a close cannot interleave.
#[derive(Default)]
struct Entries {
    map: HashMap<String, Pending>,
    closed: bool,
}

/// The questions an agent backend is waiting on, keyed by opaque token.
pub(crate) struct Parked {
    entries: parking_lot::Mutex<Entries>,
    ttl: Duration,
}

impl Parked {
    pub(crate) fn new(ttl: Duration) -> Self {
        Self {
            entries: parking_lot::Mutex::new(Entries::default()),
            ttl,
        }
    }

    /// Park a task and return its token, or say why not (the caller then
    /// cancels the task instead of holding it).
    pub(crate) fn park(
        &self,
        task_id: String,
        context_id: Option<String>,
        identity: Option<&str>,
        headers: Vec<(String, String)>,
        now: Instant,
    ) -> Result<String, ParkRefused> {
        let mut entries = self.entries.lock();
        if entries.closed {
            return Err(ParkRefused::Closed);
        }
        if entries.map.len() >= PARKED_CAP {
            return Err(ParkRefused::Full);
        }
        // A system RNG that cannot answer leaves nothing safe to issue.
        let token = fresh_token().ok_or(ParkRefused::Full)?;
        entries.map.insert(
            token.clone(),
            Pending {
                task_id,
                context_id,
                identity: identity.map(str::to_owned),
                headers,
                expires: now + self.ttl,
            },
        );
        Ok(token)
    }

    /// Redeem `token` for `identity`, once. An expired entry is removed and
    /// handed back in `Err` so its task can be canceled; a token presented by
    /// another identity stays for its owner.
    pub(crate) fn take(
        &self,
        token: &str,
        identity: Option<&str>,
        now: Instant,
    ) -> Result<Pending, (Refused, Option<Pending>)> {
        let mut entries = self.entries.lock();
        let Some(entry) = entries.map.get(token) else {
            return Err((Refused::NotYours, None));
        };
        if entry.expires <= now {
            return Err((Refused::NotYours, entries.map.remove(token)));
        }
        if entry.identity.as_deref() != identity {
            return Err((Refused::NotYours, None));
        }
        entries.map.remove(token).ok_or((Refused::NotYours, None))
    }

    /// Remove and return every expired entry.
    pub(crate) fn drain_expired(&self, now: Instant) -> Vec<Pending> {
        let mut entries = self.entries.lock();
        let expired: Vec<String> = entries
            .map
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
            .map(|(token, _)| token.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|token| entries.map.remove(&token))
            .collect()
    }

    /// Refuse every later park and return every waiting entry (the backend
    /// is closing).
    pub(crate) fn close(&self) -> Vec<Pending> {
        let mut entries = self.entries.lock();
        entries.closed = true;
        entries.map.drain().map(|(_, entry)| entry).collect()
    }
}

/// 128 random bits, base64url: unguessable, and says nothing about the task.
fn fresh_token() -> Option<String> {
    use base64::Engine as _;
    use ring::rand::SecureRandom as _;
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Send one best-effort `CancelTask` without waiting for it. Bounded by the
/// client's own timeout; a failure is logged, never retried.
pub(crate) fn spawn_cancel(
    client: A2aClient,
    endpoint: Endpoint,
    task_id: String,
    headers: Vec<(String, String)>,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(task_id, "no runtime to cancel an abandoned A2A task on");
        return;
    };
    runtime.spawn(async move {
        match client.cancel_task(&endpoint, &task_id, &headers).await {
            Ok(super::client::Reply::Answer(_)) => {}
            Ok(super::client::Reply::AgentError { code, message }) => {
                tracing::warn!(
                    task_id,
                    code,
                    message,
                    "the A2A agent refused to cancel a task"
                );
            }
            Err(error) => {
                tracing::warn!(task_id, %error, "canceling an abandoned A2A task failed");
            }
        }
    });
}

/// Owns an in-flight task: armed once the agent names it, disarmed when the
/// call ends with an answer or hands the task to [`Parked`]. Dropped while
/// armed, it cancels the task.
pub(crate) struct CancelGuard {
    client: A2aClient,
    endpoint: Endpoint,
    headers: Vec<(String, String)>,
    task_id: Option<String>,
}

impl CancelGuard {
    pub(crate) fn new(
        client: A2aClient,
        endpoint: Endpoint,
        headers: Vec<(String, String)>,
    ) -> Self {
        Self {
            client,
            endpoint,
            headers,
            task_id: None,
        }
    }

    pub(crate) fn arm(&mut self, task_id: &str) {
        self.task_id = Some(task_id.to_owned());
    }

    pub(crate) fn disarm(&mut self) {
        self.task_id = None;
    }

    /// Whether the guard owns a task it would cancel.
    pub(crate) fn is_armed(&self) -> bool {
        self.task_id.is_some()
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(task_id) = self.task_id.take() {
            spawn_cancel(
                self.client.clone(),
                self.endpoint.clone(),
                task_id,
                std::mem::take(&mut self.headers),
            );
        }
    }
}

#[cfg(test)]
#[path = "delegation_tests.rs"]
mod tests;
