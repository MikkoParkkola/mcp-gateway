// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A claimed upstream `tasks/cancel` that was not confirmed is retried
//! (MIK-8347, design r3.5).
//!
//! The claim keeps the row's cancel pending until a peer answers. One sender
//! at a time per row, under an in-process lock taken before the claim and
//! held through the send and the outcome write. The request path never
//! queues on it: a contender bumps the row's generation and returns, and the
//! holder, once it lets go, claims again if the generation moved. A worker's
//! offer that found the row still working is parked under the lock, so a
//! later claim on that row still names the handle. Retries are spawned,
//! never awaited by the sweep that finds them.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::OwnedMutexGuard;
use tokio::task::JoinHandle;

use super::{TaskExecutor, UpstreamHandle, UpstreamRecovery};
use crate::gateway::task_service::TaskService;
use crate::gateway::task_service::record::UpstreamRecord;
use crate::gateway::task_service::store::targets::CancelClaim;
use crate::protocol::tasks::TaskStatus;

/// Failed attempts (sent toward a ready backend, not confirmed) after which a
/// row's cancel is given up. `NotReady` attempts do not count.
pub(crate) const MAX_CANCEL_ATTEMPTS: u8 = 6;

/// How long a claimed cancel is retried, from its claim, whatever the row's
/// retention: unlimited retention must not mean unlimited retrying.
pub(crate) const MAX_CANCEL_PENDING_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Seconds before the sweep retries a cancel the backend was not ready for.
/// A start of that backend retries it sooner.
pub(crate) const NOT_READY_RETRY: i64 = 60;

/// Seconds before the sweep retries after the `attempts`-th failed send.
pub(crate) fn backoff_after(attempts: u8) -> i64 {
    match attempts {
        0 | 1 => 10,
        2 => 30,
        3 => 120,
        4 => 600,
        _ => 1_800,
    }
}

/// The parked offer a lock holder may leave for the next claim.
type Parked = Option<UpstreamRecord>;

/// One row's send exclusion.
#[derive(Default)]
pub(crate) struct RowSend {
    /// Held from before a claim through its send and outcome write; carries
    /// the worker's offer parked on a still-working row.
    lock: Arc<tokio::sync::Mutex<Parked>>,
    /// Bumped by every sender before it tries the lock, never reset: a
    /// holder that sees it moved claims again (design r3.5).
    generation: AtomicU64,
}

/// One entry per row with a send in flight, a parked offer, or a pending
/// cancel.
#[derive(Default)]
pub(crate) struct CancelSends(
    parking_lot::Mutex<HashMap<String, Arc<RowSend>>>,
    #[cfg(test)] parking_lot::Mutex<Option<(Hook, Arc<ClaimPause>)>>,
);

impl CancelSends {
    /// The row's entry, created on first use, its generation bumped.
    fn contend(&self, id: &str) -> Arc<RowSend> {
        let row = Arc::clone(self.0.lock().entry(id.to_owned()).or_default());
        row.generation.fetch_add(1, Ordering::SeqCst);
        row
    }

    /// Drop the row's entry when nothing holds or parks anything in it.
    /// Under the map lock, so no sender can take the entry meanwhile.
    pub(crate) fn forget(&self, id: &str) {
        let mut rows = self.0.lock();
        let idle = rows.get(id).is_some_and(|row| {
            Arc::strong_count(row) == 1 && row.lock.try_lock().is_ok_and(|parked| parked.is_none())
        });
        if idle {
            rows.remove(id);
        }
    }

    /// Drop a deleted row's entry, its parked offer included, unless a
    /// sender still holds it (that sender's own `forget` then finds the row
    /// gone and its offer unusable).
    pub(crate) fn release_row(&self, id: &str) {
        let mut rows = self.0.lock();
        let free = rows
            .get(id)
            .is_some_and(|row| Arc::strong_count(row) == 1 && row.lock.try_lock().is_ok());
        if free {
            rows.remove(id);
        }
    }
}

/// Where a test pauses the next claim made under a row lock.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hook {
    /// Under the lock, after the claim decided.
    AfterClaim,
    /// After the lock is released, before the holder's re-check.
    AfterRelease,
}

/// Holds one claim at its hook until released.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct ClaimPause {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl CancelSends {
    /// Pause the next claim made under a row lock at `hook`, once.
    pub(crate) fn pause_at(&self, hook: Hook) -> Arc<ClaimPause> {
        let pause = Arc::new(ClaimPause::default());
        *self.1.lock() = Some((hook, Arc::clone(&pause)));
        pause
    }

    /// Hold here if a test armed `at`.
    async fn hook(&self, at: Hook) {
        let pause = {
            let mut armed = self.1.lock();
            if armed.as_ref().is_some_and(|(hook, _)| *hook == at) {
                armed.take().map(|(_, pause)| pause)
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
    }
}

/// When a lock holder sends a pending cancel it did not just claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Due {
    /// Only once its back-off or its age says so (the sweep, a re-check).
    ByTime,
    /// Now: its backend's start just succeeded.
    Now,
}

/// What a lock holder needs: the store and the adapter, never the executor,
/// so a detached send keeps nothing else alive.
#[derive(Clone)]
struct Sender {
    service: Arc<TaskService>,
    adapter: Arc<dyn UpstreamRecovery>,
}

impl Sender {
    /// Under the row lock: claim the row's cancel if nobody has, with
    /// `offered` or the parked offer. Returns whether this call claimed. An
    /// offer the claim could not use on a row that is not terminal is parked
    /// for the next claim (design r3.5).
    async fn claim(
        &self,
        (owner, id): (&str, &str),
        parked: &mut OwnedMutexGuard<Parked>,
        offered: Option<UpstreamRecord>,
    ) -> bool {
        let store = &self.service.store;
        if store.pending_cancel(owner, id).is_some() {
            return false;
        }
        let offer = offered.or_else(|| parked.take());
        match store.claim_upstream_cancel(owner, id, offer.clone()).await {
            Ok(CancelClaim::Claimed(_)) => true,
            Ok(CancelClaim::AlreadyClaimed) => false,
            Ok(CancelClaim::NotOurs) => {
                let open = store.get(owner, id).is_ok_and(|row| {
                    !matches!(
                        row.task.status(),
                        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                    )
                });
                if open {
                    **parked = offer;
                }
                false
            }
            Err(error) => {
                tracing::warn!(task_id = %id, ?error, "upstream cancel claim not written; nothing sent");
                **parked = offer;
                false
            }
        }
    }

    /// Under the row lock: send the row's pending cancel if it is due, and
    /// write what the attempt established. A row past its age, or naming no
    /// backend, is given up without a send.
    async fn send(&self, (owner, id): (&str, &str), due: Option<Due>) {
        let store = &self.service.store;
        let Some(pending) = store.pending_cancel(owner, id) else {
            return;
        };
        let Ok(now) = store.now().map(|now| now.timestamp()) else {
            return;
        };
        let attempt = match (&pending.backend, due) {
            (Some(_), _) if pending.aged(now) => None,
            (Some(_), Some(Due::ByTime)) if pending.next_after > now => return,
            (Some(backend), _) => {
                let handle = UpstreamHandle {
                    backend: backend.clone(),
                    handle: pending.handle.clone(),
                };
                let deadline = crate::gateway::meta_mcp::upstream::QUERY_DEADLINE;
                Some(self.adapter.cancel(&handle, deadline).await)
            }
            (None, _) => None,
        };
        if let Err(error) = store.record_cancel_attempt(owner, id, attempt).await {
            tracing::warn!(task_id = %id, ?error, "upstream cancel outcome not written");
        }
    }

    /// Claim and send under `held`, let go, and go again while the row's
    /// generation moved meanwhile. `due` is `None` for a first sender, which
    /// sends only what it claims. `done` is a first pass the caller already
    /// made under `held`: the generation it read before claiming, and whether
    /// it claimed (its send included). Returns whether the first pass claimed.
    async fn run(
        self,
        row: Arc<RowSend>,
        mut held: OwnedMutexGuard<Parked>,
        (owner, id): (String, String),
        (mut offered, mut due): (Option<UpstreamRecord>, Option<Due>),
        mut done: Option<(u64, bool)>,
    ) -> bool {
        let mut first = None;
        loop {
            let (seen, claimed) = if let Some(pass) = done.take() {
                pass
            } else {
                let seen = row.generation.load(Ordering::SeqCst);
                let claimed = self.claim((&owner, &id), &mut held, offered.take()).await;
                #[cfg(test)]
                self.service.cancel_sends.hook(Hook::AfterClaim).await;
                if claimed {
                    self.send((&owner, &id), Some(Due::Now)).await;
                } else if let Some(due) = due {
                    self.send((&owner, &id), Some(due)).await;
                }
                (seen, claimed)
            };
            first.get_or_insert(claimed);
            drop(held);
            #[cfg(test)]
            self.service.cancel_sends.hook(Hook::AfterRelease).await;
            if row.generation.load(Ordering::SeqCst) == seen {
                break;
            }
            // Someone met the lock: claim again, and send what is due.
            held = Arc::clone(&row.lock).lock_owned().await;
            due = Some(Due::ByTime);
        }
        drop(row);
        self.service.cancel_sends.forget(&id);
        first.unwrap_or(false)
    }
}

impl TaskExecutor {
    /// The one way into a row's upstream cancel for a first sender: the
    /// owner's cancel (`Detach`: never queues on the lock, sends detached)
    /// or a worker with the handle it holds (`Inline`: waits, sends here).
    /// Returns whether this call claimed.
    pub(super) async fn claim_and_send(
        &self,
        (owner, id): (&str, &str),
        offered: Option<UpstreamRecord>,
        detach: bool,
    ) -> bool {
        let Some(adapter) = self.recovery().cloned() else {
            return false;
        };
        let sender = Sender {
            service: Arc::clone(&self.service),
            adapter,
        };
        let row = self.service.cancel_sends.contend(id);
        let key = (owner.to_owned(), id.to_owned());
        if !detach {
            let held = Arc::clone(&row.lock).lock_owned().await;
            return sender.run(row, held, key, (offered, None), None).await;
        }
        let Ok(mut held) = Arc::clone(&row.lock).try_lock_owned() else {
            return false;
        };
        // The claim is answered here, as before; the send and any re-check
        // run detached, still under this lock.
        let seen = row.generation.load(Ordering::SeqCst);
        let claimed = sender.claim((owner, id), &mut held, offered).await;
        tokio::spawn(async move {
            if claimed {
                sender.send((&key.0, &key.1), Some(Due::Now)).await;
            }
            sender
                .run(row, held, key, (None, None), Some((seen, claimed)))
                .await
        });
        claimed
    }
    /// Retry the pending cancels of `backend`'s rows now, or, with `None`,
    /// every row whose retry is due. Each send is spawned; the handles are
    /// returned so a caller that must not wait (the sweep) can drop them. A
    /// row whose lock is held is skipped: its holder re-checks.
    pub(crate) fn flush_pending_cancels(
        self: &Arc<Self>,
        backend: Option<&str>,
    ) -> Vec<JoinHandle<()>> {
        match backend {
            Some(backend) => self.flush(Some(backend), Due::Now),
            None => self.flush(None, Due::ByTime),
        }
    }

    fn flush(self: &Arc<Self>, backend: Option<&str>, due: Due) -> Vec<JoinHandle<()>> {
        let Some(adapter) = self.recovery().cloned() else {
            return Vec::new();
        };
        let Ok(now) = self.service.store.now() else {
            return Vec::new();
        };
        // `Now` with no backend is every pending row (a lagged start feed).
        let now = if backend.is_none() && due == Due::Now {
            i64::MAX
        } else {
            now.timestamp()
        };
        let rows = self.service.store.pending_cancels(backend, now);
        rows.into_iter()
            .filter_map(|(owner, id)| {
                let sender = Sender {
                    service: Arc::clone(&self.service),
                    adapter: Arc::clone(&adapter),
                };
                let row = self.service.cancel_sends.contend(&id);
                let held = Arc::clone(&row.lock).try_lock_owned().ok()?;
                Some(tokio::spawn(async move {
                    sender
                        .run(row, held, (owner, id), (None, Some(due)), None)
                        .await;
                }))
            })
            .collect()
    }

    /// Install the recovery adapter and, when it reports backend starts,
    /// retry each started backend's pending cancels at once.
    pub(super) fn adopt_recovery(self: &Arc<Self>, adapter: Arc<dyn UpstreamRecovery>) -> bool {
        let feed = adapter.started();
        if self.recovery.set(adapter).is_err() {
            return false;
        }
        if let Some(feed) = feed {
            self.listen_for_starts(feed);
        }
        true
    }

    /// Holds only a weak reference, so the listener never keeps the executor
    /// alive; it ends with the executor or the feed.
    fn listen_for_starts(self: &Arc<Self>, mut feed: tokio::sync::broadcast::Receiver<String>) {
        use tokio::sync::broadcast::error::RecvError;
        let executor = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let started = match feed.recv().await {
                    Ok(backend) => Some(backend),
                    Err(RecvError::Lagged(_)) => None,
                    Err(RecvError::Closed) => return,
                };
                let Some(executor) = executor.upgrade() else {
                    return;
                };
                // Detached: the next start is heard while these send.
                drop(executor.flush(started.as_deref(), Due::Now));
            }
        });
    }

    /// Wait until no send holds `id`'s lock, so a test's next flush is not
    /// skipped by a send that has written its outcome but not yet let go.
    #[cfg(test)]
    pub(crate) async fn cancel_send_idle(&self, id: &str) {
        let row = self.service.cancel_sends.0.lock().get(id).cloned();
        if let Some(row) = row {
            drop(row.lock.lock().await);
        }
    }
}

#[cfg(test)]
#[path = "pending_cancel_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "pending_cancel_edge_tests.rs"]
mod edge_tests;
