// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit owner of an HTTP `/mcp` request (D2.3): its calls' invocation
//! records wait here for the scan of the answer the client receives, and
//! each is written exactly once, with that scan's verdict. Every other
//! caller, and every nested step, writes its record where the call ends.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Notify;

use super::audit::{AnswerVerdict, InvocationRecord};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::admission::SyncLease;

tokio::task_local! {
    static OWNER: Owner;
}

struct Owner {
    /// `None` in a nested step's scope: its records are written inline.
    meta: Option<Arc<MetaMcp>>,
    pending: RefCell<Vec<InvocationRecord>>,
    refused: Cell<bool>,
}

impl Owner {
    fn verdict(&self) -> AnswerVerdict {
        if self.refused.get() {
            AnswerVerdict::Refused
        } else {
            AnswerVerdict::Delivered
        }
    }
}

impl Drop for Owner {
    /// A request dropped before its commit (its client went away): the
    /// records it holds are still written, never lost and never twice.
    fn drop(&mut self) {
        let pending = self.pending.take();
        if let Some(meta) = self.meta.take()
            && !pending.is_empty()
        {
            hand_off(meta, pending, self.verdict());
        }
    }
}

/// Write `pending` off the request: it was dropped, so nothing awaits it.
/// The write is one of the gateway's audit jobs, which shutdown waits for.
fn hand_off(meta: Arc<MetaMcp>, pending: Vec<InvocationRecord>, verdict: AnswerVerdict) {
    let jobs = Arc::clone(&meta.audit_jobs);
    jobs.spawn(async move {
        for record in pending {
            let appended = meta.append_record(record, verdict).await;
            if let Err(error) = meta.settle_record(appended, None) {
                tracing::error!(%error, "invocation record of a dropped request not written");
            }
        }
    });
}

/// The gateway's audit jobs: record writes handed off a request that no
/// longer awaits them (D2.5). Graceful shutdown waits for them after the
/// listener's drain, within its grace bound, and reports any still open.
#[derive(Debug, Default)]
pub(crate) struct AuditJobs {
    open: AtomicUsize,
    idle: Notify,
    #[cfg(test)]
    pub(crate) seams: JobSeams,
}

/// Test hooks on the jobs of one gateway: park a request at its commit (so
/// only its drop can write its records), hold each job at a gate, and
/// report each drain with the jobs open when it started.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct JobSeams {
    pub(crate) hold_commit: std::sync::atomic::AtomicBool,
    pub(crate) parked: Notify,
    pub(crate) gate_jobs: std::sync::atomic::AtomicBool,
    /// Set (then `job_gate` woken) to let every gated job run.
    pub(crate) gate_open: std::sync::atomic::AtomicBool,
    pub(crate) job_gate: Notify,
    pub(crate) drains: std::sync::Mutex<Vec<usize>>,
    pub(crate) draining: Notify,
}

/// Ends one job when dropped, so a job that panics still ends.
struct JobEnd(Arc<AuditJobs>);

#[cfg(test)]
impl JobSeams {
    /// Wait until the row opens the gate; registered before each check, so
    /// an opening in between is not missed.
    async fn wait_for_gate(&self) {
        loop {
            let opened = self.job_gate.notified();
            tokio::pin!(opened);
            opened.as_mut().enable();
            if self.gate_open.load(Ordering::SeqCst) {
                return;
            }
            opened.await;
        }
    }

    /// Let every gated job run, now and later.
    pub(crate) fn open_gate(&self) {
        self.gate_open.store(true, Ordering::SeqCst);
        self.job_gate.notify_waiters();
    }
}

impl Drop for JobEnd {
    fn drop(&mut self) {
        if self.0.open.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

impl AuditJobs {
    /// Run `job` on the runtime as one of these jobs. With no runtime (a
    /// drop during runtime teardown) the job cannot run and is reported.
    pub(crate) fn spawn(self: Arc<Self>, job: impl Future<Output = ()> + Send + 'static) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::error!("an audit job was handed off with no runtime to run it");
            return;
        };
        self.open.fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        let gated = self.seams.gate_jobs.load(Ordering::SeqCst);
        let end = JobEnd(self);
        runtime.spawn(async move {
            #[cfg(test)]
            if gated {
                end.0.seams.wait_for_gate().await;
            }
            job.await;
            // Also dropped if `job` panics: the future owns it.
            drop(end);
        });
    }

    /// Wait until no job is open, or `within` has passed. Returns how many
    /// are still open (0 when all ended).
    pub(crate) async fn drain(&self, within: std::time::Duration) -> usize {
        #[cfg(test)]
        {
            let open = self.open.load(Ordering::Acquire);
            self.seams
                .drains
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(open);
            self.seams.draining.notify_one();
        }
        let _ = tokio::time::timeout(within, async {
            loop {
                let idle = self.idle.notified();
                tokio::pin!(idle);
                // Registered before the count is read, so a job ending in
                // between still wakes this wait.
                idle.as_mut().enable();
                if self.open.load(Ordering::Acquire) == 0 {
                    return;
                }
                idle.await;
            }
        })
        .await;
        self.open.load(Ordering::Acquire)
    }

    /// Park the request at its commit while `hold_commit` is set.
    #[cfg(test)]
    pub(crate) async fn before_commit_for_test(&self) {
        if self.seams.hold_commit.load(Ordering::SeqCst) {
            self.seams.parked.notify_one();
            std::future::pending::<()>().await;
        }
    }
}

/// Run one HTTP `/mcp` request as the owner of its calls' records. A record
/// the request's answer path never committed (an early answer) is written
/// when `request` ends.
pub(crate) async fn owned<F: Future>(meta: Arc<MetaMcp>, request: F) -> F::Output {
    let owner = Owner {
        meta: Some(meta),
        pending: RefCell::default(),
        refused: Cell::new(false),
    };
    OWNER
        .scope(owner, async {
            let output = request.await;
            if let Err(error) = commit(None).await {
                tracing::error!(%error, "invocation record of an early answer not written");
            }
            output
        })
        .await
}

/// Run a nested step: its records are written inline, never held by the
/// request's owner.
pub(crate) fn inline<F: Future>(step: F) -> impl Future<Output = F::Output> {
    let owner = Owner {
        meta: None,
        pending: RefCell::default(),
        refused: Cell::new(false),
    };
    OWNER.scope(owner, step)
}

/// Hold `record` for the open owner; with none open it comes back to be
/// written now.
pub(super) fn defer(record: InvocationRecord) -> Option<InvocationRecord> {
    let mut record = Some(record);
    let _ = OWNER.try_with(|owner| {
        if owner.meta.is_some() {
            owner.pending.borrow_mut().extend(record.take());
        }
    });
    record
}

/// The response firewall refused the answer this request delivers.
pub(super) fn answer_refused() {
    let _ = OWNER.try_with(|owner| owner.refused.set(true));
}

/// Write every held record once, with the scan's verdict: after the answer
/// was finalized, before it is judged or stored. `Err` only when a write
/// failed under fail-closed; the answer must then be withheld (D1-f).
pub(crate) async fn commit(lease: Option<&SyncLease>) -> crate::Result<()> {
    let Ok((meta, pending, verdict)) =
        OWNER.try_with(|owner| (owner.meta.clone(), owner.pending.take(), owner.verdict()))
    else {
        return Ok(());
    };
    let Some(meta) = meta else {
        return Ok(());
    };
    let mut written = Ok(());
    for record in pending {
        // The write is a job of its own (D2.3): the request may be cancelled
        // or dropped while it appends, and the record still lands, once.
        let (sent, received) = tokio::sync::oneshot::channel();
        let job = Arc::clone(&meta);
        Arc::clone(&meta.audit_jobs).spawn(async move {
            let _ = sent.send(job.append_record(record, verdict).await);
        });
        let landed = match received.await {
            Ok(appended) => meta.settle_record(appended, lease),
            // The job ended with no verdict (it panicked, or no runtime ran
            // it): the record is not known to have landed, which each
            // failure policy treats as it treats a failed write.
            Err(_) => {
                tracing::error!("an invocation record's write ended with no verdict");
                let closed = meta.transparency_logger.as_ref().is_some_and(|log| {
                    log.failure_policy() == crate::security::audit::AuditFailurePolicy::FailClosed
                });
                if closed {
                    Err(crate::Error::AuditUnavailable)
                } else {
                    Ok(())
                }
            }
        };
        written = written.and(landed);
    }
    written
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "audit_owner_tests.rs"]
mod tests;
