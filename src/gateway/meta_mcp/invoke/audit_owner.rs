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
            if let Err(error) = meta.write_record(record, verdict, None).await {
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
}

/// Ends one job when dropped, so a job that panics still ends.
struct JobEnd(Arc<AuditJobs>);

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
        let end = JobEnd(self);
        runtime.spawn(async move {
            let _end = end;
            job.await;
        });
    }

    /// Wait until no job is open, or `within` has passed. Returns how many
    /// are still open (0 when all ended).
    pub(crate) async fn drain(&self, within: std::time::Duration) -> usize {
        let _ = within;
        self.open.load(Ordering::Acquire)
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
        let landed = meta.write_record(record, verdict, lease).await;
        written = written.and(landed);
    }
    written
}
