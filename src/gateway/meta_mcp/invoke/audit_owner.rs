// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The audit owner of an HTTP `/mcp` request (D2.3): its calls' invocation
//! records wait here for the scan of the answer the client receives, and
//! each is written exactly once, with that scan's verdict. Every other
//! caller, and every nested step, writes its record where the call ends.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::sync::Arc;

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
fn hand_off(meta: Arc<MetaMcp>, pending: Vec<InvocationRecord>, verdict: AnswerVerdict) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::error!(
            records = pending.len(),
            "invocation records dropped with no runtime to write them"
        );
        return;
    };
    runtime.spawn(async move {
        for record in pending {
            if let Err(error) = meta.write_record(record, verdict, None).await {
                tracing::error!(%error, "invocation record of a dropped request not written");
            }
        }
    });
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
pub(crate) async fn inline<F: Future>(step: F) -> F::Output {
    let owner = Owner {
        meta: None,
        pending: RefCell::default(),
        refused: Cell::new(false),
    };
    OWNER.scope(owner, step).await
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
