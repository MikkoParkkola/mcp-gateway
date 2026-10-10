// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task worker's clock channel through the invoke funnel (MIK-8202 AC12,
//! AC13).
//!
//! A request thread that cannot read its clock refuses at once: there is no
//! worker to wait in, and the caller can retry. A task worker can wait, so the
//! funnel hands it two typed outcomes instead of a refusal the worker would
//! have to parse out of a message:
//!
//! - [`Withheld`]: the backend asked for input but the clock could not date a
//!   continuation. The gated payload and the original binding go to the
//!   worker, which waits, then seals with one checked time. Never
//!   client-visible: the funnel's own answer is still the refusal.
//! - a refused redemption sample: the clock could not date the open, so
//!   nothing was spent or dispatched, and the worker retries.
//!
//! The channel lives on the worker's [`DispatchLog`], reached through the
//! same task-local, so a request thread (no log) never sees it.

use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::gateway::task_service::TaskStore;

/// What an exchange was bound to when the backend asked: owned, so a late mint
/// keeps the original binding (MRTR.2).
pub(crate) struct Binding {
    pub(super) server: String,
    pub(super) fingerprint: String,
    pub(super) digest: String,
}

/// An interim round whose continuation could not be dated yet.
pub(crate) struct Withheld {
    result: Value,
    binding: Binding,
    backend_request_state: Option<String>,
}

impl Withheld {
    /// Seal the envelope at `now`, the worker's one checked time, and return
    /// the payload carrying it, or `None` when it cannot be bound or held.
    pub(crate) async fn seal(
        self,
        continuation: &std::sync::Arc<crate::protocol::continuation::ContinuationState>,
        now: u64,
    ) -> Option<Value> {
        let (envelope, _hold) = super::continuation::seal_exchange(
            continuation,
            self.binding,
            self.backend_request_state,
            now,
        )
        .await?;
        let mut result = self.result;
        result["requestState"] = json!(envelope);
        crate::gateway::gateway_writes::note(
            crate::gateway::gateway_writes::Layer::Value,
            crate::gateway::gateway_writes::REQUEST_STATE,
            &result,
        );
        Some(result)
    }
}

/// The part of a worker's dispatch log the funnel and the worker share.
#[derive(Default)]
pub(crate) struct WorkerChannel {
    store: Mutex<Option<TaskStore>>,
    withheld: Mutex<Option<Withheld>>,
    redemption_unreadable: AtomicBool,
    redemption_expired: AtomicBool,
}

impl WorkerChannel {
    /// Arm the channel with the store whose clock dates this worker's calls.
    pub(crate) fn arm(&self, store: &TaskStore) {
        *self.store.lock() = Some(store.clone());
    }

    /// The round the funnel withheld, once.
    pub(crate) fn take_withheld(&self) -> Option<Withheld> {
        self.withheld.lock().take()
    }

    /// Whether a redemption's open refused the envelope as expired against a
    /// readable sample, once: a typed fact, never read from the message.
    pub(crate) fn take_redemption_expired(&self) -> bool {
        self.redemption_expired.swap(false, Ordering::SeqCst)
    }

    /// Whether a redemption was refused for an unreadable clock, once.
    pub(crate) fn take_redemption_unreadable(&self) -> bool {
        self.redemption_unreadable.swap(false, Ordering::SeqCst)
    }
}

/// The task worker whose dispatch is being awaited: `None` on a request thread.
fn armed() -> Option<(
    std::sync::Arc<crate::gateway::meta_mcp::dispatch_log::DispatchLog>,
    TaskStore,
)> {
    let log = crate::gateway::meta_mcp::dispatch_log::current_worker()?;
    let store = log.worker().store.lock().clone()?;
    Some((log, store))
}

/// What a mint came to.
pub(super) enum Minted {
    Sealed(String, String),
    /// A worker will seal it later; the funnel must not.
    Withheld(Binding, Option<String>),
    Refused,
}

/// Mint on the clock a request reads, or, for a task worker whose store clock
/// is unreadable, withhold the round for the worker to seal.
pub(super) async fn mint_or_withhold(
    continuation: &std::sync::Arc<crate::protocol::continuation::ContinuationState>,
    source: crate::protocol::mrtr::PrincipalSource<'_>,
    target: (&str, Option<u64>),
    tool: &str,
    arguments: &Value,
    backend_request_state: Option<String>,
) -> Minted {
    if armed().is_some_and(|(_, store)| store.now().is_err()) {
        return match super::continuation::bind(source, target, tool, arguments) {
            Some(binding) => Minted::Withheld(binding, backend_request_state),
            None => Minted::Refused,
        };
    }
    match super::continuation::mint_continuation(
        continuation,
        source,
        target,
        tool,
        arguments,
        backend_request_state,
    )
    .await
    {
        Some((envelope, hold)) => Minted::Sealed(envelope, hold),
        None => Minted::Refused,
    }
}

/// Hand the gated payload to the worker. The funnel's own answer stays the
/// refusal, so a path that drops the channel is today's behaviour.
pub(super) fn hand_to_worker(
    (binding, backend_request_state): (Binding, Option<String>),
    gated: Value,
) -> bool {
    let Some((log, _)) = armed() else {
        return false;
    };
    *log.worker().withheld.lock() = Some(Withheld {
        result: gated,
        binding,
        backend_request_state,
    });
    true
}

/// The one time a redemption samples, immediately before the open.
///
/// `None` off a worker: the request reads `crate::clock` as before. On a
/// worker, `Some(Err(..))` is a clock that cannot date the open: the channel
/// notes it, and nothing has been spent or dispatched.
pub(super) fn redemption_sample()
-> Option<Result<u64, crate::protocol::continuation::ContinuationError>> {
    use crate::protocol::continuation::ContinuationError;
    let (log, store) = armed()?;
    let sample = store
        .redemption_now()
        .ok()
        .and_then(|at| u64::try_from(at.timestamp()).ok());
    Some(sample.ok_or_else(|| {
        log.worker()
            .redemption_unreadable
            .store(true, Ordering::SeqCst);
        ContinuationError::ClockUnreadable
    }))
}

/// Note, for the worker, that the open refused `error`: only a real expiry
/// matters, and it closes the round.
pub(super) fn note_open_refusal(error: &crate::protocol::continuation::ContinuationError) {
    use crate::protocol::continuation::ContinuationError;
    if *error == ContinuationError::Expired
        && let Some((log, _)) = armed()
    {
        log.worker()
            .redemption_expired
            .store(true, Ordering::SeqCst);
    }
}
