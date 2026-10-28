// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task executor: one admission, one publication seam, one spawned owner.

mod context;
mod expiry;
mod input_round;
mod observe;
mod operations;
#[cfg(debug_assertions)]
pub(crate) mod pause_hook;
pub(crate) mod pending_cancel;
mod recovery;
#[cfg(test)]
pub(crate) mod resume_seams;
mod settle_followed;
mod settlement;
mod upstream;
mod worker;

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot};

pub(crate) use context::{OwnedAdmissionRequest, OwnedCallerContext};
/// The guard the gateway holds for the periodic sweep it started.
pub(crate) use expiry::ExpirySweep;
pub(crate) use input_round::InputOutcome;
pub(crate) use observe::{
    CancelDelivery, CancelOutcome, CommitObserver, CommitStage, DrainOutcome, UpstreamAnswer,
    UpstreamHandle, UpstreamRecovery,
};
use observe::{Handoff, HandoffRegistry};
pub(in crate::gateway::task_service) use recovery::recovery_event;
pub(crate) use upstream::UpstreamCapture;
/// Reachable at the visibility of [`TaskExecutor::commit`], which returns it.
pub(crate) use worker::CommitFailure;
use worker::commit_and_run;
#[cfg(test)]
pub(crate) use worker::rescue_seam;

use super::record::{CommittedTask, ErrorAuthor, Target};
use super::service::{CreateOutcome, ServiceError, TaskService};
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};
use crate::protocol::{JsonRpcResponse, RequestId};

/// The log target the executor's events have always carried, kept by the
/// methods moved into [`operations`].
const EXECUTION_TARGET: &str = module_path!();

pub(crate) struct TaskCall {
    pub tool: String,
    pub arguments: Value,
    /// Where a surfaced `tool` resolved at intake, read
    /// inside the request's snapshot. The worker and a resume dispatch there
    /// or refuse; `None` for a non-surfaced call and for a record from before
    /// the field, which resolves live as before.
    pub surfaced_server: Option<super::record::SurfacedTarget>,
}

/// `'static` intent: nothing borrowed from the request-thread caller.
///
/// Public because it travels on the public `task` field of the meta-MCP caller
/// context, and opaque because nothing outside this crate can build or read
/// one: every field is `pub(crate)` and there is no constructor. An external
/// caller can still write `task: None`, which is the only shape it ever had.
pub struct TaskIntent {
    pub(crate) executor: Arc<TaskExecutor>,
    pub(crate) owned: OwnedCallerContext,
    pub(crate) request: OwnedAdmissionRequest,
    pub(crate) options: TaskOptions,
}

/// Request-facing outcomes never own a worker permit.
pub(crate) enum BeginOutcome {
    Created(CommittedTask),
    /// A repeat of a key that already owns a task: the stored task, carrying
    /// its holds, delivered only by adopting them (MIK-8176 N1).
    Existing(crate::gateway::meta_mcp::sealed_hold::Held<CommittedTask>),
    Mismatch,
    InFlight,
    Capacity,
    Unavailable,
    /// New keyed tasks are sealed (MIK-8052).
    Sealed,
}

impl BeginOutcome {
    pub(crate) fn into_response(self, id: RequestId) -> JsonRpcResponse {
        match self {
            Self::Created(_) | Self::Existing(_) => {
                // A fresh task carries no holds; a stored one's are adopted
                // into this request's scope before its wire form is built.
                let task = match self {
                    Self::Created(task) => {
                        created_serves_no_output(&task);
                        task
                    }
                    Self::Existing(held) => {
                        held.deliver(crate::gateway::meta_mcp::sealed_hold::HoldSink::Scope)
                    }
                    _ => unreachable!("matched above"),
                };
                let mut value = task.delivered_wire();
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("resultType".into(), json!("task"));
                }
                // MIK-7939: the envelope is the gateway's; a receipt reads
                // only the slot it delivers.
                crate::gateway::meta_mcp::invoke::gateway_writes::note_task_envelope(&value);
                JsonRpcResponse::success(id, value)
            }
            Self::Mismatch => JsonRpcResponse::error(
                Some(id),
                INVALID_PARAMS,
                "idempotency key already used with a different request",
            ),
            Self::InFlight => JsonRpcResponse::error(
                Some(id),
                -32002,
                "a task with this idempotency key is already being created",
            ),
            // Refused at once, never queued: a pool whose workers all wait
            // (for a backend, or for a host clock that reads before 1970)
            // must not hang new submissions (MIK-8202).
            Self::Capacity => JsonRpcResponse::error(
                Some(id),
                INTERNAL_ERROR,
                "every task worker is busy; retry later",
            ),
            Self::Unavailable => {
                JsonRpcResponse::error(Some(id), INTERNAL_ERROR, "task store unavailable")
            }
            // The code the synchronous path gives a sealed call, so a client
            // sees one refusal for it on either path.
            Self::Sealed => {
                JsonRpcResponse::error(Some(id), 409, crate::idempotency::admission::SEALED_MESSAGE)
            }
        }
    }
}

/// A write that creates a task. Its own type, not a variant of the transitions:
/// what a create can answer (created, existing, refused) and what a transition
/// can answer (the committed record) never overlap, so neither caller has an
/// arm for the other's outcome.
pub(crate) struct CreateWrite<'a> {
    pub(crate) request: &'a OwnedAdmissionRequest,
    pub(crate) task: &'a Task,
    pub(crate) backend: &'a str,
    /// The single backend call the task makes, when it makes exactly one.
    pub(crate) targets: Vec<Target>,
}

/// A write that moves an existing task. It answers with the committed record.
pub(crate) enum TransitionWrite<'a> {
    Settle {
        principal: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
        /// A plan's dispatched calls, committed in the same write as its
        /// outcome. `None` for a call whose target was recorded at creation.
        targets: crate::gateway::task_service::record::Provenance,
        /// Who wrote a `Fail` event's error (MIK-7887.RECEIPT.1).
        author: ErrorAuthor,
        /// The members of a `Complete` result the gateway wrote (MIK-7993).
        writes: crate::gateway::gateway_writes::WriteRecord,
    },
    Cancel {
        principal: &'a str,
        id: &'a str,
        revision: u64,
    },
    /// Startup only, and the one write that names an owner by the digest the
    /// record persisted: recovery has no principal to hash, and hashing a stored
    /// digest again would address a task nobody owns.
    Recover {
        owner_digest: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
        /// Who wrote a `Fail` event's error (MIK-7887.RECEIPT.1).
        author: ErrorAuthor,
        /// The members of a recovered `Complete` result the gateway wrote
        /// while processing it (MIK-7993); empty for a startup settlement.
        writes: crate::gateway::gateway_writes::WriteRecord,
    },
}

/// A callback told of each committed task transition.
pub(crate) type PublicationHook =
    Arc<dyn Fn(&str, TaskStatus, chrono::DateTime<chrono::Utc>, Option<String>) + Send + Sync>;

/// The one owner of a committed task record.
///
/// A `begin` accepts a handoff, spawns the future that commits and dispatches
/// it, and answers the request thread over a `oneshot`; the record belongs to
/// the spawned owner from that moment, so a request future that goes away
/// cannot take it back. [`Self::drain`] joins those owners. Nothing here closes
/// the executor: a drained executor still admits.
pub struct TaskExecutor {
    pub(crate) service: Arc<TaskService>,
    subscriptions: Arc<SubscriptionRegistry>,
    workers: Arc<Semaphore>,
    max_workers: usize,
    handoffs: HandoffRegistry,
    /// Installed AFTER the backends are started, from `server/mod.rs`, because
    /// an adapter needs a live backend registry and `open` runs before one
    /// exists. `OnceLock` rather than a constructor field for exactly that
    /// ordering, and write-once so a running gateway cannot have its trusted
    /// recovery vocabulary swapped underneath an in-flight read.
    recovery: std::sync::OnceLock<Arc<dyn UpstreamRecovery>>,
    /// One in-flight upstream query per record. `tasks/get` is read-only, but
    /// two concurrent reads of the same row would each commit the outcome, and
    /// the second would find a revision that moved.
    query_gate: tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    observer: Mutex<Option<Arc<dyn CommitObserver>>>,
    /// Told of every committed transition (the events source), once installed.
    publication_hook: std::sync::OnceLock<PublicationHook>,
    /// The adapters startup recovery deferred to, kept so the sweep that
    /// serves a repaired row decides the same way (MIK-8121). Write-once.
    pub(super) managed: std::sync::OnceLock<Arc<[String]>>,
    /// Cancelled once, by a shutdown whose drain ran out; every worker runs
    /// under it ([`Self::spawn_worker`]).
    shutdown: tokio_util::sync::CancellationToken,
    /// Test-only: replaces the produce-seam wait, so a test can tell "woken"
    /// from "timed out" by whether an update answers at all, not by how long
    /// it took (MIK-8222).
    #[cfg(test)]
    produce_seam_wait: std::sync::OnceLock<Duration>,
    /// Test-only: counts commit attempts and injects conflicts (MIK-8202 r4.1).
    #[cfg(test)]
    commit_hook: std::sync::OnceLock<test_hooks::CommitAttemptHook>,
}

/// The three states a task never leaves.
///
/// Spelled here as well as at `worker_settle.rs` because that one is private to
/// the worker module; the two are the same three variants and a fourth
/// terminal status would have to be added to both by the same edit that adds
/// it to [`TaskStatus`].
fn is_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

fn commit_to_service(error: CommitFailure) -> ServiceError {
    match error {
        CommitFailure::Service(error) => error,
        // The request boundary: a client retries a clock before 1970 later
        // (MIK-8202 P4a r3). The worker never comes here; it waits instead.
        CommitFailure::RevisionConflict | CommitFailure::ClockUnreadable => {
            ServiceError::Unavailable
        }
    }
}

#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod spawn_tests;

#[cfg(test)]
mod test_hooks;

/// A task this request just created has run nothing yet, so it serves no
/// backend output and needs no stored-read judgement (MIK-8392 F3). Tests
/// observe a breach by count instead of a panic.
fn created_serves_no_output(task: &CommittedTask) {
    let serves = task.serves_backend_output();
    #[cfg(test)]
    if serves {
        CREATED_SERVING_OUTPUT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(not(test))]
    debug_assert!(!serves, "a just-created task serves backend output");
}

/// Test-only (MIK-8392 F3): Created answers that carried backend output.
#[cfg(test)]
pub(crate) static CREATED_SERVING_OUTPUT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
