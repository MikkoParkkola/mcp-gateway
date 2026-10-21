// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The login gate's task-local scopes and detached-step bounds.

use super::{Cohort, LoginGate};
use crate::Error;
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The one bound on a detached token step, from the moment it set out
/// (design v2.3: `set_out + 2 x OAUTH_AUTHORIZATION_WINDOW`). Every stage is
/// bounded by `min(its own bound, this deadline)`, so stalls cannot add up.
pub(crate) const DETACHED_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(2 * crate::oauth::OAUTH_AUTHORIZATION_WINDOW.as_secs());

/// A stage's end: its own `bound` from now, or the step's `deadline`,
/// whichever comes first (MIK-8339).
pub(crate) fn stage_end(
    bound: std::time::Duration,
    deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    (tokio::time::Instant::now() + bound).min(deadline)
}

/// Resolves when a detached step's one `deadline` passes, never when there is
/// none (MIK-8339): the arm a stage with no window of its own races.
pub(crate) async fn past(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// What [`LoginGate::set_out_now`] captures.
pub(crate) struct SetOut {
    /// The cancel epoch the step set out at.
    pub(crate) since: u64,
    /// The cohort it belongs to.
    pub(crate) cohort: Arc<Cohort>,
    /// Its one deadline.
    pub(crate) deadline: tokio::time::Instant,
}

tokio::task_local! {
    static PROVENANCE: Arc<Provenance>;
    static FILL: Arc<AtomicBool>;
    static NON_INTERACTIVE: ContentionClass;
    static SET_OUT: (u64, Arc<Cohort>);
}

/// Run a shared metadata fill's `work` with its `mark`: a request the fill
/// hands to the transport sets it, and every caller that joined the fill reads
/// it when its own deadline passes (MIK-8046).
pub(crate) async fn fill_scope<F: std::future::Future>(
    mark: Arc<AtomicBool>,
    work: F,
) -> F::Output {
    FILL.scope(mark, work).await
}

/// Run the start `work` as one that set out at the gate's cancel `epoch`
/// with the `cohort` it captured before it queued: its login is refused if a
/// restart or stop cancelled logins since, however late its detached OAuth
/// task is first scheduled, and shares that cohort's recorded failure at
/// `begin` instead of opening a second login (MIK-8339). One entry point,
/// so no start can omit its cohort.
pub(crate) async fn set_out_with_cohort<F: std::future::Future>(
    epoch: u64,
    cohort: Arc<Cohort>,
    work: F,
) -> F::Output {
    SET_OUT.scope((epoch, cohort), work).await
}

/// The cohort the current start captured (`None` outside a start). Read
/// before any `tokio::spawn`.
pub(crate) fn set_out_cohort() -> Option<Arc<Cohort>> {
    SET_OUT.try_with(|(_, cohort)| Arc::clone(cohort)).ok()
}

/// The epoch the current start set out at (`None` outside a start). Read
/// before any `tokio::spawn`, as [`interactive`] is.
pub(crate) fn set_out_epoch() -> Option<u64> {
    SET_OUT.try_with(|(epoch, _)| *epoch).ok()
}

/// The caller's task-local scopes, captured synchronously in the caller so a
/// detached task re-enters the SAME Arcs (MIK-8339): marks the task makes
/// (`mark_waited` inside `authorize_shared`) land on the caller's own
/// Provenance and fill.
pub(crate) struct Carried {
    provenance: Option<Arc<Provenance>>,
    fill: Option<Arc<AtomicBool>>,
    set_out: Option<(u64, Arc<Cohort>)>,
}

/// Capture the current scopes; call it in the caller, never in the task.
pub(crate) fn carry_scopes() -> super::Carried {
    Carried {
        provenance: PROVENANCE.try_with(Arc::clone).ok(),
        fill: FILL.try_with(Arc::clone).ok(),
        set_out: SET_OUT.try_with(Clone::clone).ok(),
    }
}

impl Carried {
    /// Run `work` inside the captured scopes.
    pub(crate) async fn run<F: std::future::Future>(self, work: F) -> F::Output {
        let Self {
            provenance,
            fill,
            set_out,
        } = self;
        let work = async move {
            match set_out {
                Some(set_out) => SET_OUT.scope(set_out, work).await,
                None => work.await,
            }
        };
        let work = async move {
            match fill {
                Some(mark) => FILL.scope(mark, work).await,
                None => work.await,
            }
        };
        match provenance {
            Some(provenance) => PROVENANCE.scope(provenance, work).await,
            None => work.await,
        }
    }
}

/// Which contention budget a credential-lock waiter gets (MIK-8619 r4.4):
/// chosen by the caller's own deadline, not by whether it may log in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::oauth) enum ContentionClass {
    /// The default: wait up to the full contention budget, then adopt what
    /// the holder stored.
    Long,
    /// A caller whose own deadline is at or below the short wait (the health
    /// probe, era discovery, connection close).
    Short,
}

/// Run `work` as a caller that never begins or waits on a login (the health
/// probe, MIK-7982 C2): where it would, it gets `AuthorizationRequired`.
/// It keeps the caller's contention class: Long by default, Short inside [`short_contention`].
pub(crate) async fn non_interactive<F: std::future::Future>(work: F) -> F::Output {
    NON_INTERACTIVE.scope(contention_class(), work).await
}

/// Run `work` as a Short contention caller: one whose own deadline is at or
/// below the short contention wait (the health probe, era discovery, a
/// connection close). It never begins or waits on a login, as
/// [`non_interactive`]. The class is task-local: a spawned or detached task
/// does not inherit it and waits the long budget. A `Carried` re-entry does
/// not carry the class either, so a detached step of a Short caller waits the
/// long budget.
/// One scope, not two nested ones, so a Short future is no deeper than a non-interactive one.
pub(crate) async fn short_contention<F: std::future::Future>(work: F) -> F::Output {
    NON_INTERACTIVE.scope(ContentionClass::Short, work).await
}

/// Whether the current task may begin or wait on a login. Read before any
/// `tokio::spawn`: a spawned task does not inherit the scope.
pub(crate) fn interactive() -> bool {
    NON_INTERACTIVE.try_get().is_err()
}

/// The current task's contention class: `Short` inside [`short_contention`],
/// else `Long`. Read before any `tokio::spawn`: a spawned task does not
/// inherit the scope.
pub(in crate::oauth) fn contention_class() -> ContentionClass {
    NON_INTERACTIVE.try_get().unwrap_or(ContentionClass::Long)
}

/// Whose deadline it is (MIK-7982 C3): the cohort a bounded caller captured
/// and whether its own start already handed it a transport. Caller-local, in
/// a task-local scope, never a backend-wide flag: another caller's timeout
/// must not read as this caller's pending login.
#[derive(Debug)]
pub(crate) struct Provenance {
    gate: Arc<LoginGate>,
    cohort: Arc<Cohort>,
    /// The scope's start returned a transport.
    started: AtomicBool,
    /// A request of the started transport went past its token step.
    dispatched: AtomicBool,
    /// The scope itself led or joined a login (a request-time token step).
    waited: AtomicBool,
    /// The mark of the shared fill this scope is waiting on, if it joined
    /// one instead of running it (MIK-8046).
    joined: Mutex<Option<Arc<AtomicBool>>>,
}

impl Provenance {
    /// Run `work` as a caller bounded by its own deadline, capturing the
    /// cohort now, before it can queue on a start lock.
    pub(crate) async fn scope<F: std::future::Future>(gate: &Arc<LoginGate>, work: F) -> F::Output {
        let provenance = Arc::new(Self {
            gate: Arc::clone(gate),
            cohort: gate.cohort(),
            started: AtomicBool::new(false),
            dispatched: AtomicBool::new(false),
            waited: AtomicBool::new(false),
            joined: Mutex::new(None),
        });
        PROVENANCE.scope(provenance, work).await
    }

    /// The scope's start returned a transport.
    pub(crate) fn mark_started() {
        let _ = PROVENANCE.try_with(|p| p.started.store(true, Ordering::SeqCst));
    }

    /// A request went past its token step. Counts only once the scope's own
    /// start returned: a handshake request inside the start is not the
    /// caller's request (MIK-7982 C3).
    pub(crate) fn mark_dispatched() {
        let _ = PROVENANCE.try_with(|p| {
            if p.started.load(Ordering::SeqCst) {
                p.dispatched.store(true, Ordering::SeqCst);
            }
        });
        // The fill's mark has no `started` gate, on purpose: any request of a
        // fill that got past its token step (handshake or page) had its token,
        // so the fill was waiting on the backend, not on a login. Gating it as
        // above would leave a joined discovery fill unmarked (MIK-8046).
        let _ = FILL.try_with(|mark| mark.store(true, Ordering::SeqCst));
    }

    /// The scope now waits on the shared fill marked `fill` (`None`: it runs
    /// the fill itself). Replaces any earlier fill, so a retry never reads a
    /// fill the scope left (MIK-8046).
    pub(crate) fn joined(fill: Option<Arc<AtomicBool>>) {
        let _ = PROVENANCE.try_with(|p| *p.joined.lock() = fill);
    }

    /// The scope led or joined a login itself. Kept on the scope, because a
    /// lead dropped by the deadline releases the gate before the deadline's
    /// error is classified.
    pub(crate) fn mark_waited() {
        let _ = PROVENANCE.try_with(|p| p.waited.store(true, Ordering::SeqCst));
    }

    /// The error a deadline that expired in this scope reports:
    /// `AuthorizationPending` when nothing was dispatched, by the scope or by
    /// the fill it joined, and the scope waited on a login, or the captured
    /// cohort's login is in flight or ended; else `otherwise`.
    pub(crate) fn expired(backend: &str, otherwise: Error) -> Error {
        let waited_on_login = PROVENANCE
            .try_with(|p| {
                let joined_dispatched = p
                    .joined
                    .lock()
                    .as_ref()
                    .is_some_and(|fill| fill.load(Ordering::SeqCst));
                !p.dispatched.load(Ordering::SeqCst)
                    && !joined_dispatched
                    && (p.waited.load(Ordering::SeqCst)
                        || p.gate.pending_in(&p.cohort)
                        || p.cohort.outcome().is_some())
            })
            .unwrap_or(false);
        if waited_on_login {
            Error::AuthorizationPending {
                backend: backend.to_string(),
            }
        } else {
            otherwise
        }
    }
}

#[cfg(test)]
mod tests;
