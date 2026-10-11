// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One interactive login per backend at a time, shared by every start that
//! waits on it (MIK-7982).
//!
//! Starts serialize on their slot's start lock, so a caller queued behind a
//! login never reaches `authorize`. It captures the [`Cohort`] before it
//! queues instead; when the login ends unfinished, cancelled or failed, the
//! outcome is set on that cohort and a fresh one swapped in. A queued caller
//! whose cohort has an outcome ends with it rather than starting a login of
//! its own; a caller that arrives later belongs to the fresh cohort and
//! begins afresh. The lock is never held across an await.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::Error;

/// How a login that produced no token ended, kept as data because [`Error`]
/// is not `Clone`: every caller of the cohort gets its own typed copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoginOutcome {
    /// Nobody completed it within the window.
    Incomplete { window_secs: u64 },
    /// A restart or shutdown ended it.
    Cancelled,
    /// The authorization server refused it (the message of the OAuth error).
    Failed(String),
    /// The gateway's own destination policy refused a step of it (the
    /// message of the `Protocol` error), kept as that variant.
    Refused(String),
}

impl LoginOutcome {
    fn of(error: &Error) -> Self {
        match error {
            Error::AuthorizationIncomplete { window_secs, .. } => Self::Incomplete {
                window_secs: *window_secs,
            },
            Error::AuthorizationCancelled { .. } => Self::Cancelled,
            Error::OAuth(message) => Self::Failed(message.clone()),
            Error::Protocol(message) => Self::Refused(message.clone()),
            other => Self::Failed(other.to_string()),
        }
    }

    /// This outcome as the error a caller of `backend` returns.
    pub(crate) fn to_error(&self, backend: &str) -> Error {
        let backend = backend.to_string();
        match self {
            Self::Incomplete { window_secs } => Error::AuthorizationIncomplete {
                backend,
                window_secs: *window_secs,
            },
            Self::Cancelled => Error::AuthorizationCancelled { backend },
            Self::Failed(message) => Error::OAuth(message.clone()),
            Self::Refused(message) => Error::Protocol(message.clone()),
        }
    }
}

/// The callers that may share one login: everyone who arrived before it ended.
#[derive(Debug, Default)]
pub(crate) struct Cohort {
    outcome: OnceLock<LoginOutcome>,
}

impl Cohort {
    /// How this cohort's login ended, once it ended without a token.
    pub(crate) fn outcome(&self) -> Option<&LoginOutcome> {
        self.outcome.get()
    }
}

/// One login in flight.
#[derive(Debug)]
pub(crate) struct Attempt {
    cohort: Arc<Cohort>,
    cancel: CancellationToken,
    /// Fired once this login's callback listeners have let go of their
    /// sockets (or it never bound any).
    closed: CancellationToken,
    /// Where this login stands, as its joiners see it.
    finished: watch::Sender<Progress>,
}

/// A login's progress: running, or ended (`None` on a token, else its outcome).
#[derive(Debug, Clone)]
enum Progress {
    Running,
    Ended(Option<LoginOutcome>),
}

impl Attempt {
    /// Wait until this login has ended: `None` on a token, else its outcome.
    pub(crate) async fn finished(&self) -> Option<LoginOutcome> {
        let mut rx = self.finished.subscribe();
        // The sender lives in `self`, so the channel cannot close here.
        let Ok(ended) = rx.wait_for(|p| matches!(p, Progress::Ended(_))).await else {
            return None;
        };
        match &*ended {
            Progress::Ended(outcome) => outcome.clone(),
            Progress::Running => None,
        }
    }
}

/// What [`LoginGate::begin`] hands a caller about to authorize.
pub(crate) enum Begin {
    /// No login in flight: this caller runs it.
    Lead(Lead),
    /// A login is in flight: wait on it.
    Join(Arc<Attempt>),
    /// A restart or shutdown cancelled logins since this caller set out, or
    /// the backend is stopped: it begins nothing.
    Refused,
    /// The caller's captured cohort already ended without a token: it shares
    /// that end instead of opening another login (MIK-8339, read under the
    /// state lock `release` sets it under).
    Ended(LoginOutcome),
}

/// The caller leading a login, which ends it with [`Lead::end`]. Dropped
/// before that (a request-time caller whose deadline passed mid-wait), the
/// login is abandoned: joiners get `Cancelled`, the cohort keeps no outcome,
/// and the next caller begins afresh rather than joining a login nobody runs.
pub(crate) struct Lead {
    gate: Arc<LoginGate>,
    attempt: Arc<Attempt>,
    /// Handed to the login's callback server, which drops it only once its
    /// listeners have let go of their sockets.
    listeners: Option<DropGuard>,
    ended: bool,
}

impl Lead {
    /// The token that ends this login early.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.attempt.cancel
    }

    /// The guard the login's callback server holds until its listeners are
    /// closed (taken once).
    pub(crate) fn take_listeners_guard(&mut self) -> Option<DropGuard> {
        self.listeners.take()
    }

    /// Record how this login ended: `None` on a token.
    pub(crate) fn end(mut self, error: Option<&Error>) {
        self.ended = true;
        self.gate.end(&self.attempt, error);
    }
}

impl Drop for Lead {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        // Abandoned mid-login: its dropped callback server aborts listeners
        // that free their port only when next polled. The attempt stays
        // registered until they have, so the next login can bind a fixed port.
        drop(self.listeners.take());
        let (gate, attempt) = (Arc::clone(&self.gate), Arc::clone(&self.attempt));
        let release = move || gate.release(&attempt, None, Some(LoginOutcome::Cancelled));
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) if !self.attempt.closed.is_cancelled() => {
                let closed = self.attempt.closed.clone();
                runtime.spawn(async move {
                    closed.cancelled().await;
                    release();
                });
            }
            _ => release(),
        }
    }
}

#[derive(Debug, Default)]
struct State {
    cohort: Arc<Cohort>,
    attempt: Option<Arc<Attempt>>,
    /// Bumped by every cancel, so a start that set out before one (and was
    /// still discovering when it came) cannot open a login after it.
    epoch: u64,
    /// The backend stopped: no login begins again.
    closed: bool,
}

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

/// What [`LoginGate::set_out_now`] captures.
pub(crate) struct SetOut {
    /// The cancel epoch the step set out at.
    pub(crate) since: u64,
    /// The cohort it belongs to.
    pub(crate) cohort: Arc<Cohort>,
    /// Its one deadline.
    pub(crate) deadline: tokio::time::Instant,
}

/// A backend's one login at a time. See the module docs.
#[derive(Debug)]
pub(crate) struct LoginGate {
    state: Mutex<State>,
    /// `(epoch, closed)`, published under the state lock by every cancel
    /// and by `close` (MIK-8339): detached work before a login begins waits
    /// on it, so a restart or stop ends that work too.
    revoked: watch::Sender<(u64, bool)>,
    /// Test-only: request-time token steps of this backend that detached
    /// (MIK-8339 LOGINDL.10, .15). Per gate, so parallel tests never share it.
    #[cfg(test)]
    detached: std::sync::atomic::AtomicUsize,
}

impl Default for LoginGate {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            revoked: watch::Sender::new((0, false)),
            #[cfg(test)]
            detached: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl LoginGate {
    /// The cohort a caller belongs to, captured before it queues.
    pub(crate) fn cohort(&self) -> Arc<Cohort> {
        Arc::clone(&self.state.lock().cohort)
    }

    /// Whether any login is in flight.
    pub(crate) fn in_flight(&self) -> bool {
        self.state.lock().attempt.is_some()
    }

    /// Whether a login of `cohort` is still in flight.
    pub(crate) fn pending_in(&self, cohort: &Arc<Cohort>) -> bool {
        self.state
            .lock()
            .attempt
            .as_ref()
            .is_some_and(|attempt| Arc::ptr_eq(&attempt.cohort, cohort))
    }

    /// The cancel epoch a start captures before it discovers anything.
    pub(crate) fn epoch(&self) -> u64 {
        self.state.lock().epoch
    }

    /// Lead a new login, or join the one in flight. `since` is the epoch
    /// the caller captured when it set out; `cohort` the cohort it captured
    /// before it queued, whose recorded failure it shares rather than opening
    /// a second login (MIK-8339). Checked in this order, under one lock:
    /// refused, ended, join, lead.
    pub(crate) fn begin(
        self: &Arc<Self>,
        since: Option<u64>,
        cohort: Option<&Arc<Cohort>>,
    ) -> Begin {
        let mut state = self.state.lock();
        if state.closed || since.is_some_and(|epoch| epoch != state.epoch) {
            return Begin::Refused;
        }
        if let Some(outcome) = cohort.and_then(|cohort| cohort.outcome()) {
            return Begin::Ended(outcome.clone());
        }
        if let Some(attempt) = &state.attempt {
            return Begin::Join(Arc::clone(attempt));
        }
        let attempt = Arc::new(Attempt {
            cohort: Arc::clone(&state.cohort),
            cancel: CancellationToken::new(),
            closed: CancellationToken::new(),
            finished: watch::Sender::new(Progress::Running),
        });
        state.attempt = Some(Arc::clone(&attempt));
        Begin::Lead(Lead {
            gate: Arc::clone(self),
            listeners: Some(attempt.closed.clone().drop_guard()),
            attempt,
            ended: false,
        })
    }

    /// Record how the led login `attempt` ended (`None` on a token). An
    /// unfinished, cancelled or failed login is set on its cohort, and a fresh
    /// cohort swapped in so the next caller begins afresh.
    fn end(&self, attempt: &Arc<Attempt>, error: Option<&Error>) {
        let outcome = error.map(LoginOutcome::of);
        self.release(attempt, outcome.as_ref(), outcome.clone());
    }

    /// Clear `attempt`, set `on_cohort` on its cohort (swapping in a fresh
    /// one), and tell its joiners `to_joiners`.
    fn release(
        &self,
        attempt: &Arc<Attempt>,
        on_cohort: Option<&LoginOutcome>,
        to_joiners: Option<LoginOutcome>,
    ) {
        {
            let mut state = self.state.lock();
            if let Some(outcome) = on_cohort {
                let _ = attempt.cohort.outcome.set(outcome.clone());
                if Arc::ptr_eq(&state.cohort, &attempt.cohort) {
                    state.cohort = Arc::new(Cohort::default());
                }
            }
            if state
                .attempt
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, attempt))
            {
                state.attempt = None;
            }
        }
        attempt.finished.send_replace(Progress::Ended(to_joiners));
    }

    /// End the login in flight, if any, and wait until it has closed its
    /// callback listener: a restart or shutdown of the backend.
    pub(crate) async fn cancel_and_join(&self) {
        let attempt = {
            let mut state = self.state.lock();
            state.epoch += 1;
            self.revoked.send_replace((state.epoch, state.closed));
            state.attempt.clone()
        };
        if let Some(attempt) = attempt {
            attempt.cancel.cancel();
            attempt.finished().await;
        }
    }

    /// The backend stopped: refuse every later login, then end the one in
    /// flight as [`Self::cancel_and_join`] does.
    pub(crate) async fn close(&self) {
        {
            let mut state = self.state.lock();
            state.closed = true;
            self.revoked.send_replace((state.epoch, true));
        }
        self.cancel_and_join().await;
    }

    /// Test-only: count a detached token step of this backend.
    #[cfg(test)]
    pub(crate) fn note_detached(&self) {
        self.detached.fetch_add(1, Ordering::SeqCst);
    }

    /// Test-only: detached token steps of this backend so far.
    #[cfg(test)]
    pub(crate) fn detached_for_test(&self) -> usize {
        self.detached.load(Ordering::SeqCst)
    }

    /// What a detached token step captures before it queues (MIK-8339): the
    /// current start's set-out epoch and cohort, else the gate's now, and the
    /// one deadline every stage of that step is bounded by. One helper for
    /// the request path and `connect`, so the two cannot drift.
    pub(crate) fn set_out_now(&self) -> SetOut {
        SetOut {
            since: set_out_epoch().unwrap_or_else(|| self.epoch()),
            cohort: set_out_cohort().unwrap_or_else(|| self.cohort()),
            deadline: tokio::time::Instant::now() + DETACHED_DEADLINE,
        }
    }

    /// Resolve when a restart or stop has revoked work that set out at
    /// `since`: the backend closed, or the cancel epoch moved (MIK-8339).
    /// Lock-free: it reads the published `(epoch, closed)`.
    pub(crate) async fn revoked_since(&self, since: u64) {
        let mut rx = self.revoked.subscribe();
        // The sender lives in `self`, so the channel cannot close here.
        let _ = rx
            .wait_for(|(epoch, closed)| *closed || *epoch != since)
            .await;
    }

    /// Whether work that set out at `since` has been revoked, read under
    /// the state lock (the re-check on a success path before Lead).
    pub(crate) fn is_revoked(&self, since: u64) -> bool {
        let state = self.state.lock();
        state.closed || state.epoch != since
    }

    /// The error for detached work whose own bound expired before it led or
    /// joined a login (MIK-8339): the captured cohort's recorded end, else
    /// `AuthorizationPending` while a login of that cohort is open, else
    /// `otherwise` (the backend's timeout). Both reads under one lock.
    pub(crate) fn classify(&self, cohort: &Arc<Cohort>, backend: &str, otherwise: Error) -> Error {
        let state = self.state.lock();
        if let Some(outcome) = cohort.outcome() {
            return outcome.to_error(backend);
        }
        let pending = state
            .attempt
            .as_ref()
            .is_some_and(|attempt| Arc::ptr_eq(&attempt.cohort, cohort));
        if pending {
            Error::AuthorizationPending {
                backend: backend.to_string(),
            }
        } else {
            otherwise
        }
    }
}

tokio::task_local! {
    static PROVENANCE: Arc<Provenance>;
    static FILL: Arc<AtomicBool>;
    static NON_INTERACTIVE: ();
    static SET_OUT: (u64, Option<Arc<Cohort>>);
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
    SET_OUT.scope((epoch, Some(cohort)), work).await
}

/// The cohort the current start captured (`None` outside a start, or a start
/// that captured none). Read before any `tokio::spawn`.
pub(crate) fn set_out_cohort() -> Option<Arc<Cohort>> {
    SET_OUT
        .try_with(|(_, cohort)| cohort.clone())
        .ok()
        .flatten()
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
    set_out: Option<(u64, Option<Arc<Cohort>>)>,
}

/// Capture the current scopes; call it in the caller, never in the task.
pub(crate) fn carry_scopes() -> Carried {
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

/// Run `work` as a caller that never begins or waits on a login (the health
/// probe, MIK-7982 C2): where it would, it gets `AuthorizationRequired`.
pub(crate) async fn non_interactive<F: std::future::Future>(work: F) -> F::Output {
    NON_INTERACTIVE.scope((), work).await
}

/// Whether the current task may begin or wait on a login. Read before any
/// `tokio::spawn`: a spawned task does not inherit the scope.
pub(crate) fn interactive() -> bool {
    NON_INTERACTIVE.try_get().is_err()
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
mod tests {
    use super::*;

    /// MIK-8339 LOGINDL.8b: a caller whose captured cohort's login already
    /// failed shares that failure at `begin`, read under the state lock: it
    /// opens no second login, and nothing is left in flight.
    #[test]
    fn a_failed_cohort_ends_its_queued_callers_at_begin() {
        let gate = Arc::new(LoginGate::default());
        let queued = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("no login in flight, so the first caller leads");
        };
        lead.end(Some(&Error::OAuth("invalid_grant".into())));

        match gate.begin(None, Some(&queued)) {
            Begin::Ended(outcome) => assert_eq!(Some(&outcome), queued.outcome()),
            _ => panic!("a caller of a failed cohort opened or joined another login"),
        }
        assert!(!gate.in_flight(), "nothing is left in flight");
        assert!(
            matches!(gate.begin(None, Some(&gate.cohort())), Begin::Lead(_)),
            "a caller of the fresh cohort leads"
        );
    }

    /// MIK-8339: `classify` reads the captured cohort's end, then its
    /// pending login, else the fallback, all under one lock.
    #[test]
    fn classify_prefers_the_cohorts_end_then_its_pending_login() {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let timeout = || Error::BackendTimeout("b".into());
        assert!(matches!(
            gate.classify(&cohort, "b", timeout()),
            Error::BackendTimeout(_)
        ));
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("first caller leads");
        };
        assert!(matches!(
            gate.classify(&cohort, "b", timeout()),
            Error::AuthorizationPending { .. }
        ));
        lead.end(Some(&Error::AuthorizationIncomplete {
            backend: "b".into(),
            window_secs: 300,
        }));
        assert!(matches!(
            gate.classify(&cohort, "b", timeout()),
            Error::AuthorizationIncomplete { .. }
        ));
    }

    #[test]
    fn an_unfinished_login_ends_its_cohort_and_the_next_caller_begins_afresh() {
        let gate = Arc::new(LoginGate::default());
        let queued = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("no login in flight, so the first caller leads");
        };
        assert!(gate.pending_in(&queued));
        assert!(matches!(gate.begin(None, None), Begin::Join(_)));

        lead.end(Some(&Error::AuthorizationCancelled {
            backend: "b".into(),
        }));

        assert_eq!(queued.outcome(), Some(&LoginOutcome::Cancelled));
        assert!(!gate.pending_in(&queued));
        assert!(gate.cohort().outcome().is_none(), "a fresh cohort");
        assert!(matches!(gate.begin(None, None), Begin::Lead(_)));
    }

    #[test]
    fn a_login_that_got_a_token_sets_no_outcome() {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("leads");
        };
        lead.end(None);
        assert!(cohort.outcome().is_none());
        assert!(Arc::ptr_eq(&cohort, &gate.cohort()), "the cohort stays");
    }

    #[tokio::test]
    async fn an_abandoned_lead_frees_the_gate_and_cancels_its_joiners() {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let Begin::Lead(lead) = gate.begin(None, None) else {
            panic!("leads");
        };
        let Begin::Join(joined) = gate.begin(None, None) else {
            panic!("joins the lead's login");
        };

        drop(lead);

        assert_eq!(joined.finished().await, Some(LoginOutcome::Cancelled));
        assert!(
            cohort.outcome().is_none(),
            "an abandoned login sets no outcome"
        );
        assert!(
            matches!(gate.begin(None, None), Begin::Lead(_)),
            "the next caller leads"
        );
    }

    #[tokio::test]
    async fn a_start_that_set_out_before_a_cancel_begins_nothing() {
        let gate = Arc::new(LoginGate::default());
        let set_out = gate.epoch();
        gate.cancel_and_join().await;
        assert!(matches!(gate.begin(Some(set_out), None), Begin::Refused));
        assert!(matches!(
            gate.begin(Some(gate.epoch()), None),
            Begin::Lead(_)
        ));
        gate.close().await;
        assert!(
            matches!(gate.begin(None, None), Begin::Refused),
            "a stopped backend logs in no more"
        );
    }

    #[test]
    fn a_failed_login_replays_as_the_same_typed_error() {
        let failed = LoginOutcome::of(&Error::OAuth("invalid_grant".into()));
        assert!(matches!(failed.to_error("b"), Error::OAuth(m) if m == "invalid_grant"));
        let refused = LoginOutcome::of(&Error::Protocol("ssrf".into()));
        assert!(matches!(refused.to_error("b"), Error::Protocol(m) if m == "ssrf"));
    }

    /// MIK-7982 (delta review): an abandoned lead whose callback listeners
    /// are still closing keeps its attempt registered until they have, so
    /// the next login cannot race them for a fixed callback port.
    #[tokio::test]
    async fn an_abandoned_lead_holds_the_gate_until_its_listeners_close() {
        let gate = Arc::new(LoginGate::default());
        let Begin::Lead(mut lead) = gate.begin(None, None) else {
            panic!("no login in flight, so the first caller leads");
        };
        let listeners = lead.take_listeners_guard().expect("guard handed once");
        drop(lead);
        tokio::task::yield_now().await;
        assert!(gate.in_flight(), "released while its listeners still ran");

        drop(listeners);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while gate.in_flight() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("released once its listeners closed");
        assert!(matches!(gate.begin(None, None), Begin::Lead(_)));
    }
}
