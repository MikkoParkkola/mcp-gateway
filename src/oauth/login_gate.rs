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

use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

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
    /// `None` while running; then `Some(None)` on a token, or the outcome.
    finished: watch::Sender<Option<Option<LoginOutcome>>>,
}

impl Attempt {
    /// Wait until this login has ended: `None` on a token, else its outcome.
    pub(crate) async fn finished(&self) -> Option<LoginOutcome> {
        let mut rx = self.finished.subscribe();
        // The sender lives in `self`, so the channel cannot close here.
        let ended = rx.wait_for(Option::is_some).await;
        ended.ok().and_then(|value| value.clone()).flatten()
    }
}

/// What [`LoginGate::begin`] hands a caller about to authorize.
pub(crate) enum Begin {
    /// No login in flight: this caller runs it.
    Lead(Lead),
    /// A login is in flight: wait on it.
    Join(Arc<Attempt>),
}

/// The caller leading a login, which ends it with [`Lead::end`]. Dropped
/// before that (a request-time caller whose deadline passed mid-wait), the
/// login is abandoned: joiners get `Cancelled`, the cohort keeps no outcome,
/// and the next caller begins afresh rather than joining a login nobody runs.
pub(crate) struct Lead {
    gate: Arc<LoginGate>,
    attempt: Arc<Attempt>,
    ended: bool,
}

impl Lead {
    /// The token that ends this login early.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.attempt.cancel
    }

    /// Record how this login ended: `None` on a token.
    pub(crate) fn end(mut self, error: Option<&Error>) {
        self.ended = true;
        self.gate.end(&self.attempt, error);
    }
}

impl Drop for Lead {
    fn drop(&mut self) {
        if !self.ended {
            self.gate
                .release(&self.attempt, None, Some(LoginOutcome::Cancelled));
        }
    }
}

#[derive(Debug, Default)]
struct State {
    cohort: Arc<Cohort>,
    attempt: Option<Arc<Attempt>>,
}

/// A backend's one login at a time. See the module docs.
#[derive(Debug, Default)]
pub(crate) struct LoginGate {
    state: Mutex<State>,
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

    /// Lead a new login, or join the one in flight.
    pub(crate) fn begin(self: &Arc<Self>) -> Begin {
        let mut state = self.state.lock();
        if let Some(attempt) = &state.attempt {
            return Begin::Join(Arc::clone(attempt));
        }
        let attempt = Arc::new(Attempt {
            cohort: Arc::clone(&state.cohort),
            cancel: CancellationToken::new(),
            finished: watch::Sender::new(None),
        });
        state.attempt = Some(Arc::clone(&attempt));
        Begin::Lead(Lead {
            gate: Arc::clone(self),
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
        attempt.finished.send_replace(Some(to_joiners));
    }

    /// End the login in flight, if any, and wait until it has closed its
    /// callback listener: a restart or shutdown of the backend.
    pub(crate) async fn cancel_and_join(&self) {
        let attempt = self.state.lock().attempt.clone();
        if let Some(attempt) = attempt {
            attempt.cancel.cancel();
            attempt.finished().await;
        }
    }
}

tokio::task_local! {
    static PROVENANCE: Arc<Provenance>;
    static NON_INTERACTIVE: ();
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
    dispatched: std::sync::atomic::AtomicBool,
}

impl Provenance {
    /// Run `work` as a caller bounded by its own deadline, capturing the
    /// cohort now, before it can queue on a start lock.
    pub(crate) async fn scope<F: std::future::Future>(gate: &Arc<LoginGate>, work: F) -> F::Output {
        let provenance = Arc::new(Self {
            gate: Arc::clone(gate),
            cohort: gate.cohort(),
            dispatched: std::sync::atomic::AtomicBool::new(false),
        });
        PROVENANCE.scope(provenance, work).await
    }

    /// The scope's start returned a transport: from here a deadline is the
    /// backend's, not the login's.
    pub(crate) fn mark_dispatched() {
        let _ = PROVENANCE.try_with(|p| {
            p.dispatched
                .store(true, std::sync::atomic::Ordering::SeqCst)
        });
    }

    /// The error a deadline that expired in this scope reports:
    /// `AuthorizationPending` when nothing was dispatched and the captured
    /// cohort's login is in flight or ended, else `otherwise`.
    pub(crate) fn expired(backend: &str, otherwise: Error) -> Error {
        let waited_on_login = PROVENANCE
            .try_with(|p| {
                !p.dispatched.load(std::sync::atomic::Ordering::SeqCst)
                    && (p.gate.pending_in(&p.cohort) || p.cohort.outcome().is_some())
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

    #[test]
    fn an_unfinished_login_ends_its_cohort_and_the_next_caller_begins_afresh() {
        let gate = Arc::new(LoginGate::default());
        let queued = gate.cohort();
        let Begin::Lead(lead) = gate.begin() else {
            panic!("no login in flight, so the first caller leads");
        };
        assert!(gate.pending_in(&queued));
        assert!(matches!(gate.begin(), Begin::Join(_)));

        lead.end(Some(&Error::AuthorizationCancelled {
            backend: "b".into(),
        }));

        assert_eq!(queued.outcome(), Some(&LoginOutcome::Cancelled));
        assert!(!gate.pending_in(&queued));
        assert!(gate.cohort().outcome().is_none(), "a fresh cohort");
        assert!(matches!(gate.begin(), Begin::Lead(_)));
    }

    #[test]
    fn a_login_that_got_a_token_sets_no_outcome() {
        let gate = Arc::new(LoginGate::default());
        let cohort = gate.cohort();
        let Begin::Lead(lead) = gate.begin() else {
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
        let Begin::Lead(lead) = gate.begin() else {
            panic!("leads");
        };
        let Begin::Join(joined) = gate.begin() else {
            panic!("joins the lead's login");
        };

        drop(lead);

        assert_eq!(joined.finished().await, Some(LoginOutcome::Cancelled));
        assert!(
            cohort.outcome().is_none(),
            "an abandoned login sets no outcome"
        );
        assert!(
            matches!(gate.begin(), Begin::Lead(_)),
            "the next caller leads"
        );
    }

    #[test]
    fn a_failed_login_replays_as_the_same_typed_error() {
        let failed = LoginOutcome::of(&Error::OAuth("invalid_grant".into()));
        assert!(matches!(failed.to_error("b"), Error::OAuth(m) if m == "invalid_grant"));
        let refused = LoginOutcome::of(&Error::Protocol("ssrf".into()));
        assert!(matches!(refused.to_error("b"), Error::Protocol(m) if m == "ssrf"));
    }
}
