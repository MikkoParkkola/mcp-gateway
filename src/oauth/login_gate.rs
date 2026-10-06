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
}

impl LoginOutcome {
    fn of(error: &Error) -> Self {
        match error {
            Error::AuthorizationIncomplete { window_secs, .. } => Self::Incomplete {
                window_secs: *window_secs,
            },
            Error::AuthorizationCancelled { .. } => Self::Cancelled,
            Error::OAuth(message) => Self::Failed(message.clone()),
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
    /// The token that ends this login early.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

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
    /// No login in flight: this caller runs it, and must call
    /// [`LoginGate::end`] with how it ended.
    Lead(Arc<Attempt>),
    /// A login is in flight: wait on it.
    Join(Arc<Attempt>),
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

    /// Whether a login of `cohort` is still in flight.
    pub(crate) fn pending_in(&self, cohort: &Arc<Cohort>) -> bool {
        self.state
            .lock()
            .attempt
            .as_ref()
            .is_some_and(|attempt| Arc::ptr_eq(&attempt.cohort, cohort))
    }

    /// Lead a new login, or join the one in flight.
    pub(crate) fn begin(&self) -> Begin {
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
        Begin::Lead(attempt)
    }

    /// Record how the led login `attempt` ended (`None` on a token). An
    /// unfinished, cancelled or failed login is set on its cohort, and a fresh
    /// cohort swapped in so the next caller begins afresh.
    pub(crate) fn end(&self, attempt: &Arc<Attempt>, error: Option<&Error>) {
        let outcome = error.map(LoginOutcome::of);
        {
            let mut state = self.state.lock();
            if let Some(outcome) = &outcome {
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
        attempt.finished.send_replace(Some(outcome));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unfinished_login_ends_its_cohort_and_the_next_caller_begins_afresh() {
        let gate = LoginGate::default();
        let queued = gate.cohort();
        let Begin::Lead(attempt) = gate.begin() else {
            panic!("no login in flight, so the first caller leads");
        };
        assert!(gate.pending_in(&queued));
        assert!(matches!(gate.begin(), Begin::Join(_)));

        gate.end(
            &attempt,
            Some(&Error::AuthorizationCancelled {
                backend: "b".into(),
            }),
        );

        assert_eq!(queued.outcome(), Some(&LoginOutcome::Cancelled));
        assert!(!gate.pending_in(&queued));
        assert!(gate.cohort().outcome().is_none(), "a fresh cohort");
        assert!(matches!(gate.begin(), Begin::Lead(_)));
    }

    #[test]
    fn a_login_that_got_a_token_sets_no_outcome() {
        let gate = LoginGate::default();
        let cohort = gate.cohort();
        let Begin::Lead(attempt) = gate.begin() else {
            panic!("leads");
        };
        gate.end(&attempt, None);
        assert!(cohort.outcome().is_none());
        assert!(Arc::ptr_eq(&cohort, &gate.cohort()), "the cohort stays");
    }

    #[test]
    fn a_failed_login_replays_as_the_same_typed_error() {
        let failed = LoginOutcome::of(&Error::OAuth("invalid_grant".into()));
        assert!(matches!(failed.to_error("b"), Error::OAuth(m) if m == "invalid_grant"));
    }
}
