// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The engine of a UI sign-in: it starts the login on a task of its own that
//! owns the backend's login gate until the flow ends, moves the flow through
//! its two windows, and records how it ended. The routes only ask it things.

use std::sync::Arc;

use axum::http::StatusCode;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::backend::Backend;
use crate::backend::sign_in_flow::{Flow, Outcome, Phase};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::oauth::client::sign_in::{PendingGrant, UiSink};
use crate::oauth::login_gate::{Begin, Lead};
use crate::oauth::{OAUTH_AUTHORIZATION_WINDOW, OAuthClient};
use crate::{Error, Result};

/// Who holds a login that is in the way of a start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Holder {
    /// A sign-in started from the dashboard.
    Dashboard,
    /// A command-line or startup login.
    Gateway,
}

impl Holder {
    /// The word the answer shows.
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Gateway => "gateway",
        }
    }
}

/// How a start ended.
pub(super) enum Started {
    /// The login is running; this is its link, once.
    Link {
        url: String,
        attempt_id: String,
        expires_at: std::time::SystemTime,
    },
    /// Another login holds the gate.
    InProgress {
        holder: Holder,
        expires_at: std::time::SystemTime,
        retry_after_secs: u64,
    },
}

/// A random, URL-safe attempt id.
fn new_attempt_id() -> String {
    use base64::Engine as _;
    use rand::RngExt as _;
    let bytes: [u8; 16] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The answer for a start that finds a login in the way.
fn in_progress(backend: &Backend) -> Started {
    let flow = backend.with_flow(|slot| {
        slot.as_ref()
            .map(|flow| (flow.until_at, flow.retry_after_secs()))
    });
    if let Some((expires_at, retry_after_secs)) = flow {
        return Started::InProgress {
            holder: Holder::Dashboard,
            expires_at,
            retry_after_secs,
        };
    }
    // A login the gate holds that is not ours: its own end is the gate's.
    let left = backend
        .login_gate
        .current_end()
        .map_or(OAUTH_AUTHORIZATION_WINDOW, |end| {
            end.saturating_duration_since(Instant::now())
        });
    Started::InProgress {
        holder: Holder::Gateway,
        expires_at: crate::clock::system_time_or_before_epoch() + left,
        retry_after_secs: left.as_secs() + u64::from(left.subsec_nanos() > 0),
    }
}

/// Start a sign-in on `backend` for `owner`: take the login gate, record the
/// flow, run the login on a task that keeps the gate, and wait for its link.
///
/// # Errors
///
/// Returns an error when the client cannot be built or the login ends before
/// it has a link.
pub(super) async fn start(
    state: &Arc<AppState>,
    backend: &Arc<Backend>,
    owner: String,
    caller: Option<AuthenticatedClient>,
) -> Result<Started> {
    if backend.with_flow(|slot| slot.is_some()) {
        return Ok(in_progress(backend));
    }
    let client = backend.sign_in_client().await?;
    let Begin::Lead(lead) = backend.login_gate.begin(None, None) else {
        return Ok(in_progress(backend));
    };
    let windows = backend.sign_in_windows();
    let deadline = Instant::now() + windows.start;
    lead.set_end(deadline);
    let attempt_id = new_attempt_id();
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let flow = Flow {
        owner,
        attempt_id: attempt_id.clone(),
        phase: Phase::AwaitingCallback,
        until: deadline,
        until_at: crate::clock::system_time_or_before_epoch() + windows.start,
        grant: None,
        wait_generation: 0,
        caller,
        outcome: Some(outcome_tx),
        attempt: lead.attempt(),
        cancel: lead.cancel_token().clone(),
        client: Arc::clone(&client),
    };
    let expires_at = flow.until_at;
    backend.with_flow(|slot| *slot = Some(flow));

    let (link_tx, link_rx) = oneshot::channel();
    let (callback_tx, callback_rx) = oneshot::channel();
    let run = Run {
        state: Arc::clone(state),
        backend: Arc::clone(backend),
        client,
        attempt_id: attempt_id.clone(),
        deadline,
    };
    let sink = UiSink {
        link: link_tx,
        callback: callback_tx,
        confirm_window: windows.confirm,
    };
    tokio::spawn(run.drive(lead, sink, callback_rx, outcome_rx));
    match link_rx.await {
        Ok(url) => Ok(Started::Link {
            url,
            attempt_id,
            expires_at,
        }),
        Err(_) => Err(Error::OAuth(
            "the sign-in ended before it had a link".to_owned(),
        )),
    }
}

/// What the engine's task carries.
struct Run {
    state: Arc<AppState>,
    backend: Arc<Backend>,
    client: Arc<OAuthClient>,
    attempt_id: String,
    deadline: Instant,
}

impl Run {
    /// Take the flow out of its slot if it is still this attempt's.
    fn take_flow(&self) -> Option<Flow> {
        self.backend.with_flow(|slot| {
            if slot
                .as_ref()
                .is_some_and(|f| f.attempt_id == self.attempt_id)
            {
                slot.take()
            } else {
                None
            }
        })
    }

    /// The callback landed: the confirm window starts now.
    fn callback_landed(&self, lead: &Lead) {
        let at = Instant::now() + self.backend.sign_in_windows().confirm;
        let generation = self.backend.auth_wait_generation();
        self.backend.with_flow(|slot| {
            if let Some(flow) = slot.as_mut().filter(|f| f.attempt_id == self.attempt_id) {
                flow.phase = Phase::AwaitingConfirm;
                flow.wait_generation = generation;
                flow.end_at(at);
            }
        });
        lead.set_end(at);
    }

    /// Run the login to its end, then wait out the confirm window.
    async fn drive(
        self,
        lead: Lead,
        ui: UiSink,
        callback: oneshot::Receiver<()>,
        outcome: oneshot::Receiver<Outcome>,
    ) {
        let mut lead = lead;
        let cancel = lead.cancel_token().clone();
        let listeners = lead.take_listeners_guard();
        let auth = self
            .client
            .authorize_for_ui(&cancel, listeners, self.deadline, ui);
        let granted = self.watch_login(&lead, auth, callback).await;
        match granted {
            Ok(grant) => self.hold(lead, grant, outcome).await,
            Err(error) => {
                if let Some(flow) = self.take_flow() {
                    self.record_end(&flow, &error);
                }
                lead.end(Some(&error));
            }
        }
    }

    /// Wait for the login, starting the confirm window the moment its callback
    /// signal is seen.
    async fn watch_login<F>(
        &self,
        lead: &Lead,
        auth: F,
        callback: oneshot::Receiver<()>,
    ) -> Result<PendingGrant>
    where
        F: std::future::Future<Output = Result<PendingGrant>>,
    {
        tokio::pin!(auth);
        tokio::pin!(callback);
        let mut called = false;
        loop {
            // Biased to the callback: it is sent before the code is redeemed,
            // so when both are ready the callback must be seen first, or the
            // confirm window would never start.
            tokio::select! {
                biased;
                landed = &mut callback, if !called => {
                    called = true;
                    if landed.is_ok() {
                        self.callback_landed(lead);
                    }
                }
                result = &mut auth => return result,
            }
        }
    }

    /// Keep the grant until a decision takes it or the window ends.
    async fn hold(
        &self,
        lead: Lead,
        grant: crate::oauth::client::sign_in::PendingGrant,
        mut outcome: oneshot::Receiver<Outcome>,
    ) {
        #[cfg(test)]
        self.backend.sign_in.hold_pause.pause().await;
        // Re-checked under the flow lock after the exchange. This covers an
        // exchange that already returned before a cancel took effect: the
        // cancel took the flow out, and a later start may have put another
        // attempt's flow in its place. The grant is then dropped and wiped
        // here, never stored on a flow that is not this attempt's.
        let until = self.backend.with_flow(|slot| {
            // A backstop: while this task holds the login gate no other attempt
            // can have a flow, so this filter cannot take effect today. The live
            // guard is `cancel_flow` taking the flow out of the slot.
            let flow = slot.as_mut().filter(|f| f.attempt_id == self.attempt_id)?;
            flow.grant = Some(grant);
            Some(flow.until)
        });
        let Some(until) = until else {
            return lead.end(Some(&self.cancelled()));
        };
        let cancel = lead.cancel_token().clone();
        let end = tokio::select! {
            biased;
            decided = &mut outcome => decided,
            () = cancel.cancelled() => match self.take_flow() {
                // Still in the slot: nobody decided, the backend did.
                Some(_) => Ok(Outcome::Cancelled),
                // A confirm took it: its commit runs to completion, so wait
                // for the outcome it reaches.
                None => outcome.await,
            },
            () = tokio::time::sleep_until(until) => {
                #[cfg(test)]
                self.backend.sign_in.expiry_pause.pause().await;
                match self.take_flow() {
                    Some(flow) => {
                        let expired = Error::AuthorizationIncomplete {
                            backend: self.backend.name.clone(),
                            window_secs: self.backend.sign_in_windows().confirm.as_secs(),
                        };
                        self.record_end(&flow, &expired);
                        return lead.end(Some(&expired));
                    }
                    // A confirm took it and is still saving: its outcome
                    // ends the login, not the clock.
                    None => outcome.await,
                }
            }
        };
        self.finish(lead, end);
    }

    /// End the login with what the decision was: success only after a
    /// committed save.
    fn finish(&self, lead: Lead, end: Result<Outcome, oneshot::error::RecvError>) {
        match end {
            Ok(Outcome::Confirmed(Ok(()))) => lead.end(None),
            Ok(Outcome::Confirmed(Err(error))) => lead.end(Some(&error)),
            // A decision channel that closed with nothing sent was dropped.
            Ok(Outcome::Cancelled) | Err(_) => lead.end(Some(&self.cancelled())),
        }
    }

    fn cancelled(&self) -> Error {
        Error::AuthorizationCancelled {
            backend: self.backend.name.clone(),
        }
    }

    /// Append the record of how the flow ended: the backend and the outcome,
    /// never a link, state, verifier, code or token.
    fn record_end(&self, flow: &Flow, error: &Error) {
        let outcome = match error {
            Error::AuthorizationIncomplete { .. } => "expired",
            Error::AuthorizationCancelled { .. } => return,
            _ => "failed",
        };
        record_outcome(
            &self.state,
            &self.backend.name,
            outcome,
            flow.caller.as_ref(),
        );
    }
}

/// Append an `admin_action` for a sign-in outcome no request carries (an
/// expiry, a failed exchange, a failed save), naming the starting caller.
pub(super) fn record_outcome(
    state: &AppState,
    backend: &str,
    outcome: &str,
    caller: Option<&AuthenticatedClient>,
) {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "route".into(),
        crate::gateway::routes::UI_BACKEND_SIGNIN.into(),
    );
    fields.insert("method".into(), "POST".into());
    fields.insert("backend".into(), backend.into());
    fields.insert("sign_in_outcome".into(), outcome.into());
    let _ = super::super::admin_audit::record_admin_action_as(
        state,
        "admin_ui",
        (caller, None),
        fields,
        StatusCode::OK,
    );
}

/// What the caller of a confirm asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Decision {
    Confirm,
    Cancel,
}

/// How a confirm or cancel ended.
pub(super) enum Decided {
    /// Done: saved on a confirm, discarded on a cancel.
    Done,
    /// No such sign-in for this caller: none in flight, another owner,
    /// another attempt, or past its window.
    NoSignIn,
    /// The callback has not landed and its code is not redeemed yet.
    NotReady { retry_after_secs: u64 },
    /// The save failed; the grant is discarded.
    SaveFailed,
}

/// What a decision takes out of the flow.
struct Taken {
    grant: crate::oauth::client::sign_in::PendingGrant,
    generation: u64,
    until: Instant,
    outcome: Option<oneshot::Sender<Outcome>>,
    attempt: Arc<crate::oauth::login_gate::Attempt>,
    client: Arc<OAuthClient>,
    caller: Option<AuthenticatedClient>,
}

/// Take the grant out of the flow if `owner` and `attempt` are its and the
/// window is open. One lock, so confirm, cancel and expiry cannot all win.
fn take_for(backend: &Backend, owner: &str, attempt: &str) -> std::result::Result<Taken, Decided> {
    use crate::gateway::record_principal::same_owner;
    backend.with_flow(|slot| {
        let flow = slot.as_mut().ok_or(Decided::NoSignIn)?;
        if !same_owner(&flow.owner, owner) || !same_owner(&flow.attempt_id, attempt) {
            return Err(Decided::NoSignIn);
        }
        if Instant::now() >= flow.until && flow.phase == Phase::AwaitingConfirm {
            return Err(Decided::NoSignIn);
        }
        let Some(grant) = flow.grant.take() else {
            return Err(Decided::NotReady {
                retry_after_secs: flow.retry_after_secs(),
            });
        };
        let taken = Taken {
            grant,
            generation: flow.wait_generation,
            until: flow.until,
            outcome: flow.outcome.take(),
            attempt: Arc::clone(&flow.attempt),
            client: Arc::clone(&flow.client),
            caller: flow.caller.clone(),
        };
        *slot = None;
        Ok(taken)
    })
}

/// Hand the flow task a decision's outcome and answer only once the gate
/// reflects it: the task ends the lead with the outcome, and the attempt's
/// `finished()` is published in the step that clears the gate.
async fn settle(
    attempt: &crate::oauth::login_gate::Attempt,
    outcome: Option<oneshot::Sender<Outcome>>,
    decided: Outcome,
) {
    if let Some(outcome) = outcome {
        let _ = outcome.send(decided);
    }
    attempt.finished().await;
}

/// End the sign-in `owner` started as `attempt`, in any phase: discard what it
/// holds, cancel the login so its callback listener closes and a late callback
/// reaches no exchange, and hand the gate back.
async fn cancel_flow(backend: &Backend, owner: &str, attempt: &str) -> Decided {
    use crate::gateway::record_principal::same_owner;
    let ended = backend.with_flow(|slot| {
        let theirs = slot
            .as_ref()
            .is_some_and(|f| same_owner(&f.owner, owner) && same_owner(&f.attempt_id, attempt));
        if theirs { slot.take() } else { None }
    });
    let Some(mut flow) = ended else {
        return Decided::NoSignIn;
    };
    flow.cancel.cancel();
    #[cfg(test)]
    backend.sign_in.outcome_pause.pause().await;
    settle(&flow.attempt, flow.outcome.take(), Outcome::Cancelled).await;
    Decided::Done
}

/// Confirm or cancel the sign-in `owner` started as `attempt`.
pub(super) async fn decide(
    state: &AppState,
    backend: &Backend,
    owner: &str,
    attempt: &str,
    decision: Decision,
) -> Decided {
    if decision == Decision::Cancel {
        return cancel_flow(backend, owner, attempt).await;
    }
    let taken = match take_for(backend, owner, attempt) {
        Ok(taken) => taken,
        Err(refused) => return refused,
    };
    let Taken {
        grant,
        generation,
        until,
        outcome,
        attempt,
        client,
        caller,
    } = taken;
    #[cfg(test)]
    backend.sign_in.commit_pause.pause().await;
    // Once the confirm has taken the flow its commit runs to completion: a
    // backend cancel that lands now waits for this outcome (`hold` waits for
    // it), so the save takes a token nothing cancels, and ends at the flow's
    // own `until`.
    let never = tokio_util::sync::CancellationToken::new();
    let saved = client.save_confirmed(grant, &never, until).await;
    let ok = saved.is_ok();
    if ok {
        backend.clear_auth_wait_if(generation);
    } else {
        record_outcome(state, &backend.name, "failed", caller.as_ref());
    }
    #[cfg(test)]
    backend.sign_in.outcome_pause.pause().await;
    settle(&attempt, outcome, Outcome::Confirmed(saved)).await;
    if ok {
        Decided::Done
    } else {
        Decided::SaveFailed
    }
}

#[cfg(test)]
#[path = "signin_flow_tests.rs"]
mod tests;
