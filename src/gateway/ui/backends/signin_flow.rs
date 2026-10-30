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
use crate::backend::sign_in_flow::{Flow, Phase};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::oauth::client::sign_in::UiSink;
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
    let ended = Arc::new(tokio::sync::Notify::new());
    let flow = Flow {
        owner,
        attempt_id: attempt_id.clone(),
        phase: Phase::AwaitingCallback,
        until: deadline,
        until_at: crate::clock::system_time_or_before_epoch() + windows.start,
        grant: None,
        held_since: None,
        wait_generation: 0,
        caller,
        ended: Arc::clone(&ended),
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
        ended,
    };
    let sink = UiSink {
        link: link_tx,
        callback: callback_tx,
        confirm_window: windows.confirm,
    };
    tokio::spawn(run.drive(lead, sink, callback_rx));
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
    ended: Arc<tokio::sync::Notify>,
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
    async fn drive(self, lead: Lead, ui: UiSink, callback: oneshot::Receiver<()>) {
        let mut lead = lead;
        let cancel = lead.cancel_token().clone();
        let listeners = lead.take_listeners_guard();
        let auth = self
            .client
            .authorize_for_ui(&cancel, listeners, self.deadline, ui);
        tokio::pin!(auth);
        tokio::pin!(callback);
        let mut called = false;
        let granted = loop {
            tokio::select! {
                result = &mut auth => break result,
                landed = &mut callback, if !called => {
                    called = true;
                    if landed.is_ok() {
                        self.callback_landed(&lead);
                    }
                }
            }
        };
        match granted {
            Ok(grant) => self.hold(lead, grant).await,
            Err(error) => {
                if let Some(flow) = self.take_flow() {
                    self.record_end(&flow, &error);
                }
                lead.end(Some(&error));
            }
        }
    }

    /// Keep the grant until a decision takes it or the window ends.
    async fn hold(&self, lead: Lead, grant: crate::oauth::client::sign_in::PendingGrant) {
        let until = self.backend.with_flow(|slot| {
            let flow = slot.as_mut().filter(|f| f.attempt_id == self.attempt_id)?;
            flow.grant = Some(grant);
            flow.held_since = Some(Instant::now());
            Some(flow.until)
        });
        let Some(until) = until else {
            return lead.end(None);
        };
        tokio::select! {
            () = self.ended.notified() => lead.end(None),
            () = tokio::time::sleep_until(until) => {
                #[cfg(test)]
                self.backend.sign_in_expiry_pause.pause().await;
                if let Some(flow) = self.take_flow() {
                    let expired = Error::AuthorizationIncomplete {
                        backend: self.backend.name.clone(),
                        window_secs: self.backend.sign_in_windows().confirm.as_secs(),
                    };
                    self.record_end(&flow, &expired);
                    lead.end(Some(&expired));
                } else {
                    lead.end(None);
                }
            }
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
    held_for: std::time::Duration,
    generation: u64,
    ended: Arc<tokio::sync::Notify>,
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
            held_for: flow
                .held_since
                .map_or_else(Default::default, |at| at.elapsed()),
            generation: flow.wait_generation,
            ended: Arc::clone(&flow.ended),
            client: Arc::clone(&flow.client),
            caller: flow.caller.clone(),
        };
        *slot = None;
        Ok(taken)
    })
}

/// Confirm or cancel the sign-in `owner` started as `attempt`.
pub(super) async fn decide(
    state: &AppState,
    backend: &Backend,
    owner: &str,
    attempt: &str,
    decision: Decision,
) -> Decided {
    let taken = match take_for(backend, owner, attempt) {
        Ok(taken) => taken,
        Err(refused) => return refused,
    };
    let Taken {
        grant,
        held_for,
        generation,
        ended,
        client,
        caller,
    } = taken;
    if decision == Decision::Cancel {
        drop(grant);
        release(backend, &ended).await;
        return Decided::Done;
    }
    let cancel = tokio_util::sync::CancellationToken::new();
    let by = Instant::now() + backend.sign_in_windows().confirm;
    let saved = client.save_confirmed(grant, held_for, &cancel, by).await;
    release(backend, &ended).await;
    if saved.is_ok() {
        backend.clear_auth_wait_if(generation);
        Decided::Done
    } else {
        record_outcome(state, &backend.name, "failed", caller.as_ref());
        Decided::SaveFailed
    }
}

/// Tell the flow's task a decision ended it, and let it hand the login gate
/// back before the answer goes out, so the next start does not meet it.
async fn release(backend: &Backend, ended: &tokio::sync::Notify) {
    ended.notify_one();
    for _ in 0..64 {
        if !backend.login_gate.in_flight() {
            break;
        }
        tokio::task::yield_now().await;
    }
}
