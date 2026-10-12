// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what each session was last told of each backend, and the
//! fan-out that tells a session of a `tools/list_changed` only when its own
//! view of that backend moved.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use super::copy::CopyAudience;
use super::{ClientSession, NotificationMultiplexer, TaggedNotification};
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{Audience, Delivery, HeldCredential, delivery};

/// What a session was last told of one backend: the fingerprint of what the
/// session is shown of it, and a generation a refresh bumps, so a stale commit
/// is dropped (MIK-8350 B11).
#[derive(Debug, Clone)]
pub(super) struct Told {
    fingerprint: String,
    generation: u64,
}

/// The write-time record of a delivered `tools/list_changed`: a
/// compare-and-set against the generation its fingerprint was read under.
#[derive(Debug)]
pub(crate) struct ToldCommit {
    session: Arc<ClientSession>,
    backend: String,
    fingerprint: String,
    generation: u64,
}

impl ToldCommit {
    /// Record the fingerprint as told, unless a refresh moved the generation.
    pub(crate) fn apply(&self) {
        let mut told = self.session.told.write();
        match told.get_mut(&self.backend) {
            Some(entry) if entry.generation != self.generation => {}
            Some(entry) => entry.fingerprint.clone_from(&self.fingerprint),
            None => {
                told.insert(
                    self.backend.clone(),
                    Told {
                        fingerprint: self.fingerprint.clone(),
                        generation: self.generation,
                    },
                );
            }
        }
    }
}

/// Decides what a listener is shown, for the per-listener `list_changed`
/// filter (MIK-8350). Installed by the router, which owns the visibility
/// state the multiplexer does not.
pub(crate) trait ViewJudge: Send + Sync {
    /// The fingerprint of what `credential` is shown of `backend` now, or
    /// `None` when the credential no longer resolves to a caller.
    fn fingerprint<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
        backend: &'a str,
    ) -> futures::future::BoxFuture<'a, Option<String>>;

    /// Every backend's fingerprint for `credential`, taken when a stream opens
    /// so the first change after attach is judged against what it saw.
    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        credential: Option<&'a HeldCredential>,
        session_id: &'a str,
    ) -> futures::future::BoxFuture<'a, HashMap<String, String>>;
}

/// Whether `notification` is the `tools/list_changed` hint.
fn is_tools_list_changed(notification: &TaggedNotification) -> bool {
    notification.data.get("method").and_then(Value::as_str)
        == Some("notifications/tools/list_changed")
}

impl ClientSession {
    /// Whether `fingerprint` differs from what this session was last told of
    /// `backend`: the generation to commit under if so. A session with no
    /// record yet has taken no baseline, so it records this one and is owed
    /// nothing (a new listener is never told of a change it never saw).
    fn peek_told(&self, backend: &str, fingerprint: &str) -> Option<u64> {
        let mut told = self.told.write();
        match told.get(backend) {
            None => {
                told.insert(
                    backend.to_owned(),
                    Told {
                        fingerprint: fingerprint.to_owned(),
                        generation: 0,
                    },
                );
                None
            }
            Some(entry) if entry.fingerprint == fingerprint => None,
            Some(entry) => Some(entry.generation),
        }
    }
}

impl NotificationMultiplexer {
    /// Take `session_id`'s baseline: what each backend shows its credential
    /// now, recorded as what it was last told. Called when a stream opens, so
    /// the first change after attach is judged against what it saw.
    pub(crate) async fn take_baseline(&self, session_id: &str, judge: &dyn ViewJudge) {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return;
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return;
        };
        let credential = session.credential.read().clone();
        let baseline = judge
            .baseline(&authorizer, credential.as_ref(), session_id)
            .await;
        // Only what the session has no record of: a resumed or re-keyed
        // stream keeps what it was last told, so a change withheld at write
        // is still owed after the reopen (MIK-8350 B1, B2').
        let mut told = session.told.write();
        for (backend, fingerprint) in baseline {
            told.entry(backend).or_insert(Told {
                fingerprint,
                generation: 0,
            });
        }
    }

    /// The caller of `session_id` has just been shown its current view (a
    /// `tools/list` answer, a profile switch): record that as told for every
    /// backend and bump the generation, so a hint already queued from before
    /// is not written for a view the caller now holds (MIK-8350 B9).
    pub(crate) async fn refresh_told(&self, session_id: &str, judge: &dyn ViewJudge) {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return;
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return;
        };
        let credential = session.credential.read().clone();
        let baseline = judge
            .baseline(&authorizer, credential.as_ref(), session_id)
            .await;
        let mut told = session.told.write();
        for (backend, fingerprint) in baseline {
            let generation = told.get(&backend).map_or(0, |t| t.generation + 1);
            told.insert(
                backend,
                Told {
                    fingerprint,
                    generation,
                },
            );
        }
    }

    /// Deliver to every session whose caller may access `backend` now; returns the count.
    ///
    /// Each session's credential is re-validated at delivery, so a revoked or
    /// expired token receives nothing even on a stream opened while it was valid.
    pub(crate) async fn broadcast_to_backend(
        &self,
        notification: &TaggedNotification,
        backend: &str,
    ) -> usize {
        self.broadcast_to_backend_raw(notification, backend, None, None)
            .await
    }

    /// [`Self::broadcast_to_backend`] for a `tools/list_changed`, told only to
    /// the sessions `judge` finds a moved view for (MIK-8350).
    pub(crate) async fn broadcast_to_backend_judged(
        &self,
        notification: &TaggedNotification,
        backend: &str,
        judge: &dyn ViewJudge,
    ) -> usize {
        self.broadcast_to_backend_raw(notification, backend, None, Some(judge))
            .await
    }

    /// [`Self::broadcast_to_backend`] for an item transformed from a raw
    /// inbound value (a webhook body): each copy is also judged on what
    /// `raw` named before the transform dropped it (MIK-7116.MIN.2, §4.4).
    pub(crate) async fn broadcast_to_backend_raw(
        &self,
        notification: &TaggedNotification,
        backend: &str,
        raw: Option<&Value>,
        judge: Option<&dyn ViewJudge>,
    ) -> usize {
        let hidden = raw.and_then(|raw| self.reads.get().and_then(|judge| judge.raw(raw)));
        let Some(authorizer) = self.authorizer.read().clone() else {
            return 0;
        };
        // Copied out so no lock is held across the re-validation awaits. The
        // session itself is held, not its sender, so an unopened one stays
        // unopened and a stream that subscribes meanwhile is still reached.
        let targets: Vec<_> = self
            .sessions
            .read()
            .values()
            .map(|s| (Arc::clone(s), s.credential.read().clone()))
            .collect();
        let audience = CopyAudience::Backend(Arc::from(backend));
        let hint = is_tools_list_changed(notification);
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            if verdict != Delivery::Deliver {
                continue;
            }
            // MIK-8350: a `tools/list_changed` is owed only to a session whose
            // own view of `backend` moved since it was last told. The record
            // is made when the stream writes the frame, not here.
            let mut commit = None;
            if hint && let Some(judge) = judge {
                let Some(fingerprint) = judge
                    .fingerprint(
                        &authorizer,
                        credential.as_ref(),
                        session.id.expose_secret(),
                        backend,
                    )
                    .await
                else {
                    continue;
                };
                let Some(generation) = session.peek_told(backend, &fingerprint) else {
                    continue;
                };
                commit = Some(Arc::new(ToldCommit {
                    session: Arc::clone(&session),
                    backend: backend.to_owned(),
                    fingerprint,
                    generation,
                }));
            }
            if self
                .enqueue(
                    &session,
                    notification.clone(),
                    hidden.as_ref(),
                    None,
                    audience.clone(),
                    commit,
                )
                .is_ok()
            {
                reached += 1;
            }
        }
        reached
    }
}
