// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: what each session was last told of each backend, and the
//! fan-out that tells a session of a `tools/list_changed` only when its own
//! view of that backend moved.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::copy::CopyAudience;
use super::{ClientSession, NotificationMultiplexer, TaggedNotification};
use crate::gateway::auth::AuthState;
use crate::gateway::auth::live::{Audience, Delivery, HeldCredential, delivery};

/// What one caller is shown of one backend: the served `tools/list` result,
/// which is the caller's own and shared by every backend, and the backend's
/// own listing as discovery shows it. The two are kept apart so a change
/// the caller cannot see on one backend never reads as a change on another
/// (MIK-8350).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ViewDigest {
    pub(crate) served: String,
    /// Empty when the caller is shown nothing of the backend.
    pub(crate) shown: String,
}

/// What a caller was last told of one backend, and a generation a refresh
/// bumps so a stale commit is dropped (MIK-8350 B11).
#[derive(Debug, Clone)]
struct Told {
    shown: String,
    generation: u64,
}

/// What a caller was last told: its one served-list digest and, per backend,
/// what it was shown of it. Shared by the legacy GET session and the listen
/// stream, so both judge a view the same way.
#[derive(Debug, Default)]
pub(crate) struct ToldState {
    baselined: bool,
    served: Option<String>,
    backends: HashMap<String, Told>,
}

/// The verdict on a view against a [`ToldState`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Peek {
    /// Nothing the caller does not already hold.
    Quiet,
    /// The caller is owed a hint; the generation to commit under.
    Owed(u64),
}

impl ToldState {
    /// Forget everything: the next attach takes a fresh baseline.
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }

    /// Record `view` for the backends this state has no record of; what it
    /// already holds is kept, so a change withheld at write stays owed after a
    /// resumed or re-keyed stream reopens (MIK-8350 B1, B2').
    pub(crate) fn baseline(&mut self, view: HashMap<String, ViewDigest>) {
        self.baselined = true;
        for (backend, digest) in view {
            self.served.get_or_insert(digest.served);
            self.backends.entry(backend).or_insert(Told {
                shown: digest.shown,
                generation: 0,
            });
        }
    }

    /// The caller was just shown `view`: record it for every backend and bump
    /// each generation, so a hint queued before is not written for a view the
    /// caller now holds (MIK-8350 B9).
    pub(crate) fn refresh(&mut self, view: HashMap<String, ViewDigest>) {
        self.baselined = true;
        for (backend, digest) in view {
            let generation = self.backends.get(&backend).map_or(0, |t| t.generation + 1);
            self.served = Some(digest.served);
            self.backends.insert(
                backend,
                Told {
                    shown: digest.shown,
                    generation,
                },
            );
        }
    }

    /// Whether `digest` is a view of `backend` the caller was not told. A
    /// state that never took a baseline records this one and is owed nothing
    /// (a stream is never told of a change it never saw); once one is taken, a
    /// backend it has no record of is new, and owed when it shows anything.
    pub(crate) fn peek(&mut self, backend: &str, digest: &ViewDigest) -> Peek {
        if !self.baselined {
            self.baseline(HashMap::from([(backend.to_owned(), digest.clone())]));
            return Peek::Quiet;
        }
        let served_moved = self.served.as_deref() != Some(digest.served.as_str());
        match self.backends.get(backend) {
            Some(told) if !served_moved && told.shown == digest.shown => Peek::Quiet,
            Some(told) => Peek::Owed(told.generation),
            None if served_moved || !digest.shown.is_empty() => Peek::Owed(0),
            None => {
                self.backends.insert(
                    backend.to_owned(),
                    Told {
                        shown: String::new(),
                        generation: 0,
                    },
                );
                Peek::Quiet
            }
        }
    }

    /// Record that `digest` of `backend` was told, once its frame is written.
    /// `false` when there is nothing to record and so nothing to write: the
    /// state was cleared, a refresh moved the generation, or the caller
    /// already holds this view.
    pub(crate) fn commit(&mut self, backend: &str, digest: &ViewDigest, generation: u64) -> bool {
        if !self.baselined {
            return false;
        }
        let served_moved = self.served.as_deref() != Some(digest.served.as_str());
        let owed = match self.backends.get(backend) {
            Some(told) => {
                told.generation == generation && (served_moved || told.shown != digest.shown)
            }
            None => generation == 0,
        };
        if owed {
            self.served = Some(digest.served.clone());
            self.backends.insert(
                backend.to_owned(),
                Told {
                    shown: digest.shown.clone(),
                    generation,
                },
            );
        }
        owed
    }
}

/// The identities a stream was opened under, besides its credential: part of
/// what its caller is shown, so the judge builds the scope a POST of that
/// caller would (MIK-8350 D11).
#[derive(Clone, Default)]
pub(crate) struct ViewSubject {
    pub(crate) grant_subject: Option<crate::identity_grants::GrantSubject>,
    pub(crate) oauth_agent: Option<crate::gateway::oauth::AgentIdentity>,
    pub(crate) cert: Option<crate::mtls::CertIdentity>,
}

impl std::fmt::Debug for ViewSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewSubject").finish_non_exhaustive()
    }
}

/// The write-time record of a delivered `tools/list_changed`: a
/// compare-and-set against the generation, and the session's credential
/// epoch, its digest was read under.
#[derive(Debug)]
pub(crate) struct ToldCommit {
    session: Arc<ClientSession>,
    backend: String,
    digest: ViewDigest,
    generation: u64,
    epoch: u64,
}

impl ToldCommit {
    /// Record the digest as told. `false` when the frame should not be
    /// written: a refresh or a rekey got there first, or it is already told.
    pub(crate) fn apply(&self) -> bool {
        let mut told = self.session.told.write();
        self.session.epoch.load(Ordering::Acquire) == self.epoch
            && told.commit(&self.backend, &self.digest, self.generation)
    }
}

/// Decides what a listener is shown, for the per-listener `list_changed`
/// filter (MIK-8350). Installed by the router, which owns the visibility
/// state the multiplexer does not.
pub(crate) trait ViewJudge: Send + Sync {
    /// What `credential` is shown of `backend` now, or `None` when the
    /// credential no longer resolves to a caller.
    fn digest<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: (Option<&'a HeldCredential>, Option<&'a ViewSubject>),
        session_id: &'a str,
        backend: &'a str,
    ) -> futures::future::BoxFuture<'a, Option<ViewDigest>>;

    /// Every backend's view for `credential`, taken when a stream opens so the
    /// first change after attach is judged against what it saw.
    fn baseline<'a>(
        &'a self,
        auth: &'a AuthState,
        caller: (Option<&'a HeldCredential>, Option<&'a ViewSubject>),
        session_id: &'a str,
    ) -> futures::future::BoxFuture<'a, HashMap<String, ViewDigest>>;
}

/// Whether `notification` is the `tools/list_changed` hint.
fn is_tools_list_changed(notification: &TaggedNotification) -> bool {
    notification.data.get("method").and_then(Value::as_str)
        == Some("notifications/tools/list_changed")
}

impl NotificationMultiplexer {
    /// Bind the identities `session_id`'s stream was opened under, which its
    /// view is judged with (MIK-8350 D11).
    pub(crate) fn bind_view_subject(&self, session_id: &str, subject: ViewSubject) {
        if let Some(session) = self.sessions.read().get(session_id) {
            *session.subject.write() = Some(Arc::new(subject));
        }
    }

    /// What `session_id`'s caller is shown of every backend now, with the
    /// credential epoch it was read under; `None` when there is nothing to
    /// judge (no authorizer, no such session).
    async fn view_of(
        &self,
        session_id: &str,
        judge: &dyn ViewJudge,
    ) -> Option<(Arc<ClientSession>, u64, HashMap<String, ViewDigest>)> {
        let authorizer = self.authorizer.read().clone()?;
        let session = self.sessions.read().get(session_id).map(Arc::clone)?;
        let epoch = session.epoch.load(Ordering::Acquire);
        let credential = session.credential.read().clone();
        let subject = session.subject.read().clone();
        let view = judge
            .baseline(
                &authorizer,
                (credential.as_ref(), subject.as_deref()),
                session_id,
            )
            .await;
        Some((session, epoch, view))
    }

    /// Take `session_id`'s baseline: what each backend shows its credential
    /// now, recorded as what it was last told. Called when a stream opens, so
    /// the first change after attach is judged against what it saw.
    pub(crate) async fn take_baseline(&self, session_id: &str, judge: &dyn ViewJudge) {
        if let Some((session, epoch, view)) = self.view_of(session_id, judge).await {
            let mut told = session.told.write();
            if session.epoch.load(Ordering::Acquire) == epoch {
                told.baseline(view);
            }
        }
    }

    /// The caller of `session_id` has just been shown its current view (a
    /// `tools/list` answer, a profile switch): record that as told for every
    /// backend. The view is read before the answer is built, so a change that
    /// lands in between leaves the caller owed one hint rather than none.
    pub(crate) async fn refresh_told(&self, session_id: &str, judge: &dyn ViewJudge) {
        if let Some((session, epoch, view)) = self.view_of(session_id, judge).await {
            let mut told = session.told.write();
            if session.epoch.load(Ordering::Acquire) == epoch {
                told.refresh(view);
            }
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
        // MIK-8350: a `tools/list_changed` judged by view is a constant hint
        // that carries nothing of the backend, so it is owed to a caller whose
        // view moved even when that move is losing the backend; only a dead
        // credential is refused, here and again at write.
        let judge = judge.filter(|_| is_tools_list_changed(notification));
        let audience = match judge {
            Some(_) => CopyAudience::Any,
            None => CopyAudience::Backend(Arc::from(backend)),
        };
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            if verdict == Delivery::Dead || (verdict != Delivery::Deliver && judge.is_none()) {
                continue;
            }
            let mut commit = None;
            if let Some(judge) = judge {
                commit = self
                    .owed_commit(&session, &authorizer, credential.as_ref(), backend, judge)
                    .await;
                if commit.is_none() {
                    continue;
                }
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

    /// The record to make when `session` is written a `tools/list_changed` for
    /// `backend`, or `None` when its view of `backend` did not move. The record
    /// is made when the stream writes the frame, not here.
    async fn owed_commit(
        &self,
        session: &Arc<ClientSession>,
        authorizer: &AuthState,
        credential: Option<&HeldCredential>,
        backend: &str,
        judge: &dyn ViewJudge,
    ) -> Option<Arc<ToldCommit>> {
        let epoch = session.epoch.load(Ordering::Acquire);
        let subject = session.subject.read().clone();
        let digest = judge
            .digest(
                authorizer,
                (credential, subject.as_deref()),
                session.id.expose_secret(),
                backend,
            )
            .await?;
        let mut told = session.told.write();
        if session.epoch.load(Ordering::Acquire) != epoch {
            return None;
        }
        let Peek::Owed(generation) = told.peek(backend, &digest) else {
            return None;
        };
        Some(Arc::new(ToldCommit {
            session: Arc::clone(session),
            backend: backend.to_owned(),
            digest,
            generation,
            epoch,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(served: &str, shown: &str) -> ViewDigest {
        ViewDigest {
            served: served.to_owned(),
            shown: shown.to_owned(),
        }
    }

    fn baselined(views: &[(&str, ViewDigest)]) -> ToldState {
        let mut told = ToldState::default();
        told.baseline(
            views
                .iter()
                .map(|(backend, view)| ((*backend).to_owned(), view.clone()))
                .collect(),
        );
        told
    }

    #[test]
    fn a_state_with_no_baseline_records_the_first_view_and_is_owed_nothing() {
        let mut told = ToldState::default();
        assert_eq!(told.peek("a", &digest("s0", "x")), Peek::Quiet);
        assert_eq!(told.peek("a", &digest("s0", "x")), Peek::Quiet);
        assert_eq!(told.peek("a", &digest("s0", "y")), Peek::Owed(0));
    }

    #[test]
    fn a_backend_added_after_the_baseline_is_owed_when_it_shows_anything() {
        let mut told = baselined(&[("a", digest("s0", "x"))]);
        assert_eq!(told.peek("new", &digest("s0", "t")), Peek::Owed(0));
        assert_eq!(told.peek("hidden", &digest("s0", "")), Peek::Quiet);
    }

    #[test]
    fn one_served_digest_serves_every_backend() {
        let mut told = baselined(&[("a", digest("s0", "x")), ("b", digest("s0", "y"))]);
        let moved = digest("s1", "x2");
        assert_eq!(told.peek("a", &moved), Peek::Owed(0));
        assert!(told.commit("a", &moved, 0));
        // b's own listing did not move, and the served list is now told.
        assert_eq!(told.peek("b", &digest("s1", "y")), Peek::Quiet);
    }

    #[test]
    fn a_commit_is_refused_after_a_clear_a_refresh_or_a_repeat() {
        let view = digest("s1", "x2");
        let mut cleared = baselined(&[("a", digest("s0", "x"))]);
        cleared.clear();
        assert!(!cleared.commit("a", &view, 0), "cleared: nothing to record");

        let mut refreshed = baselined(&[("a", digest("s0", "x"))]);
        refreshed.refresh(HashMap::from([("a".to_owned(), digest("s1", "x2"))]));
        assert!(
            !refreshed.commit("a", &view, 0),
            "a refresh moved the generation"
        );

        let mut told = baselined(&[("a", digest("s0", "x"))]);
        assert!(told.commit("a", &view, 0));
        assert!(!told.commit("a", &view, 0), "already told");
    }

    #[test]
    fn a_refresh_bumps_the_generation_and_holds_the_view() {
        let mut told = baselined(&[("a", digest("s0", "x"))]);
        told.refresh(HashMap::from([("a".to_owned(), digest("s1", "x2"))]));
        assert_eq!(told.peek("a", &digest("s1", "x2")), Peek::Quiet);
        assert_eq!(told.peek("a", &digest("s1", "x3")), Peek::Owed(1));
    }
}
