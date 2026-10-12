// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350: the multiplexer's side of the per-stream view records: attaching
//! a stream's view, reading a refresh, and fanning a judged hint out. Split
//! from `streaming_told.rs` for size; it shares that module's private types.

use super::{
    Arc, AtAttach, Audience, AuthState, ClientSession, CopyAudience, DeadReason, Delivery,
    HeldCredential, Judged, NotificationMultiplexer, Peek, PendingRefresh, StreamView,
    TaggedNotification, Value, ViewJudge, ViewSubject, dead_at_attach, delivery,
    is_tools_list_changed,
};

impl NotificationMultiplexer {
    /// The view `session_id`'s stream opens with: its own subject's record on
    /// the session, with a baseline of what each backend shows its caller now,
    /// so the first change after attach is judged against what it saw
    /// (MIK-8350). Streams of one session with different subjects get
    /// different records and never judge one another (D17e).
    pub(crate) async fn attach_view(
        &self,
        session_id: &str,
        subject: ViewSubject,
        judge: Arc<dyn ViewJudge>,
    ) -> Result<Option<StreamView>, DeadReason> {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return Ok(None);
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return Ok(None);
        };
        let subject = Arc::new(subject);
        let record = session.record_for(&subject);
        let credential = session.credential.read().clone();
        match judge
            .resolve(&authorizer, (credential.as_ref(), &subject))
            .await
        {
            Judged::Live(caller) => {
                let (stamp, view) = record
                    .read(async { judge.baseline(&caller, &subject, session_id) })
                    .await;
                record.state().baseline(stamp, view);
            }
            // A caller that does not resolve at attach gets no stream, unless
            // it presented nothing at all: a public path admits it
            // anonymously, and nothing is ever delivered to it.
            Judged::Dead(reason) => match dead_at_attach(credential.as_ref(), reason, &subject) {
                AtAttach::Refuse => {
                    reason.count();
                    return Err(reason);
                }
                AtAttach::OpenAnonymous => {}
            },
        }
        Ok(Some(StreamView {
            subject,
            record,
            judge,
        }))
    }

    /// Take `session_id`'s baseline for the default subject: for a session no
    /// stream has opened a view on (a bare receiver).
    #[cfg(test)]
    pub(crate) async fn take_baseline(&self, session_id: &str, judge: &Arc<dyn ViewJudge>) {
        let _ = self
            .attach_view(session_id, ViewSubject::default(), Arc::clone(judge))
            .await;
    }

    /// Read what `session_id`'s caller, under `subject`, is shown now, ahead
    /// of an answer that will show it (a `tools/list`, a profile switch). The
    /// result is applied by [`PendingRefresh::settle`] only once that answer
    /// has cleared every delivery gate (MIK-8350 B9, D17h). Empty when no
    /// stream holds a view for that subject.
    pub(crate) async fn read_refresh(
        &self,
        session_id: &str,
        subject: &ViewSubject,
        judge: &dyn ViewJudge,
    ) -> PendingRefresh {
        let Some(authorizer) = self.authorizer.read().clone() else {
            return PendingRefresh::default();
        };
        let Some(session) = self.sessions.read().get(session_id).map(Arc::clone) else {
            return PendingRefresh::default();
        };
        let Some((_, record)) = session.existing_record(subject) else {
            return PendingRefresh::default();
        };
        let epoch = record.epoch();
        let credential = session.credential.read().clone();
        let Judged::Live(caller) = judge
            .resolve(&authorizer, (credential.as_ref(), subject))
            .await
        else {
            return PendingRefresh::default();
        };
        let (stamp, view) = record
            .read(async { judge.baseline(&caller, subject, session_id) })
            .await;
        PendingRefresh(Some((record, epoch, stamp, view)))
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
        // credential is refused, here and again at write. Each stream then
        // judges it again for itself when it writes (D17d).
        let judge = judge.filter(|_| is_tools_list_changed(notification));
        let audience = match judge {
            Some(_) => CopyAudience::Any,
            None => CopyAudience::Backend(Arc::from(backend)),
        };
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            // A judged hint goes to a dead caller too: the write-time check
            // closes its stream (D17i).
            if judge.is_none() && verdict != Delivery::Deliver {
                continue;
            }
            if let Some(judge) = judge
                && !self
                    .view_moved(&session, &authorizer, credential.as_ref(), backend, judge)
                    .await
            {
                continue;
            }
            let judged = judge.map(|_| Arc::from(backend));
            if self
                .enqueue(
                    &session,
                    notification.clone(),
                    hidden.as_ref(),
                    None,
                    audience.clone(),
                    judged,
                )
                .is_ok()
            {
                reached += 1;
            }
        }
        reached
    }

    /// Whether any view held on `session` is owed a hint for `backend`. A
    /// session no stream opened a view on has none, so it is judged as the
    /// default subject would be.
    async fn view_moved(
        &self,
        session: &Arc<ClientSession>,
        authorizer: &AuthState,
        credential: Option<&HeldCredential>,
        backend: &str,
        judge: &dyn ViewJudge,
    ) -> bool {
        let mut views = session.views();
        if views.is_empty() {
            views.push((
                Arc::new(ViewSubject::default()),
                session.record_for(&ViewSubject::default()),
            ));
        }
        for (subject, record) in views {
            let caller = match judge.resolve(authorizer, (credential, &subject)).await {
                Judged::Live(caller) => caller,
                // A dead caller is closed by the write-time check, so the copy
                // still goes; an anonymous `Bearer` death is silence, not a move.
                Judged::Dead(reason) => {
                    if let (None, DeadReason::Bearer) = (credential, reason) {
                        continue;
                    }
                    return true;
                }
            };
            let (stamp, digest) = record
                .read(async {
                    judge.digest(&caller, &subject, session.id.expose_secret(), backend)
                })
                .await;
            if record.state().peek(stamp, backend, &digest) == Peek::Owed {
                return true;
            }
        }
        false
    }
}
