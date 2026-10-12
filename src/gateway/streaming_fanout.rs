// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Seeding a session and fanning a backend's notification out to its
//! subscribed sessions.

use super::{
    Arc, Audience, CopyAudience, Delivery, NotificationMultiplexer, TaggedNotification, Value,
    delivery,
};
#[cfg(test)]
use super::{SessionFrame, SessionOwner, broadcast};

impl NotificationMultiplexer {
    /// Test seam: an anonymous session under a chosen id, which production
    /// never creates (every production id is minted, F9).
    #[cfg(test)]
    pub(crate) fn seed_session(&self, id: &str) -> broadcast::Receiver<SessionFrame> {
        self.insert_session(&mut self.sessions.write(), id, SessionOwner::Anonymous)
            .subscribe()
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
        self.broadcast_to_backend_raw(notification, backend, None)
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
        let mut reached = 0;
        for (session, credential) in targets {
            let verdict =
                delivery(&authorizer, credential.as_ref(), Audience::Backend(backend)).await;
            if verdict == Delivery::Deliver
                && self
                    .enqueue(
                        &session,
                        notification.clone(),
                        hidden.as_ref(),
                        None,
                        audience.clone(),
                    )
                    .is_ok()
            {
                reached += 1;
            }
        }
        reached
    }
}
