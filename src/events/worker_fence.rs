// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A vault row's grant at delivery: read fresh after every wait, just
//! before the row that signs, under one deadline that bounds everything
//! from the read to the request's end. A record observed under a grant that
//! has since moved is buried; one whose grant cannot be read now waits.

use std::time::Duration;

use super::{Attempt, OutboxRecord, Services, quiet_dead, unsent_later};
use crate::events::EventsHub;
use crate::events::listener_credential::{FENCE_READ, FenceRead};
use crate::events::outbox::DeadReason;
use crate::events::records::Subscription;
use crate::identity_propagation::PropagationStrategyKind;

/// From the fence read starting to the request ending, at most this: the
/// callback client's own total, so the read and the store waits before the
/// send cannot stretch the time a rotated grant may still be sent under.
pub(super) const FENCE_WINDOW: Duration = crate::events::client::TOTAL_TIMEOUT;

/// Custody could not answer in time: the record waits, unsent.
const FENCE_UNAVAILABLE: &str = "fence_unavailable";
/// The grant gives no view (revoked, reconnect required, descriptor moved).
const GRANT_NO_VIEW: &str = "grant_no_view";
/// The window ran out before the send: the record waits, unsent.
const FENCE_STALE: &str = "fence_stale";

/// What delivery read of a row's grant.
pub(super) enum Fence {
    /// Not a vault row: nothing rotates under it.
    Unfenced,
    /// The vault grant's fence binding now.
    Bound(String),
}

impl Fence {
    pub(super) fn binding(&self) -> Option<&str> {
        match self {
            Self::Unfenced => None,
            Self::Bound(binding) => Some(binding),
        }
    }
}

impl EventsHub {
    /// `sub`'s grant now, or `None` when the attempt is settled here: a busy
    /// or slow custody sends the record back unsent (its retry window still
    /// bounds it: every attempt asks `overdue` first), and no view of the
    /// grant buries it.
    pub(super) async fn fence_now<'a>(
        &self,
        services: &Services,
        sub: &Subscription,
        record: &OutboxRecord,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) -> Option<Fence> {
        if sub
            .obs_basis
            .as_ref()
            .is_none_or(|basis| basis.strategy != PropagationStrategyKind::Vault)
        {
            return Some(Fence::Unfenced);
        }
        match self.read_fence(sub).await {
            Ok(binding) => Some(Fence::Bound(binding)),
            Err(FenceRead::Busy) => {
                services.audit_outcome(&ended(FENCE_UNAVAILABLE)).await;
                self.settle_with(services, record, |now| {
                    unsent_later(FENCE_UNAVAILABLE, record, now)
                })
                .await;
                None
            }
            Err(FenceRead::Closed) => {
                services.audit_outcome(&ended(GRANT_NO_VIEW)).await;
                self.settle(services, record, quiet_dead(DeadReason::Observation))
                    .await;
                None
            }
        }
    }

    /// The vault grant `sub` observes under, read without minting.
    async fn read_fence(&self, sub: &Subscription) -> Result<String, FenceRead> {
        let (Some((backend, _)), Some(identity)) = (
            crate::events::upstream::parse_name(&sub.name),
            sub.observed_as(),
        ) else {
            return Err(FenceRead::Closed);
        };
        let Some(mint) = self.runtime.listener_mint.get() else {
            return Err(FenceRead::Busy);
        };
        match tokio::time::timeout(FENCE_READ, mint.fence_binding(backend, &identity)).await {
            Ok(Ok(Some(binding))) => Ok(binding),
            // A vault row with no vault grant behind it now is not unchanged.
            Ok(Ok(None) | Err(FenceRead::Closed)) => Err(FenceRead::Closed),
            Ok(Err(FenceRead::Busy)) | Err(_) => Err(FenceRead::Busy),
        }
    }

    /// What remains of the fence window for the send, or `None` when the
    /// window ran out and the record went back unsent.
    pub(super) async fn fence_remaining<'a>(
        &self,
        services: &Services,
        record: &OutboxRecord,
        deadline: tokio::time::Instant,
        ended: &(impl Fn(&'static str) -> Attempt<'a> + Sync),
    ) -> Option<Duration> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            return Some(remaining);
        }
        services.audit_outcome(&ended(FENCE_STALE)).await;
        self.settle_with(services, record, |now| {
            unsent_later(FENCE_STALE, record, now)
        })
        .await;
        None
    }
}
