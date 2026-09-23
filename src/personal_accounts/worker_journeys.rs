// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `JourneyService`: the router's handle on the consent-journey table (design
//! §5.3, §6.4). Object-safe, like `AccountRevocation`, so the router holds it
//! without naming the provider transport. Every call is offloaded exactly as
//! `commit_grant_if` is: the synchronous store never runs on the event loop.

use std::sync::Arc;

use super::{CustodyError, CustodyHandle};
use crate::personal_accounts::AccountKey;
use crate::personal_accounts::AccountRevocation;
use crate::personal_accounts::config::{AccountDescriptor, AccountsLimits};
use crate::personal_accounts::service::{CredentialReleaseObserver, RefreshProvider};
use crate::personal_accounts::storage::journey::{
    JourneyError, JourneyId, JourneyLimits, JourneyView, START_WINDOW,
};

/// The custody halves the accounts routes hold, object-safe so the router
/// never names the provider transport.
#[derive(Clone)]
pub(crate) struct AccountHandles {
    pub(crate) revocation: Arc<dyn AccountRevocation>,
    pub(crate) journeys: Arc<dyn JourneyService>,
}

/// A created journey: its id and its `start_by` deadline (unix seconds).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JourneyCreated {
    pub(crate) journey_id: JourneyId,
    pub(crate) expires_at: u64,
}

/// The outer `CustodyError` is admission (busy, shutting down); the inner
/// `JourneyError` is the journey table's own answer.
pub(crate) type JourneyResult<T> = Result<Result<T, JourneyError>, CustodyError>;

#[async_trait::async_trait]
pub(crate) trait JourneyService: Send + Sync {
    /// Create a journey for `owner` against the configured `descriptor`.
    async fn create(
        &self,
        limits: JourneyLimits,
        owner: AccountKey,
        descriptor: AccountDescriptor,
        return_path: String,
    ) -> JourneyResult<JourneyCreated>;

    /// Status of `id` for the principal `(authority, subject)` only.
    async fn status(
        &self,
        limits: JourneyLimits,
        id: String,
        principal: (String, String),
    ) -> JourneyResult<JourneyView>;
}

#[async_trait::async_trait]
impl<P, O> JourneyService for CustodyHandle<P, O>
where
    P: RefreshProvider + Send + Sync + 'static,
    O: CredentialReleaseObserver + Send + Sync + 'static,
{
    async fn create(
        &self,
        limits: JourneyLimits,
        owner: AccountKey,
        descriptor: AccountDescriptor,
        return_path: String,
    ) -> JourneyResult<JourneyCreated> {
        self.offload(move |service| {
            let now = now_seconds();
            Ok(service
                .store()
                .create_connect_journey(now, &limits, owner, &descriptor, return_path)
                .map(|journey_id| JourneyCreated {
                    journey_id,
                    expires_at: now.saturating_add(START_WINDOW),
                }))
        })
        .await
    }

    async fn status(
        &self,
        limits: JourneyLimits,
        id: String,
        principal: (String, String),
    ) -> JourneyResult<JourneyView> {
        self.offload(move |service| {
            let parts = (principal.0.as_str(), principal.1.as_str());
            Ok(service
                .store()
                .journey_status_owned(now_seconds(), &limits, &id, parts))
        })
        .await
    }
}

impl From<&AccountsLimits> for JourneyLimits {
    fn from(limits: &AccountsLimits) -> Self {
        Self {
            journeys_total: limits.journeys_total,
            journeys_per_user: limits.journeys_per_user,
            starts_per_minute_per_user: limits.starts_per_minute_per_user,
            journeys_created_per_minute: limits.journeys_created_per_minute,
        }
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
