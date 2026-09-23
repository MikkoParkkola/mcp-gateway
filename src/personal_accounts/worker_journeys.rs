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
use crate::personal_accounts::provider::{Clock, PersonalOAuthRefresh, ProviderHttp, SecretSource};
use crate::personal_accounts::service::CredentialReleaseObserver;
use crate::personal_accounts::storage::journey::{
    JourneyError, JourneyId, JourneyLimits, JourneyView, START_WINDOW, StartSecrets,
};
use crate::personal_accounts::{AccountError, PersonalAccountStore};

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

/// A started journey, as the browser needs it. The PKCE verifier never leaves
/// custody; `binding` goes only into the journey's `Set-Cookie`.
pub(crate) struct JourneyStarted {
    pub(crate) authorize_url: url::Url,
    pub(crate) binding: String,
    /// Seconds until `callback_by`, from the same `now` that armed it.
    pub(crate) max_age: u64,
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

    /// Design §4.2 step 1: the account an active journey names. Runs before
    /// the browser's session is read, so a dead link asks Open `WebUI` nothing.
    async fn account_of(&self, limits: JourneyLimits, id: String) -> JourneyResult<String>;

    /// Steps 6-8: compare `owner` with the journey's owner, arm the journey,
    /// and build the authorize URL on the pinned endpoint from the minted
    /// state and verifier.
    async fn start(
        &self,
        limits: JourneyLimits,
        id: String,
        owner: AccountKey,
    ) -> JourneyResult<JourneyStarted>;
}

#[async_trait::async_trait]
impl<H, C, S, O> JourneyService for CustodyHandle<Arc<PersonalOAuthRefresh<H, C, S>>, O>
where
    H: ProviderHttp + 'static,
    C: Clock + 'static,
    S: SecretSource + 'static,
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

    async fn account_of(&self, limits: JourneyLimits, id: String) -> JourneyResult<String> {
        self.offload(move |service| {
            Ok(service
                .store()
                .active_journey_account(now_seconds(), &limits, &id))
        })
        .await
    }

    async fn start(
        &self,
        limits: JourneyLimits,
        id: String,
        owner: AccountKey,
    ) -> JourneyResult<JourneyStarted> {
        let account = owner.backend_id.clone();
        let armed = self
            .offload(move |service| Ok(arm(service.store(), &limits, &id, &owner)))
            .await?;
        let (secrets, max_age) = match armed {
            Ok(armed) => armed,
            Err(error) => return Ok(Err(error)),
        };
        // The URL carries exactly the state the store sealed; a URL the
        // provider cannot build is a descriptor fault, not the user's.
        let url = self
            .provider()?
            .authorize_url_for_verifier(&account, &secrets.state, &secrets.verifier)
            .map_err(|_| JourneyError::Storage(AccountError::InvalidConfiguration));
        Ok(url.map(|authorize_url| JourneyStarted {
            authorize_url,
            binding: secrets.binding,
            max_age,
        }))
    }
}

/// One `now` for the arm and the deadline read, so `max_age` is exactly
/// `callback_by - now`.
fn arm(
    store: &PersonalAccountStore,
    limits: &JourneyLimits,
    id: &str,
    owner: &AccountKey,
) -> Result<(StartSecrets, u64), JourneyError> {
    let now = now_seconds();
    let secrets = store.start_journey(now, limits, id, owner)?;
    let deadline = store.journey_status(now, limits, id)?.expires_at;
    Ok((secrets, deadline.unwrap_or(now).saturating_sub(now)))
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
