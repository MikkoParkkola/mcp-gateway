// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /accounts/v1/callback` inside custody (design §6.2 steps 1-11, §6.3,
//! §7). Store work is offloaded; the exchange and revocation run with no lock
//! held. Tokens never leave this module: the router gets a closed outcome.
//! `now` is the provider's clock, the time base of every deadline it checks.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::CustodyHandle;
use crate::personal_accounts::config::{AccessType, AccountDescriptor};
use crate::personal_accounts::provider::{
    Clock, PersonalOAuthRefresh, ProviderHttp, ProviderRevocation, SecretSource, TokenTypeHint,
};
use crate::personal_accounts::service::{
    CredentialReleaseObserver, ProviderRefreshError, TokenRefresh,
};
use crate::personal_accounts::storage::journey::{
    Admitted, JourneyCommit, JourneyError, JourneyLimits, JourneyReason, JourneyRefusal,
    JourneyStatus,
};
use crate::personal_accounts::{AccountKey, GrantRecord, PersonalAccountStore};
use crate::security::TransparencyLogger;

/// A minted state or binding is 43 characters (mirrors the store's own cap,
/// which a binding for another journey never reaches).
const CALLBACK_SECRET_MAX: usize = 64;

/// One callback as the router parsed it. Raw provider text is matched here
/// and never stored or rendered.
pub(crate) struct CallbackRequest {
    pub(crate) limits: JourneyLimits,
    pub(crate) state: String,
    pub(crate) code: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) iss: Option<String>,
    /// Journey id to binding cookie value, one per journey cookie sent.
    pub(crate) bindings: BTreeMap<String, String>,
    /// The live descriptors, for the revision (`config_changed`) and grant checks.
    pub(crate) descriptors: BTreeMap<String, AccountDescriptor>,
    pub(crate) audit: Option<Arc<TransparencyLogger>>,
}

/// What the page says. `message` is gateway text built from closed reasons.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CallbackOutcome {
    /// No journey this request can name: `invalid_request`.
    Invalid,
    /// The store or custody could not answer.
    Unavailable,
    Page {
        journey_id: String,
        message: String,
        return_path: String,
    },
}

/// Whether an abort must still record the journey's terminal reason, or the
/// store already did in the write that refused the commit.
#[derive(Clone, Copy)]
enum Mark {
    Record,
    AlreadyRecorded,
}

/// Every step either continues or ends the callback with its outcome.
type Step<T> = Result<T, CallbackOutcome>;

/// The admitted journey plus what its page links back to.
struct Journey {
    now: u64,
    limits: JourneyLimits,
    admitted: Admitted,
}

impl Journey {
    fn page(&self, message: String) -> CallbackOutcome {
        CallbackOutcome::Page {
            journey_id: self.admitted.journey_id.clone(),
            message,
            return_path: self.admitted.return_path.clone(),
        }
    }
}

/// The closed wire name of a reason (its serde form).
fn reason_text(reason: JourneyReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn plain_page(journey_id: &str, message: &str) -> CallbackOutcome {
    CallbackOutcome::Page {
        journey_id: journey_id.to_owned(),
        message: message.to_owned(),
        return_path: "/".to_owned(),
    }
}

/// A store refusal of an identified journey. Replays keep their original
/// status; only the page says why nothing happened.
fn refused(journey_id: &str, error: JourneyError) -> CallbackOutcome {
    match error {
        JourneyError::Refused(JourneyRefusal::Replay) => plain_page(journey_id, "already used"),
        JourneyError::Refused(JourneyRefusal::Expired) => plain_page(journey_id, "expired"),
        JourneyError::Refused(JourneyRefusal::BrowserMismatch) => {
            plain_page(journey_id, "browser_mismatch")
        }
        JourneyError::Refused(_) => CallbackOutcome::Invalid,
        JourneyError::Storage(_) => CallbackOutcome::Unavailable,
    }
}

/// Design §7: the raw `error` is only matched, never carried.
fn provider_error(error: &str) -> (JourneyStatus, JourneyReason) {
    match error {
        "access_denied" => (JourneyStatus::Cancelled, JourneyReason::UserDenied),
        "consent_required"
        | "interaction_required"
        | "login_required"
        | "account_selection_required" => {
            (JourneyStatus::Cancelled, JourneyReason::ConsentNotCompleted)
        }
        "temporarily_unavailable" | "server_error" => {
            (JourneyStatus::Failed, JourneyReason::ProviderUnavailable)
        }
        _ => (JourneyStatus::Failed, JourneyReason::ProviderError),
    }
}

/// Step 9. An omitted `scope` means the requested scopes (RFC 6749 §5.1).
fn invalid_grant(descriptor: &AccountDescriptor, tokens: &TokenRefresh) -> Option<JourneyReason> {
    let requested = descriptor.scopes.as_deref().unwrap_or_default();
    let granted = tokens.scopes.as_deref().unwrap_or(requested);
    let offline = descriptor
        .authorize_extra
        .as_ref()
        .and_then(|extra| extra.access_type)
        == Some(AccessType::Offline);
    if !requested.iter().all(|scope| granted.contains(scope)) {
        Some(JourneyReason::ScopeMissing)
    } else if !tokens.token_type.eq_ignore_ascii_case("bearer") || tokens.access_token.is_empty() {
        Some(JourneyReason::UnexpectedTokenForm)
    } else if offline && tokens.refresh_token.is_none() {
        Some(JourneyReason::NoRefreshToken)
    } else {
        None
    }
}

/// The owner's key and the first-generation grant (step 11). `None` when the
/// descriptor cannot name the key or the grant, which the commit could not
/// store either.
fn grant_of(
    journey: &Journey,
    descriptor: &AccountDescriptor,
    tokens: &TokenRefresh,
) -> Option<(AccountKey, GrantRecord)> {
    let admitted = &journey.admitted;
    let key = AccountKey {
        principal_authority: admitted.owner_authority.clone(),
        principal_subject: admitted.owner_subject.clone(),
        backend_id: admitted.account_id.clone(),
        resource: descriptor.resource.clone()?,
        oauth_issuer: admitted.issuer.clone(),
    };
    let requested = descriptor.scopes.clone().unwrap_or_default();
    let mut scopes = tokens.scopes.clone().unwrap_or(requested);
    scopes.sort();
    scopes.dedup();
    let record = GrantRecord {
        generation: crate::personal_accounts::storage::random_hex().ok()?,
        token_revision: 1,
        authorization_epoch: 1,
        descriptor_revision: admitted.descriptor_revision.clone(),
        scopes,
        access_token: tokens.access_token.clone(),
        refresh_token: tokens.refresh_token.clone(),
        token_type: tokens.token_type.clone(),
        expires_at: tokens.expires_at,
        provider_account_id: None,
        client_id: descriptor.client_id.clone()?,
    };
    Some((key, record))
}

fn revocation_text(outcome: ProviderRevocation) -> &'static str {
    match outcome {
        ProviderRevocation::Confirmed => "provider_revoked",
        ProviderRevocation::Failed => "provider_revoke_failed",
        ProviderRevocation::Unsupported => "provider_revoke_unsupported",
    }
}

type Provider<H, C, S> = Arc<PersonalOAuthRefresh<H, C, S>>;

impl<H, C, S, O> CustodyHandle<Provider<H, C, S>, O>
where
    H: ProviderHttp + 'static,
    C: Clock + 'static,
    S: SecretSource + 'static,
    O: CredentialReleaseObserver + Send + Sync + 'static,
{
    /// The whole callback; every exit is an outcome the router renders.
    pub(super) async fn complete_callback(&self, request: CallbackRequest) -> CallbackOutcome {
        match self.run_callback(request).await {
            Ok(outcome) | Err(outcome) => outcome,
        }
    }

    /// One journey-table operation off the event loop.
    async fn journey_op<T, F>(&self, work: F) -> Step<Result<T, JourneyError>>
    where
        T: Send + 'static,
        F: FnOnce(&PersonalAccountStore) -> Result<T, JourneyError> + Send + 'static,
    {
        self.offload(move |service| Ok(work(service.store())))
            .await
            .map_err(|_| CallbackOutcome::Unavailable)
    }

    /// Steps 1-4: the caps come before any store work, then the state names
    /// the journey whose binding cookie is judged.
    async fn admit_journey(&self, request: &CallbackRequest, now: u64) -> Step<Journey> {
        let over = |value: &String| value.len() > CALLBACK_SECRET_MAX;
        if over(&request.state) || request.bindings.values().any(over) {
            return Err(CallbackOutcome::Invalid);
        }
        let (limits, state) = (request.limits, request.state.clone());
        let id = self
            .journey_op(move |store| store.callback_journey(now, &limits, &state))
            .await?
            .map_err(|error| match error {
                JourneyError::Storage(_) => CallbackOutcome::Unavailable,
                JourneyError::Refused(_) => CallbackOutcome::Invalid,
            })?;
        let binding = request.bindings.get(&id).cloned();
        let state = request.state.clone();
        let admitted = self
            .journey_op(move |store| store.admit_callback(now, &limits, &state, binding.as_deref()))
            .await?
            .map_err(|error| refused(&id, error))?;
        Ok(Journey {
            now,
            limits,
            admitted,
        })
    }

    /// Records a terminal reason and renders it. A journey the store will not
    /// finish any more (swept meanwhile) still gets its reason on the page.
    async fn finish(
        &self,
        journey: &Journey,
        status: JourneyStatus,
        reason: JourneyReason,
    ) -> CallbackOutcome {
        let (now, limits) = (journey.now, journey.limits);
        let id = journey.admitted.journey_id.clone();
        let finished = self
            .journey_op(move |store| store.finish_journey(now, &limits, &id, status, Some(reason)))
            .await;
        match finished {
            Ok(Err(JourneyError::Storage(_))) | Err(_) => CallbackOutcome::Unavailable,
            Ok(_) => journey.page(reason_text(reason)),
        }
    }

    /// Steps 5-6 and 7, in that order; `Ok` carries the consumed verifier
    /// and the live descriptor the exchange result is checked against.
    async fn pre_exchange<'r>(
        &self,
        request: &'r CallbackRequest,
        journey: &Journey,
    ) -> Step<(String, String, &'r AccountDescriptor)> {
        if let Some(error) = &request.error {
            let (status, reason) = provider_error(error);
            return Err(self.finish(journey, status, reason).await);
        }
        let failed = |reason| self.finish(journey, JourneyStatus::Failed, reason);
        let Some(code) = request.code.clone() else {
            return Err(failed(JourneyReason::ProviderError).await);
        };
        let admitted = &journey.admitted;
        if crate::oauth::client::validate_issuer(request.iss.as_deref(), &admitted.issuer).is_err()
        {
            return Err(failed(JourneyReason::IssuerMismatch).await);
        }
        let descriptor = request
            .descriptors
            .get(&admitted.account_id)
            .filter(|live| admitted.created_against(live));
        let Some(descriptor) = descriptor else {
            return Err(failed(JourneyReason::ConfigChanged).await);
        };
        let (now, limits) = (journey.now, journey.limits);
        let (state, binding) = (
            request.state.clone(),
            request.bindings.get(&admitted.journey_id).cloned(),
        );
        let consumed = self
            .journey_op(move |store| {
                store.consume_callback(now, &limits, &state, binding.as_deref())
            })
            .await?
            .map_err(|error| refused(&admitted.journey_id, error))?;
        Ok((code, consumed.verifier, descriptor))
    }

    async fn run_callback(&self, request: CallbackRequest) -> Step<CallbackOutcome> {
        let provider = self.provider().map_err(|_| CallbackOutcome::Unavailable)?;
        let mut journey = self.admit_journey(&request, provider.now_unix()).await?;
        let (code, verifier, descriptor) = self.pre_exchange(&request, &journey).await?;
        let account = journey.admitted.account_id.as_str();
        let exchanged = provider.exchange_code(account, &code, &verifier).await;
        // The exchange can outlast the journey's window: every later store
        // write sweeps at the time it ended, so a lapsed journey is never
        // committed (R2-2).
        journey.now = provider.now_unix();
        let tokens = match exchanged {
            Ok(tokens) => tokens,
            Err(error) => {
                let reason = if matches!(error, ProviderRefreshError::InvalidGrant) {
                    JourneyReason::ProviderError
                } else {
                    JourneyReason::ProviderUnavailable
                };
                return Ok(self.finish(&journey, JourneyStatus::Failed, reason).await);
            }
        };
        let abort =
            |reason, mark| self.abort_after_exchange(&provider, &journey, reason, mark, &tokens);
        if let Some(reason) = invalid_grant(descriptor, &tokens) {
            return Ok(abort(reason, Mark::Record).await);
        }
        let audit = |action| {
            crate::identity_propagation::audit_identity_propagation(
                request.audit.as_ref(),
                action,
                &journey.admitted.owner_subject,
                account,
                None,
                None,
            )
        };
        if audit("account_grant_attempt").await.is_err() {
            return Ok(abort(JourneyReason::AuditUnavailable, Mark::Record).await);
        }
        let Some((key, record)) = grant_of(&journey, descriptor, &tokens) else {
            return Ok(abort(JourneyReason::StorageUnavailable, Mark::Record).await);
        };
        let committed = self.commit(&journey, key, record).await;
        // Best effort after the fact (§6.2 step 10); a failure is already logged.
        let message = match committed {
            Ok(JourneyCommit::Committed) => "connected",
            Ok(JourneyCommit::CommittedStatusUnavailable) => "connected; status unavailable",
            Ok(JourneyCommit::Fenced) => {
                let _ = audit("account_grant_fenced").await;
                return Ok(abort(JourneyReason::SupersededGrant, Mark::AlreadyRecorded).await);
            }
            Ok(JourneyCommit::JourneyGone) => {
                return Ok(abort(JourneyReason::JourneyGone, Mark::AlreadyRecorded).await);
            }
            Err(()) => {
                return Ok(abort(JourneyReason::StorageUnavailable, Mark::AlreadyRecorded).await);
            }
        };
        let _ = audit("account_grant").await;
        Ok(journey.page(message.to_owned()))
    }

    /// Step 11 in one store acquisition. `Err` is any storage answer: the
    /// store has already ended the journey `storage_unavailable`.
    async fn commit(
        &self,
        journey: &Journey,
        key: AccountKey,
        record: GrantRecord,
    ) -> Result<JourneyCommit, ()> {
        let (now, limits) = (journey.now, journey.limits);
        let (expected, id) = (
            journey.admitted.expected.clone(),
            journey.admitted.journey_id.clone(),
        );
        let committed = self
            .journey_op(move |store| {
                store.commit_journey_grant_if(now, &limits, &key, &expected, &record, &id)
            })
            .await;
        match committed {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(_)) | Err(_) => Err(()),
        }
    }

    /// The ONE exit after a successful exchange that commits nothing (H2):
    /// record the reason if the store has not, revoke the fresh tokens at the
    /// provider (the refresh token if present, else the access token), and
    /// report both on the page. The tokens are dropped with the caller.
    async fn abort_after_exchange(
        &self,
        provider: &Provider<H, C, S>,
        journey: &Journey,
        reason: JourneyReason,
        mark: Mark,
        tokens: &TokenRefresh,
    ) -> CallbackOutcome {
        if let Mark::Record = mark {
            // Best effort: the page reports the reason even if the write fails.
            let _ = self.finish(journey, JourneyStatus::Failed, reason).await;
        }
        let account = journey.admitted.account_id.as_str();
        let (token, hint) = tokens.refresh_token.as_ref().map_or(
            (&tokens.access_token, TokenTypeHint::AccessToken),
            |refresh| (refresh, TokenTypeHint::RefreshToken),
        );
        let revocation = provider.revoke_token(account, token, hint).await;
        journey.page(format!(
            "{}; {}",
            reason_text(reason),
            revocation_text(revocation)
        ))
    }
}
