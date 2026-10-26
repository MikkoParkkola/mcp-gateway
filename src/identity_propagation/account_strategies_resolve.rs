// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The registry's credential resolution and its recheck after an upstream
//! refusal, kept beside the registry to hold its file under the size
//! ceiling. A pure move: bodies and visibility are unchanged.

use std::sync::Arc;

use super::{
    AccountCredential, AccountStrategyRegistry, BackendDescriptor, CallerProof, DescriptorMode,
    Minter, PreparedAccountCredential, audit_subject, mark,
};
use crate::{Error, Result};

impl AccountStrategyRegistry {
    /// Resolve one `auth.account` reference into a credential, or refuse.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an unresolved reference, a provider mismatch, a
    /// missing installation, a missing verified identity, a strategy refusal or
    /// an unusable minted header; [`Error::Internal`] when a required account
    /// would mint without a durable audit record. Every one of these is a
    /// refusal, never a fallback.
    pub(crate) async fn resolve(
        &self,
        descriptor_id: &str,
        auth_key: &str,
        caller: CallerProof<'_>,
    ) -> Result<AccountCredential> {
        let Some(installed) = self.declared_installed(descriptor_id, auth_key)? else {
            return Ok(AccountCredential::Legacy);
        };

        let logger = self.audit.read().clone();
        let audience = installed.audience.as_str();

        // WHO THIS CALL IS MADE AS. A verified identity where one exists; the
        // deployment's own sole-operator assertion where a managed descriptor's
        // strategy was installed under it. An external descriptor is unchanged:
        // it has no assertion to consult and still needs a verified caller.
        let Some(principal) = Self::principal(installed.as_ref(), caller) else {
            Self::audit_refusal(
                logger.as_ref(),
                &audit_subject(caller.verified()),
                descriptor_id,
                audience,
                "the request carries no verified end-user identity",
            )
            .await;
            return Err(Error::Config(format!(
                "capability auth references account '{descriptor_id}' but the request carries no \
                 verified end-user identity. Refusing rather than falling back to the \
                 gateway-held credential for '{auth_key}'."
            )));
        };
        // The principal that will actually be minted under, so a sole-operator
        // release is audited as the sole operator rather than as "unauthenticated".
        let subject_id = principal.stable_actor_id();

        let backend = BackendDescriptor {
            // The descriptor id is the logical backend id of the account key,
            // which is what the strategy's own audience check compares against.
            id: descriptor_id.to_string(),
            audience: installed.audience.clone(),
            token_exchange_endpoint: installed.token_exchange_endpoint.clone(),
            token_exchange_scope: installed.token_exchange_scope.clone(),
        };

        let minted = Self::mint(installed.as_ref(), principal, &backend).await;
        let (credential, managed) = match minted {
            Ok(minted) => minted,
            // A busy custody at the mint: see `transient_mint_refusal`.
            Err(crate::personal_accounts::MintError::Busy(error)) => {
                return Err(self
                    .transient_mint_refusal(logger.as_ref(), descriptor_id, caller, &error)
                    .await);
            }
            Err(crate::personal_accounts::MintError::Other(error)) => {
                let reason = error.to_string();
                Self::audit_refusal(
                    logger.as_ref(),
                    &subject_id,
                    descriptor_id,
                    audience,
                    &reason,
                )
                .await;
                let refused = Error::Config(format!(
                    "account '{descriptor_id}' produced no credential for this caller: {reason}"
                ));
                return Err(mark(refused, &error, Some(descriptor_id)));
            }
        };

        // AN EXTERNAL CREDENTIAL IS CHECKED AGAINST ITS OWN PUBLISHED EXPIRY
        // HERE, at the INITIAL resolve — before the outer response cache is
        // keyed, before the inner capability cache is consulted and before any
        // egress. The revalidate below re-asks the same question, but only a
        // credential that got past THIS point can reach it, and the outer cache
        // key is built from the binding this function returns.
        //
        // A managed credential is exempt: `expires_at <= minted_at` is the
        // vault's per-dispatch signal, not staleness, and its real freshness is
        // decided by the lease recheck. Nothing here invents a lifetime for
        // either kind — an external strategy that publishes no usable expiry
        // publishes no usable credential.
        // A clock before 1970 can judge no expiry and stamp no mint time, so
        // the credential is refused, managed or not.
        let minted_at = match crate::clock::utc_now() {
            Err(_) => Err("the gateway clock reads before 1970, so no expiry can be judged"),
            Ok(now) if managed.is_none() && credential.expires_at <= now.timestamp() => {
                Err("the external strategy published an expiry that has already passed")
            }
            Ok(now) => Ok(now.timestamp()),
        };
        let minted_at = match minted_at {
            Ok(minted_at) => minted_at,
            Err(reason) => {
                Self::audit_refusal(
                    logger.as_ref(),
                    &subject_id,
                    descriptor_id,
                    audience,
                    reason,
                )
                .await;
                return Err(Error::Config(format!(
                    "account '{descriptor_id}' minted a credential that is already expired: {reason}. \
                     Refusing rather than caching or dispatching with it."
                )));
            }
        };

        Self::validate_and_audit_mint(
            logger.as_ref(),
            &subject_id,
            descriptor_id,
            audience,
            installed.required,
            &credential,
        )
        .await?;

        Ok(AccountCredential::Prepared(Arc::new(
            PreparedAccountCredential {
                descriptor_id: descriptor_id.to_string(),
                auth_key: auth_key.to_string(),
                actor_id: subject_id,
                audience: installed.audience.clone(),
                // The strategy's own values, copied. Never re-derived, never
                // widened and never rounded.
                cache_binding: credential.cache_binding,
                expires_at: credential.expires_at,
                minted_at,
                strategy: installed.minter.strategy(),
                managed,
                headers: credential.headers,
            },
        )))
    }

    /// Recheck a credential resolved earlier in THIS dispatch, before it is
    /// allowed to select a cache entry or go on the wire.
    ///
    /// This is a validation, not a second mint: it re-answers, against the
    /// registry as it stands NOW, every question [`Self::resolve`] answered —
    /// the descriptor is still declared, still non-`shared`, still owned by the
    /// same provider, still installed, still installed with the SAME strategy
    /// instance and the same audience — and adds the two the carrying step
    /// makes possible: the credential belongs to the identity this call is
    /// being made as, and a published lifetime has not run out.
    ///
    /// AND, FOR A MANAGED ACCOUNT, IT ASKS DURABLE CUSTODY. The registry checks
    /// above are configuration checks: none of them can see a grant that was
    /// revoked, re-authorized or rotated after the credential was prepared,
    /// because the registry is not where that state lives. So a managed
    /// credential's lease is re-released through the SAME custody that released
    /// it (`VaultStrategy::recheck`), under the store's authority lock, and a
    /// retired lease — revoked, reconnect-required, superseded generation,
    /// authorization or token revision — refuses HERE, before an inner cache
    /// entry may be selected and before any egress. Nothing is refreshed and
    /// nothing is re-minted: acquiring a new lease to answer "still valid"
    /// would be pretending a retired credential is the current one. External
    /// descriptors keep exactly the published-expiry behaviour they had; there
    /// is no global fallback path here for either kind.
    ///
    /// A reload that dropped, re-pointed or re-installed the descriptor between
    /// the resolve and this point therefore refuses here rather than letting a
    /// credential minted under the previous configuration reach a cache lookup
    /// or an upstream.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for every mismatch and for a custody refusal. None of
    /// them falls back to the gateway-held credential, and none of them degrades
    /// into a cache miss.
    pub(crate) async fn revalidate(
        &self,
        prepared: &PreparedAccountCredential,
        caller: CallerProof<'_>,
    ) -> Result<()> {
        let descriptor_id = prepared.descriptor_id.as_str();
        let refuse = |reason: &str| {
            Err(Error::Config(format!(
                "account '{descriptor_id}' no longer validates for this dispatch: {reason}. \
                 Refusing rather than serving a cached result or dispatching with a credential \
                 nothing rechecked."
            )))
        };

        let Some(declared) = self.declared(descriptor_id) else {
            return refuse("the descriptor is no longer declared");
        };
        if declared.mode == DescriptorMode::Shared {
            return refuse(
                "the descriptor is now declared shared, so a per-caller credential \
                           minted for it is no longer the configured behaviour",
            );
        }
        if prepared.auth_key != Self::expected_auth_key(&declared.provider) {
            return refuse("the descriptor's provider no longer matches the capability auth key");
        }
        let Some(installed) = self.installed(descriptor_id) else {
            return refuse("no account strategy is installed for it any more");
        };
        if installed.audience != prepared.audience {
            return refuse("the installed audience changed after the credential was minted");
        }
        // One match decides that the installed minter is still the one that
        // minted: same kind, same instance. A replaced strategy of either kind,
        // or a descriptor re-installed as the other kind, refuses here.
        let custody = match (&installed.minter, prepared.managed.as_ref()) {
            (Minter::External(current), None) if Arc::ptr_eq(current, &prepared.strategy) => None,
            (Minter::Managed(current), Some(lease)) if lease.minted_by(current) => {
                Some((lease, current))
            }
            _ => {
                return refuse(
                    "the installed strategy was replaced after the credential was minted",
                );
            }
        };
        // The SAME question `resolve` asked, asked the same way: the registry
        // as it stands NOW decides who this call is made as. A descriptor whose
        // managed install was replaced by one with a different sole-operator
        // setting therefore fails the actor comparison below rather than being
        // rechecked as though nothing changed.
        let Some(principal) = Self::principal(installed.as_ref(), caller) else {
            return refuse("the request carries no verified end-user identity");
        };
        if principal.stable_actor_id() != prepared.actor_id {
            return refuse("it was minted for a different caller");
        }
        // An unreadable clock reads as a lifetime that has run out.
        let lifetime = crate::clock::expired_by_utc(|now| {
            if prepared.published_lifetime_open(now.timestamp()) {
                crate::clock::Validity::Live
            } else {
                crate::clock::Validity::Expired
            }
        });
        if lifetime == crate::clock::Validity::Expired {
            return refuse("its published lifetime has run out");
        }
        // THE DURABLE HALF. Last, because the checks above are cheap and this
        // one takes the store's authority lock; first in importance, because it
        // is the only one that can see a revocation committed since the mint.
        // The custody refusal text names the account state (revoked, reconnect
        // required, retired lease), never a token.
        if let Some((lease, current)) = custody
            && let Err(error) = lease.recheck(current).await
        {
            // Nothing is sent before it: a busy custody frees the key.
            let crate::personal_accounts::MintError::Busy(error) = error else {
                let error = error.into_error();
                return refuse(&format!("durable custody refused its lease: {error}"));
            };
            let logger = self.audit.read().clone();
            let busy = self.transient_mint_refusal(logger.as_ref(), descriptor_id, caller, &error);
            return Err(busy.await);
        }
        Ok(())
    }
}
