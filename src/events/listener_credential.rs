// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user listener's credential:
//! every request it sends carries its subscriber's own credential, minted
//! fresh through the gateway's audited path, or lent from their passthrough
//! lease. Never the gateway's.

use std::sync::{Arc, Weak};

use futures::future::BoxFuture;

use super::EventsHub;
use super::lease::LeaseKey;
use super::upstream_listener::ListenerKey;
use crate::identity_propagation::PropagationStrategyKind;
use crate::key_server::oidc::VerifiedIdentity;
use crate::transport::upstream_tap::{CredentialSource, CredentialedSend, ListenerCredential};

/// Mints a listener's credential through the same audited path a call uses
/// (B2); implemented by the gateway at events wiring.
#[async_trait::async_trait]
pub(crate) trait ListenerMint: Send + Sync {
    /// Fresh headers for a listener of `backend` observing as `identity`.
    ///
    /// # Errors
    /// The strategy refuses, auditing is unavailable, or nothing was minted:
    /// the listener sends nothing (fail closed).
    async fn mint(
        &self,
        backend: &str,
        identity: &VerifiedIdentity,
    ) -> crate::Result<Vec<(String, String)>>;

    /// The grant binding a listener of `backend` observing as `identity` is
    /// fenced on, read without minting; `None` for a backend no vault
    /// grant backs.
    ///
    /// # Errors
    /// The binding cannot be read now ([`FenceRead::Busy`]) or the grant
    /// gives no view ([`FenceRead::Closed`]).
    async fn fence_binding(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        Ok(None)
    }
}

/// Why a fence binding could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FenceRead {
    /// Custody is busy or the read timed out: retry, never send.
    Busy,
    /// No view of the grant: fail closed.
    Closed,
}

/// `signed_assertion`, `token_exchange` and vault: a fresh, audited mint for
/// every request, so a rotation or a revocation takes effect at the next one.
pub(super) struct Minted {
    pub mint: Arc<dyn ListenerMint>,
    pub backend: String,
    pub identity: VerifiedIdentity,
    /// The listener's observation: its session bucket.
    pub obs: String,
}

impl CredentialSource for Minted {
    fn with_credential<'a>(
        &'a self,
        send: CredentialedSend<'a>,
    ) -> BoxFuture<'a, crate::Result<reqwest::Response>> {
        Box::pin(async move {
            let headers = self.mint.mint(&self.backend, &self.identity).await?;
            send(headers).await
        })
    }

    fn identity_key(&self) -> Option<&str> {
        Some(&self.obs)
    }
}

/// `passthrough`: the subscriber's own token, lent from their lease for one
/// send under its generation (C4). A 401 wipes the lease at once (C5).
pub(super) struct Leased {
    pub hub: Weak<EventsHub>,
    pub key: LeaseKey,
    pub generation: u128,
}

impl CredentialSource for Leased {
    fn with_credential<'a>(
        &'a self,
        send: CredentialedSend<'a>,
    ) -> BoxFuture<'a, crate::Result<reqwest::Response>> {
        Box::pin(async move {
            let hub = self
                .hub
                .upgrade()
                .ok_or_else(|| crate::Error::Transport("events hub stopped".to_owned()))?;
            let response = hub
                .leases
                .with_credential(&self.key, self.generation, send)
                .await?;
            // At the response boundary, before any recovery or fallback: the
            // backend refused the token itself. A 403 refuses one read only.
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                hub.leases.on_rejection(&self.key, self.generation).await;
            }
            Ok(response)
        })
    }

    fn identity_key(&self) -> Option<&str> {
        Some(&self.key.obs)
    }
}

/// What a listener of `key` sends with: the shared credential for a shared
/// key; for a per-user key its subscriber's own, leased (passthrough) or
/// minted (every other strategy). `None` when a per-user key has none to
/// be had now (no lease, no stored identity, no mint wired): it then does
/// not run, and never falls back to the gateway's credential.
pub(super) fn for_key(key: &ListenerKey, hub: &Weak<EventsHub>) -> Option<ListenerCredential> {
    let Some(obs) = &key.obs else {
        return Some(ListenerCredential::shared());
    };
    let live = hub.upgrade()?;
    let config = live.runtime.services.get()?.live.get();
    let binding = super::observation::binding(&config, &key.backend)?;
    let source: Arc<dyn CredentialSource> =
        if binding.basis.strategy == PropagationStrategyKind::Passthrough {
            let lease = LeaseKey {
                backend: key.backend.clone(),
                obs: obs.clone(),
            };
            let generation = live.leases.held_generation(&lease)?;
            Arc::new(Leased {
                hub: hub.clone(),
                key: lease,
                generation,
            })
        } else {
            let identity = live
                .store
                .subscriptions()
                .into_iter()
                .find(|s| live.listens_as(s, key))?
                .observed_as()?;
            Arc::new(Minted {
                mint: Arc::clone(live.runtime.listener_mint.get()?),
                backend: key.backend.clone(),
                identity,
                obs: obs.clone(),
            })
        };
    Some(ListenerCredential {
        identity_key: Some(obs.clone()),
        source: Some(source),
    })
}
