// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user listener's credential:
//! every request it sends carries its subscriber's own credential, minted
//! fresh through the gateway's audited path, or lent from their passthrough
//! lease. Never the gateway's.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

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
    /// Fresh headers for a listener of `backend` observing as `identity`,
    /// with the fence binding of the grant they were released under.
    ///
    /// # Errors
    /// The strategy refuses, auditing is unavailable, or nothing was minted:
    /// the listener sends nothing (fail closed).
    async fn mint(
        &self,
        backend: &str,
        identity: &VerifiedIdentity,
    ) -> crate::Result<ListenerGrant>;

    /// The grant binding a listener of `backend` observing as `identity` is
    /// fenced on, read without minting; `None` for a backend no vault
    /// grant backs.
    ///
    /// # Errors
    /// The binding cannot be read now ([`FenceRead::Busy`]) or the grant
    /// gives no view ([`FenceRead::Closed`]).
    async fn fence_binding(
        &self,
        backend: &str,
        identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead>;
}

/// One listener mint: the headers to send with, and the fence binding of
/// the grant they were released under (`None` when no vault grant backs
/// them, so nothing rotates under them).
pub(crate) struct ListenerGrant {
    pub headers: Vec<(String, String)>,
    pub fence: Option<String>,
}

/// Why a fence binding could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FenceRead {
    /// Custody is busy or the read timed out: retry, never send.
    Busy,
    /// No view of the grant: fail closed.
    Closed,
}

/// The longest a fence read may take; longer is read as busy.
pub(crate) const FENCE_READ: Duration = Duration::from_secs(5);

/// A per-user listener run's fence: the binding of the grant its first mint
/// released, fixed for the run, so every occurrence the run emits carries
/// one binding. A later mint, or the run's own periodic read, that finds
/// another binding or no view of the grant ends the run; that mint's request
/// is never sent.
pub(super) struct RunFence {
    mint: Arc<dyn ListenerMint>,
    backend: String,
    identity: VerifiedIdentity,
    binding: OnceLock<Option<String>>,
    ended: AtomicBool,
}

impl RunFence {
    /// Whether a mint releasing `minted` may send in this run; the first
    /// mint fixes the run's binding.
    fn admits(&self, minted: Option<&str>) -> bool {
        let fixed = self.binding.get_or_init(|| minted.map(str::to_owned));
        if fixed.as_deref() != minted {
            self.ended.store(true, Ordering::SeqCst);
        }
        !self.ended()
    }

    /// The run's binding, stamped on every occurrence it emits: `None`
    /// before its first mint, or for a grant no vault backs.
    pub(super) fn binding(&self) -> Option<String> {
        self.binding.get().cloned().flatten()
    }

    /// The run's first mint has fixed its binding.
    pub(super) fn is_fixed(&self) -> bool {
        self.binding.get().is_some()
    }

    /// The grant this run was fixed on has moved or gives no view.
    pub(super) fn ended(&self) -> bool {
        self.ended.load(Ordering::SeqCst)
    }

    /// A quiet run's own read: ends it when the grant moved or gives no
    /// view. A busy or slow custody keeps it, since every occurrence is
    /// checked again at delivery.
    pub(super) async fn recheck(&self) {
        let Some(fixed) = self.binding.get() else {
            return;
        };
        let read = self.mint.fence_binding(&self.backend, &self.identity);
        match tokio::time::timeout(FENCE_READ, read).await {
            Ok(Ok(now)) if now == *fixed => {}
            Ok(Err(FenceRead::Busy)) | Err(_) => {}
            Ok(Ok(_) | Err(FenceRead::Closed)) => self.ended.store(true, Ordering::SeqCst),
        }
    }
}

/// `signed_assertion`, `token_exchange` and vault: a fresh, audited mint for
/// every request, so a rotation or a revocation takes effect at the next one.
pub(super) struct Minted {
    pub run: Arc<RunFence>,
    /// The listener's observation: its session bucket.
    pub obs: String,
}

impl CredentialSource for Minted {
    fn with_credential<'a>(
        &'a self,
        send: CredentialedSend<'a>,
    ) -> BoxFuture<'a, crate::Result<reqwest::Response>> {
        Box::pin(async move {
            let run = &self.run;
            let grant = match run.mint.mint(&run.backend, &run.identity).await {
                Ok(grant) => grant,
                // A refusal may be a revoked grant: the fence says, and no
                // view ends the run now rather than at its next read.
                Err(refused) => {
                    run.recheck().await;
                    return Err(refused);
                }
            };
            // The mint's contract: nothing minted is a refusal. Held here too,
            // because a per-user slot of a required binding takes this send's
            // credential as the subscriber's own and adds none of its own.
            if grant.headers.is_empty() {
                return Err(crate::Error::Transport(
                    "the listener's mint lent no credential".to_owned(),
                ));
            }
            if !run.admits(grant.fence.as_deref()) {
                return Err(crate::Error::Transport(
                    "the listener's grant moved; its run ends".to_owned(),
                ));
            }
            send(grant.headers).await
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

/// What one listener run sends with, and what it stamps its occurrences
/// with: a minted run's fence, or a leased run's generation.
pub(super) struct RunCredential {
    pub credential: ListenerCredential,
    pub fence: Option<Arc<RunFence>>,
    /// The lease generation a leased run sends under, read once at its
    /// start: the run stamps what it reads with it, and ends when the lease
    /// moves.
    pub lease: Option<u128>,
}

/// What a listener of `key` sends with: the shared credential for a shared
/// key; for a per-user key its subscriber's own, leased (passthrough) or
/// minted (every other strategy). `None` when a per-user key has none to
/// be had now (no lease, no stored identity, no mint wired): it then does
/// not run, and never falls back to the gateway's credential. A minted
/// credential comes with its run's fence, a leased one with its generation.
pub(super) fn for_key(key: &ListenerKey, hub: &Weak<EventsHub>) -> Option<RunCredential> {
    let Some(obs) = &key.obs else {
        return Some(RunCredential {
            credential: ListenerCredential::shared(),
            fence: None,
            lease: None,
        });
    };
    let mut fence = None;
    let mut leased = None;
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
            leased = Some(generation);
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
            let run = Arc::new(RunFence {
                mint: Arc::clone(live.runtime.listener_mint.get()?),
                backend: key.backend.clone(),
                identity,
                binding: OnceLock::new(),
                ended: AtomicBool::new(false),
            });
            fence = Some(Arc::clone(&run));
            Arc::new(Minted {
                run,
                obs: obs.clone(),
            })
        };
    let credential = ListenerCredential {
        identity_key: Some(obs.clone()),
        source: Some(source),
    };
    Some(RunCredential {
        credential,
        fence,
        lease: leased,
    })
}

#[cfg(test)]
#[path = "listener_credential_tests.rs"]
mod tests;
