// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gate in front of both writers of a caller's held slot.
//!
//! A fill resolves its credential, fetches, and only then publishes the
//! binding it used; the grant may have rotated or been revoked in between.
//! Both writers (`remember_caller_slot` and `ColdFill::run`) ask this gate
//! first. It judges the binding directly against a fresh mint-free custody
//! read, never through the request memo, whose binding is the one the
//! publishing call itself read.

use std::sync::Arc;

use super::MetaMcp;
use super::discovery_fetch::record_read;
use crate::backend::Backend;
use crate::identity_propagation::CallerProof;
use crate::personal_accounts::identity::OwnedPrincipal;
use crate::personal_accounts::{VaultStrategy, ViewBinding};

/// The gate's answer for one publish.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Publish {
    /// The binding is the grant's current one: index it.
    Allow,
    /// The grant has moved past `binding` (rotated or revoked): leave the
    /// index alone.
    Superseded,
    /// The grant could not be read (busy or unavailable custody): fail
    /// closed, leave the index alone.
    Unread,
}

/// What the gate needs to read a caller's grant, owned so a spawned fill can
/// carry it.
pub(crate) struct GateInputs {
    vault: Arc<VaultStrategy>,
    principal: OwnedPrincipal,
}

impl GateInputs {
    /// Judge `binding`, about to be published on `backend`, against a fresh
    /// classified read. The read is recorded as this request's account read
    /// when a request memo is open. `Bound(other)` and a revoked grant also
    /// forget an entry that already holds `binding`; a failed read only
    /// refuses.
    pub(crate) async fn judge(&self, backend: &Backend, binding: &str) -> Publish {
        let principal = self.principal.as_principal();
        let read = self.vault.view_binding_classified(principal).await;
        record_read(backend, &read);
        match read {
            ViewBinding::Bound(current) if current == binding => Publish::Allow,
            ViewBinding::Bound(_) | ViewBinding::NoView(_) => {
                let id = principal.stable_actor_id();
                if let Some(held) = backend.caller_slot_held(&id)
                    && held.binding() == binding
                {
                    backend.forget_caller_held(&id, &held);
                }
                Publish::Superseded
            }
            _ => Publish::Unread,
        }
    }
}

impl MetaMcp {
    /// The gate's inputs for `caller` on `backend`: `None` when the backend
    /// has no managed account or the caller no principal there, which have no
    /// grant to rotate and publish as before.
    pub(crate) fn gate_inputs(
        &self,
        backend: &Backend,
        caller: CallerProof<'_>,
    ) -> Option<GateInputs> {
        let principal = self.principal_for(backend, caller)?;
        let vault = self
            .account_strategies
            .managed_vault(backend.account_descriptor_id())?;
        Some(GateInputs {
            vault,
            principal: OwnedPrincipal::of(principal),
        })
    }
}
