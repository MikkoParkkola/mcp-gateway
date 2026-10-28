// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A managed credential's per-send recheck: the same custody release the
//! dispatch ran, judged as a transport send needs it, a refusal that says the
//! grant is gone apart from one that says nothing about it.

use std::sync::Arc;

use super::{ManagedLease, VaultStrategy};
use crate::personal_accounts::service::AccountServiceError;
use crate::personal_accounts::worker::CustodyError;
use crate::transport::Refusal;

impl ManagedLease {
    /// Whether this lease may still be sent now.
    ///
    /// # Errors
    ///
    /// [`Refusal::Definitive`] when the grant is revoked, removed or no longer
    /// releasable, the token's durable expiry has passed, or `installed` is
    /// not the vault that released the lease. [`Refusal::Transient`] for
    /// every other fault, a busy or stopping custody included.
    pub(crate) async fn recheck_send(&self, installed: &Arc<VaultStrategy>) -> Result<(), Refusal> {
        if !self.minted_by(installed) {
            return Err(Refusal::Definitive);
        }
        let released = self
            .strategy
            .custody
            .release(&self.lease)
            .await
            .map_err(|error| classify(&error))?;
        // A lease that still matches says nothing about a token that has
        // since run out; an unreadable clock says nothing about the grant.
        let now = crate::clock::unix_secs().map_err(|_| Refusal::Transient)?;
        if released.expires_at <= now {
            return Err(Refusal::Definitive);
        }
        Ok(())
    }
}

/// What a custody refusal says about the grant. Only an explicit statement
/// that it is gone or not releasable is definitive; a busy or stopping
/// custody, a provider or store fault, anything unexpected, says nothing.
fn classify(error: &CustodyError) -> Refusal {
    match error {
        CustodyError::Account(
            AccountServiceError::ConnectOffer
            | AccountServiceError::Revoked
            | AccountServiceError::ReconnectRequired
            | AccountServiceError::LeaseRetired,
        ) => Refusal::Definitive,
        _ => Refusal::Transient,
    }
}
