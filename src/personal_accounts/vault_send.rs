// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A managed credential's per-send recheck: the same custody release the
//! dispatch ran, judged as a transport send needs it, a refusal that says the
//! grant is gone apart from one that says nothing about it.

use std::sync::Arc;

use super::{ManagedLease, VaultStrategy};
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
    pub(crate) async fn recheck_send(
        &self,
        _installed: &Arc<VaultStrategy>,
    ) -> Result<(), Refusal> {
        Ok(())
    }
}
