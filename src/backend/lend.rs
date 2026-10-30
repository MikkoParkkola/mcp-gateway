// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A dispatch's loan on its per-user slot: what a lent-only slot sends as.

use super::Backend;
use crate::{Error, Result};

impl Backend {
    /// The loan a dispatch holds on its per-user slot for its whole run, the
    /// slot's start included (ADR-007 IDP.7): a lent-only slot
    /// sends only this dispatch's credential. `None` for a Shared slot and
    /// for a slot that keeps its configured headers. A required binding's
    /// dispatch that carries no credential is refused before anything is
    /// built or sent: there is no subscriber to send as.
    pub(super) fn lend_to_slot(
        &self,
        key: &super::pool::PoolKey,
        entry: &super::pool::PooledEntry,
        credential: &crate::transport::LentCredential,
    ) -> Result<Option<crate::transport::Loan>> {
        if !matches!(key, super::pool::PoolKey::PerUser { .. })
            || self.per_user_slot_credential() != crate::transport::SlotCredential::LentOnly
        {
            return Ok(None);
        }
        if credential.headers.is_empty() {
            return Err(Error::Forbidden {
                code: -32001,
                status: 403,
                message: format!(
                    "backend '{}' is reached only with each user's own credential, and this call carried none",
                    self.name
                ),
            });
        }
        Ok(Some(entry.lender.lend(credential.clone())))
    }
}
