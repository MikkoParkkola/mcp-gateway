// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A revocation half whose store refuses every tombstone, counting any
//! provider call that gets past the refusal.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::revoke::{ProviderOutcome, RevocationMaterial};
use super::super::service::AccountServiceError;
use super::super::worker::CustodyError;
use super::super::{AccountError, AccountKey, AccountRevocation};

#[derive(Default)]
pub(crate) struct StoreDown {
    provider_calls: AtomicUsize,
}

impl StoreDown {
    pub(crate) fn provider_calls(&self) -> usize {
        self.provider_calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AccountRevocation for StoreDown {
    async fn invalidate(
        &self,
        _account: &AccountKey,
    ) -> Result<Option<RevocationMaterial>, CustodyError> {
        Err(CustodyError::Account(AccountServiceError::Store(
            AccountError::StorageUnavailable,
        )))
    }

    async fn revoke_at_provider(
        &self,
        _account_id: &str,
        _material: Option<RevocationMaterial>,
    ) -> ProviderOutcome {
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        ProviderOutcome::Confirmed
    }

    async fn connected(&self, _account: &AccountKey) -> Result<bool, CustodyError> {
        Ok(false)
    }
}
