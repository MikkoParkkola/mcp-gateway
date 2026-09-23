// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Revoke with token capture (MIK-6745 design §8.1).
//!
//! `commit::revoke` deletes the record once the tombstone is durable, so the
//! provider tokens must be read out under the SAME authority acquisition that
//! publishes the tombstone. Read before and revoke after would be two
//! acquisitions, and a grant committed between them would be revoked locally
//! while its predecessor's tokens were sent to the provider.

use std::sync::Arc;

use super::provider::{Clock, PersonalOAuthRefresh, ProviderHttp, SecretSource};
use super::provider::{ProviderRevocation, TokenTypeHint};
use super::service::CredentialReleaseObserver;
use super::worker::{CustodyError, CustodyHandle};
use super::{AccountError, AccountKey, GrantRecord, PersonalAccountStore};

/// A token copied out of a retained record. The bytes are overwritten on drop.
struct WipedToken(Vec<u8>);

impl WipedToken {
    fn new(token: String) -> Self {
        Self(token.into_bytes())
    }

    fn as_str(&self) -> &str {
        // Built only from a `String`, so the bytes are UTF-8 by construction.
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl Drop for WipedToken {
    fn drop(&mut self) {
        // No `zeroize` crate in the tree; `black_box` keeps the stores from
        // being elided as writes to memory about to be freed.
        self.0.iter_mut().for_each(|byte| *byte = 0);
        std::hint::black_box(&self.0);
    }
}

/// Every provider token a revoked grant still held, refresh first.
pub(crate) struct RevocationMaterial {
    tokens: Vec<(WipedToken, TokenTypeHint)>,
}

impl std::fmt::Debug for RevocationMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationMaterial")
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

impl RevocationMaterial {
    /// Moves the tokens out; the record's own copies are left empty.
    fn take_from(mut record: GrantRecord) -> Option<Self> {
        let mut tokens = Vec::with_capacity(2);
        if let Some(refresh) = record.refresh_token.take().filter(|t| !t.is_empty()) {
            tokens.push((WipedToken::new(refresh), TokenTypeHint::RefreshToken));
        }
        let access = std::mem::take(&mut record.access_token);
        if !access.is_empty() {
            tokens.push((WipedToken::new(access), TokenTypeHint::AccessToken));
        }
        (!tokens.is_empty()).then_some(Self { tokens })
    }

    /// Tokens and hints in send order, for assertions only.
    #[cfg(test)]
    pub(crate) fn tokens_for_test(&self) -> Vec<(String, TokenTypeHint)> {
        self.tokens
            .iter()
            .map(|(token, hint)| (token.as_str().to_string(), *hint))
            .collect()
    }
}

/// The `provider_revocation` field of the DELETE response (design §8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderOutcome {
    Confirmed,
    Failed,
    Unsupported,
    NotApplicable,
}

impl ProviderOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
            Self::NotApplicable => "not_applicable",
        }
    }
}

impl PersonalAccountStore {
    /// Tombstone the account and return the provider tokens it still held.
    ///
    /// ONE authority acquisition covers the read and the tombstone. `Revoked`
    /// and `Absent` yield `None` and stay idempotent no-ops.
    pub(crate) fn revoke_capturing(
        &self,
        account: &AccountKey,
    ) -> Result<Option<RevocationMaterial>, AccountError> {
        let mut authority = self.lock_authority();
        #[cfg(test)]
        super::store_probe::entered(super::store_probe::StoreOp::Revoke, &self.config.store_dir);
        super::storage::commit::revoke(&self.config, &mut authority, account)?;
        Ok(None)
    }
}

/// The revoke half of custody, object-safe so the router holds it without
/// naming the provider transport.
#[async_trait::async_trait]
pub(crate) trait AccountRevocation: Send + Sync {
    /// Durable tombstone; the material is whatever the grant still held.
    async fn invalidate(
        &self,
        account: &AccountKey,
    ) -> Result<Option<RevocationMaterial>, CustodyError>;

    /// One RFC 7009 request per token, refresh first. `Confirmed` only if
    /// every request was answered 200.
    async fn revoke_at_provider(
        &self,
        account_id: &str,
        material: Option<RevocationMaterial>,
    ) -> ProviderOutcome;
}

#[async_trait::async_trait]
impl<H, C, S, O> AccountRevocation for CustodyHandle<Arc<PersonalOAuthRefresh<H, C, S>>, O>
where
    H: ProviderHttp + 'static,
    C: Clock + 'static,
    S: SecretSource + 'static,
    O: CredentialReleaseObserver + 'static,
{
    async fn invalidate(
        &self,
        account: &AccountKey,
    ) -> Result<Option<RevocationMaterial>, CustodyError> {
        CustodyHandle::invalidate(self, account).await
    }

    async fn revoke_at_provider(
        &self,
        _account_id: &str,
        _material: Option<RevocationMaterial>,
    ) -> ProviderOutcome {
        ProviderOutcome::NotApplicable
    }
}
