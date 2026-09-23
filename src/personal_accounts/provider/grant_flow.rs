// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The provider half of the hosted consent journey: the authorize URL, the
//! authorization-code exchange and RFC 7009 revocation.
//!
//! Every endpoint used here is one bootstrap PINNED; nothing is discovered and
//! nothing is taken from a request. Credentials still leave only through
//! `ProviderHttp::post_token`.
#![cfg_attr(
    all(not(test), not(kani)),
    expect(
        dead_code,
        reason = "hosted consent journey provider half; the callback and DELETE routes that call it land in MIK-6745 slices 4 and 5"
    )
)]

use serde::{Deserialize, Serialize};
use url::Url;

use super::{Clock, PersonalOAuthRefresh, ProviderHttp, SecretSource};
use crate::personal_accounts::service::{ProviderRefreshError, TokenRefresh};

/// Extra authorize-request parameters, as a CLOSED vocabulary.
///
/// A free-form map could name `state`, `redirect_uri` or
/// `code_challenge_method` and silently override the parameters this module
/// exists to pin, so every key and every value is a type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorizeExtra {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_type: Option<AccessType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prompt: Option<Prompt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) include_granted_scopes: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AccessType {
    Offline,
    Online,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Prompt {
    Consent,
    SelectAccount,
    None,
}

/// RFC 7009 §2.1 `token_type_hint`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TokenTypeHint {
    RefreshToken,
    AccessToken,
}

/// What the provider said about a revocation. "Nothing to revoke" is not a
/// provider answer, so it is the caller's to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderRevocation {
    Confirmed,
    Failed,
    Unsupported,
}

/// STUB: red commit only.
pub(crate) fn new_state() -> String {
    String::new()
}

/// STUB: red commit only.
pub(crate) fn new_code_verifier() -> String {
    String::new()
}

/// STUB: red commit only.
pub(crate) fn code_challenge_s256(verifier: &str) -> String {
    verifier.to_string()
}

impl<H: ProviderHttp, C: Clock, S: SecretSource> PersonalOAuthRefresh<H, C, S> {
    /// STUB: red commit only.
    pub(crate) fn authorize_url(
        &self,
        _account_id: &str,
        _extra: AuthorizeExtra,
        _state: &str,
        _code_challenge: &str,
    ) -> Result<Url, ProviderRefreshError> {
        Err(ProviderRefreshError::Unavailable)
    }

    /// STUB: red commit only.
    pub(crate) async fn exchange_code(
        &self,
        _account_id: &str,
        _code: &str,
        _code_verifier: &str,
    ) -> Result<TokenRefresh, ProviderRefreshError> {
        Err(ProviderRefreshError::Unavailable)
    }

    /// STUB: red commit only.
    pub(crate) async fn revoke_token(
        &self,
        _account_id: &str,
        _token: &str,
        _hint: TokenTypeHint,
    ) -> ProviderRevocation {
        ProviderRevocation::Failed
    }
}
