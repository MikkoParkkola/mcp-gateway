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

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};
use url::Url;

use super::{Clock, PersonalOAuthRefresh, ProviderHttp, SecretSource, required};
use crate::oauth::AuthorizationServerMetadata;
use crate::personal_accounts::config::{
    AccessType, AccountDescriptor, AuthorizeExtra, DescriptorMode, Prompt,
};
use crate::personal_accounts::service::{ProviderRefreshError, TokenRefresh};

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

impl TokenTypeHint {
    fn as_str(self) -> &'static str {
        match self {
            Self::RefreshToken => "refresh_token",
            Self::AccessToken => "access_token",
        }
    }
}

/// A fresh OAuth `state`: 256 bits, unpadded base64url (43 characters).
pub(crate) fn new_state() -> String {
    random_256()
}

/// A fresh PKCE `code_verifier`: 256 bits, unpadded base64url (43 characters,
/// inside RFC 7636's 43..=128 range).
pub(crate) fn new_code_verifier() -> String {
    random_256()
}

/// RFC 7636 §4.2 `S256`: `BASE64URL(SHA256(ASCII(code_verifier)))`.
pub(crate) fn code_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_256() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

impl<H: ProviderHttp, C: Clock, S: SecretSource> PersonalOAuthRefresh<H, C, S> {
    /// The browser-facing authorize URL for one managed account.
    ///
    /// Built on the PINNED authorization endpoint. Reads no secret and sends
    /// nothing: the URL is handed to a browser, which is no place for a
    /// client secret.
    pub(crate) fn authorize_url(
        &self,
        account_id: &str,
        state: &str,
        code_challenge: &str,
    ) -> Result<Url, ProviderRefreshError> {
        let (descriptor, pinned) = self.managed(account_id)?;
        let resource = resource_parameter(descriptor)?;
        let client_id = required(descriptor.client_id.as_deref())?;
        let redirect_uri = required(descriptor.redirect_uri.as_deref())?;
        let extra = authorize_extra(descriptor);
        let scopes = descriptor
            .scopes
            .as_deref()
            .filter(|scopes| !scopes.is_empty())
            .ok_or(ProviderRefreshError::Unavailable)?
            .join(" ");
        let mut url = Url::parse(pinned.authorization_endpoint.as_str())
            .map_err(|_| ProviderRefreshError::Unavailable)?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &scopes)
                .append_pair("state", state)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(resource) = resource {
                query.append_pair("resource", resource);
            }
            for (key, value) in extra {
                query.append_pair(key, value);
            }
        }
        Ok(url)
    }

    /// Redeem an authorization code at the PINNED token endpoint (RFC 6749
    /// §4.1.3 plus the PKCE verifier).
    ///
    /// `redirect_uri` is the descriptor's, never a caller's: it must be the
    /// value the authorize URL carried, and that URL was built from the same
    /// descriptor. The response maps exactly as a refresh response does.
    pub(crate) async fn exchange_code(
        &self,
        account_id: &str,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenRefresh, ProviderRefreshError> {
        let (descriptor, pinned) = self.managed(account_id)?;
        let resource = resource_parameter(descriptor)?;
        let redirect_uri = required(descriptor.redirect_uri.as_deref())?;
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        form.extend(self.client_authentication(descriptor)?);
        if let Some(resource) = resource {
            form.push(("resource".to_string(), resource.to_string()));
        }
        let response = self
            .http
            .post_token(pinned.token_endpoint.as_str(), &form)
            .await
            .map_err(|_| ProviderRefreshError::Unavailable)?;
        self.map_token_response(&response)
    }

    /// RFC 7009 revocation at the PINNED revocation endpoint.
    ///
    /// Only an endpoint the operator CONFIGURED is used: bootstrap binds a
    /// configured endpoint to the metadata, and an unconfigured one that the
    /// metadata merely advertises was never bound, so it gets no token and no
    /// client secret.
    pub(crate) async fn revoke_token(
        &self,
        account_id: &str,
        token: &str,
        hint: TokenTypeHint,
    ) -> ProviderRevocation {
        let Ok((descriptor, pinned)) = self.managed(account_id) else {
            return ProviderRevocation::Failed;
        };
        let endpoint = match (&descriptor.revocation_endpoint, &pinned.revocation_endpoint) {
            (Some(_), Some(endpoint)) => endpoint.as_str(),
            _ => return ProviderRevocation::Unsupported,
        };
        let Ok(credentials) = self.client_authentication(descriptor) else {
            return ProviderRevocation::Failed;
        };
        let mut form = vec![
            ("token".to_string(), token.to_string()),
            ("token_type_hint".to_string(), hint.as_str().to_string()),
        ];
        form.extend(credentials);
        match self.http.post_token(endpoint, &form).await {
            Ok(response) if response.status == 200 => ProviderRevocation::Confirmed,
            _ => ProviderRevocation::Failed,
        }
    }

    /// The managed descriptor and its pinned metadata, or a refusal before any
    /// HTTP.
    fn managed(
        &self,
        account_id: &str,
    ) -> Result<(&AccountDescriptor, &AuthorizationServerMetadata), ProviderRefreshError> {
        let descriptor = self
            .descriptors
            .get(account_id)
            .filter(|descriptor| descriptor.mode == DescriptorMode::PersonalManaged)
            .ok_or(ProviderRefreshError::Unavailable)?;
        let pinned = self
            .pinned
            .get(account_id)
            .ok_or(ProviderRefreshError::Unavailable)?;
        Ok((descriptor, pinned))
    }
}

/// `Some(resource)` when the descriptor declares `true`, `None` when it
/// declares `false`; undeclared is refused, never defaulted.
fn resource_parameter(
    descriptor: &AccountDescriptor,
) -> Result<Option<&str>, ProviderRefreshError> {
    let send = descriptor
        .send_resource_parameter
        .ok_or(ProviderRefreshError::Unavailable)?;
    let resource = required(descriptor.resource.as_deref())?;
    Ok(send.then_some(resource))
}

/// The descriptor's `authorize_extra` as query pairs. Every key and value is
/// a literal chosen by an exhaustive match on the closed config type, so no
/// pair can shadow a pinned parameter.
fn authorize_extra(descriptor: &AccountDescriptor) -> Vec<(&'static str, &'static str)> {
    let Some(extra) = descriptor.authorize_extra else {
        return Vec::new();
    };
    let AuthorizeExtra {
        access_type,
        prompt,
        include_granted_scopes,
    } = extra;
    let access_type = access_type.map(|value| match value {
        AccessType::Offline => ("access_type", "offline"),
        AccessType::Online => ("access_type", "online"),
    });
    let prompt = prompt.map(|value| match value {
        Prompt::Consent => ("prompt", "consent"),
        Prompt::SelectAccount => ("prompt", "select_account"),
        Prompt::Silent => ("prompt", "none"),
    });
    let include = include_granted_scopes.map(|value| {
        (
            "include_granted_scopes",
            if value { "true" } else { "false" },
        )
    });
    [access_type, prompt, include]
        .into_iter()
        .flatten()
        .collect()
}
