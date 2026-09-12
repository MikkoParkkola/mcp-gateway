// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Personal-account OAuth refresh provider.
//!
//! The production dependency managed custody needs: the `RefreshProvider`
//! implementation `AccountService` calls when a grant has expired. It owns no
//! grant store. The store, the compare-and-swap, the fence and the
//! omitted-field preservation all stay in `service.rs`; this module answers one
//! question — what did the authorization server say when we presented this
//! account's current refresh token.
//!
//! THE ACCEPTANCE BOUNDARY IS THE CONSTRUCTOR. [`PersonalOAuthRefresh::bootstrap`]
//! is `async` and EAGER: it discovers, validates and pins the issuer metadata of
//! EVERY managed descriptor before returning `Ok`, so a Gateway cannot reach
//! Serving holding a provider that would discover lazily on a later refresh. One
//! unacceptable descriptor refuses the whole provider. An empty descriptor map
//! is a SUCCESS that performs no HTTP and reads no secret, because a store-only
//! deployment must still start.
//!
//! SECRETS ARE RESOLVED LATE. Bootstrap fetches unauthenticated metadata and
//! nothing else. A client secret is read at refresh time only, and only against
//! a snapshot bootstrap already accepted — until that document was accepted we
//! did not know which endpoint we would be presenting a secret to.
//!
//! `OAuthClient::refresh_token` is deliberately not reused: it writes the legacy
//! `TokenStorage` and caches into its own `current_token`, which would give the
//! gateway a second grant store the custody service does not fence. Its HTTP and
//! response-parsing SEMANTICS are reused; its persistence is not.
//!
//! The real transport lives in [`http`] — one `reqwest` client with certificate
//! validation, redirect refusal, DNS pinning and the existing SSRF checks.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use url::Url;

use super::config::{AccountDescriptor, DescriptorMode};
use super::service::{ProviderRefreshError, RefreshProvider, TokenRefresh};
use super::{AccountKey, GrantRecord};
use crate::oauth::AuthorizationServerMetadata;

mod http;

pub(crate) use http::GatewayProviderHttp;

#[cfg(test)]
mod provider_tests;
#[cfg(test)]
mod wire_tests;

/// A response body and its status. Carries no headers on purpose: nothing in
/// this flow branches on one, and a header map is the easiest place for a
/// credential to end up in a trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) body: String,
}

/// A failure that permits trying the NEXT discovery candidate. The document was
/// never obtained, so nothing about the issuer has been asserted by anyone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetrievalFailure {
    /// Connection refused, DNS miss, timeout -- no answer at all.
    Unreachable,
}

/// A failure that ENDS discovery. Trying another location after one of these is
/// the attacker fallback the approved contract forbids: a certificate or
/// redirect failure is a statement about the host we are talking to, and a
/// document that parsed but bound the wrong issuer is a statement about who is
/// answering for it. Neither is repaired by asking somewhere else.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TerminalFailure {
    /// Certificate validation failed.
    Certificate,
    /// The server tried to redirect. We do not follow redirects.
    Redirect,
    /// Refused by the existing SSRF/DNS pinning policy.
    Blocked,
    /// A response this flow will not read: past the body bound, or not UTF-8.
    Unacceptable,
    /// A transport failure the client cannot prove is benign. `reqwest` reports
    /// a rejected certificate and a refused connection through the same
    /// predicates, so the pair is treated as the dangerous one.
    Unclassified,
}

/// Transport failure, split so the discovery loop CANNOT advance on a terminal
/// one -- the two cases are different types, not two spellings in one enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HttpError {
    Retryable(RetrievalFailure),
    Terminal(TerminalFailure),
}

/// The provider's only outbound seam. Two methods rather than one so the
/// credential flow is inspectable by type: a metadata GET has no parameter that
/// could carry a secret, and every call that does carry one is a `post_token`.
///
/// Implementations must apply certificate-validated HTTPS, refuse redirects and
/// apply the existing SSRF/DNS policy. That obligation lives with the
/// implementation because no signature can express it.
pub(crate) trait ProviderHttp: Send + Sync {
    /// Unauthenticated GET of an issuer metadata document.
    fn get_metadata(
        &self,
        url: &str,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send;

    /// Form POST to the pinned token endpoint. The only credential-bearing call.
    fn post_token(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send;
}

/// Wall clock seam. `expires_at` is absolute, so a test that pins the clock
/// pins the mapped value exactly.
pub(crate) trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

/// Production clock.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// Resolves an `env:VARIABLE` client-secret reference. The reference stays a
/// reference in configuration; only this seam ever holds the value, and only at
/// refresh time, against metadata that bootstrap already accepted.
///
/// A trait because the overlay type is not this module's to own, and because a
/// test must be able to assert that a secret was NOT read.
pub(crate) trait SecretSource: Send + Sync {
    /// `None` means the reference did not resolve.
    fn resolve(&self, reference: &str) -> Option<String>;
}

/// The production [`SecretSource`]: the gateway's own environment overlay.
///
/// The SAME `LiveEnv` the config was validated against, never a second
/// environment source and never the process environment — the account's client
/// secret is assigned by an env file, which no process ever sees.
pub(crate) struct EnvSecrets {
    env: Arc<crate::config::LiveEnv>,
}

impl EnvSecrets {
    pub(crate) fn new(env: Arc<crate::config::LiveEnv>) -> Self {
        Self { env }
    }
}

impl SecretSource for EnvSecrets {
    fn resolve(&self, reference: &str) -> Option<String> {
        // `env:` only, exactly as the configuration layer documents. A literal
        // is not accepted here: accepting one would make a mistyped secret in a
        // config file work, which is how it ends up committed.
        let variable = reference.strip_prefix("env:")?;
        // The guard is taken and dropped inside this synchronous call, so no
        // environment read is held across an await.
        self.env.get().resolve(variable)
    }
}

/// Why a production provider could not be built.
///
/// `InvalidMetadata` is a POLICY refusal reached only after a document was
/// actually fetched and judged. Neither variant carries a payload: the
/// descriptor identity belongs in the call trace and the log, not in an error
/// that is rendered near credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProviderBuildError {
    #[error("a managed account descriptor has unacceptable issuer metadata")]
    InvalidMetadata,
    #[error("the personal account OAuth HTTP client could not be built")]
    Transport,
}

/// The MCP-defined discovery locations, in priority order, deduplicated.
///
/// RFC 8414 inserted before the issuer path, then OIDC inserted before it, then
/// OIDC appended after it. The third is generated unconditionally and removed by
/// the deduplication when the issuer is origin-only -- writing the dedupe as the
/// rule rather than as a special case is what keeps the origin-only and
/// path-bearing shapes from drifting apart.
pub(crate) fn discovery_urls(issuer: &str) -> Result<Vec<String>, ProviderRefreshError> {
    let url = Url::parse(issuer).map_err(|_| ProviderRefreshError::Unavailable)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderRefreshError::Unavailable);
    }
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    let candidates = [
        format!("{origin}/.well-known/oauth-authorization-server{path}"),
        format!("{origin}/.well-known/openid-configuration{path}"),
        format!("{origin}{path}/.well-known/openid-configuration"),
    ];
    let mut ordered: Vec<String> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !ordered.contains(&candidate) {
            ordered.push(candidate);
        }
    }
    Ok(ordered)
}

/// The refresh provider `AccountService` holds.
///
/// Descriptors are keyed by the configured account id, which IS the logical
/// `backend_id` of an account key. A refresh selects by that id and by nothing
/// else: two descriptors may share `provider = "google"` and remain distinct
/// accounts, so joining on provider name would let one account's grant be
/// refreshed against another's registration.
pub(crate) struct PersonalOAuthRefresh<H, C, S> {
    descriptors: BTreeMap<String, AccountDescriptor>,
    http: H,
    clock: C,
    secrets: S,
    /// Metadata accepted DURING BOOTSTRAP and pinned for the provider's
    /// lifetime.
    ///
    /// A plain map behind `&self`, with no interior mutability, is the whole
    /// pinning mechanism: after the constructor returns there is no code path
    /// that can add, replace or invalidate an entry, so "re-validated per
    /// refresh" is not a behaviour this type can express. A replacement arrives
    /// with a configuration reload, which builds a new provider.
    pinned: BTreeMap<String, AuthorizationServerMetadata>,
}

impl<H: ProviderHttp, C: Clock, S: SecretSource> PersonalOAuthRefresh<H, C, S> {
    /// Eagerly build the provider: discover, validate and pin the metadata of
    /// every managed descriptor, then return.
    ///
    /// `Ok` means the Gateway may start Serving. `Err(InvalidMetadata)` means at
    /// least one descriptor could not be accepted and NO provider exists —
    /// partial acceptance is lazy discovery under another name, because it would
    /// let Serving start with a descriptor still to be discovered.
    ///
    /// Non-managed descriptors are not this provider's business: `shared` and
    /// `external` accounts carry no personal grant, so nothing is fetched for
    /// them and their presence cannot refuse a bootstrap.
    pub(crate) async fn bootstrap(
        descriptors: BTreeMap<String, AccountDescriptor>,
        http: H,
        clock: C,
        secrets: S,
    ) -> Result<Self, ProviderBuildError> {
        let mut pinned = BTreeMap::new();
        for (account_id, descriptor) in &descriptors {
            if descriptor.mode != DescriptorMode::PersonalManaged {
                continue;
            }
            pinned.insert(account_id.clone(), discover(&http, descriptor).await?);
        }
        Ok(Self {
            descriptors,
            http,
            clock,
            secrets,
            pinned,
        })
    }

    async fn refresh_inner(
        &self,
        account: &AccountKey,
        current: &GrantRecord,
    ) -> Result<TokenRefresh, ProviderRefreshError> {
        // Everything down to the token POST is a refusal before any HTTP.
        let descriptor = self
            .descriptors
            .get(&account.backend_id)
            .ok_or(ProviderRefreshError::Unavailable)?;
        if descriptor.mode != DescriptorMode::PersonalManaged {
            return Err(ProviderRefreshError::Unavailable);
        }
        let issuer = required(descriptor.issuer.as_deref())?;
        let resource = required(descriptor.resource.as_deref())?;
        // Exact equality both ways. The account key names the issuer and
        // resource the grant was authorized against; a descriptor that has since
        // been pointed elsewhere is a different authorization, not this one.
        if account.oauth_issuer != issuer || account.resource != resource {
            return Err(ProviderRefreshError::Unavailable);
        }
        let client_id = required(descriptor.client_id.as_deref())?;
        let send_resource = descriptor
            .send_resource_parameter
            .ok_or(ProviderRefreshError::Unavailable)?;
        let refresh_token = current
            .refresh_token
            .as_deref()
            .ok_or(ProviderRefreshError::Unavailable)?;

        // The snapshot bootstrap accepted, and the only endpoint this refresh
        // will talk to. No discovery happens here, ever.
        let token_endpoint = self
            .pinned
            .get(&account.backend_id)
            .ok_or(ProviderRefreshError::Unavailable)?
            .token_endpoint
            .as_str();

        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), client_id.to_string()),
        ];
        if let Some(reference) = descriptor.client_secret_ref.as_deref() {
            let secret = self
                .secrets
                .resolve(reference)
                .ok_or(ProviderRefreshError::Unavailable)?;
            form.push(("client_secret".to_string(), secret));
        }
        if send_resource {
            form.push(("resource".to_string(), resource.to_string()));
        }

        let response = self
            .http
            .post_token(token_endpoint, &form)
            .await
            .map_err(|_| ProviderRefreshError::Unavailable)?;
        self.map_token_response(&response)
    }

    fn map_token_response(
        &self,
        response: &HttpResponse,
    ) -> Result<TokenRefresh, ProviderRefreshError> {
        if response.status != 200 {
            // Only the RFC 6749 error code is read; no byte of the body reaches
            // the error, which is a fieldless enum for exactly that reason.
            let code = serde_json::from_str::<ErrorBody>(&response.body)
                .ok()
                .and_then(|body| body.error);
            return Err(if code.as_deref() == Some("invalid_grant") {
                ProviderRefreshError::InvalidGrant
            } else {
                ProviderRefreshError::Unavailable
            });
        }
        let body: TokenResponseBody =
            serde_json::from_str(&response.body).map_err(|_| ProviderRefreshError::Unavailable)?;
        if body.access_token.is_empty() || body.token_type.is_empty() {
            return Err(ProviderRefreshError::Unavailable);
        }
        // `expires_in` is required here although RFC 6749 §5.1 makes it
        // optional: `TokenRefresh` has no spelling for "unknown", and inventing
        // a default lifetime would let a stale token be served as fresh.
        let expires_in = body.expires_in.ok_or(ProviderRefreshError::Unavailable)?;
        let expires_at = self
            .clock
            .now_unix()
            .checked_add(expires_in)
            .ok_or(ProviderRefreshError::Unavailable)?;
        Ok(TokenRefresh {
            access_token: body.access_token,
            // None is preserved, never rewritten to the current token: the
            // service reads it as "the provider rotated nothing".
            refresh_token: body.refresh_token,
            scopes: body
                .scope
                .map(|scope| scope.split_whitespace().map(String::from).collect()),
            token_type: body.token_type,
            expires_at,
        })
    }
}

impl<H, C, S> RefreshProvider for PersonalOAuthRefresh<H, C, S>
where
    H: ProviderHttp,
    C: Clock,
    S: SecretSource,
{
    fn refresh(
        &self,
        account: &AccountKey,
        current: &GrantRecord,
    ) -> impl Future<Output = Result<TokenRefresh, ProviderRefreshError>> + Send {
        self.refresh_inner(account, current)
    }
}

/// Discover and accept one descriptor's issuer metadata, or refuse.
///
/// A free function rather than a method because it runs BEFORE any `Self`
/// exists — a method would need a half-built provider to be callable, which is
/// the state this constructor is designed not to have.
async fn discover<H: ProviderHttp>(
    http: &H,
    descriptor: &AccountDescriptor,
) -> Result<AuthorizationServerMetadata, ProviderBuildError> {
    let issuer = descriptor
        .issuer
        .as_deref()
        .filter(|issuer| !issuer.is_empty())
        .ok_or(ProviderBuildError::InvalidMetadata)?;
    let candidates = discovery_urls(issuer).map_err(|_| ProviderBuildError::InvalidMetadata)?;
    for url in candidates {
        match http.get_metadata(&url).await {
            Ok(response) if response.status == 200 => {
                // A document arrived. From here the answer is this descriptor's,
                // accepted or terminally rejected -- never a reason to ask the
                // next location.
                return accept_metadata(descriptor, &response.body)
                    .ok_or(ProviderBuildError::InvalidMetadata);
            }
            // No document: this location does not serve one. Next.
            Ok(_) | Err(HttpError::Retryable(_)) => {}
            Err(HttpError::Terminal(_)) => return Err(ProviderBuildError::InvalidMetadata),
        }
    }
    // Every location exhausted. A provider that would "try again later" is
    // exactly the lazy one this constructor exists to prevent.
    Err(ProviderBuildError::InvalidMetadata)
}

fn required(value: Option<&str>) -> Result<&str, ProviderRefreshError> {
    value
        .filter(|v| !v.is_empty())
        .ok_or(ProviderRefreshError::Unavailable)
}

/// Accept a metadata document for this descriptor, or reject it terminally.
///
/// Exact string equality throughout, in both directions: the configured value
/// is the operator's registration and the metadata value is the issuer's own
/// spelling, and a difference between them is a disagreement about identity,
/// not a formatting question. Cross-origin endpoints are FINE -- Google binds
/// `https://accounts.google.com` to a token endpoint on `oauth2.googleapis.com`
/// -- because what makes an endpoint trustworthy is that the authenticated
/// document for the configured issuer advertised it, not where it lives.
fn accept_metadata(
    descriptor: &AccountDescriptor,
    body: &str,
) -> Option<AuthorizationServerMetadata> {
    let metadata: AuthorizationServerMetadata = serde_json::from_str(body).ok()?;
    if metadata.issuer.as_str() != descriptor.issuer.as_deref()? {
        return None;
    }
    if metadata.authorization_endpoint.as_str() != descriptor.authorization_endpoint.as_deref()? {
        return None;
    }
    if metadata.token_endpoint.as_str() != descriptor.token_endpoint.as_deref()? {
        return None;
    }
    // Optional only when unused. Configured means it will be used, so it is
    // held to the same binding as the rest.
    if let Some(configured) = descriptor.revocation_endpoint.as_deref()
        && metadata.revocation_endpoint.as_deref() != Some(configured)
    {
        return None;
    }
    for endpoint in [&metadata.authorization_endpoint, &metadata.token_endpoint]
        .into_iter()
        .chain(metadata.revocation_endpoint.as_ref())
    {
        if !is_https_with_host(endpoint) {
            return None;
        }
    }
    Some(metadata)
}

fn is_https_with_host(endpoint: &str) -> bool {
    // URL userinfo is refused HERE, at the pin, because the client that will
    // dial this endpoint refuses it: an endpoint we know is unusable must fail
    // the bootstrap, not the first refresh.
    Url::parse(endpoint).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

/// RFC 6749 §5.1. Local rather than shared with `oauth::client` because that
/// type travels with `TokenInfo` and the legacy storage write; factoring the
/// two together is a later review, not a dependency this module takes now.
#[derive(Deserialize)]
struct TokenResponseBody {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// RFC 6749 §5.2. Only the code is read.
#[derive(Deserialize)]
struct ErrorBody {
    error: Option<String>,
}
