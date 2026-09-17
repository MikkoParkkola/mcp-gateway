// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The provider's real outbound transport.
//!
//! One `reqwest` client, owned here, with a policy the personal-account flow
//! needs and the gateway's shared transport does not have: redirects are not
//! followed AT ALL, the existing DNS-pinning resolver is installed so a name
//! cannot be re-resolved between the SSRF check and the connection, proxies are
//! disabled so nothing can route around that resolver, and only `https` is
//! accepted. No cookie store exists (the `cookies` feature is not enabled), no
//! header travels except `accept`, and the metadata GET carries no credential
//! of any kind.
//!
//! WHY THE FAILURE MAPPING IS PESSIMISTIC. `reqwest` exposes no predicate that
//! separates a rejected certificate from a refused connection: both arrive as
//! transport errors and `is_connect()` answers the same for each. Discovery may
//! advance to the next candidate ONLY on a failure that asserts nothing about
//! the host, so anything not provably benign is terminal. This costs nothing
//! real: all three discovery candidates share one origin, so a connection that
//! cannot be made to the first cannot be made to the others either.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt as _;

use super::{
    HttpError, HttpResponse, ProviderBuildError, ProviderHttp, RetrievalFailure, TerminalFailure,
};
use crate::security::ssrf::{PinningResolver, SystemResolver, validate_url_not_ssrf};

/// Whole-request bound, connection included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Separate connect bound so a black-holed host fails before the request one.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Metadata documents run to a few kilobytes and token responses to less. The
/// bound exists so a hostile endpoint cannot stream until the process dies.
const MAX_BODY_BYTES: usize = 256 * 1024;

/// The gateway's real HTTP dependency for personal-account OAuth.
pub(crate) struct GatewayProviderHttp {
    client: reqwest::Client,
}

/// The one client policy this module has. Production and every test build
/// from HERE: a second builder would be a second policy, and the one that is
/// not tested is the one that ships.
fn strict_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        // Not `Policy::limited(0)`: `none()` also refuses to strip the
        // authorization off a cross-origin hop, because no hop happens.
        .redirect(reqwest::redirect::Policy::none())
        .https_only(true)
        // A proxy performs its own name resolution, which would make the
        // pinning resolver below decorative.
        .no_proxy()
        .dns_resolver(Arc::new(PinningResolver::new(SystemResolver)))
    // Default roots and default certificate/hostname verification. No
    // `danger_accept_invalid_*` call exists in this file, and adding one
    // is what would make every terminal-failure test meaningless.
}

impl GatewayProviderHttp {
    /// Build the client this module owns.
    pub(crate) fn new() -> Result<Self, ProviderBuildError> {
        Self::build(strict_builder())
    }

    /// The same strict client with test-supplied additions applied ON TOP.
    ///
    /// `cfg(test)` so it cannot be reached from a production path. It takes a
    /// builder rather than a client so a test ADDS to the production policy
    /// instead of restating it — every setting above is already applied when the
    /// closure runs.
    ///
    /// WHAT THIS DOES NOT DO, stated plainly because the r1 comment claimed the
    /// opposite: the closure CAN override what `strict_builder` set. A later
    /// `.redirect(...)`, `.https_only(false)` or `danger_accept_invalid_certs`
    /// wins, because `ClientBuilder` is last-call-wins. Nothing here prevents
    /// that. The boundary is a REVIEW boundary: this constructor exists only
    /// under `cfg(test)`, its callers are in one reviewed file, and today they
    /// pass exactly two additions — `add_root_certificate` and `resolve`. A
    /// change to that is visible in a diff, not blocked by a type.
    #[cfg(test)]
    pub(crate) fn for_test(
        configure: impl FnOnce(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    ) -> Result<Self, ProviderBuildError> {
        Self::build(configure(strict_builder()))
    }

    fn build(builder: reqwest::ClientBuilder) -> Result<Self, ProviderBuildError> {
        let client = builder.build().map_err(|_| ProviderBuildError::Transport)?;
        Ok(Self { client })
    }

    async fn get_inner(&self, url: String) -> Result<HttpResponse, HttpError> {
        guard(&url)?;
        // `accept` only. A metadata document is public, and every header this
        // request does not carry is a header that cannot leak.
        let request = self.client.get(&url).header("accept", "application/json");
        send(request).await
    }

    async fn post_inner(
        &self,
        url: String,
        form: Vec<(String, String)>,
    ) -> Result<HttpResponse, HttpError> {
        guard(&url)?;
        let request = self
            .client
            .post(&url)
            .header("accept", "application/json")
            .form(&form);
        send(request).await
    }
}

impl ProviderHttp for GatewayProviderHttp {
    fn get_metadata(
        &self,
        url: &str,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.get_inner(url.to_string())
    }

    fn post_token(
        &self,
        url: &str,
        form: &[(String, String)],
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.post_inner(url.to_string(), form.to_vec())
    }
}

/// The synchronous half of the SSRF policy: an IP-literal host is refused
/// before a connection is attempted. The name case is the resolver's, on the
/// connection itself, which is where the rebinding window would otherwise be.
fn guard(url: &str) -> Result<(), HttpError> {
    // `reqwest` turns embedded userinfo into a `Basic` Authorization header even
    // though this module sets only `accept`. No credential strategy of that kind
    // exists for managed personal accounts, so a URL carrying one is refused
    // before any network work rather than silently authenticated.
    let parsed = url::Url::parse(url).map_err(|_| HttpError::Terminal(TerminalFailure::Blocked))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(HttpError::Terminal(TerminalFailure::Unacceptable));
    }
    validate_url_not_ssrf(url).map_err(|_| HttpError::Terminal(TerminalFailure::Blocked))
}

async fn send(request: reqwest::RequestBuilder) -> Result<HttpResponse, HttpError> {
    let response = request.send().await.map_err(|e| classify(&e))?;
    let status = response.status();
    // With `Policy::none()` a redirect is DELIVERED rather than raised as an
    // error, so it arrives here as a 3xx status. Treating it as an ordinary
    // non-200 would let discovery advance past a host that just tried to send
    // us somewhere else — the exact fallback the policy forbids.
    if status.is_redirection() {
        return Err(HttpError::Terminal(TerminalFailure::Redirect));
    }
    let body = read_bounded(response).await?;
    Ok(HttpResponse {
        status: status.as_u16(),
        body,
    })
}

/// Read at most [`MAX_BODY_BYTES`], counting as the chunks arrive.
///
/// `Response::bytes` would buffer whatever the server chooses to send;
/// `content-length` is a claim the sender controls, so the count is kept on
/// what actually arrived.
async fn read_bounded(response: reqwest::Response) -> Result<String, HttpError> {
    let mut stream = response.bytes_stream();
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| classify(&e))?;
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(HttpError::Terminal(TerminalFailure::Unacceptable));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| HttpError::Terminal(TerminalFailure::Unacceptable))
}

/// Map a transport error, defaulting to terminal. See the module header for why
/// the default is the safe direction rather than the informative one.
fn classify(error: &reqwest::Error) -> HttpError {
    if error.is_redirect() {
        HttpError::Terminal(TerminalFailure::Redirect)
    } else if error.is_timeout() {
        // No answer at all, and no statement about the host: the one case that
        // may legitimately advance to the next candidate.
        HttpError::Retryable(RetrievalFailure::Unreachable)
    } else if names_certificate_failure(error) {
        HttpError::Terminal(TerminalFailure::Certificate)
    } else {
        HttpError::Terminal(TerminalFailure::Unclassified)
    }
}

/// Whether the error chain names a TLS failure.
///
/// PURELY DIAGNOSTIC, and deliberately so: `Certificate` and `Unclassified` are
/// both terminal, so a miss here changes what an operator reads and never what
/// the discovery loop does. There is no typed predicate to use instead —
/// `reqwest` reports a rejected certificate as a connect error, the same as a
/// refused connection — so this reads the chain the TLS backend wrote rather
/// than claiming a distinction the API does not offer.
fn names_certificate_failure(error: &reqwest::Error) -> bool {
    const MARKERS: [&str; 4] = ["certificate", "tls", "handshake", "verification"];
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(current) = source {
        let rendered = current.to_string().to_ascii_lowercase();
        if MARKERS.iter().any(|marker| rendered.contains(marker)) {
            return true;
        }
        source = current.source();
    }
    false
}

#[cfg(test)]
mod embedded_userinfo_guard_tests {
    use super::*;

    /// Synthetic markers only. These are not credentials for anything.
    const USER: &str = "not-a-real-user";
    const PASS: &str = "not-a-real-secret";

    fn is_unacceptable(result: Result<(), HttpError>) -> bool {
        matches!(
            result,
            Err(HttpError::Terminal(TerminalFailure::Unacceptable))
        )
    }

    #[test]
    fn public_https_anchor_is_accepted() {
        assert!(guard("https://accounts.example.com/.well-known/openid-configuration").is_ok());
    }

    #[test]
    fn at_sign_in_path_or_query_is_not_userinfo() {
        // Guards against a blunt substring match on '@' rejecting benign URLs.
        assert!(guard("https://accounts.example.com/users/a@b.example/profile").is_ok());
        assert!(guard("https://accounts.example.com/token?login_hint=a@b.example").is_ok());
    }

    #[test]
    fn username_and_password_are_terminal_unacceptable() {
        let url = format!("https://{USER}:{PASS}@accounts.example.com/token");
        let result = guard(&url);
        assert!(
            is_unacceptable(result),
            "embedded user:pass must be Terminal(Unacceptable), not a DNS/SSRF refusal"
        );
    }

    #[test]
    fn username_only_is_terminal_unacceptable() {
        let url = format!("https://{USER}@accounts.example.com/token");
        assert!(is_unacceptable(guard(&url)));
    }

    #[test]
    fn empty_username_with_password_is_terminal_unacceptable() {
        let url = format!("https://:{PASS}@accounts.example.com/token");
        assert!(is_unacceptable(guard(&url)));
    }
}
