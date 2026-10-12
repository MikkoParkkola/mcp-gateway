// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 D16: what a stream opened by a request keeps of the identity the
//! request was admitted under, read once at intake.

use axum::http::{Extensions, HeaderMap};

use super::Intake;
use crate::gateway::router::AppState;
use crate::gateway::streaming::{Redacted, ViewSubject};
use crate::key_server::oidc::VerifiedIdentity;

/// The facts that outlive the request: the adapter's verdict on its
/// assertion, the raw Cloudflare Access assertion or the trusted proxy's peer
/// (whichever is the identity source), and the certificate's `notAfter`.
pub(super) struct ViewFacts {
    adapter: Option<crate::gateway::openwebui_adapter::AdapterAssertion>,
    cf_assertion: Option<Redacted>,
    proxy_peer: Option<std::net::SocketAddr>,
    cert_not_after: Option<u64>,
}

impl ViewFacts {
    pub(super) fn capture(
        state: &AppState,
        (headers, extensions): (&HeaderMap, &Extensions),
        verified: Option<&VerifiedIdentity>,
    ) -> Self {
        let (cf_assertion, proxy_peer) = crate::gateway::router::identity::identity_source_facts(
            state.meta_mcp.caller_identity(),
            (headers, extensions),
            verified,
        );
        Self {
            adapter: extensions
                .get::<crate::gateway::openwebui_adapter::AdapterAssertion>()
                .copied(),
            cf_assertion,
            proxy_peer,
            cert_not_after: extensions
                .get::<crate::mtls::identity::CertNotAfter>()
                .map(|not_after| not_after.0),
        }
    }
}

impl Intake<'_> {
    /// The view this request's caller is shown, as a stream opened by the same
    /// request would hold it (MIK-8350 D16).
    pub(super) fn view_subject(&self) -> ViewSubject {
        let facts = &self.view_facts;
        ViewSubject {
            grant_subject: self.grant_subject.clone(),
            oauth_agent: self.oauth_agent_identity.clone(),
            cert: self.cert_identity.clone(),
            code_mode_url: self.code_mode_url_active,
            verified_identity: self.verified_identity.clone(),
            adapter: facts.adapter,
            cert_not_after: facts.cert_not_after,
            cf_assertion: facts.cf_assertion.clone(),
            proxy_peer: facts.proxy_peer,
        }
    }
}
