// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8350 D16: what a stream opened by a request keeps of the identity the
//! request was admitted under, read once at intake.

use axum::http::Extensions;

use super::Intake;
use crate::gateway::streaming::{HeldSource, ViewSubject};

/// The facts that outlive the request: the adapter's verdict on its
/// assertion, the identity source the admission selected, and the
/// certificate's `notAfter`.
pub(super) struct ViewFacts {
    adapter: Option<crate::gateway::openwebui_adapter::AdapterAssertion>,
    source: HeldSource,
    cert_not_after: Option<u64>,
}

impl ViewFacts {
    pub(super) fn capture(extensions: &Extensions, source: HeldSource) -> Self {
        Self {
            adapter: extensions
                .get::<crate::gateway::openwebui_adapter::AdapterAssertion>()
                .copied(),
            source,
            cert_not_after: extensions
                .get::<crate::mtls::identity::CertNotAfter>()
                .map(|not_after| not_after.0),
        }
    }
}

impl Intake<'_> {
    /// The view this request's caller is shown, as a stream opened by the same
    /// request would hold it (MIK-8350 D16).
    pub(in crate::gateway::router::handlers) fn view_subject(&self) -> ViewSubject {
        let facts = &self.view_facts;
        ViewSubject {
            grant_subject: self.grant_subject.clone(),
            oauth_agent: self.oauth_agent_identity.clone(),
            cert: self.cert_identity.clone(),
            code_mode_url: self.code_mode_url_active,
            verified_identity: self.verified_identity.clone(),
            adapter: facts.adapter,
            cert_not_after: facts.cert_not_after,
            identity_source: facts.source.clone(),
            cf_grace: std::sync::Arc::default(),
        }
    }
}
