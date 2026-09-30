// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a request proved about the caller behind it.
//!
//! Its own file because the account boundary asks exactly one question of a
//! request — who is calling, and how well that is known — and the answer must
//! not be assembled differently by each consumer.

use super::VerifiedIdentity;
use crate::gateway::StdioNonce;

/// How a request established its caller, APART from any verified identity.
///
/// Three states, and the middle one exists because two different facts would
/// otherwise share one name. A value that answers two questions is the defect
/// this module was written to remove, so the difference is recorded in the type
/// rather than in prose: a later call site that needs a validated secret
/// specifically must match on it, and the compiler makes it say so.
///
/// [`Self::Anonymous`] is the `Default`, so anything that does not know
/// refuses rather than mints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CallerProvenance {
    /// Nothing established the caller. A public path's anonymous request is
    /// here, and so is every request on a gateway with auth switched off.
    #[default]
    Anonymous,
    /// The transport itself establishes the operator. A stdio gateway is
    /// spawned BY the person using it and serves exactly that one client, so
    /// there is no second party on the pipe to tell apart. No secret was
    /// presented, and `STDIO_CREDENTIAL_PRINCIPAL`'s own doc says reaching the
    /// gateway over stdio already grants full tool access
    /// (`gateway/server/mod.rs`). Reached only through
    /// [`Self::local_transport`], never from text.
    LocalTransport,
    /// A credential was presented and validated — a bearer token or an API
    /// key. Still nothing that identifies WHICH human holds it.
    Credential,
}

impl CallerProvenance {
    /// Classify from the credential principal text a request carried.
    ///
    /// The ONE place text is mapped. `credential_principal` is a digest of the
    /// validated secret and is "Empty for an identity that presented no
    /// credential" (`AuthenticatedClient::principal`, `gateway/auth.rs`), which
    /// is exactly what a public path's caller carries — the same test
    /// `handlers::session_owner_key` makes.
    ///
    /// Text never yields [`Self::LocalTransport`], whatever it spells, the stdio
    /// principal included (MIK-7272.OWNER.3): only
    /// [`Self::local_transport`] does, and it needs the transport's mark.
    pub(crate) fn classify(credential_principal: Option<&str>) -> Self {
        match credential_principal {
            Some("") | None => Self::Anonymous,
            Some(_) => Self::Credential,
        }
    }

    /// The stdio transport's provenance. The argument is the proof: a
    /// [`StdioNonce`] is constructible only by the stdio transport module, so no
    /// request data can reach this constructor.
    pub(crate) fn local_transport(_mark: &StdioNonce) -> Self {
        Self::LocalTransport
    }

    /// Whether this is enough to be trusted with a deployment-wide principal.
    ///
    /// Both established states qualify TODAY, and the operator's ruling is why:
    /// every current user is a solo user and stdio is their transport, so
    /// excluding it would break the shipped case to satisfy a definition.
    /// Kept as one method so the policy lives in one place if that changes.
    ///
    /// `pub(crate)` because the ENFORCEMENT POINT is in another module
    /// (`personal_accounts::vault`), and a predicate the enforcement point
    /// cannot call is a comment. Carrying the provenance in the type only helps
    /// if something reads it.
    pub(crate) fn establishes_the_operator(self) -> bool {
        match self {
            Self::LocalTransport | Self::Credential => true,
            Self::Anonymous => false,
        }
    }
}

/// What a request proved about the caller behind it.
///
/// IDENTITY AND AUTHENTICATION ARE DIFFERENT QUESTIONS, and the account
/// boundary needs both answers: a stored OAuth grant may be served under a
/// principal the CONFIGURATION asserts, but only to a caller the REQUEST
/// established.
///
/// The shipped starter configuration (`commands::generate_config`) is why that
/// distinction is load-bearing rather than pedantic: it sets `auth.enabled` and
/// `auth.single_user` AND lists `/mcp` under `public_paths`, so a default
/// install serves tool dispatch to callers that presented nothing.
/// `auth.enabled` describes the deployment; only this type describes the caller.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CallerProof<'a> {
    /// An identity provider verified this caller: issuer and subject are its
    /// answer, and a per-user account key can name the human.
    Verified(&'a VerifiedIdentity),
    /// No identity, but the request established the operator. Enough for a
    /// deployment-wide principal, never enough to name a person.
    Operator(CallerProvenance),
    /// Nothing established the caller.
    Anonymous,
}

impl<'a> CallerProof<'a> {
    /// Combine the two facts a request carries.
    ///
    /// A verified identity outranks the provenance: it is already a proof, and
    /// letting provenance veto it would change how OIDC callers are served
    /// today.
    pub(crate) fn new(
        identity: Option<&'a VerifiedIdentity>,
        provenance: CallerProvenance,
    ) -> Self {
        match identity {
            Some(identity) => Self::Verified(identity),
            None if provenance.establishes_the_operator() => Self::Operator(provenance),
            None => Self::Anonymous,
        }
    }

    /// The verified identity, when an identity provider produced one.
    pub(crate) fn verified(self) -> Option<&'a VerifiedIdentity> {
        match self {
            Self::Verified(identity) => Some(identity),
            Self::Operator(_) | Self::Anonymous => None,
        }
    }

    /// The provenance behind an operator-level caller, for a consumer that
    /// must tell a validated secret from a trusted transport.
    pub(crate) fn provenance(self) -> CallerProvenance {
        match self {
            Self::Verified(_) | Self::Operator(CallerProvenance::Credential) => {
                CallerProvenance::Credential
            }
            Self::Operator(provenance) => provenance,
            Self::Anonymous => CallerProvenance::Anonymous,
        }
    }
}

#[cfg(test)]
#[path = "caller_proof_tests.rs"]
mod caller_proof_tests;
