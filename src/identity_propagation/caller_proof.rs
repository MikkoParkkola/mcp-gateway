// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a request proved about the caller behind it.
//!
//! Its own file because the account boundary asks exactly one question of a
//! request — who is calling, and how well that is known — and the answer must
//! not be assembled differently by each consumer.

use super::VerifiedIdentity;
use crate::gateway::STDIO_CREDENTIAL_PRINCIPAL;

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
    /// (`gateway/server/mod.rs`).
    LocalTransport,
    /// A credential was presented and validated — a bearer token or an API
    /// key. Still nothing that identifies WHICH human holds it.
    Credential,
}

impl CallerProvenance {
    /// Classify from the credential principal a request carried.
    ///
    /// The ONE place the mapping is made. `credential_principal` is a digest of
    /// the validated secret and is "Empty for an identity that presented no
    /// credential" (`AuthenticatedClient::principal`, `gateway/auth.rs`), which
    /// is exactly what a public path's caller carries — the same test
    /// `handlers::session_owner_key` makes. The stdio constant is matched by
    /// name rather than counted as a secret, because it is not one.
    ///
    /// COMPARED IN A GUARD, NEVER AS A PATTERN. `Some(STDIO_CREDENTIAL_PRINCIPAL)`
    /// reads like a constant comparison and is not one unless the path resolves
    /// to a constant: otherwise it is an irrefutable BINDING that matches every
    /// `Some(_)`, makes the arms below unreachable, and classifies an anonymous
    /// caller as the operator. The compiler says so only through an
    /// `unused variable` warning naming the constant, which is a warning and not
    /// an error. A guard cannot degrade that way — an unresolved name is a hard
    /// error — so the stronger-failing form is the one used here.
    ///
    /// THE EMPTINESS TEST COMES FIRST. An anonymous caller carries `Some("")`,
    /// so if `STDIO_CREDENTIAL_PRINCIPAL` were ever edited to the empty string,
    /// a later emptiness check would classify every anonymous request as
    /// `LocalTransport` — the same anonymous-as-operator defect the guard form
    /// above exists to prevent, arriving through the constant instead of through
    /// the pattern.
    ///
    /// `Some("")` is a PATTERN here while the constant above is a GUARD, and the
    /// difference is not inconsistency: a string *literal* in pattern position
    /// is always a literal. Only a bare *path* can silently resolve to a binding
    /// instead of a comparison, which is the failure the constant is guarded
    /// against.
    pub(crate) fn classify(credential_principal: Option<&str>) -> Self {
        match credential_principal {
            Some("") | None => Self::Anonymous,
            Some(principal) if principal == STDIO_CREDENTIAL_PRINCIPAL => Self::LocalTransport,
            Some(_) => Self::Credential,
        }
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
