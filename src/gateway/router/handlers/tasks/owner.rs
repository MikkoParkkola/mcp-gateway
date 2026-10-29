// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Who owns a task: the one owner every task arm of a request uses, the
//! events owner, and the admission principal.

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::oauth::OAuthAgentIdentity;
use crate::gateway::router::AppState;
use crate::key_server::oidc::VerifiedIdentity;
use crate::mtls::CertIdentity;

/// The five identity facts of one caller, as the request carries them.
pub(in crate::gateway::router) struct TaskCaller<'a> {
    pub(in crate::gateway::router) verified_identity: Option<&'a VerifiedIdentity>,
    pub(in crate::gateway::router) agent: Option<&'a OAuthAgentIdentity>,
    pub(in crate::gateway::router) subject: Option<&'a crate::identity_grants::GrantSubject>,
    pub(in crate::gateway::router) cert: Option<&'a CertIdentity>,
    pub(in crate::gateway::router) client: Option<&'a AuthenticatedClient>,
}

/// The owners [`route_owners`] resolves for one request: the task owner, its
/// events owner, and the admission principal. The events owner never comes
/// from the agent arm: an event subscription is re-checked at each delivery
/// by its gateway credential, and an agent-only caller has none to
/// re-check, so it stays without an events principal (MIK-8055 K6).
///
/// With authentication off, a caller with a proven subject (an mTLS
/// certificate, a grant) owns its tasks by that subject, never by the pooled
/// anonymous owner, so two such callers cannot read or cancel each other's
/// tasks (MIK-8193).
///
/// The admission principal is the owner itself, except the pooled anonymous
/// owner, which is no principal (a keyed sync call stays refused). The
/// synchronous lease admits under it, so one key cannot admit one operation
/// once per spelling (MIK-8193).
pub(in crate::gateway::router) struct TaskOwners {
    pub(in crate::gateway::router) task: String,
    pub(in crate::gateway::router) events: String,
    pub(in crate::gateway::router) admission: String,
}

/// The owner a gateway with authentication switched off records tasks under.
///
/// A gateway-internal constant, never anything the request carried: an owner
/// derived from request data would let a caller name its own bucket. It cannot
/// collide with a verified identity (`stable_actor_id` always prefixes `oidc:`)
/// nor with a session key (`credential:`), and it is non-empty because the
/// admission request refuses an empty principal.
pub(super) const AUTH_DISABLED_TASK_OWNER: &str = "local:auth-disabled:tasks:v1";

/// The owner key of a stateless task: the validated API-key credential. Only
/// `route_task_owner` reads it (the firewall keys on `identity::caller_key`);
/// tasks keep this encoding so an upgrade does not orphan stored ones. Empty
/// when the caller is unauthenticated: that is not an identity by itself, but
/// `route_task_owner` may still give a validated agent token its own owner.
fn session_owner_key(client: Option<&crate::gateway::auth::AuthenticatedClient>) -> String {
    client
        .and_then(|c| c.credential_principal())
        .map_or_else(String::new, |principal| {
            format!(
                "{}{}",
                crate::gateway::auth::CREDENTIAL_OWNER_PREFIX,
                principal.storage_form()
            )
        })
}

/// The owner key a task records when the caller has no OIDC identity: the
/// proven subject when one resolved, else the credential.
///
/// A subject outranks the credential as it does for sessions
/// (`handlers::owner::owner_of`), so two people a trusted proxy, Cloudflare
/// Access or a client certificate names behind one shared key never own one
/// task (MIK-7967). A subject only SPLITS a credential's bucket: with no
/// credential the key stays empty, so a subject header alone owns nothing and
/// the unattributed gate still refuses it.
pub(super) fn task_owner_key(proven: Option<&str>, client: Option<&AuthenticatedClient>) -> String {
    let credential = session_owner_key(client);
    if credential.is_empty() {
        return credential;
    }
    proven.map_or(credential, ToOwned::to_owned)
}

/// The ONE owner every task-touching arm of a request uses.
///
/// Resolved once per request and then reused for create, get, update, cancel,
/// idempotent replay and subscription ownership. Two renderings of one caller
/// is how a task is created under one string and looked up under another.
pub(super) fn route_task_owner(
    state: &AppState,
    verified_identity: Option<&VerifiedIdentity>,
    agent: Option<&OAuthAgentIdentity>,
    owner_key: &str,
) -> String {
    match verified_identity {
        Some(identity) => identity.stable_actor_id(),
        // Agent auth runs whether or not gateway auth does, so with gateway
        // auth off a validated agent JWT is still an identity: pooling it with
        // every other agent would let one read and cancel another's tasks
        // (MIK-8031).
        //
        // With authentication ON the owner key decides (`task_owner_key`:
        // proven subject, else credential). A validated agent with no gateway
        // credential (a public path) owns as its `client_id`, the same owner
        // it has with auth off (MIK-8055). With neither, the owner is empty
        // and refused upstream rather than pooled here.
        None if !state.live_config.generation().auth().enabled || owner_key.is_empty() => {
            match agent {
                Some(agent) => agent_task_owner(&agent.client_id),
                None if !state.live_config.generation().auth().enabled => {
                    AUTH_DISABLED_TASK_OWNER.to_owned()
                }
                None => String::new(),
            }
        }
        None => owner_key.to_owned(),
    }
}

/// [`route_task_owner`] for a request, then its events owner. The events
/// owner never comes from the agent arm: an event subscription is re-checked
/// at each delivery by its gateway credential, and an agent-only caller has
/// none to re-check, so it stays without an events principal (MIK-8055 K6).
///
/// With authentication off, a caller with a proven subject (an mTLS
/// certificate, a grant) owns its tasks by that subject, never by the pooled
/// anonymous owner, so two such callers cannot read or cancel each other's
/// tasks (MIK-8193).
///
/// Also returns the admission principal: the owner itself, except the pooled
/// anonymous owner, which is no principal (a keyed sync call stays refused).
/// The synchronous lease admits under it, so one key cannot admit one
/// operation once per spelling (MIK-8193).
pub(in crate::gateway::router) fn route_owners(
    state: &AppState,
    caller: &TaskCaller<'_>,
) -> TaskOwners {
    let proven = super::super::super::identity::subject_key(caller.subject, caller.cert);
    let owner_key = task_owner_key(proven.as_deref(), caller.client);
    // `via_agent` is the agent arm this owner may use: the task owner passes
    // the request's agent, the events owner never does (MIK-8055 K6).
    let route = |via_agent: Option<&OAuthAgentIdentity>| match (via_agent, &proven) {
        (None, Some(subject))
            if !state.live_config.generation().auth().enabled
                && caller.verified_identity.is_none() =>
        {
            subject.clone()
        }
        _ => route_task_owner(state, caller.verified_identity, via_agent, &owner_key),
    };
    let owner = route(caller.agent);
    let admission = if owner == AUTH_DISABLED_TASK_OWNER {
        String::new()
    } else {
        owner.clone()
    };
    TaskOwners {
        task: owner,
        events: route(None),
        admission,
    }
}

/// The owner of a validated agent's tasks on a gateway with auth off.
///
/// The `client_id` enters as its SHA-256 digest: a fixed 74-byte owner fits task
/// admission's metadata bound whatever the id's length, and no `client_id` can
/// spell another's owner. Prefixed apart from `oidc:`, `credential:`,
/// `subject:` and `local:`. `client_id` is the agent registry's key, so two
/// agents never share one owner.
fn agent_task_owner(client_id: &str) -> String {
    format!(
        "agent-jwt:{}",
        crate::hashing::sha256_hex(client_id.as_bytes())
    )
}

#[cfg(test)]
mod agent_owner_tests;
#[cfg(test)]
mod owners_tests;

#[cfg(test)]
mod mik_8659_owner_tests {
    fn client(authenticated: bool, principal: &str) -> crate::gateway::auth::AuthenticatedClient {
        crate::gateway::auth::AuthenticatedClient {
            name: "k".to_owned(),
            rate_limit: 0,
            backends: vec!["*".to_owned()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            // MIK-6704.IDENT.1a: a synthetic fixture, not an authorization path.
            principal: crate::gateway::record_principal::InternalPrincipal::new(
                principal.to_owned(),
            ),
            quota_principal: None,
            authenticated,
            credential_kind: crate::security::audit::CredentialKind::ApiKey,
        }
    }

    /// MIK-8659 T2 (GREEN): the task owner key needs an authenticated
    /// non-empty principal; `{false, "p"}` and `{true, ""}` give no key.
    #[test]
    fn t2_task_owner_key_needs_a_principal() {
        assert_eq!(super::session_owner_key(None), "");
        let unauthenticated = client(false, "p");
        assert_eq!(super::session_owner_key(Some(&unauthenticated)), "");
        let empty = client(true, "");
        assert_eq!(super::session_owner_key(Some(&empty)), "");
        let ok = client(true, "p");
        assert_eq!(
            super::session_owner_key(Some(&ok)),
            format!("{}{}", crate::gateway::auth::CREDENTIAL_OWNER_PREFIX, "p")
        );
    }
}
