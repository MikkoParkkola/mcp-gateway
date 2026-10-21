// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8518 T1: an `api_key:<name>` grant subject names one API key, never
//! another credential.
//!
//! The identity-grant fallback builds its subject from the caller's display
//! name (`visibility.rs:435-438`), so the static bearer (`bearer`), the
//! dashboard session (`dashboard`), the auth-off caller (`anonymous`), the
//! public-path caller (`public`) and every other credential without a
//! verified subject match grants written for an API key of that name. After
//! the fix only an authenticated API-key credential gets the
//! `api_key:<name>` fallback.
//!
//! Each row builds a [`MetaMcpCallerContext`] the way
//! `cost_key_caller_tests.rs` does and judges it through
//! `may_invoke(..., ctx.scope(), ...)`, with the personal capability plus
//! one identity grant from `grant_agent_key_tests.rs`. Every row is RED on
//! the base except the two whose doc comments say green by design.

use std::sync::Arc;

use super::{Authentication, MetaMcp, MetaMcpCallerContext, anonymous_caller};
use crate::backend::BackendRegistry;
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};
use crate::security::audit::CredentialKind;

const SERVER: &str = "personal_caps";
const TOOL: &str = "calendar_read";

/// A personal capability owned by `(authority, subject)`: the
/// `grant_agent_key_tests.rs` shape with the owner parameterized, so the
/// grant below is the deciding factor.
fn capability_yaml(authority: &str, subject: &str) -> String {
    format!(
        "fulcrum: '1.0'\nname: {TOOL}\ndescription: Read a personal calendar\nschema:\n  input:\n    type: object\n  output:\n    type: object\nmetadata:\n  exposure: personal\n  identity_owner:\n    authority: '{authority}'\n    subject: '{subject}'\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: 'https://example.invalid'\n      path: /calendar\n      method: GET\n"
    )
}

/// One live grant for `(authority, subject)` on [`TOOL`]: any agent, execute
/// scope, the grant's owner equal to its subject, so the caller's identity
/// is what admits or refuses.
fn grant_for(authority: &str, subject: &str) -> IdentityGrant {
    let grant_subject = GrantSubject::checked(authority, subject, None)
        .expect("a test grant subject names someone");
    IdentityGrant {
        grant_id: "g-8518".to_string(),
        subject: grant_subject.clone(),
        agent: GrantAgent::Any,
        capability: TOOL.to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: Some(grant_subject),
        expires_at: None,
        revoked_at: None,
        provenance: "unit-test".to_string(),
        reason: "MIK-8518".to_string(),
    }
}

async fn meta_with_grant_for(authority: &str, subject: &str) -> (MetaMcp, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("a dir for the fixture capability");
    std::fs::write(
        dir.path().join(format!("{TOOL}.yaml")),
        capability_yaml(authority, subject),
    )
    .expect("the fixture capability writes");
    let caps = Arc::new(CapabilityBackend::new(
        SERVER,
        Arc::new(CapabilityExecutor::new()),
    ));
    caps.load_from_directory(dir.path().to_str().expect("a utf-8 temp path"))
        .await
        .expect("the fixture capability loads");
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new())).with_identity_grants(
        LocalIdentityGrantStore::from_grants([grant_for(authority, subject)]),
    );
    meta.set_capabilities(caps);
    (meta, dir)
}

/// A caller of `kind`, the way `cost_key_caller_tests.rs` builds one, with
/// `authentication` set explicitly: the fixture's variable under test.
fn caller(
    kind: CredentialKind,
    authentication: Authentication,
    api_key_name: Option<&'static str>,
    grant_subject: Option<GrantSubject>,
) -> MetaMcpCallerContext<'static> {
    MetaMcpCallerContext {
        api_key_name,
        credential_kind: kind,
        authentication,
        grant_subject,
        ..anonymous_caller()
    }
}

/// The grant refusal every negative row pins: "Identity grant denied".
fn assert_refused(result: crate::Result<()>, who: &str) {
    let Err(refusal) = result else {
        panic!("{who}: admitted, want the identity-grant refusal");
    };
    assert!(
        refusal.to_string().contains("Identity grant denied"),
        "{who}: {refusal}"
    );
}

/// T1 positive: an authenticated API key named `bearer` matches its own
/// `api_key:bearer` grant. Green on the base, by design.
#[tokio::test]
async fn an_authenticated_api_key_matches_its_own_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::ApiKey,
        Authentication::Authenticated,
        Some("bearer"),
        None,
    );
    if let Err(refusal) = meta.may_invoke(SERVER, TOOL, ctx.scope(), None) {
        panic!("the API key is refused by its own grant: {refusal}");
    }
}

/// T1: the static bearer named `bearer` is refused against `api_key:bearer`.
/// RED on the base: the fallback turns its display name into the grant
/// subject and admits it.
#[tokio::test]
async fn the_static_bearer_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::StaticBearer,
        Authentication::Authenticated,
        Some("bearer"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "static bearer",
    );
}

/// T1-dashboard: the dashboard session named `dashboard` is refused against
/// `api_key:dashboard`. RED on the base: admitted through the fallback.
#[tokio::test]
async fn the_dashboard_session_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "dashboard").await;
    let ctx = caller(
        CredentialKind::DashboardSession,
        Authentication::Authenticated,
        Some("dashboard"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "dashboard session",
    );
}

/// T1b: the auth-off caller named `anonymous` is refused against
/// `api_key:anonymous`. RED on the base: admitted through the fallback.
#[tokio::test]
async fn the_anonymous_caller_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "anonymous").await;
    let ctx = caller(
        CredentialKind::None,
        Authentication::Anonymous,
        Some("anonymous"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "anonymous caller",
    );
}

/// T1b: the public-path caller named `public` is refused against
/// `api_key:public`. RED on the base: admitted through the fallback.
#[tokio::test]
async fn the_public_caller_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "public").await;
    let ctx = caller(
        CredentialKind::None,
        Authentication::Anonymous,
        Some("public"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "public caller",
    );
}

/// T1c: a key-server caller named `bearer` with no verified subject is
/// refused against `api_key:bearer`. RED on the base: admitted through the
/// fallback. A synthetic defence-in-depth row: production refuses a
/// nameless key-server identity at `key_server/mod.rs:128-130`, so no
/// key-server caller reaches the fallback; the row pins the fallback
/// predicate anyway.
#[tokio::test]
async fn a_key_server_caller_without_a_verified_subject_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::KeyServerToken,
        Authentication::Authenticated,
        Some("bearer"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "key-server caller",
    );
}

/// T1d: an OIDC bearer named `bearer` with no verified subject is refused
/// against `api_key:bearer`. RED on the base: admitted through the
/// fallback.
#[tokio::test]
async fn an_oidc_bearer_without_a_verified_subject_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::OidcBearer,
        Authentication::Authenticated,
        Some("bearer"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "oidc bearer",
    );
}

/// T1d: a local-transport caller named `bearer` with no verified subject is
/// refused against `api_key:bearer`. RED on the base: admitted through the
/// fallback.
#[tokio::test]
async fn a_local_transport_caller_without_a_verified_subject_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::LocalTransport,
        Authentication::Authenticated,
        Some("bearer"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "local transport",
    );
}

/// T1e positive precedence: a caller with a verified subject is decided by
/// that subject, never by `api_key:<name>`. With only the `api_key:bearer`
/// grant it is refused (its subject is not the owner); with only its own
/// `(issuer, subject)` grant it is admitted. Green on the base, by design:
/// the verified-subject arm is untouched by the bug.
#[tokio::test]
async fn a_verified_subject_decides_precedence_over_the_api_key_name() {
    let verified = GrantSubject::checked("https://idp.example", "alice", None)
        .expect("a verified test subject");
    let ctx = || {
        caller(
            CredentialKind::ApiKey,
            Authentication::Authenticated,
            Some("bearer"),
            Some(verified.clone()),
        )
    };
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx().scope(), None),
        "api_key grant only",
    );
    let (meta, _dir) = meta_with_grant_for("https://idp.example", "alice").await;
    if let Err(refusal) = meta.may_invoke(SERVER, TOOL, ctx().scope(), None) {
        panic!("the verified subject is refused by its own grant: {refusal}");
    }
}

/// T1f: an API-key credential that did not authenticate is refused against
/// `api_key:bearer`: the fallback needs authentication, not just the kind.
/// RED on the base: the fallback reads the display name alone and admits
/// it.
#[tokio::test]
async fn an_unauthenticated_api_key_credential_does_not_match_an_api_key_grant() {
    let (meta, _dir) = meta_with_grant_for("api_key", "bearer").await;
    let ctx = caller(
        CredentialKind::ApiKey,
        Authentication::Anonymous,
        Some("bearer"),
        None,
    );
    assert_refused(
        meta.may_invoke(SERVER, TOOL, ctx.scope(), None),
        "unauthenticated api-key credential",
    );
}
