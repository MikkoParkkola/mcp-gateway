// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8518 T2: every router `InvokeScope` builder admits only an API key
//! for an `api_key:<name>` grant.
//!
//! One row per builder, each driving the builder through its real entry
//! with two callers sharing the display name `bearer`: the static bearer
//! (`CredentialKind::StaticBearer`, refused) and an authenticated API key
//! (`CredentialKind::ApiKey`, admitted), against a personal capability
//! with an `api_key:bearer` grant. The Bearer [REDACTED] is RED on the base:
//! the builder hands the display name to the grant fallback, so the bearer
//! matches a grant written for the key. The API-key row is green on the
//! base, by design.

use std::sync::Arc;

use serde_json::json;

use super::direct_guards_fixture::{
    Answer, BEARER_SECRET, fixture_with_bearer, post_direct, post_meta_invoke, sanitizing, send,
};
use crate::capability::{CapabilityBackend, CapabilityExecutor};
use crate::config::SurfacedToolConfig;
use crate::events::ApiKeyRef;
use crate::events::watch_source::{CredentialUse, Holder, Target, WatchHost};
use crate::gateway::auth::principal_of;
use crate::gateway::streaming::{ResolvedCaller, ViewSubject};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, LocalIdentityGrantStore,
};

/// The API key's token: `fixture_with_bearer` names the key `bearer`, and a
/// key's token is its name.
const KEY: &str = "bearer";
/// The direct route's served marker (`Answer::Text` payload).
const DIRECT_MARKER: &str = "grant-key-direct-served";
/// The probe capability's served marker.
const PROBE_MARKER: &str = "served-probe";

/// A loopback probe answering one static marker, the
/// `identity_collapse_tests.rs` shape without its hit counter.
async fn start_probe() -> u16 {
    // port-check: the listener serves on in the spawned task
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the probe binds loopback");
    let port = listener.local_addr().expect("the probe has a port").port();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/probe",
            axum::routing::get(|| async { axum::Json(json!({"answer": PROBE_MARKER})) }),
        );
        axum::serve(listener, app).await.expect("the probe serves");
    });
    port
}

/// A personal REST capability `tool` on backend `backend`, owned by
/// `api_key:bearer`: the `identity_collapse_tests.rs` shape without its
/// cache block.
async fn personal_caps(
    backend: &str,
    tool: &str,
    base_url: &str,
) -> (Arc<CapabilityBackend>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("a dir for the fixture capability");
    std::fs::write(
        dir.path().join(format!("{tool}.yaml")),
        format!(
            "name: {tool}\ndescription: MIK-8518 personal probe\nmetadata:\n  read_only: true\n  exposure: personal\n  identity_owner:\n    authority: 'api_key'\n    subject: 'bearer'\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: '{base_url}'\n      path: /probe\n      method: GET\n"
        ),
    )
    .expect("the fixture capability writes");
    let executor = CapabilityExecutor::new().with_test_http_client(reqwest::Client::new());
    let caps = Arc::new(CapabilityBackend::new(backend, Arc::new(executor)));
    caps.load_from_directory(dir.path().to_str().expect("a utf-8 temp path"))
        .await
        .expect("the fixture capability loads");
    (caps, dir)
}

/// One live `api_key:bearer` grant for `tool`: any agent, execute scope,
/// the grant's owner equal to its subject.
fn bearer_grant(tool: &str) -> IdentityGrant {
    let subject =
        GrantSubject::checked("api_key", "bearer", None).expect("api_key:bearer names someone");
    IdentityGrant {
        grant_id: format!("g-8518-{tool}"),
        subject: subject.clone(),
        agent: GrantAgent::Any,
        capability: tool.to_string(),
        tool: None,
        scope: GrantScope::Execute,
        owner: Some(subject),
        expires_at: None,
        revoked_at: None,
        provenance: "unit-test".to_string(),
        reason: "MIK-8518 T2".to_string(),
    }
}

/// The `handlers.rs:129` scope, through `gateway_invoke` of the personal
/// capability: the static bearer is refused. RED on the base: the route
/// check admits it through the fallback and the probe answers.
#[tokio::test]
async fn handlers_tools_call_refuses_the_static_bearer_for_an_api_key_grant() {
    let port = start_probe().await;
    let (caps, _dir) = personal_caps("caps", "probe", &format!("http://localhost:{port}")).await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = fixture_with_bearer(Answer::Ok, {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let (_, body) =
        post_meta_invoke(&fx, BEARER_SECRET, "caps", "probe", json!({}), None, None).await;
    assert_eq!(
        body["error"]["code"],
        json!(-32001),
        "the static caller is refused at the grant as not found: {body}"
    );
    assert_eq!(
        body["error"]["message"],
        json!("Tool not found: 'probe'"),
        "the static caller is refused at the grant as not found: {body}"
    );
    assert!(
        !body.to_string().contains("caller identity is required"),
        "the call stopped at the grant, before execution: {body}"
    );
    assert!(body.get("error").is_some(), "the bearer is refused: {body}");
    assert!(
        !body.to_string().contains(PROBE_MARKER),
        "the bearer is refused: {body}"
    );
}

/// The `handlers.rs:129` scope, through `gateway_invoke`: the API key is
/// admitted by its own grant. Green on the base, by design: the grant admits
/// and execution then fails, since an API-key caller has no propagated caller
/// identity (`execution_context.rs:507-510`), so the row pins the grant
/// decision, not the execution result.
#[tokio::test]
async fn handlers_tools_call_admits_the_api_key_for_its_grant() {
    let port = start_probe().await;
    let (caps, _dir) = personal_caps("caps", "probe", &format!("http://localhost:{port}")).await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = fixture_with_bearer(Answer::Ok, {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let (_, body) = post_meta_invoke(&fx, KEY, "caps", "probe", json!({}), None, None).await;
    assert!(
        !body.to_string().contains("Identity grant denied"),
        "the key passes its grant: {body}"
    );
    assert!(
        body.to_string().contains("caller identity is required"),
        "the key passes its grant to execution: {body}"
    );
}

/// The `dispatch_intake_run.rs:275` scope, observed at intake itself: with
/// sanitizing on, intake's scope judges the surfaced personal name first
/// and records the visibility memo, so a bearer the memo withholds answers
/// as an absent name (`-32601`), never a dispatch denial. RED on the base:
/// the memo admits it through the fallback and the probe answers.
#[tokio::test]
async fn intake_withholds_a_surfaced_personal_name_from_the_static_bearer() {
    let port = start_probe().await;
    let (caps, _dir) = personal_caps("caps", "probe", &format!("http://localhost:{port}")).await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = Box::pin(sanitizing(
        true,
        fixture_with_bearer(Answer::Ok, {
            let caps = Arc::clone(&caps);
            move |meta| {
                let meta = meta.with_surfaced_tools(vec![SurfacedToolConfig {
                    server: "caps".to_string(),
                    tool: "probe".to_string(),
                }]);
                meta.set_capabilities(caps);
                meta.set_identity_grants(grants);
                meta
            }
        }),
    ))
    .await;
    let (_, body) = send(
        &fx,
        "/mcp",
        BEARER_SECRET,
        "tools/call",
        json!({"name": "probe", "arguments": {}}),
        None,
    )
    .await;
    assert_eq!(
        body["error"]["code"],
        json!(-32601),
        "intake withholds the name at the grant (visibility): {body}"
    );
    assert!(
        !body.to_string().contains(PROBE_MARKER),
        "intake withholds the name at the grant (visibility): {body}"
    );
}

/// The `dispatch_intake_run.rs:275` scope, through the surfaced name: the
/// API key is admitted by its own grant. Green on the base, by design: the
/// grant admits and execution then fails, since an API-key caller has no
/// propagated caller identity (`execution_context.rs:507-510`), so the row
/// pins the grant decision, not the execution result.
#[tokio::test]
async fn intake_shows_a_surfaced_personal_name_to_the_api_key() {
    let port = start_probe().await;
    let (caps, _dir) = personal_caps("caps", "probe", &format!("http://localhost:{port}")).await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = Box::pin(sanitizing(
        true,
        fixture_with_bearer(Answer::Ok, {
            let caps = Arc::clone(&caps);
            move |meta| {
                let meta = meta.with_surfaced_tools(vec![SurfacedToolConfig {
                    server: "caps".to_string(),
                    tool: "probe".to_string(),
                }]);
                meta.set_capabilities(caps);
                meta.set_identity_grants(grants);
                meta
            }
        }),
    ))
    .await;
    let (_, body) = send(
        &fx,
        "/mcp",
        KEY,
        "tools/call",
        json!({"name": "probe", "arguments": {}}),
        None,
    )
    .await;
    assert_ne!(
        body["error"]["code"],
        json!(-32601),
        "the key is shown the name: {body}"
    );
    assert!(
        !body.to_string().contains("Identity grant denied"),
        "the key passes its grant: {body}"
    );
    assert!(
        body.to_string().contains("caller identity is required"),
        "the key passes its grant to execution: {body}"
    );
}

/// The `view_judge.rs:172` scope, through the streaming judge's `digest`:
/// the static bearer is shown nothing of the granted capability. RED on
/// the base: its digest carries the capability through the fallback.
#[tokio::test]
async fn view_judge_hides_a_granted_capability_from_the_static_bearer() {
    let (caps, _dir) = personal_caps("caps", "probe", "https://example.invalid").await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = fixture_with_bearer(Answer::Ok, {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let Some((bearer, _)) = fx
        .state
        .live_config
        .generation()
        .auth()
        .validate_token_with_origin(BEARER_SECRET)
    else {
        panic!("the fixture static bearer resolves");
    };
    let judge = super::view_judge::OwnedViewJudge::shared(&fx.state);
    let digest = judge.digest(
        &ResolvedCaller {
            client: bearer,
            identity: None,
            agent: None,
        },
        &ViewSubject::default(),
        "",
        "caps",
    );
    assert!(
        digest.shown.is_empty(),
        "the Bearer [REDACTED] shown nothing: {}",
        digest.shown
    );
}

/// The `view_judge.rs:172` scope, through the streaming judge's `digest`:
/// the API key is shown its granted capability. Green on the base, by
/// design.
#[tokio::test]
async fn view_judge_shows_a_granted_capability_to_the_api_key() {
    let (caps, _dir) = personal_caps("caps", "probe", "https://example.invalid").await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = fixture_with_bearer(Answer::Ok, {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let Some((key, _)) = fx
        .state
        .live_config
        .generation()
        .auth()
        .validate_token_with_origin(KEY)
    else {
        panic!("the fixture api key resolves");
    };
    let judge = super::view_judge::OwnedViewJudge::shared(&fx.state);
    let digest = judge.digest(
        &ResolvedCaller {
            client: key,
            identity: None,
            agent: None,
        },
        &ViewSubject::default(),
        "",
        "caps",
    );
    assert!(!digest.shown.is_empty(), "the key is shown its capability");
}

/// The `direct_permit.rs:44` scope, through the direct route: the static
/// bearer is refused. The capability backend shares the registry backend's
/// name (`alpha`), which is the only shape under which the direct route's
/// chokepoint judges a personal grant at all. RED on the base: the permit
/// admits it through the fallback and the backend answers.
#[tokio::test]
async fn direct_permit_refuses_the_static_bearer_for_an_api_key_grant() {
    let (caps, _dir) = personal_caps("alpha", "read", "https://example.invalid").await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("read")]);
    let fx = fixture_with_bearer(Answer::Text(DIRECT_MARKER), {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let (_, body) = post_direct(&fx, "alpha", BEARER_SECRET, "read", json!({}), None, None).await;
    assert_eq!(
        body["error"]["code"],
        json!(-32004),
        "the static caller is refused at the grant: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("Identity grant denied")),
        "the static caller is refused at the grant: {body}"
    );
    assert!(
        !body.to_string().contains(DIRECT_MARKER),
        "the bearer is refused: {body}"
    );
}

/// The `direct_permit.rs:44` scope, through the direct route: the API key
/// is admitted by its own grant. Green on the base, by design.
#[tokio::test]
async fn direct_permit_admits_the_api_key_for_its_grant() {
    let (caps, _dir) = personal_caps("alpha", "read", "https://example.invalid").await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("read")]);
    let fx = fixture_with_bearer(Answer::Text(DIRECT_MARKER), {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let (_, body) = post_direct(&fx, "alpha", KEY, "read", json!({}), None, None).await;
    assert!(
        body.to_string().contains(DIRECT_MARKER),
        "the key is admitted: {body}"
    );
}

/// The `watch_poll.rs:197` scope, through the watch host's `may_invoke`:
/// the API key is admitted by its own grant. Green on the base, by design.
/// There is no bearer row: the holder's client comes only from
/// `client_for_key_at`, which resolves API keys, so no other credential
/// can reach this builder.
#[tokio::test]
async fn watch_poll_admits_the_api_key_for_its_grant() {
    let (caps, _dir) = personal_caps("caps", "probe", "https://example.invalid").await;
    let grants = LocalIdentityGrantStore::from_grants([bearer_grant("probe")]);
    let fx = fixture_with_bearer(Answer::Ok, {
        let caps = Arc::clone(&caps);
        move |meta| {
            meta.set_capabilities(caps);
            meta.set_identity_grants(grants);
            meta
        }
    })
    .await;
    let host = super::watch_poll::GatewayWatchHost::new(&fx.state);
    let holder = Holder {
        principal: "subscriber".to_string(),
        api_key: ApiKeyRef {
            name: KEY.to_string(),
            principal: principal_of(KEY).storage_form().to_owned(),
        },
    };
    let target = Target {
        capability: "probe".to_string(),
        backend: "caps".to_string(),
        read_only: true,
        credential: CredentialUse::Keyed,
        input_schema: json!({}),
    };
    assert!(
        host.may_invoke(
            &holder,
            &target,
            crate::clock::utc_now().expect("a readable clock")
        ),
        "the api key keeps its grant"
    );
}
