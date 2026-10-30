// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `events/lease` at the hub: only the
//! owner's live row on that passthrough backend takes a lease, and only a
//! token with an `exp`.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use zeroize::Zeroizing;

use crate::events::lease::{LeaseKey, LeaseState};
use crate::events::observation::observe_subscriber;
use crate::events::{EventsHub, LiveCredentials, Services};
use crate::key_server::oidc::VerifiedIdentity;

const CONFIG: &str = "backends:\n  \
     pt:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n  \
     other:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: passthrough\n      audience: https://other\n      session_mode: per_user\n  \
     signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: signed_assertion\n      audience: https://s\n      session_mode: per_user\n  \
     agent:\n    a2a_url: https://agent.test\n    identity_propagation:\n      \
     strategy: signed_assertion\n      audience: https://agent\n      session_mode: per_user\n";

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@mail.test"),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

fn token(exp: Option<u64>) -> Zeroizing<String> {
    let claims = match exp {
        Some(exp) => json!({"sub": "p", "exp": exp}),
        None => json!({"sub": "p"}),
    };
    Zeroizing::new(format!(
        "Bearer {}.{}.sig",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    ))
}

fn in_an_hour() -> u64 {
    crate::clock::unix_secs().expect("clock") + 3600
}

struct Fixture {
    hub: Arc<EventsHub>,
    config: Arc<crate::config::Config>,
    dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    fixture_with(CONFIG)
}

fn fixture_with(yaml: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config: crate::config::Config = crate::yaml::from_str(yaml).expect("config");
    let live = Arc::new(crate::config_reload::LiveConfig::new(config));
    let config = live.get();
    let _ = hub.runtime.services.set(Arc::new(Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }));
    Fixture { hub, config, dir }
}

/// Commit `principal`'s row on `backend`, observed as `subject`; its handle.
fn subscribe(f: &Fixture, principal: &str, backend: &str, subject: &str) -> String {
    let now = crate::clock::utc_now().expect("clock");
    let mut row: crate::events::records::Subscription = serde_json::from_value(json!({
        "v": 1, "id": format!("sub_{principal}_{backend}"), "principal": principal,
        "api_key": null, "url": "https://cb.test/hook",
        "name": format!("backend.{backend}.tools_changed"), "arguments": {},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": now, "expires_at": now + crate::duration_bound::delta!(hours, 1), "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    row.credential_kind = Some(crate::security::audit::CredentialKind::None);
    let observed = observe_subscriber(&f.config, backend, Some(&person(subject)))
        .expect("observes")
        .expect("per-user");
    row.obs_basis = Some(observed);
    row.observed_identity = Some(person(subject));
    let id = row.id.clone();
    f.hub
        .store
        .admit(
            row,
            true,
            crate::events::store::Caps {
                per_principal: 10,
                global: 10,
            },
            chrono::Duration::zero(),
            now,
            crate::events::tail_policy(&crate::config::EventsConfig::default()),
        )
        .expect("io")
        .expect("admitted");
    f.hub.handle(&id).expect("handle")
}

fn lease_key(f: &Fixture, subject: &str) -> LeaseKey {
    LeaseKey {
        backend: "pt".into(),
        obs: crate::events::observation::binding(&f.config, "pt")
            .expect("per-user")
            .observe(&person(subject))
            .expect("observes"),
    }
}

#[tokio::test]
async fn the_owner_leases_their_own_row() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let answer = f
        .hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect("leased");
    assert_eq!(answer["state"], "active");
    assert!(matches!(
        f.hub.leases.state(&lease_key(&f, "p")).await,
        LeaseState::Active { .. }
    ));
    assert_eq!(
        f.hub.held_leases().await,
        1,
        "the count LEASE-T0 reads sees it"
    );
}

/// LEASE-T9 / E3: a handle on backend `other` is refused on `/mcp/pt`.
#[tokio::test]
async fn lease_t9_a_handle_on_another_backend_is_refused() {
    let f = fixture();
    let handle = subscribe(&f, "p", "other", "p");
    let refused = f
        .hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect_err("another backend's row");
    assert_eq!(refused.code, -32012);
    assert_eq!(
        f.hub.leases.state(&lease_key(&f, "p")).await,
        LeaseState::CredentialNeeded
    );
}

#[tokio::test]
async fn another_principals_handle_is_refused() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let refused = f
        .hub
        .lease(
            Some("q"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect_err("not q's row");
    assert_eq!(refused.code, -32012);
    assert_eq!(
        f.hub.leases.state(&lease_key(&f, "p")).await,
        LeaseState::CredentialNeeded,
        "q's token never reaches p's lease"
    );
}

#[tokio::test]
async fn a_backend_that_is_not_passthrough_takes_no_lease() {
    let f = fixture();
    let handle = subscribe(&f, "p", "signed", "p");
    let refused = f
        .hub
        .lease(
            Some("p"),
            "signed",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect_err("signed assertion mints its own");
    assert_eq!(refused.code, -32012);
}

#[tokio::test]
async fn a_missing_token_or_handle_is_invalid_and_no_principal_is_forbidden() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let params = json!({ "subscription": handle });
    let no_token = f.hub.lease(Some("p"), "pt", Some(&params), None).await;
    assert_eq!(no_token.err().map(|e| e.code), Some(-32602));
    let no_handle = f
        .hub
        .lease(Some("p"), "pt", None, Some(token(Some(in_an_hour()))))
        .await;
    assert_eq!(no_handle.err().map(|e| e.code), Some(-32602));
    let anonymous = f
        .hub
        .lease(None, "pt", Some(&params), Some(token(Some(in_an_hour()))))
        .await;
    assert_eq!(anonymous.err().map(|e| e.code), Some(-32012));
}

/// LEASE-T1 at the wire: a token with no `exp` is refused `-32014`.
#[tokio::test]
async fn a_token_without_exp_is_refused_with_its_reason() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let refused = f
        .hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(None)),
        )
        .await
        .expect_err("no exp");
    assert_eq!(refused.code, -32014);
    assert_eq!(
        refused.data.as_ref().and_then(|d| d.get("reason")),
        Some(&json!("passthrough_token_no_expiry"))
    );
}

/// L4 / LEASE-T3: the subscriber's last interest on the backend ends their
/// lease; an interest that remains keeps it.
#[tokio::test]
async fn the_last_interest_on_the_backend_wipes_the_lease() {
    use crate::events::EventSource;
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    f.hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect("leased");
    let key = lease_key(&f, "p");
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(Arc::new(crate::backend::Backend::new(
        "pt",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))));
    let listeners = crate::events::upstream_listener::UpstreamListeners::new(
        registry,
        Arc::downgrade(&f.hub),
        Arc::new(std::collections::BTreeSet::new),
    );
    let source = crate::events::backend_source::BackendSource {
        names: Arc::new(|| vec!["pt".to_owned()]),
        upstream: Some(crate::events::backend_source::Upstream {
            listeners,
            ineligible: Arc::new(std::collections::BTreeSet::new),
        }),
    };
    let lifecycle = |name: &str| {
        crate::events::backend_source::backend_key(Some(&key.obs), name, &json!({})).expect("key")
    };
    let (tools, prompts) = ("backend.pt.tools_changed", "backend.pt.prompts_changed");
    for name in [tools, prompts] {
        source
            .on_first_subscriber(&lifecycle(name), "p", name, &json!({}))
            .await
            .expect("counted");
    }
    source.on_last_subscriber(&lifecycle(prompts)).await;
    assert!(
        matches!(f.hub.leases.state(&key).await, LeaseState::Active { .. }),
        "tools interest remains"
    );
    source.on_last_subscriber(&lifecycle(tools)).await;
    assert_eq!(f.hub.leases.state(&key).await, LeaseState::CredentialNeeded);
}

/// LEASE-T8 / E7: a passthrough subscriber with no lease is parked, with no
/// task and so no request; `events/lease` starts their listener.
#[tokio::test]
async fn lease_t8_no_listener_runs_until_the_lease() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    assert!(registry.register(Arc::new(crate::backend::Backend::new(
        "pt",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))));
    let listeners = crate::events::upstream_listener::UpstreamListeners::new(
        registry,
        Arc::downgrade(&f.hub),
        Arc::new(std::collections::BTreeSet::new),
    );
    f.hub
        .register_source(Arc::new(crate::events::backend_source::BackendSource {
            names: Arc::new(|| vec!["pt".to_owned()]),
            upstream: Some(crate::events::backend_source::Upstream {
                listeners: Arc::clone(&listeners),
                ineligible: Arc::new(std::collections::BTreeSet::new),
            }),
        }));
    let source = f
        .hub
        .source(crate::events::types::SourceKind::BackendNotification)
        .expect("registered");
    let key = lease_key(&f, "p");
    let name = "backend.pt.tools_changed";
    let lifecycle =
        crate::events::backend_source::backend_key(Some(&key.obs), name, &json!({})).expect("key");
    source
        .on_first_subscriber(&lifecycle, "p", name, &json!({}))
        .await
        .expect("parked, not refused");
    let starts = || listeners.starts.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(starts(), 0, "parked: no task, so no request");
    let listener = crate::events::upstream_listener::ListenerKey {
        backend: "pt".into(),
        obs: Some(key.obs.clone()),
    };
    assert!(listeners.holds(&listener), "the interest is counted");
    f.hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token(Some(in_an_hour()))),
        )
        .await
        .expect("leased");
    assert_eq!(starts(), 1, "the lease started the listener");
}

/// What a bearer-only peer saw: `(request, carried the token, carried the
/// backend's static header)`.
type Seen = Vec<(String, bool, bool)>;

/// A legacy Streamable HTTP peer at `/mcp` that answers nothing, its
/// `initialize` included, without `expected` as the `Authorization` header.
async fn bearer_only_peer(expected: String) -> (String, Arc<std::sync::Mutex<Seen>>) {
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    let log: Arc<std::sync::Mutex<Seen>> = Arc::default();
    let check = move |what: &str, h: &HeaderMap, log: &std::sync::Mutex<Seen>| {
        let authorized =
            h.get("authorization").and_then(|v| v.to_str().ok()) == Some(expected.as_str());
        let statics = h.contains_key("x-static");
        log.lock()
            .expect("log")
            .push((what.to_owned(), authorized, statics));
        authorized
    };
    let (get_check, get_log) = (check.clone(), Arc::clone(&log));
    let post_log = Arc::clone(&log);
    let app = axum::Router::new().route(
        "/mcp",
        axum::routing::get(move |headers: HeaderMap| async move {
            if !get_check("GET", &headers, &get_log) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            let body = async_stream::stream! {
                yield Ok::<_, std::io::Error>(": open\n\n".to_owned());
                std::future::pending::<()>().await;
            };
            (
                [("content-type", "text/event-stream")],
                axum::body::Body::from_stream(body),
            )
                .into_response()
        })
        .post(
            move |headers: HeaderMap, axum::Json(frame): axum::Json<serde_json::Value>| async move {
                let method = frame["method"].as_str().unwrap_or_default().to_owned();
                if !check(&method, &headers, &post_log) {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                let Some(id) = frame.get("id") else {
                    return StatusCode::ACCEPTED.into_response();
                };
                let answer = if method == "server/discover" {
                    json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": "not found"}})
                } else {
                    json!({"jsonrpc": "2.0", "id": id, "result": {}})
                };
                ([("mcp-session-id", "s-1")], axum::Json(answer)).into_response()
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("address"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, log)
}

/// A per-user listener reaches a backend that refuses every request without
/// its subscriber's own bearer: the era probe, `initialize` and the session
/// stream all carry the leased token on a transport of the listener's own,
/// none carries the backend's static header, and the shared slot (the
/// gateway's credential) never sends at all.
#[tokio::test]
async fn a_per_user_listener_handshakes_with_the_leased_token_alone() {
    let token = token(Some(in_an_hour()));
    let (url, seen) = bearer_only_peer(token.to_string()).await;
    let f = fixture_with(&format!(
        "backends:\n  pt:\n    http_url: {url}\n    streamable_http: true\n    \
         headers:\n      X-Static: gateway-key\n    identity_propagation:\n      \
         strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n"
    ));
    let handle = subscribe(&f, "p", "pt", "p");
    let (_listeners, backend) = parked_listener(&f).await;
    f.hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle })),
            Some(token),
        )
        .await
        .expect("leased");
    let opened = || seen.lock().expect("log").iter().any(|s| s.0 == "GET");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !opened() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let seen = seen.lock().expect("log").clone();
    let methods: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
    assert!(
        methods.starts_with(&[
            "server/discover",
            "initialize",
            "notifications/initialized",
            "GET"
        ]),
        "{seen:?}"
    );
    for (method, authorized, statics) in &seen {
        assert!(authorized, "{method}: the subscriber's own token: {seen:?}");
        assert!(!statics, "{method}: no static header of the gateway's");
    }
    assert_eq!(
        backend.connected_streamable(),
        None,
        "the shared slot never started"
    );
}

/// B3: a reload that changes a backend's identity config revokes the rows
/// observed under the old one; rows it leaves observable stay.
#[tokio::test]
async fn a_changed_identity_config_revokes_its_rows() {
    let f = fixture();
    let _ = subscribe(&f, "p", "pt", "p");
    let _ = subscribe(&f, "p", "other", "p");
    let services = f.hub.runtime.services.get().expect("services");
    let moved = CONFIG.replace("audience: https://pt\n", "audience: https://pt-v2\n");
    assert_ne!(moved, CONFIG, "premise: the audience changed");
    services
        .live
        .set(crate::yaml::from_str(&moved).expect("config"));
    f.hub.revoke_unobservable(None).await;
    let left: Vec<String> = f
        .hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(left, ["backend.other.tools_changed"], "{left:?}");
}

/// A2/B3: a record's stamp is its row's observation; a rotated lease, a
/// re-grant or a new identity config each make the row observe differently,
/// so a record stamped before it is buried at its send.
#[tokio::test]
async fn a_rotation_regrant_or_config_change_moves_the_observation() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let row = || {
        f.hub
            .store
            .subscriptions()
            .into_iter()
            .find(|s| s.name == "backend.pt.tools_changed")
            .expect("row")
    };
    let params = json!({ "subscription": handle });
    let lease = |exp: u64| {
        f.hub
            .lease(Some("p"), "pt", Some(&params), Some(token(Some(exp))))
    };
    lease(in_an_hour()).await.expect("leased");
    let stamp = f
        .hub
        .observed_now(&row(), &f.config, None)
        .expect("observable");
    assert!(stamp.as_ref().and_then(|s| s.lease.as_ref()).is_some());
    assert_eq!(
        f.hub.observed_now(&row(), &f.config, None),
        Ok(stamp.clone())
    );
    lease(in_an_hour() + 60).await.expect("replaced");
    assert_ne!(
        f.hub.observed_now(&row(), &f.config, None),
        Ok(stamp.clone()),
        "a rotated lease"
    );
    let mut regranted = row();
    regranted.incarnation += 1;
    assert_ne!(
        f.hub.observed_now(&regranted, &f.config, None),
        Ok(stamp.clone())
    );
    let moved: crate::config::Config = crate::yaml::from_str(
        &CONFIG.replace("audience: https://pt\n", "audience: https://pt-v2\n"),
    )
    .expect("config");
    assert!(
        f.hub.observed_now(&row(), &moved, None).is_err(),
        "unobservable"
    );
    let mut shared = row();
    shared.obs_basis = None;
    assert_eq!(f.hub.observed_now(&shared, &f.config, None), Ok(None));
}

/// C8 fallback: a per-user row whose subscriber no longer passes admission
/// is revoked, so its listener stops; an undatable refusal keeps it.
#[tokio::test(flavor = "current_thread")]
async fn a_subscriber_who_lost_admission_is_revoked() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let f = fixture();
    let _ = subscribe(&f, "p", "pt", "p");
    {
        let _undated = forced_verdict::answer(AccessVerdict::Undated);
        f.hub.revoke_inadmissible(None).await;
    }
    assert_eq!(
        f.hub.store.subscriptions().len(),
        1,
        "the clock's refusal keeps it"
    );
    {
        let _refused = forced_verdict::answer(AccessVerdict::Refuses);
        f.hub.revoke_inadmissible(None).await;
    }
    assert!(f.hub.store.subscriptions().is_empty(), "revoked");
}

/// L5: the admin view lists each passthrough subscription's held credential
/// by backend, handle, state and expiry, and never the token.
#[tokio::test]
async fn the_admin_view_lists_held_credentials_without_the_token() {
    let f = fixture();
    let handle = subscribe(&f, "p", "pt", "p");
    let _ = subscribe(&f, "p", "signed", "p");
    let listed = f.hub.list_leases().await;
    assert_eq!(listed.len(), 1, "only the passthrough row: {listed:?}");
    assert_eq!(listed[0]["state"], "credential_needed");
    let held = token(Some(in_an_hour()));
    let held_text = held.to_string();
    f.hub
        .lease(
            Some("p"),
            "pt",
            Some(&json!({ "subscription": handle.clone() })),
            Some(held),
        )
        .await
        .expect("leased");
    let listed = f.hub.list_leases().await;
    assert_eq!(listed[0]["backend"], "pt");
    assert_eq!(listed[0]["subscription"], json!(handle));
    assert_eq!(listed[0]["state"], "active");
    assert!(listed[0]["expiresAt"].is_u64());
    let rendered = serde_json::to_string(&listed).expect("json");
    let payload = held_text.split('.').nth(1).expect("jwt payload");
    assert!(!rendered.contains(payload), "the token never appears");
}

/// A per-user `tools_changed` on an identity-bound A2A backend is refused
/// `-32014 a2a_no_such_capability`: its listener has no read of its own to
/// poll with, so the subscription could never fire.
#[cfg(feature = "a2a")]
#[tokio::test]
async fn a_per_user_a2a_tools_subscription_is_refused() {
    use crate::events::EventSource;
    let f = fixture();
    let source = crate::events::backend_source::BackendSource {
        names: Arc::new(|| vec!["agent".to_owned()]),
        upstream: Some(crate::events::backend_source::Upstream {
            listeners: crate::events::upstream_listener::UpstreamListeners::new(
                Arc::new(crate::backend::BackendRegistry::new()),
                Arc::downgrade(&f.hub),
                Arc::new(std::collections::BTreeSet::new),
            ),
            ineligible: Arc::new(std::collections::BTreeSet::new),
        }),
    };
    let name = "backend.agent.tools_changed";
    let key =
        crate::events::backend_source::backend_key(Some("idp:p"), name, &json!({})).expect("key");
    let refused = source
        .on_first_subscriber(&key, "p", name, &json!({}))
        .await
        .expect_err("never a silent subscription");
    assert_eq!(refused.code, -32014);
    assert_eq!(
        refused.data.as_ref().and_then(|d| d.get("reason")),
        Some(&json!("a2a_no_such_capability"))
    );
}

/// ISO-T6, the fallback's bound: with no revocation signal, a subscriber who
/// lost access is revoked by the worker's sweep within its 30-second period,
/// and not before it, so the row pins the cadence and not merely "eventually".
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn iso_t6_the_sweep_revokes_a_lost_subscriber_within_its_period() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let f = fixture();
    let _ = subscribe(&f, "p", "pt", "p");
    let services = Arc::clone(f.hub.runtime.services.get().expect("services"));
    let worker = Arc::clone(&f.hub);
    // The worker sweeps once as it starts, while the subscriber still has access.
    let admits = forced_verdict::answer(AccessVerdict::Admits);
    tokio::spawn(async move { worker.deliver_forever(&services).await });
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(f.hub.store.subscriptions().len(), 1, "admitted at start");
    drop(admits);
    let _refused = forced_verdict::answer(AccessVerdict::Refuses);
    tokio::time::sleep(std::time::Duration::from_secs(28)).await;
    assert_eq!(
        f.hub.store.subscriptions().len(),
        1,
        "29 s in: the next sweep has not run, and nothing else revoked it"
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(
        f.hub.store.subscriptions().is_empty(),
        "31 s in: the sweep at 30 s revoked it"
    );
}

/// The listener map and `pt`'s backend; both live as long as the test.
type ListenersAndBackend = (
    Arc<crate::events::upstream_listener::UpstreamListeners>,
    Arc<crate::backend::Backend>,
);

/// Register `pt` and the backend-notification source on `f`'s hub, and park
/// `p`'s `tools_changed` listener until a lease starts it.
async fn parked_listener(f: &Fixture) -> ListenersAndBackend {
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let backend = Arc::new(crate::backend::Backend::new(
        "pt",
        f.config.backends["pt"].clone(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ));
    assert!(registry.register(Arc::clone(&backend)));
    let listeners = crate::events::upstream_listener::UpstreamListeners::new(
        registry,
        Arc::downgrade(&f.hub),
        Arc::new(std::collections::BTreeSet::new),
    );
    f.hub
        .register_source(Arc::new(crate::events::backend_source::BackendSource {
            names: Arc::new(|| vec!["pt".to_owned()]),
            upstream: Some(crate::events::backend_source::Upstream {
                listeners: Arc::clone(&listeners),
                ineligible: Arc::new(std::collections::BTreeSet::new),
            }),
        }));
    // Started as the hub starts a stored row, so the hub records the key and
    // a revocation's stop reaches it; registering the source spawns the
    // same replay, and the hub starts each key once.
    f.hub.replay_starts().await;
    (listeners, backend)
}

#[path = "lease_replace_tests.rs"]
mod replace;
