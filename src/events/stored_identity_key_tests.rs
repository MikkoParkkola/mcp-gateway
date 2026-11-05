// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A per-user backend row whose stored identity names nobody gets no
//! listener key at all: never the backend's shared key, which would run it
//! on the gateway's own credential.

use super::*;

const CONFIG: &str = "backends:\n  \
     signed:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: signed_assertion\n      audience: https://mail\n      session_mode: per_user\n";

fn services() -> Services {
    let config: crate::config::Config = crate::yaml::from_str(CONFIG).expect("config");
    Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(config)),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }
}

/// A row on `name` as the store reads it from disk, with `identity` stored
/// and the basis a subscribe on `signed` records.
fn row(name: &str, identity: &serde_json::Value) -> records::Subscription {
    let config: crate::config::Config = crate::yaml::from_str(CONFIG).expect("config");
    let witness = crate::key_server::oidc::VerifiedIdentity::checked(
        "https://idp".into(),
        "witness".into(),
        "w@h".into(),
        None,
        Vec::new(),
    )
    .expect("names someone");
    let basis = observation::observe_subscriber(&config, "signed", Some(&witness))
        .expect("observes")
        .expect("per-user");
    serde_json::from_value(serde_json::json!({
        "v": 1, "id": "i", "principal": "p", "api_key": null, "url": "https://cb",
        "name": name, "arguments": {}, "secret": "s",
        "previous_secret": null, "previous_until": null,
        "granted_at": "2026-10-25T00:00:00Z", "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "observed_identity": identity,
        "obs_basis": serde_json::to_value(basis).expect("basis serializes"),
    }))
    .expect("a stored row loads")
}

fn identity(subject: &str) -> serde_json::Value {
    serde_json::json!({
        "subject": subject, "email": "q@h", "groups": [], "issuer": "https://idp",
    })
}

#[test]
fn a_per_user_row_naming_nobody_gets_no_listener_key() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let registry = Arc::new(crate::backend::BackendRegistry::new());
    let none: backend_source::Ineligible = Arc::new(std::collections::BTreeSet::new);
    hub.install_backend_source_with_upstream(
        Arc::new(|| vec!["signed".to_owned()]),
        registry,
        none,
    );
    assert!(hub.runtime.services.set(Arc::new(services())).is_ok());
    let source = hub
        .source(types::SourceKind::BackendNotification)
        .expect("source");
    let now = chrono::Utc::now();
    let name = "backend.signed.tools_changed";
    let shared = backend_source::backend_key(None, name, &serde_json::json!({}));

    let someone = source.key_of_row(&row(name, &identity("q")), now);
    assert!(
        someone.is_some() && someone != shared,
        "control: a row naming someone gets its own per-user key, {someone:?}"
    );
    for subject in ["", "  "] {
        assert_eq!(
            source.key_of_row(&row(name, &identity(subject)), now),
            None,
            "subject {subject:?}: no key, never the shared one"
        );
    }
}

/// What the runtime start runs before it replays any key: a row whose stored
/// identity names nobody is revoked and gone, and a sibling naming someone
/// is kept.
#[tokio::test]
async fn a_row_naming_nobody_is_revoked_before_anything_starts() {
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    assert!(hub.runtime.services.set(Arc::new(services())).is_ok());
    let name = "backend.signed.tools_changed";
    for (id, subject) in [("sub_nobody", ""), ("sub_someone", "q")] {
        let mut stored = row(name, &identity(subject));
        stored.id = id.into();
        stored.principal = id.into();
        hub.store
            .admit(
                stored,
                true,
                store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                chrono::Utc::now(),
                tail_policy(&events),
            )
            .expect("io")
            .expect("admitted");
    }
    hub.revoke_unobservable(None).await;
    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(
        left,
        vec!["sub_someone".to_owned()],
        "the nobody row is revoked; the row naming someone stays"
    );
}

/// A hub with one row per `(id, subject)` on `signed`, and the services the
/// runtime start installs.
fn hub_with(rows: &[(&str, &str)]) -> (Arc<EventsHub>, tempfile::TempDir) {
    hub_with_rows(rows, |_| {})
}

/// [`hub_with`], each row passed through `change` before it is admitted.
fn hub_with_rows(
    rows: &[(&str, &str)],
    change: impl Fn(&mut records::Subscription),
) -> (Arc<EventsHub>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    assert!(hub.runtime.services.set(Arc::new(services())).is_ok());
    for (id, subject) in rows {
        let mut stored = row("backend.signed.tools_changed", &identity(subject));
        stored.id = (*id).into();
        stored.principal = (*id).into();
        change(&mut stored);
        hub.store
            .admit(
                stored,
                true,
                store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                chrono::Utc::now(),
                tail_policy(&events),
            )
            .expect("io")
            .expect("admitted");
    }
    (hub, dir)
}

fn blocking<T>(work: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(work)
}

const NOBODY: &str = "stored observed identity names nobody";

/// The revocation of a row naming nobody is warned once, by its public
/// handle; a row revoked for another reason is not warned as one.
#[test]
fn a_nobody_row_is_warned_by_its_handle_when_revoked() {
    // The second row names someone, but its basis no longer matches the
    // live config: it is revoked for that, not for naming nobody.
    let (hub, _dir) = hub_with_rows(&[("sub_nobody", ""), ("sub_moved", "q")], |row| {
        if row.id == "sub_moved" {
            row.obs_basis.as_mut().expect("basis").audience = "https://elsewhere".into();
        }
    });
    let handle = hub.handle("sub_nobody").expect("a handle");
    let ((), warned) =
        crate::test_log_capture::capture_warnings(|| blocking(hub.revoke_unobservable(None)));
    assert!(
        hub.store.subscriptions().is_empty(),
        "premise: both revoked"
    );
    let lines: Vec<&str> = warned.lines().filter(|l| l.contains(NOBODY)).collect();
    assert_eq!(
        lines.len(),
        1,
        "one warn, for the nobody row only: {warned}"
    );
    assert!(
        lines[0].contains(&handle),
        "named by its handle: {}",
        lines[0]
    );
    assert!(!warned.contains("sub_nobody"), "never by its stored id");
}

/// Revoking the same row twice warns once: the second finds it gone.
#[test]
fn a_nobody_row_revoked_twice_is_warned_once() {
    let (hub, _dir) = hub_with(&[("sub_nobody", "")]);
    let snapshot = hub.store.get("sub_nobody").expect("row");
    let ((), warned) = crate::test_log_capture::capture_warnings(|| {
        blocking(async {
            hub.revoke(&snapshot).await;
            hub.revoke(&snapshot).await;
        })
    });
    assert_eq!(
        warned.lines().filter(|l| l.contains(NOBODY)).count(),
        1,
        "{warned}"
    );
}
