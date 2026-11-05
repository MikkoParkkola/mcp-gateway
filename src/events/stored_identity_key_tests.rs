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
