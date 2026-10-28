// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T4: one subscriber's complete catalogue read never revokes another
//! subscriber's `resource_updated` rows on the same per-user backend.

use std::collections::HashSet;
use std::sync::Arc;

use crate::events::records::Subscription;
use crate::events::upstream_listener::ListenerKey;
use crate::events::{EventsHub, LiveCredentials, Services, observation, store, tail_policy};
use crate::key_server::oidc::VerifiedIdentity;

const SIGNED: &str = "backends:\n  signed:\n    http_url: https://h/mcp\n    \
    identity_propagation:\n      strategy: signed_assertion\n      audience: https://mail\n      \
    session_mode: per_user\n";

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@example.com"),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

/// `subject`'s `resource_updated` row for `uri`, as a subscribe commits it.
fn watching(config: &crate::config::Config, subject: &str, uri: &str) -> Subscription {
    let mut row: Subscription = serde_json::from_value(serde_json::json!({
        "v": 1, "id": format!("sub_{subject}"), "principal": subject, "url": "https://cb/x",
        "name": "backend.signed.resource_updated", "arguments": {"uri": uri},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": crate::clock::utc_now().expect("the clock reads after 1970"), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    let basis = observation::observe_subscriber(config, "signed", Some(&person(subject)))
        .expect("observes")
        .expect("per-user backend");
    row.obs_basis = Some(basis);
    row.observed_identity = Some(person(subject));
    row
}

fn services(config: crate::config::Config) -> Services {
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

#[tokio::test]
async fn iso_t4_one_subscribers_catalogue_read_never_revokes_anothers_rows() {
    let config: crate::config::Config = crate::yaml::from_str(SIGNED).expect("config parses");
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let _ = hub.runtime.services.set(Arc::new(services(config.clone())));
    for (subject, uri) in [("u1", "file:///u1"), ("u2", "file:///u2")] {
        hub.store
            .admit(
                watching(&config, subject, uri),
                true,
                store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                crate::clock::utc_now().expect("the clock reads after 1970"),
                tail_policy(&events),
            )
            .expect("io")
            .expect("admitted");
    }
    let u1_row = hub
        .store
        .subscriptions()
        .into_iter()
        .find(|s| s.principal == "u1")
        .expect("u1's row");
    let u1 = ListenerKey {
        backend: "signed".into(),
        obs: observation::observe_row(&config, "signed", &u1_row).expect("re-derives"),
    };
    assert!(u1.obs.is_some(), "u1 is observed per user");
    let granted = hub
        .store
        .subscriptions()
        .iter()
        .map(|s| s.incarnation)
        .max()
        .expect("rows");

    // U1's complete read lists neither URI.
    hub.revoke_absent_uris(&u1, &HashSet::new(), granted).await;

    let left: Vec<String> = hub
        .store
        .subscriptions()
        .into_iter()
        .map(|s| s.principal)
        .collect();
    assert!(
        !left.contains(&"u1".to_owned()),
        "control: u1's own absent resource is revoked by u1's read"
    );
    assert_eq!(
        left,
        vec!["u2".to_owned()],
        "u1's read never judges u2's row"
    );
}
