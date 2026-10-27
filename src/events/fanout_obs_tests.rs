// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Per-user occurrences at fan-out reach only rows observed as their
//! subscriber. Split from `fanout_tests.rs` (file-size ceiling).

use super::*;

/// An occurrence with no lifecycle key (a shared listener's)
/// never reaches a row observed as one subscriber; a shared row still gets it.
#[tokio::test]
async fn a_keyless_occurrence_skips_rows_observed_per_user() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig::default();
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    hub.register_source(Arc::new(PerPrincipal));
    let name = "watch.cap.changed";
    for (principal, per_user) in [("alice", true), ("bob", false)] {
        let mut row = subscription(name);
        row.id = format!("sub_{principal}");
        row.principal = principal.into();
        row.credential_kind = Some(crate::security::audit::CredentialKind::None);
        row.obs_basis = per_user.then(|| crate::events::observation::ObsBasis {
            strategy: crate::identity_propagation::PropagationStrategyKind::SignedAssertion,
            audience: "https://a".into(),
            token_exchange_endpoint: None,
            token_exchange_scope: None,
            descriptor_id: None,
            account_resource: None,
            account_issuer: None,
        });
        hub.store
            .admit(
                row,
                true,
                crate::events::store::Caps {
                    per_principal: 10,
                    global: 10,
                },
                chrono::Duration::zero(),
                Utc::now(),
                crate::events::tail_policy(&config),
            )
            .expect("io")
            .expect("admitted");
    }
    let services = crate::events::Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    };
    hub.fan_out(
        &services,
        &SourceEvent {
            kind: SourceKind::RestWatch,
            name: name.into(),
            backend: "cap".into(),
            scope: Visibility::Owner,
            owner: None,
            upstream_id: "k1".into(),
            occurred_at: Utc::now(),
            data: json!({}),
            lifecycle_key: None,
        },
    )
    .await;
    let records: Vec<String> = std::fs::read_dir(dir.path().join("outbox"))
        .map(|entries| {
            entries
                .flatten()
                .map(|e| std::fs::read_to_string(e.path()).expect("read"))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(records.len(), 1, "only the shared row: {records:?}");
    assert!(records[0].contains("sub_bob"), "{}", records[0]);
}
