// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The send path's observation check: a record queued for a per-user row that
//! is re-granted before the attempt is buried as `observation_changed` and
//! never sent. The first half of ISO-T3; the replay refusal is the other half
//! (`events::admin::replay_obs_tests`).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{counting_callback, offer, queued_with};
use crate::events::observation::observe_subscriber;
use crate::events::{EventsHub, Services};
use crate::key_server::oidc::VerifiedIdentity;

const CONFIG: &str = "backends:\n  \
     pt:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n";
const NAME: &str = "backend.pt.tools_changed";

fn person() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "p".into(),
        email: "p@mail.test".into(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

fn services(dir: &std::path::Path) -> Services {
    let log = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: dir.join("audit.jsonl").to_string_lossy().into_owned(),
            ..crate::security::TransparencyLogConfig::default()
        },
    ))
    .expect("log");
    let config: crate::config::Config = crate::yaml::from_str(CONFIG).expect("config");
    Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(config)),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: Some(Arc::new(log)),
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: crate::events::LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }
}

/// Queue `event` for a per-user row on `pt`, stamped with the stored row's
/// observation as fan-out stamps it. The stamp is taken after the row is
/// admitted: admission sets the incarnation the stamp must carry.
fn queued_observed(hub: &EventsHub, services: &Services, port: u16, event: &str) {
    use crate::events::outbox::{Enqueued, OutboxCaps, OutboxRecord, OutboxState};
    let config = services.live.get();
    // The helper's own record is a seed under another id; ours follows.
    queued_with(hub, port, "evt_seed", NAME, |sub, _| {
        let basis = observe_subscriber(&config, "pt", Some(&person()))
            .expect("observes")
            .expect("per-user");
        sub.obs_basis = Some(basis);
        sub.observed_identity = Some(person());
    });
    let row = hub.store.subscriptions().pop().expect("row");
    let observed = hub.observed_now(&row, &config).expect("observable");
    assert!(observed.is_some(), "premise: a per-user stamp");
    let now = crate::clock::utc_now().expect("clock");
    let record = OutboxRecord {
        v: 1,
        event_id: event.into(),
        subscription_id: row.id.clone(),
        name: NAME.into(),
        backend: "pt".into(),
        owner_scoped: false,
        callback_host: String::new(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        unsent: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        replayed: false,
        attribution: None,
        attribution_keys: Vec::new(),
        firewall: None,
        observed,
    };
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    assert_eq!(
        hub.store.enqueue(record, caps).expect("io"),
        Enqueued::Written
    );
}

/// Re-grant the stored row: the same id under a new incarnation.
fn regrant(hub: &EventsHub) {
    let row = hub.store.subscriptions().pop().expect("row");
    let before = row.incarnation;
    let now = crate::clock::utc_now().expect("clock");
    (hub.store)
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
    let after = hub.store.subscriptions().pop().expect("row").incarnation;
    assert_ne!(after, before, "premise: a new incarnation");
}

/// ISO-T3, send half: queued for U1, U1's row re-granted, then the attempt:
/// buried as `observation_changed`, and nothing reaches the callback.
#[tokio::test]
async fn a_record_queued_before_a_regrant_is_buried_as_observation_changed() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, accepted) = counting_callback().await;
    offer(&hub, &[NAME]);
    queued_observed(&hub, &services, port, "evt_regrant");
    regrant(&hub);
    hub.attempt(&services, "evt_regrant").await;
    // Buried before the send: a sent record meets a callback that drops the
    // connection, so it would retry and never be buried.
    let dead = hub.store.dead_letter_by_id("evt_regrant").expect("buried");
    assert_eq!(dead.reason, "observation_changed");
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing was sent");
}

/// Control: the same record with the row unchanged is sent.
#[tokio::test]
async fn a_record_still_observed_as_it_was_is_sent() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, accepted) = counting_callback().await;
    offer(&hub, &[NAME]);
    queued_observed(&hub, &services, port, "evt_same");
    hub.attempt(&services, "evt_same").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while accepted.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(accepted.load(Ordering::SeqCst) >= 1, "sent");
    assert!(
        hub.store.dead_letter_by_id("evt_same").is_none(),
        "not buried"
    );
}
