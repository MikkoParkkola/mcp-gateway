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
    let observed = hub.observed_now(&row, &config, None).expect("observable");
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

/// A bearer token that expires at `exp`, as a lease takes it.
fn token_until(exp: u64) -> zeroize::Zeroizing<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let part = |s: &str| URL_SAFE_NO_PAD.encode(s);
    zeroize::Zeroizing::new(format!(
        "Bearer {}.{}.sig",
        part(r#"{"alg":"RS256"}"#),
        part(&format!(r#"{{"sub":"p","exp":{exp}}}"#))
    ))
}

/// Lease `pt` for `person()` until `exp`; the key it is held under.
async fn leased(hub: &EventsHub, services: &Services, exp: u64) -> crate::events::lease::LeaseKey {
    let config = services.live.get();
    let obs = crate::events::observation::binding(&config, "pt")
        .expect("per-user")
        .observe(&person())
        .expect("observed");
    let key = crate::events::lease::LeaseKey {
        backend: "pt".into(),
        obs,
    };
    hub.leases
        .install(key.clone(), token_until(exp), u64::MAX, 0)
        .await
        .expect("leased");
    key
}

/// A record read under one lease and still queued when the lease is
/// replaced is buried at its delivery attempt, and nothing reaches the
/// callback: it was never authorized by the new token.
#[tokio::test]
async fn a_record_read_under_a_replaced_lease_is_buried_not_sent() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, accepted) = counting_callback().await;
    offer(&hub, &[NAME]);
    let now = crate::clock::unix_secs().expect("clock");
    let key = leased(&hub, &services, now + 3600).await;
    queued_observed(&hub, &services, port, "evt_replaced");
    hub.leases
        .install(key, token_until(now + 7200), u64::MAX, 0)
        .await
        .expect("replaced");
    hub.attempt(&services, "evt_replaced").await;
    let dead = hub.store.dead_letter_by_id("evt_replaced").expect("buried");
    assert_eq!(dead.reason, "observation_changed");
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing was sent");
}

/// The same once the lease is past its deadline, before any expiry sweep.
#[tokio::test]
async fn a_record_read_under_an_expired_lease_is_buried_before_any_sweep() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, accepted) = counting_callback().await;
    offer(&hub, &[NAME]);
    let exp = crate::clock::unix_secs().expect("clock") + 120;
    leased(&hub, &services, exp).await;
    queued_observed(&hub, &services, port, "evt_expired");
    let _clock = crate::clock::test_clock::at_secs(exp);
    hub.attempt(&services, "evt_expired").await;
    let dead = hub.store.dead_letter_by_id("evt_expired").expect("buried");
    assert_eq!(dead.reason, "observation_changed");
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "nothing was sent");
}

/// Control for the two rows above: a record read under a lease that is
/// still held and unexpired is sent, so their burials come from the replace
/// and the deadline, not from leased records never being deliverable.
#[tokio::test]
async fn a_record_read_under_a_held_lease_is_sent() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, accepted) = counting_callback().await;
    offer(&hub, &[NAME]);
    let now = crate::clock::unix_secs().expect("clock");
    leased(&hub, &services, now + 3600).await;
    queued_observed(&hub, &services, port, "evt_held");
    let row = hub.store.subscriptions().pop().expect("row");
    let stamped = hub
        .observed_now(&row, &services.live.get(), None)
        .expect("observable");
    assert!(
        stamped.is_some_and(|o| o.lease.is_some()),
        "premise: the record is stamped with the held lease, not unleased"
    );
    hub.attempt(&services, "evt_held").await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while accepted.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(accepted.load(Ordering::SeqCst) >= 1, "sent");
    assert!(
        hub.store.dead_letter_by_id("evt_held").is_none(),
        "not buried"
    );
}

/// A callback that takes one connection, reports once the client's first
/// bytes (its TLS hello) arrive, and hangs up only once released: a delivery
/// handoff held on the wire whose outcome the sender cannot know.
async fn held_callback() -> (u16, Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (reached, release) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let (arrived, hang_up) = (Arc::clone(&reached), Arc::clone(&release));
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut hello = vec![0u8; 16 * 1024];
        let _ = stream.read(&mut hello).await;
        arrived.notify_one();
        hang_up.notified().await;
        drop(stream);
    });
    (port, reached, release)
}

/// The queued record for `event_id` in the outbox under `dir`, if any.
fn queued_record(dir: &std::path::Path, event_id: &str) -> Option<serde_json::Value> {
    std::fs::read_dir(dir.join("outbox"))
        .ok()?
        .flatten()
        .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
        .find(|record: &serde_json::Value| record["event_id"] == event_id)
}

/// LEASE-T7, the committed half: a handoff already on the wire when the
/// lease is replaced is not recalled. Its attempt completes as possibly sent:
/// counted, and left for its retry to judge, never buried by the replace.
#[tokio::test]
async fn lease_t7_a_handoff_on_the_wire_at_a_replace_completes() {
    let dir = tempfile::tempdir().expect("dir");
    let config = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let services = services(dir.path());
    let (port, reached, release) = held_callback().await;
    offer(&hub, &[NAME]);
    let now = crate::clock::unix_secs().expect("clock");
    let key = leased(&hub, &services, now + 3600).await;
    queued_observed(&hub, &services, port, "evt_wire");
    let replace = async {
        crate::test_pause::within("the handoff on the wire", reached.notified()).await;
        hub.leases
            .install(key, token_until(now + 7200), u64::MAX, 0)
            .await
            .expect("replaced");
        release.notify_one();
    };
    tokio::join!(hub.attempt(&services, "evt_wire"), replace);
    assert!(
        hub.store.dead_letter_by_id("evt_wire").is_none(),
        "not buried by the replace"
    );
    let record = queued_record(dir.path(), "evt_wire").expect("still queued for its retry");
    assert!(
        record["attempt"].as_u64().is_some_and(|n| n >= 1),
        "the attempt on the wire is counted: {record}"
    );
}
