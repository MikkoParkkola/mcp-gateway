// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dead-letter replay runs the send path's observation check: a record observed
//! under a row that was since re-granted, or whose lease rotated, is refused
//! with its reason and nothing is queued; a record still observed as it was
//! replays as before.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use zeroize::Zeroizing;

use crate::events::admin::ReplayRefusal;
use crate::events::observation::observe_subscriber;
use crate::events::outbox::{DeadReason, OutboxCaps, OutboxRecord, OutboxState};
use crate::events::services::{AccessVerdict, forced_verdict};
use crate::events::store::{Claim, Settle};
use crate::events::{EventsHub, LiveCredentials, Services};
use crate::key_server::oidc::VerifiedIdentity;

const CONFIG: &str = "backends:\n  \
     pt:\n    http_url: https://h/mcp\n    identity_propagation:\n      \
     strategy: passthrough\n      audience: https://pt\n      session_mode: per_user\n";
const ROW: &str = "sub_p_pt";
const NAME: &str = "backend.pt.tools_changed";
const CAPS: OutboxCaps = OutboxCaps {
    global: 10,
    per_subscription: 10,
};

struct Fixture {
    hub: Arc<EventsHub>,
    services: Arc<Services>,
    config: Arc<crate::config::Config>,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir.path()).expect("hub");
    let config: crate::config::Config = crate::yaml::from_str(CONFIG).expect("config");
    let live = Arc::new(crate::config_reload::LiveConfig::new(config));
    let config = live.get();
    let services = Arc::new(Services {
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
    });
    assert!(hub.runtime.services.set(Arc::clone(&services)).is_ok());
    Fixture {
        hub,
        services,
        config,
        _dir: dir,
    }
}

fn person() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "p".into(),
        email: "p@mail.test".into(),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

/// Commit principal `p`'s row on `pt`, per-user unless `shared`; a second
/// call re-grants it.
fn grant(f: &Fixture, shared: bool) -> String {
    let now = crate::clock::utc_now().expect("clock");
    let mut row: crate::events::records::Subscription = serde_json::from_value(json!({
        "v": 1, "id": ROW, "principal": "p",
        "api_key": null, "url": "https://cb.test/hook",
        "name": NAME, "arguments": {},
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": now, "expires_at": now + crate::duration_bound::delta!(hours, 1), "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null
    }))
    .expect("row");
    row.credential_kind = Some(crate::security::audit::CredentialKind::None);
    if !shared {
        let basis = observe_subscriber(&f.config, "pt", Some(&person()))
            .expect("observes")
            .expect("per-user");
        row.obs_basis = Some(basis);
        row.observed_identity = Some(person());
    }
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
    f.hub.handle(ROW).expect("handle")
}

fn row(f: &Fixture) -> crate::events::records::Subscription {
    (f.hub.store.subscriptions().into_iter())
        .find(|s| s.id == ROW)
        .expect("row")
}

/// Lease a token for `p`'s row expiring at `exp`; a later call rotates it.
async fn lease(f: &Fixture, handle: &str, exp: u64) {
    let claims = json!({"sub": "p", "exp": exp});
    let token = Zeroizing::new(format!(
        "Bearer {}.{}.sig",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    ));
    let params = json!({ "subscription": handle });
    (f.hub
        .lease(Some("p"), "pt", Some(&params), Some(token))
        .await)
        .expect("leased");
}

fn in_an_hour() -> u64 {
    crate::clock::unix_secs().expect("clock") + 3600
}

/// Bury `event`, stamped with the row's observation now (`None` on a shared row).
fn bury_observed(f: &Fixture, event: &str) {
    let now = crate::clock::utc_now().expect("clock");
    let observed = f
        .hub
        .observed_now(&row(f), &f.config, None)
        .expect("observable");
    let record = OutboxRecord {
        v: 1,
        event_id: event.into(),
        subscription_id: ROW.into(),
        name: NAME.into(),
        backend: "pt".into(),
        owner_scoped: false,
        callback_host: "cb.test".into(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attribution: None,
        attribution_keys: Vec::new(),
        firewall: None,
        attempt: 0,
        unsent: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        replayed: false,
        observed,
    };
    f.hub.store.enqueue(record, CAPS).expect("io");
    let Claim::Ready(_) = f.hub.store.claim(event, now).expect("io") else {
        panic!("premise: the record is claimed");
    };
    let dead = Settle::Dead {
        reason: DeadReason::Observation,
        status: None,
    };
    (f.hub.store)
        .settle(event, now, dead, Ok(now), f.hub.dead_policy())
        .expect("io");
    assert!(
        f.hub.store.dead_letter_by_id(event).is_some(),
        "premise: buried"
    );
}

fn actor() -> crate::events::governance::Actor {
    crate::events::governance::Actor {
        who: crate::security::audit::AuditWho::gateway(),
    }
}

/// A replay that re-queues moves the record out of the dead letters, so a
/// dead letter still in place is one nothing was queued for.
fn still_dead(f: &Fixture, event: &str) -> bool {
    f.hub.store.dead_letter_by_id(event).is_some()
}

/// ISO-T3, re-grant: the record was observed under the old incarnation, so
/// its replay is refused by name and nothing is queued.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_after_a_regrant_is_refused_as_observation_changed() {
    let f = fixture();
    let _ = grant(&f, false);
    bury_observed(&f, "evt_regrant");
    let before = row(&f).incarnation;
    let _ = grant(&f, false);
    assert_ne!(row(&f).incarnation, before, "premise: a new incarnation");
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    let refused = f.hub.replay_dead("evt_regrant", &actor()).await;
    assert_eq!(
        refused.map_err(ReplayRefusal::as_str),
        Err("observation_changed")
    );
    assert!(still_dead(&f, "evt_regrant"), "nothing re-queued");
}

/// ISO-T3, lease rotation: the record was observed under the old lease, and
/// `replay_all` names the refusal per record.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_after_a_lease_rotation_is_refused_by_name() {
    let f = fixture();
    let handle = grant(&f, false);
    lease(&f, &handle, in_an_hour()).await;
    bury_observed(&f, "evt_rotated");
    lease(&f, &handle, in_an_hour() + 60).await;
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    let (replayed, refused) = f.hub.replay_all(ROW, &actor()).await;
    assert_eq!(replayed, 0);
    let refused: Vec<_> = (refused.iter())
        .map(|(id, why)| (id.as_str(), why.as_str()))
        .collect();
    assert_eq!(refused, vec![("evt_rotated", "observation_changed")]);
    assert!(still_dead(&f, "evt_rotated"), "nothing re-queued");
}

/// A row the live config can no longer observe (its audience moved) is
/// refused the same way the send path buries it.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_on_a_row_the_config_no_longer_observes_is_refused() {
    let f = fixture();
    let _ = grant(&f, false);
    bury_observed(&f, "evt_moved");
    let moved = CONFIG.replace("audience: https://pt\n", "audience: https://pt-v2\n");
    f.services
        .live
        .set(crate::yaml::from_str(&moved).expect("config"));
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    let refused = f.hub.replay_dead("evt_moved", &actor()).await;
    assert_eq!(
        refused.map_err(ReplayRefusal::as_str),
        Err("observation_changed")
    );
    assert!(still_dead(&f, "evt_moved"), "nothing re-queued");
}

/// Control: a per-user record still observed as it was replays as before.
#[tokio::test(flavor = "current_thread")]
async fn a_replay_still_observed_as_it_was_requeues() {
    let f = fixture();
    let handle = grant(&f, false);
    lease(&f, &handle, in_an_hour()).await;
    bury_observed(&f, "evt_same");
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(f.hub.replay_dead("evt_same", &actor()).await, Ok(()));
    assert!(!still_dead(&f, "evt_same"), "re-queued");
}

/// Control: a shared row's record carries no stamp and replays as before.
#[tokio::test(flavor = "current_thread")]
async fn a_shared_rows_replay_requeues() {
    let f = fixture();
    let _ = grant(&f, true);
    bury_observed(&f, "evt_shared");
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(f.hub.replay_dead("evt_shared", &actor()).await, Ok(()));
    assert!(!still_dead(&f, "evt_shared"), "re-queued");
}

/// Custody that never answers, counting how often it was asked.
#[derive(Default)]
struct BusyCustody(std::sync::atomic::AtomicUsize);

#[async_trait::async_trait]
impl crate::events::ListenerMint for BusyCustody {
    async fn mint(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> crate::Result<crate::events::ListenerGrant> {
        Err(crate::Error::Config("no listener runs here".into()))
    }

    async fn fence_binding(
        &self,
        _backend: &str,
        _identity: &VerifiedIdentity,
    ) -> Result<Option<String>, crate::events::FenceRead> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(crate::events::FenceRead::Busy)
    }
}

/// A passthrough row has no vault grant: its replay never asks custody, so
/// a custody that cannot answer does not hold it back.
#[tokio::test(flavor = "current_thread")]
async fn a_passthrough_replay_never_reads_a_vault_grant() {
    let f = fixture();
    let custody = Arc::new(BusyCustody::default());
    f.hub
        .set_listener_mint(Arc::clone(&custody) as Arc<dyn crate::events::ListenerMint>);
    let handle = grant(&f, false);
    lease(&f, &handle, in_an_hour()).await;
    bury_observed(&f, "evt_passthrough");
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    assert_eq!(f.hub.replay_dead("evt_passthrough", &actor()).await, Ok(()));
    assert!(!still_dead(&f, "evt_passthrough"), "re-queued");
    assert_eq!(
        custody.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "custody was asked"
    );
}
