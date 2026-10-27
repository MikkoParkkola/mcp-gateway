// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T2: a vault grant rotation fences delivery from the rotation itself.
//! Two users on one managed-account backend; one user's grant rotates while
//! their record is queued. That record is buried, never sent; the other
//! user's is delivered. No listener interval is waited for.

use std::collections::HashMap;
use std::sync::Mutex;

use super::*;
use crate::events::ListenerMint;
use crate::events::listener_credential::FenceRead;
use crate::events::observation::observe_subscriber;
use crate::key_server::oidc::VerifiedIdentity;

const NAME: &str = "backend.managed.tools_changed";

fn managed_config() -> crate::config::Config {
    crate::yaml::from_str(
        "backends:\n  \
         managed:\n    http_url: https://backend.fixture.test/mcp\n    account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: unit\n  store_dir: /unused/store\n  \
         authority_dir: /unused/authority\n  current_key_id: primary\n  keys:\n    \
         primary: env:UNUSED\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: c\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      scopes: [read]\n      \
         send_resource_parameter: true\n",
    )
    .expect("config parses")
}

fn person(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.into(),
        email: format!("{subject}@example.com"),
        name: None,
        groups: Vec::new(),
        issuer: "https://idp".into(),
    }
}

/// Each user's grant binding, as custody would answer it; a rotation moves
/// one user's binding only. `refuse` scripts a read custody cannot answer;
/// `reads` counts the reads.
struct Fence {
    bindings: Mutex<HashMap<String, String>>,
    refuse: Mutex<Option<FenceRead>>,
    reads: std::sync::atomic::AtomicUsize,
    /// Parks the next read, so a row can act while it is pending.
    pending: crate::test_pause::Slot,
}

impl Fence {
    fn of(subjects: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            bindings: Mutex::new(
                subjects
                    .iter()
                    .map(|s| ((*s).to_owned(), format!("acct:fence:v1:{s}:1")))
                    .collect(),
            ),
            refuse: Mutex::new(None),
            reads: std::sync::atomic::AtomicUsize::new(0),
            pending: crate::test_pause::Slot::default(),
        })
    }

    fn rotate_grant(&self, subject: &str) {
        let mut bindings = self.bindings.lock().expect("fence");
        let binding = bindings.get_mut(subject).expect("known subject");
        binding.push_str(":rotated");
    }

    fn current(&self, subject: &str) -> String {
        self.bindings.lock().expect("fence")[subject].clone()
    }
}

#[async_trait::async_trait]
impl ListenerMint for Fence {
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
        identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.pending.pause().await;
        match *self.refuse.lock().expect("fence") {
            Some(refused) => Err(refused),
            None => Ok(Some(self.current(&identity.subject))),
        }
    }
}

/// `subject`'s row on the managed backend and one record for it, stamped
/// as fan-out stamps an emission of a listener run fenced on `run`.
fn queued_for(
    hub: &EventsHub,
    config: &crate::config::Config,
    port: u16,
    subject: &str,
    run: &str,
) {
    queued_aged(hub, config, port, subject, run, |_| {});
}

/// [`queued_for`], with the record changed by `age` before it is stored.
fn queued_aged(
    hub: &EventsHub,
    config: &crate::config::Config,
    port: u16,
    subject: &str,
    run: &str,
    age: impl FnOnce(&mut OutboxRecord),
) {
    let event_id = format!("evt_{subject}");
    let edit = |sub: &mut crate::events::records::Subscription, record: &mut OutboxRecord| {
        sub.id = format!("sub_{subject}");
        sub.principal = subject.into();
        sub.obs_basis = observe_subscriber(config, "managed", Some(&person(subject)))
            .expect("observes")
            .inspect(|basis| {
                assert_eq!(
                    basis.strategy,
                    crate::identity_propagation::PropagationStrategyKind::Vault
                );
            });
        sub.observed_identity = Some(person(subject));
        record.subscription_id = sub.id.clone();
        record.backend = "managed".into();
        age(record);
    };
    // Fan-out's own stamp call (`offer`), on the stored row.
    queued_stamped(hub, port, &event_id, NAME, edit, |row, record| {
        record.observed = hub
            .observed_now(row, config, Some(run))
            .expect("observable");
    });
}

/// Why `event_id` was buried; `None` while it is not.
fn buried_as(hub: &EventsHub, event_id: &str) -> Option<String> {
    hub.store
        .dead_letter_by_id(event_id)
        .map(|dead| dead.reason)
}

#[tokio::test]
async fn iso_t2_a_rotation_buries_only_the_rotated_users_queued_record() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config = managed_config();
    let mut services = logged_services(dir.path());
    services.live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    let fence = Fence::of(&["u1", "u2"]);
    hub.set_listener_mint(Arc::clone(&fence) as Arc<dyn ListenerMint>);
    hub.register_source(Arc::new(Offering {
        kind: crate::events::types::SourceKind::BackendNotification,
        names: vec![NAME],
    }));
    let (rotated_port, rotated_posts) = counting_callback().await;
    let (other_port, other_posts) = counting_callback().await;
    queued_for(&hub, &config, rotated_port, "u1", &fence.current("u1"));
    queued_for(&hub, &config, other_port, "u2", &fence.current("u2"));

    fence.rotate_grant("u1");
    hub.attempt(&services, "evt_u1").await;
    hub.attempt(&services, "evt_u2").await;

    // The burial is settled within the attempt, before any send.
    assert_eq!(
        buried_as(&hub, "evt_u2"),
        None,
        "the other user's record is not buried"
    );
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        match other_posts.load(Ordering::SeqCst) {
            0 => std::ops::ControlFlow::Continue("no send yet".to_owned()),
            _ => std::ops::ControlFlow::Break(()),
        }
    })
    .await
    .expect("the other user's record is delivered");
    assert_eq!(
        buried_as(&hub, "evt_u1").as_deref(),
        Some(DeadReason::Observation.as_str()),
        "buried under the old grant ({} sends)",
        rotated_posts.load(Ordering::SeqCst)
    );
    assert_eq!(
        rotated_posts.load(Ordering::SeqCst),
        0,
        "nothing observed under the old grant is sent after the rotation"
    );
}

/// An emission of the old run that reaches fan-out after the rotation keeps
/// the old run's binding, so it is buried too: it never borrows the new one.
#[tokio::test]
async fn iso_t2_an_old_run_emission_after_the_rotation_is_buried() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config = managed_config();
    let mut services = logged_services(dir.path());
    services.live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    let fence = Fence::of(&["u1"]);
    hub.set_listener_mint(Arc::clone(&fence) as Arc<dyn ListenerMint>);
    hub.register_source(Arc::new(Offering {
        kind: crate::events::types::SourceKind::BackendNotification,
        names: vec![NAME],
    }));
    let (port, posts) = counting_callback().await;
    let old_run = fence.current("u1");
    fence.rotate_grant("u1");
    queued_for(&hub, &config, port, "u1", &old_run);
    hub.attempt(&services, "evt_u1").await;

    // The burial is settled within the attempt, before any send.
    assert_eq!(
        buried_as(&hub, "evt_u1").as_deref(),
        Some(DeadReason::Observation.as_str()),
        "buried under the old run's grant ({} sends)",
        posts.load(Ordering::SeqCst)
    );
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

/// The control for the burials above: after the rotation, an occurrence the
/// listener's new run emits, under the new grant, reaches the subscriber.
#[tokio::test]
async fn iso_t2_a_record_under_the_new_grant_is_delivered() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config = managed_config();
    let mut services = logged_services(dir.path());
    services.live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    let fence = Fence::of(&["u1"]);
    hub.set_listener_mint(Arc::clone(&fence) as Arc<dyn ListenerMint>);
    hub.register_source(Arc::new(Offering {
        kind: crate::events::types::SourceKind::BackendNotification,
        names: vec![NAME],
    }));
    let (port, posts) = counting_callback().await;
    fence.rotate_grant("u1");
    queued_for(&hub, &config, port, "u1", &fence.current("u1"));
    hub.attempt(&services, "evt_u1").await;

    assert_eq!(buried_as(&hub, "evt_u1"), None, "not buried");
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        match posts.load(Ordering::SeqCst) {
            0 => std::ops::ControlFlow::Continue("no send yet".to_owned()),
            _ => std::ops::ControlFlow::Break(()),
        }
    })
    .await
    .expect("the record under the new grant is delivered");
}

/// A hub with `subjects` on the managed backend, its services under the
/// managed config, the fence installed and the backend's type offered.
fn fenced(
    dir: &std::path::Path,
    subjects: &[&str],
) -> (Arc<EventsHub>, Services, crate::config::Config, Arc<Fence>) {
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir).expect("hub");
    let config = managed_config();
    let mut services = logged_services(dir);
    services.live = Arc::new(crate::config_reload::LiveConfig::new(config.clone()));
    let fence = Fence::of(subjects);
    hub.set_listener_mint(Arc::clone(&fence) as Arc<dyn ListenerMint>);
    hub.register_source(Arc::new(Offering {
        kind: crate::events::types::SourceKind::BackendNotification,
        names: vec![NAME],
    }));
    (hub, services, config, fence)
}

/// The statuses the attempts of this hub ended with, in order.
fn outcomes(dir: &std::path::Path) -> Vec<String> {
    audit_actions(dir, "events.delivery_outcome")
        .iter()
        .filter_map(|line| line["status"].as_str().map(str::to_owned))
        .collect()
}

/// VFENCE-B: custody that cannot answer sends nothing and buries nothing;
/// the record waits, across a restart.
#[tokio::test]
async fn a_busy_custody_defers_the_record_unsent() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let (port, posts) = counting_callback().await;
    {
        let (hub, services, config, fence) = fenced(dir.path(), &["u1"]);
        *fence.refuse.lock().expect("fence") = Some(FenceRead::Busy);
        queued_for(&hub, &config, port, "u1", &fence.current("u1"));
        hub.attempt(&services, "evt_u1").await;
        assert_eq!(buried_as(&hub, "evt_u1"), None, "deferred, not buried");
    }
    // A restart: the same store, a new hub.
    let (hub, services, _, fence) = fenced(dir.path(), &["u1"]);
    *fence.refuse.lock().expect("fence") = Some(FenceRead::Busy);
    hub.attempt(&services, "evt_u1").await;
    assert_eq!(buried_as(&hub, "evt_u1"), None, "still deferred");
    assert_eq!(fence.reads.load(Ordering::SeqCst), 1, "asked again");
    assert_eq!(posts.load(Ordering::SeqCst), 0, "never sent");
    assert_eq!(
        outcomes(dir.path()),
        ["fence_unavailable", "fence_unavailable"]
    );
}

/// VFENCE-B: past its retry window a record is buried `exhausted` before
/// custody is asked at all, however long custody stays busy.
#[tokio::test]
async fn an_overdue_record_is_buried_before_the_fence_is_read() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let (hub, services, config, fence) = fenced(dir.path(), &["u1"]);
    *fence.refuse.lock().expect("fence") = Some(FenceRead::Busy);
    let (port, posts) = counting_callback().await;
    queued_aged(&hub, &config, port, "u1", &fence.current("u1"), |record| {
        record.attempt = 1;
        record.first_attempt_at =
            Some(chrono::Utc::now() - crate::duration_bound::delta!(seconds, 3600));
    });
    hub.attempt(&services, "evt_u1").await;
    assert_eq!(
        buried_as(&hub, "evt_u1").as_deref(),
        Some(DeadReason::Exhausted.as_str())
    );
    assert_eq!(fence.reads.load(Ordering::SeqCst), 0, "custody never asked");
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

/// No view of the grant (revoked, reconnect required): buried at once,
/// with its own audit outcome.
#[tokio::test]
async fn no_view_of_the_grant_buries_the_record() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let (hub, services, config, fence) = fenced(dir.path(), &["u1"]);
    let (port, posts) = counting_callback().await;
    queued_for(&hub, &config, port, "u1", &fence.current("u1"));
    *fence.refuse.lock().expect("fence") = Some(FenceRead::Closed);
    hub.attempt(&services, "evt_u1").await;
    assert_eq!(
        buried_as(&hub, "evt_u1").as_deref(),
        Some(DeadReason::Observation.as_str())
    );
    assert_eq!(outcomes(dir.path()), ["grant_no_view"]);
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

/// VFENCE-W: a stall between the fence read and the send that outlasts the
/// window sends nothing; the record goes back unsent.
#[tokio::test(start_paused = true)]
async fn a_send_past_the_fence_window_is_not_made() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let (hub, services, config, fence) = fenced(dir.path(), &["u1"]);
    let (port, posts) = counting_callback().await;
    queued_for(&hub, &config, port, "u1", &fence.current("u1"));
    let (reached, release) = hub.before_send.arm();
    let stall = async {
        reached.notified().await;
        tokio::time::advance(super::fence::FENCE_WINDOW + Duration::from_secs(1)).await;
        release.notify_one();
    };
    tokio::join!(hub.attempt(&services, "evt_u1"), stall);
    assert_eq!(buried_as(&hub, "evt_u1"), None, "unsent, not buried");
    assert_eq!(outcomes(dir.path()), ["fence_stale"]);
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

/// The barrier: an unsubscribe while the fence read is pending cancels the
/// record. The row that signs is read after the fence, so nothing is sent
/// under the subscription that is gone.
#[tokio::test]
async fn an_unsubscribe_during_the_fence_read_cancels_the_record() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().expect("dir");
    let (hub, services, config, fence) = fenced(dir.path(), &["u1"]);
    let (port, posts) = counting_callback().await;
    queued_for(&hub, &config, port, "u1", &fence.current("u1"));
    let (reached, release) = fence.pending.arm();
    let unsubscribe = async {
        reached.notified().await;
        let tail = crate::events::store::TailPolicy {
            ttl: Duration::from_secs(3600),
            max: 10,
            max_per_principal: 10,
        };
        assert!(
            hub.store
                .remove("sub_u1", Ok(chrono::Utc::now()), tail)
                .expect("io"),
            "premise: removed"
        );
        release.notify_one();
    };
    tokio::join!(hub.attempt(&services, "evt_u1"), unsubscribe);
    assert_eq!(outcomes(dir.path()), ["cancelled"]);
    assert_eq!(posts.load(Ordering::SeqCst), 0);
}

#[path = "worker_vault_replay_tests.rs"]
mod replay;
