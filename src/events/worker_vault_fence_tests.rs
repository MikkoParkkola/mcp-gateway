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
/// one user's binding only.
struct Fence {
    bindings: Mutex<HashMap<String, String>>,
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
        Ok(Some(self.current(&identity.subject)))
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
    let event_id = format!("evt_{subject}");
    let edit = |sub: &mut crate::events::records::Subscription, record: &mut OutboxRecord| {
        sub.id = format!("sub_{subject}");
        sub.principal = subject.into();
        sub.obs_basis = observe_subscriber(config, "managed", Some(&person(subject)))
            .expect("observes")
            .map(|basis| {
                assert_eq!(
                    basis.strategy,
                    crate::identity_propagation::PropagationStrategyKind::Vault
                );
                basis
            });
        sub.observed_identity = Some(person(subject));
        record.subscription_id = sub.id.clone();
        record.backend = "managed".into();
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
