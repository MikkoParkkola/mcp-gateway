// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `watch.<capability>.changed` rows of the event-sources design (§7: U1-U4,
//! U11, U12), against a fake host so each poll's answer is scripted.

use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::{Value, json};

use super::super::fanout::SourceEvent;
use super::super::{EventSource, EventsHub};
use super::*;

/// A scripted gateway: its catalogue, who may invoke, and each poll's answer.
#[derive(Default)]
struct Fake {
    targets: parking_lot::Mutex<Vec<Target>>,
    /// Catalogues answered before `targets`, one per call: a reload landing
    /// between two reads.
    script: parking_lot::Mutex<VecDeque<Vec<Target>>>,
    denied: parking_lot::Mutex<Vec<String>>,
    answers: parking_lot::Mutex<VecDeque<Value>>,
    calls: parking_lot::Mutex<Vec<(String, Charge)>>,
}

#[async_trait::async_trait]
impl WatchHost for Fake {
    fn targets(&self) -> Vec<Target> {
        self.script
            .lock()
            .pop_front()
            .unwrap_or_else(|| self.targets.lock().clone())
    }
    fn may_invoke(&self, holder: &Holder, _target: &Target) -> bool {
        !self.denied.lock().contains(&holder.principal)
    }
    async fn poll(
        &self,
        holder: &Holder,
        _target: &Target,
        _arguments: &Value,
        charge: Charge,
    ) -> Result<Value, PollFailed> {
        self.calls.lock().push((holder.principal.clone(), charge));
        self.answers.lock().pop_front().ok_or(PollFailed)
    }
}

fn target(capability: &str, read_only: bool, credential: CredentialUse) -> Target {
    Target {
        capability: capability.into(),
        backend: "capabilities".into(),
        read_only,
        credential,
        input_schema: json!({"type": "object"}),
    }
}

fn fake(targets: Vec<Target>) -> Arc<Fake> {
    let fake = Arc::new(Fake::default());
    *fake.targets.lock() = targets;
    fake
}

/// A hub with its controls handed over (no firewall, no audit), so the
/// poller's live credential check can run.
fn hub(dir: &std::path::Path) -> Arc<EventsHub> {
    let hub = EventsHub::open(&crate::config::EventsConfig::default(), dir).expect("hub");
    let services = super::super::Services {
        live: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: None,
        provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: super::super::LiveCredentials::default(),
    };
    let _ = hub.runtime.services.set(Arc::new(services));
    hub
}

fn drain(hub: &EventsHub) -> tokio::sync::mpsc::Receiver<SourceEvent> {
    hub.runtime.intake.lock().take().expect("intake")
}

fn received(events: &mut tokio::sync::mpsc::Receiver<SourceEvent>) -> Vec<SourceEvent> {
    std::iter::from_fn(|| events.try_recv().ok()).collect()
}

/// Admit a live row for `principal`, presented with an API key.
fn admit(hub: &EventsHub, principal: &str, name: &str, arguments: &Value) {
    let row: Subscription = serde_json::from_value(json!({
        "v": 1, "principal": principal,
        "id": super::super::rpc::subscription_id(principal, &format!("https://h/{principal}"), name, arguments),
        "url": format!("https://h/{principal}"), "name": name, "arguments": arguments,
        "secret": "whsec_x", "previous_secret": null, "previous_until": null,
        "granted_at": Utc::now(), "expires_at": null, "active": true,
        "failed_since": null, "last_delivery_at": null, "last_error": null,
        "api_key": {"name": format!("key-{principal}"), "principal": "0123456789ab"},
        "credential_kind": serde_json::to_value(crate::security::audit::CredentialKind::None)
            .expect("kind"),
    }))
    .expect("row");
    let config = crate::config::EventsConfig::default();
    hub.store
        .admit(
            row,
            true,
            super::super::store::Caps {
                per_principal: 100,
                global: 100,
            },
            chrono::Duration::zero(),
            Utc::now(),
            super::super::tail_policy(&config),
        )
        .expect("io")
        .expect("admitted");
}

/// A poller for `principal`'s subscription, driven one poll at a time.
fn run(
    hub: &Arc<EventsHub>,
    host: &Arc<Fake>,
    principal: &str,
    name: &str,
    arguments: &Value,
) -> Run {
    let source = WatchSource::new(hub, Arc::clone(host) as Arc<dyn WatchHost>);
    let key = source.lifecycle_key(principal, name, arguments);
    let shared = host
        .targets()
        .iter()
        .any(|t| event_name(&t.capability) == name && t.credential == CredentialUse::Free);
    Run {
        stop: Arc::default(),
        hub: Arc::downgrade(hub),
        host: Arc::clone(host) as Arc<dyn WatchHost>,
        key,
        name: name.into(),
        options: options(arguments).expect("options"),
        charge: if shared {
            Charge::Global
        } else {
            Charge::Holder
        },
    }
}

/// Feed `answers` through one poller; the events it emitted.
async fn poll_all(
    hub: &Arc<EventsHub>,
    host: &Arc<Fake>,
    poller: &Run,
    answers: &[Value],
    events: &mut tokio::sync::mpsc::Receiver<SourceEvent>,
) -> Vec<SourceEvent> {
    let mut last = None;
    for answer in answers {
        host.answers.lock().push_back(answer.clone());
        assert!(matches!(poller.once(hub, &mut last).await, Step::Polled));
    }
    received(events)
}

/// U1: only a read-only capability is offered; a side-effecting one is not,
/// and a subscription to it is refused.
#[tokio::test]
async fn watch_is_offered_only_for_read_only_capabilities() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![
        target("weather", true, CredentialUse::Free),
        target("send_mail", false, CredentialUse::Free),
    ]);
    let source = WatchSource::new(&hub, host);
    let names: Vec<String> = source.descriptors().into_iter().map(|d| d.name).collect();
    assert_eq!(names, ["watch.weather.changed"]);
    assert!(source.offers("watch.weather.changed"));
    assert!(!source.offers("watch.send_mail.changed"));
    let refused = source
        .authorize("p", "watch.send_mail.changed", &json!({}))
        .await
        .expect_err("side-effecting");
    assert_eq!(refused.code, -32012);
}

/// U2: A, A, B, B, A emits after the third and fifth polls; the first poll
/// is the baseline; the payload holds pointers and digests, never a value.
#[tokio::test]
async fn watch_emits_on_digest_change_only() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    let (a, b) = (
        json!({"temp": 11, "city": "Oulu"}),
        json!({"temp": 12, "city": "Oulu"}),
    );
    let mut intake = drain(&hub);
    let answers = [a.clone(), a.clone(), b.clone(), b, a];
    let events = poll_all(&hub, &host, &poller, &answers, &mut intake).await;
    assert_eq!(events.len(), 2, "after the 3rd and the 5th poll");
    let data = &events[0].data;
    let keys: Vec<&String> = data.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        [
            "capability",
            "changed",
            "digest_after",
            "digest_before",
            "observed_at"
        ]
    );
    assert_eq!(data["changed"], json!(["/temp"]));
    assert_ne!(data["digest_before"], data["digest_after"]);
    let text = data.to_string();
    assert!(!text.contains("Oulu"), "no values: {text}");
    assert_eq!(
        events[0].lifecycle_key.as_deref(),
        Some(poller.key.as_str())
    );
}

/// U4, interval: under the 60 s floor (or over the ceiling) is refused,
/// naming the field; an account-credentialed capability is unsupported.
#[tokio::test]
async fn watch_interval_is_floored_and_accounts_are_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![
        target("weather", true, CredentialUse::Free),
        target("inbox", true, CredentialUse::Account),
    ]);
    let source = WatchSource::new(&hub, host);
    for interval in [10, 59, 3601] {
        let refused = source
            .authorize("p", "watch.weather.changed", &json!({"interval": interval}))
            .await
            .expect_err("out of range");
        assert_eq!(refused.code, -32602);
        assert_eq!(refused.data.expect("data")["field"], "arguments.interval");
    }
    source
        .authorize("p", "watch.weather.changed", &json!({"interval": 60}))
        .await
        .expect("the floor itself");
    let refused = source
        .authorize("p", "watch.inbox.changed", &json!({}))
        .await
        .expect_err("account credential");
    assert_eq!(refused.code, -32014);
}

/// U4, budget: a credentialed poll is charged to its one holder; a shared
/// one to the global budget.
#[tokio::test]
async fn watch_polls_are_charged_by_sharing() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![
        target("weather", true, CredentialUse::Free),
        target("crm", true, CredentialUse::Keyed),
    ]);
    let mut intake = drain(&hub);
    for name in ["watch.weather.changed", "watch.crm.changed"] {
        admit(&hub, "p", name, &json!({}));
        let poller = run(&hub, &host, "p", name, &json!({}));
        poll_all(&hub, &host, &poller, &[json!({"x": 1})], &mut intake).await;
    }
    let calls = host.calls.lock().clone();
    assert_eq!(
        calls,
        [
            ("p".to_owned(), Charge::Global),
            ("p".to_owned(), Charge::Holder)
        ]
    );
}

/// U3: a credential-free capability shares one lifecycle key across
/// principals; a credentialed one keys per principal, and its occurrence
/// matches only the principal it was polled for. A flap A->B->A->B is three
/// events with three distinct ids.
#[tokio::test]
async fn watch_pollers_are_shared_per_canonical_arguments_and_credential() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![
        target("weather", true, CredentialUse::Free),
        target("crm", true, CredentialUse::Keyed),
    ]);
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    let args = json!({"arguments": {"q": "x"}});
    let free = "watch.weather.changed";
    assert_eq!(
        source.lifecycle_key("alice", free, &args),
        source.lifecycle_key("bob", free, &args)
    );
    let keyed = "watch.crm.changed";
    assert_ne!(
        source.lifecycle_key("alice", keyed, &args),
        source.lifecycle_key("bob", keyed, &args)
    );
    admit(&hub, "alice", keyed, &args);
    admit(&hub, "bob", keyed, &args);
    let poller = run(&hub, &host, "alice", keyed, &args);
    let mut intake = drain(&hub);
    let (a, b) = (json!({"v": "a"}), json!({"v": "b"}));
    let events = poll_all(
        &hub,
        &host,
        &poller,
        &[a.clone(), b.clone(), a, b],
        &mut intake,
    )
    .await;
    assert_eq!(events.len(), 3);
    let mut ids: Vec<&str> = events.iter().map(|e| e.upstream_id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3, "distinct ids per transition");
    assert!(source.matches("alice", &args, &events[0]));
    assert!(
        !source.matches("bob", &args, &events[0]),
        "bob's own poller answers bob"
    );
    assert!(
        host.calls.lock().iter().all(|(p, _)| p == "alice"),
        "alice's poller runs under alice alone"
    );
}

/// U11: a capability reclassified as side-effecting stops its poller on the
/// next poll, with no call made, and its subscriptions are deleted.
#[tokio::test]
async fn watch_stops_when_its_capability_is_reclassified() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(
        host.calls.lock().is_empty(),
        "no call after the reclassification"
    );
    assert!(
        hub.store.subscriptions().is_empty(),
        "subscriptions deleted"
    );
}

/// U11: a capability removed from the catalogue stops its poller the same
/// way, with no call made and its subscriptions deleted.
#[tokio::test]
async fn watch_stops_when_its_capability_is_removed() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.targets.lock().clear();
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(host.calls.lock().is_empty(), "no call after the removal");
    assert!(
        hub.store.subscriptions().is_empty(),
        "subscriptions deleted"
    );
}

/// U4: jitter only stretches a wait, so no two polls come closer than the
/// interval, and the 60 s floor holds for the polls themselves.
#[test]
fn jitter_never_shortens_the_interval() {
    let base = std::time::Duration::from_secs(MIN_INTERVAL);
    for _ in 0..1000 {
        let wait = jitter(base);
        assert!(wait >= base, "{wait:?} under {base:?}");
        assert!(wait <= base.mul_f64(1.1), "{wait:?} over a tenth more");
    }
}

/// U11: a credential-free capability that starts needing a credential is
/// reclassified: its shared poller makes no call (one sharer's credential
/// never answers for every principal) and the type's subscriptions are
/// withdrawn, as for a side-effecting reclassification. Subscribers
/// subscribe again under the new class.
#[tokio::test]
async fn watch_stops_when_its_capability_changes_credential_class() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    *host.targets.lock() = vec![target("weather", true, CredentialUse::Keyed)];
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(host.calls.lock().is_empty(), "no call under the new class");
    assert!(hub.store.subscriptions().is_empty(), "withdrawn");
}

/// A poller that withdraws its type retires its key before it lets go of the
/// lifecycle lock: a subscribe in that gap (the capability watchable again)
/// starts a fresh poller instead of joining a key with nothing polling.
#[tokio::test]
async fn a_withdrawing_poller_retires_its_key_under_the_lock() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    let started = (SourceKind::RestWatch, poller.key.clone());
    hub.lifecycle.lock().await.insert(started.clone());
    *host.targets.lock() = vec![target("weather", false, CredentialUse::Free)];
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    // Read before the background reconcile can run: what a subscribe taking
    // the lock next would find.
    let gap = hub.lifecycle.try_lock().expect("the lock is free");
    assert!(!gap.contains(&started), "the key is no longer started");
    assert!(poller.stop.load(Ordering::Acquire), "marked stopped");
}

/// A reclassification read once is confirmed under the lifecycle lock before
/// anything is withdrawn: a capability that is watchable again by then keeps
/// its subscriptions, including one admitted after the flip back.
#[tokio::test]
async fn a_flip_back_before_the_withdrawal_keeps_every_subscription() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    admit(&hub, "q", name, &json!({"units": "metric"}));
    host.script
        .lock()
        .push_back(vec![target("weather", true, CredentialUse::Account)]);
    let mut last = None;
    poller.once(&hub, &mut last).await;
    assert_eq!(hub.store.subscriptions().len(), 2, "nothing withdrawn");
}

/// Keys and digests keep every integer: two arguments that differ past
/// 2^53 are two pollers, and an answer that changes there is a change.
#[tokio::test]
async fn keys_and_digests_are_lossless() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let name = "watch.weather.changed";
    let (a, b) = (
        json!({"arguments": {"id": 9_007_199_254_740_993_u64}}),
        json!({"arguments": {"id": 9_007_199_254_740_992_u64}}),
    );
    assert_ne!(
        source.lifecycle_key("p", name, &a),
        source.lifecycle_key("p", name, &b)
    );
    let (x, y) = (
        projection(&json!({"n": 9_007_199_254_740_993_u64}), None),
        projection(&json!({"n": 9_007_199_254_740_992_u64}), None),
    );
    assert_ne!(digest(&x), digest(&y));
}

/// A selected field that appears or disappears is a change, even when it
/// appears as `null`.
#[test]
fn an_absent_field_differs_from_a_null_one() {
    let fields = ["/gone".to_owned()];
    let (absent, null) = (
        projection(&json!({}), Some(&fields)),
        projection(&json!({"gone": null}), Some(&fields)),
    );
    assert_eq!(changed(&absent, &null), ["/gone"]);
}

/// U12: a change only in a default volatile key or in `_meta` emits nothing;
/// naming `/timestamp` in `fields` makes it count.
#[tokio::test]
async fn watch_ignores_default_volatile_fields_and_metadata() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    let mut intake = drain(&hub);
    let stamped = |n: u32| json!({"temp": 1, "timestamp": n, "_meta": {"receipt": n}});
    let plain = json!({});
    admit(&hub, "p", name, &plain);
    let poller = run(&hub, &host, "p", name, &plain);
    let answers: Vec<Value> = (0..10).map(stamped).collect();
    assert!(
        poll_all(&hub, &host, &poller, &answers, &mut intake)
            .await
            .is_empty()
    );
    let named = json!({"fields": ["/timestamp"]});
    admit(&hub, "p", name, &named);
    let poller = run(&hub, &host, "p", name, &named);
    let events = poll_all(&hub, &host, &poller, &[stamped(1), stamped(2)], &mut intake).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data["changed"], json!(["/timestamp"]));
}

/// A holder that may no longer invoke the capability is revoked before the
/// poll; with no holder left the poller stops and makes no call.
#[tokio::test]
async fn a_holder_without_access_is_revoked_before_any_call() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("crm", true, CredentialUse::Keyed)]);
    let name = "watch.crm.changed";
    admit(&hub, "p", name, &json!({}));
    let poller = run(&hub, &host, "p", name, &json!({}));
    host.denied.lock().push("p".into());
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(host.calls.lock().is_empty());
    assert!(hub.store.subscriptions().is_empty(), "revoked");
    let source = WatchSource::new(&hub, Arc::clone(&host) as Arc<dyn WatchHost>);
    admit(&hub, "p", name, &json!({}));
    let refused = source
        .authorize("p", name, &json!({}))
        .await
        .expect_err("fan-out re-check refuses");
    assert_eq!(refused.code, -32012);
}

/// A shared poller counts against the principal that opened it, so one key
/// cannot fill the gateway's pollers with distinct shared arguments.
#[tokio::test]
async fn shared_pollers_count_against_the_principal_that_opened_them() {
    let dir = tempfile::tempdir().expect("dir");
    let mut config = crate::config::EventsConfig::default();
    config.watch.max_pollers_per_principal = 1;
    let hub = EventsHub::open(&config, dir.path()).expect("hub");
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let name = "watch.weather.changed";
    let open = |n: u32| {
        let arguments = json!({"arguments": {"city": n}});
        let key = source.lifecycle_key("p", name, &arguments);
        (key, arguments)
    };
    let (key, arguments) = open(1);
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("the first");
    let (key, arguments) = open(2);
    let refused = source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect_err("past the principal's cap");
    assert_eq!(refused.code, -32013);
}

/// A poller that ended on its own leaves its entry behind until the core
/// reconciles; a subscribe in that gap starts a fresh poller instead of
/// joining the dead one.
#[tokio::test]
async fn a_subscribe_after_a_poller_exited_starts_a_fresh_one() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let source = WatchSource::new(&hub, host);
    let name = "watch.weather.changed";
    let arguments = json!({});
    let key = source.lifecycle_key("p", name, &arguments);
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("started");
    let exited = Arc::clone(&source.pollers.lock()[&key].stop);
    exited.store(true, Ordering::Release);
    source
        .on_first_subscriber(&key, "p", name, &arguments)
        .await
        .expect("restarted");
    assert!(
        !source.pollers.lock()[&key].stop.load(Ordering::Acquire),
        "a live poller holds the key"
    );
}

/// A poller that ends because no live holder is left retires its key under
/// the lifecycle lock: a subscribe before the core's next reconcile starts a
/// fresh poller instead of finding the key started with nothing polling.
#[tokio::test]
async fn a_poller_without_holders_retires_its_key() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let poller = run(&hub, &host, "p", "watch.weather.changed", &json!({}));
    let started = (SourceKind::RestWatch, poller.key.clone());
    hub.lifecycle.lock().await.insert(started.clone());
    let mut last = None;
    assert!(matches!(poller.once(&hub, &mut last).await, Step::Stop));
    assert!(
        !hub.lifecycle.lock().await.contains(&started),
        "the key is no longer started"
    );
    assert!(poller.stop.load(Ordering::Acquire), "marked stopped");
}

/// A holder that commits while the poll reads the store (its subscribe found
/// the key started and joined it) keeps the poller and the key.
#[tokio::test]
async fn a_holder_that_joins_during_the_poll_keeps_the_poller() {
    let dir = tempfile::tempdir().expect("dir");
    let hub = hub(dir.path());
    let host = fake(vec![target("weather", true, CredentialUse::Free)]);
    let name = "watch.weather.changed";
    let poller = Arc::new(run(&hub, &host, "p", name, &json!({})));
    let started = (SourceKind::RestWatch, poller.key.clone());
    let mut lock = hub.lifecycle.lock().await;
    lock.insert(started.clone());
    let task = tokio::spawn({
        let (hub, poller) = (Arc::clone(&hub), Arc::clone(&poller));
        async move { matches!(poller.once(&hub, &mut None).await, Step::Stop) }
    });
    // The poll found no holder and now waits for the lock the subscribe holds.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    admit(&hub, "p", name, &json!({}));
    drop(lock);
    assert!(!task.await.expect("poll"), "the poller goes on");
    assert!(
        hub.lifecycle.lock().await.contains(&started),
        "still started"
    );
    assert!(!poller.stop.load(Ordering::Acquire), "not stopped");
}
