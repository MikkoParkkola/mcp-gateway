// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ISO-T2 end to end: managed-account (vault) backends on a multi-user
//! gateway, each user's listener running on its own minted credential and
//! fenced on its own grant.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::events::{FenceRead, ListenerGrant, ListenerMint};

/// Two users' minted credentials and grants: user `u1` sends token 0 and
/// `u2` token 1. A rotation moves one user's grant binding, never the token,
/// so the peer sees the same credential before and after.
struct Grants {
    tokens: [String; 2],
    generation: Mutex<[u32; 2]>,
}

impl Grants {
    fn new(tokens: [String; 2]) -> Arc<Self> {
        Arc::new(Self {
            tokens,
            generation: Mutex::new([1, 1]),
        })
    }

    fn index(subject: &str) -> usize {
        usize::from(subject == "u2")
    }

    fn binding(&self, subject: &str) -> String {
        let at = Self::index(subject);
        let generation = self.generation.lock().expect("grants")[at];
        format!("acct:fence:v1:{subject}:{generation}")
    }

    fn rotate(&self, subject: &str) {
        self.generation.lock().expect("grants")[Self::index(subject)] += 1;
    }
}

#[async_trait::async_trait]
impl ListenerMint for Grants {
    async fn mint(&self, _: &str, identity: &VerifiedIdentity) -> crate::Result<ListenerGrant> {
        let subject = identity.subject.as_str();
        Ok(ListenerGrant {
            headers: vec![(
                "authorization".to_owned(),
                self.tokens[Self::index(subject)].clone(),
            )]
            .into(),
            fence: Some(self.binding(subject)),
        })
    }

    async fn fence_binding(
        &self,
        _: &str,
        identity: &VerifiedIdentity,
    ) -> Result<Option<String>, FenceRead> {
        Ok(Some(self.binding(&identity.subject)))
    }
}

/// A callback that counts the connections made to it; the handshake never
/// completes, which is all a test needs to see of a delivery.
async fn counting_callback() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("https://{}/cb", listener.local_addr().expect("addr"));
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (url, accepted)
}

/// A hub whose `pt` is a managed-account backend at `peer`, with an audit
/// log (delivery sends nothing without one) and loopback callbacks allowed.
fn managed_fixture(peer: &TwoTokenPeer) -> Fixture {
    let dir = tempfile::tempdir().expect("dir");
    let events = crate::config::EventsConfig {
        callback_allow_private: vec!["127.0.0.0/8".into()],
        ..crate::config::EventsConfig::default()
    };
    let hub = EventsHub::open(&events, dir.path()).expect("hub");
    let config: crate::config::Config =
        crate::yaml::from_str(&managed_yaml(&peer.url)).expect("config");
    let live = Arc::new(crate::config_reload::LiveConfig::new(config));
    let config = live.get();
    let log = crate::security::TransparencyLogger::open(Arc::new(
        crate::security::TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            ..crate::security::TransparencyLogConfig::default()
        },
    ))
    .expect("log");
    let _ = hub.runtime.services.set(Arc::new(Services {
        live,
        #[cfg(feature = "firewall")]
        firewall: None,
        audit: Some(Arc::new(log)),
        provenance: None,
        public_provenance: None,
        #[cfg(feature = "cost-governance")]
        budget: None,
        credentials: LiveCredentials::default(),
        record_key: Some(crate::gateway::record_principal::test_key_arc()),
    }));
    Fixture { hub, config, dir }
}

fn managed_yaml(url: &str) -> String {
    format!(
        "backends:\n  pt:\n    http_url: {url}\n    streamable_http: true\n    account: work\n\
         accounts:\n  schema_version: accounts.v1\n  enabled: true\n  \
         deployment: single_process\n  instance_id: unit\n  store_dir: /unused/store\n  \
         authority_dir: /unused/authority\n  current_key_id: primary\n  keys:\n    \
         primary: env:UNUSED\n  descriptors:\n    \
         work:\n      mode: personal_managed\n      provider: fixture\n      \
         resource: https://api.fixture.test/\n      issuer: https://issuer.fixture.test\n      \
         authorization_endpoint: https://issuer.fixture.test/authorize\n      \
         token_endpoint: https://issuer.fixture.test/token\n      client_id: c\n      \
         redirect_uri: https://gateway.fixture.test/callback\n      scopes: [read]\n      \
         send_resource_parameter: true\n"
    )
}

/// The event id, subscription and lease stamp of every record in `f`'s outbox.
fn queued(f: &Fixture) -> Vec<(String, String, Option<String>)> {
    let entries = std::fs::read_dir(f.dir.path().join("outbox")).expect("outbox");
    entries
        .flatten()
        .map(|e| {
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(e.path()).expect("read")).expect("record");
            let text = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_owned();
            (
                text(&record["event_id"]),
                text(&record["subscription_id"]),
                record["observed"]["lease"].as_str().map(str::to_owned),
            )
        })
        .collect()
}

/// The event ids of `sub`'s records in `f`'s outbox stamped `stamp`.
fn stamped(f: &Fixture, sub: &str, stamp: &str) -> Vec<String> {
    queued(f)
        .into_iter()
        .filter(|r| r.1 == sub && r.2.as_deref() == Some(stamp))
        .map(|r| r.0)
        .collect()
}

/// Run `f`'s delivery worker, startup reconciliation done: the worker sends
/// nothing before it (`dispatch`, `src/events/worker_dispatch.rs:86`).
fn start_delivery(f: &Fixture) -> tokio::task::JoinHandle<()> {
    f.hub.runtime.reconciled.store(true, Ordering::Release);
    let services = Arc::clone(f.hub.runtime.services.get().expect("services"));
    let worker = Arc::clone(&f.hub);
    tokio::spawn(async move { worker.deliver_forever(&services).await })
}

/// Two users, `u1` and `u2`, each with a minted listener open on `pt`.
struct Rig {
    peer: TwoTokenPeer,
    f: Fixture,
    grants: Arc<Grants>,
    intake: tokio::sync::mpsc::Receiver<crate::events::fanout::SourceEvent>,
    /// Connections each user's callback has seen.
    posts: [Arc<AtomicUsize>; 2],
    _listening: ListenersAndBackend,
}

async fn two_managed_users() -> Rig {
    let tokens = [token(Some(in_an_hour())), token(Some(in_an_hour() + 60))].map(|t| t.to_string());
    let mut peer = two_token_peer(tokens.clone()).await;
    let f = managed_fixture(&peer);
    let grants = Grants::new(tokens);
    f.hub
        .set_listener_mint(Arc::clone(&grants) as Arc<dyn ListenerMint>);
    let (url1, posts1) = counting_callback().await;
    let (url2, posts2) = counting_callback().await;
    subscribe_to(&f, "u1", "pt", "u1", &url1);
    subscribe_to(&f, "u2", "pt", "u2", &url2);
    let listening = parked_listener(&f).await;
    let intake = f.hub.take_intake();
    let mut opened = [peer.next().await, peer.next().await];
    opened.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        opened,
        [Some(Stream::Opened(0)), Some(Stream::Opened(1))],
        "premise: each user's listener opened under their own minted token"
    );
    Rig {
        peer,
        f,
        grants,
        intake,
        posts: [posts1, posts2],
        _listening: listening,
    }
}

/// ISO-T2, end to end: each managed-account user's own change reaches only
/// their own row, stamped with their own grant, and is delivered to their own
/// callback; the other user's callback is never touched by it.
#[tokio::test]
async fn iso_t2_managed_listeners_each_queue_and_deliver_only_their_own_change() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    let mut rig = two_managed_users().await;
    assert!(
        rig.peer.push_tools_changed(0),
        "premise: u1's stream is open"
    );
    assert!(
        fan_out_next(&rig.f, &mut rig.intake).await,
        "u1's notice was read"
    );
    let rows = queued(&rig.f);
    let stamp = format!("vault:{}", rig.grants.binding("u1"));
    assert_eq!(
        rows.iter()
            .map(|r| (r.1.as_str(), r.2.as_deref()))
            .collect::<Vec<_>>(),
        [("sub_u1_pt", Some(stamp.as_str()))],
        "u1's change queued for u1 alone, under u1's grant"
    );
    let delivery = start_delivery(&rig.f);
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        match rig.posts[0].load(Ordering::SeqCst) {
            0 => std::ops::ControlFlow::Continue("u1 not yet sent to".to_owned()),
            _ => std::ops::ControlFlow::Break(()),
        }
    })
    .await
    .expect("u1's change is delivered to u1");
    assert_eq!(
        rig.posts[1].load(Ordering::SeqCst),
        0,
        "u2 saw nothing of it"
    );
    // And the other way round: u2's change is u2's alone.
    assert!(
        rig.peer.push_tools_changed(1),
        "premise: u2's stream is open"
    );
    assert!(
        fan_out_next(&rig.f, &mut rig.intake).await,
        "u2's notice was read"
    );
    let u2_stamp = format!("vault:{}", rig.grants.binding("u2"));
    let mut rows: Vec<_> = queued(&rig.f).into_iter().map(|r| (r.1, r.2)).collect();
    rows.sort();
    assert_eq!(
        rows,
        [
            ("sub_u1_pt".to_owned(), Some(stamp)),
            ("sub_u2_pt".to_owned(), Some(u2_stamp)),
        ],
        "u2's change queued for u2 alone, under u2's grant"
    );
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        match rig.posts[1].load(Ordering::SeqCst) {
            0 => std::ops::ControlFlow::Continue("u2 not yet sent to".to_owned()),
            _ => std::ops::ControlFlow::Break(()),
        }
    })
    .await
    .expect("u2's change is delivered to u2");
    delivery.abort();
}

/// ISO-T2, end to end, with a lease rotation mid-test: u1's change observed
/// under u1's old grant is never delivered once the grant rotates, u1's
/// listener reopens under the new grant, and a change after the rotation is
/// delivered. u2, whose grant never moved, is delivered throughout.
#[tokio::test]
async fn iso_t2_a_change_observed_under_the_old_grant_is_not_delivered_after_rotation() {
    use crate::events::services::{AccessVerdict, forced_verdict};
    let _admits = forced_verdict::answer(AccessVerdict::Admits);
    let mut rig = two_managed_users().await;
    for user in 0..2 {
        assert!(
            rig.peer.push_tools_changed(user),
            "premise: stream {user} is open"
        );
        assert!(
            fan_out_next(&rig.f, &mut rig.intake).await,
            "notice {user} was read"
        );
    }
    let before = queued(&rig.f);
    let old_stamp = format!("vault:{}", rig.grants.binding("u1"));
    let old = before
        .iter()
        .find(|r| r.1 == "sub_u1_pt")
        .expect("u1's record");
    assert_eq!(
        old.2.as_deref(),
        Some(old_stamp.as_str()),
        "stamped with the old grant"
    );
    assert!(
        before.iter().any(|r| r.1 == "sub_u2_pt"),
        "u2's change queued for u2"
    );
    rig.grants.rotate("u1");
    // The old run hears one more notice, reads under the rotated grant and
    // ends; anything it announced first keeps the old grant's stamp.
    assert!(
        rig.peer.push_tools_changed(0),
        "premise: the old stream is still open"
    );
    // The close and the reopen are separate connections: either may be
    // reported first.
    let mut ends = [rig.peer.next().await, rig.peer.next().await];
    ends.sort_by_key(|s| format!("{s:?}"));
    assert_eq!(
        ends,
        [Some(Stream::Closed(0)), Some(Stream::Opened(0))],
        "the old run ended and u1 reopened under the new grant"
    );
    assert!(
        rig.peer.push_tools_changed(0),
        "the new run's stream is open"
    );
    let new_stamp = format!("vault:{}", rig.grants.binding("u1"));
    // The old run's late announcement, if any, may reach fan-out first.
    while stamped(&rig.f, "sub_u1_pt", &new_stamp).is_empty() {
        assert!(
            fan_out_next(&rig.f, &mut rig.intake).await,
            "the new notice was read"
        );
    }
    assert_eq!(
        stamped(&rig.f, "sub_u1_pt", &new_stamp).len(),
        1,
        "one change stamped with the new grant"
    );
    let mut old_grant = stamped(&rig.f, "sub_u1_pt", &old_stamp);
    assert!(
        old_grant.contains(&old.0),
        "the first change keeps the old stamp"
    );
    assert!(
        queued(&rig.f)
            .iter()
            .filter(|r| r.1 == "sub_u1_pt")
            .all(|r| [Some(old_stamp.as_str()), Some(new_stamp.as_str())]
                .contains(&r.2.as_deref())),
        "every u1 change carries the grant it was observed under"
    );
    let delivery = start_delivery(&rig.f);
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        let sent = rig.posts.iter().all(|p| p.load(Ordering::SeqCst) > 0);
        match (sent, rig.f.hub.store.dead_summaries().len()) {
            (true, dead) if dead == old_grant.len() => std::ops::ControlFlow::Break(()),
            (sent, dead) => std::ops::ControlFlow::Continue(format!("sent {sent}, dead {dead}")),
        }
    })
    .await
    .expect("u2 and u1's new change are delivered, the old ones buried");
    let dead = rig.f.hub.store.dead_summaries();
    assert!(
        dead.iter()
            .all(|d| d.reason == crate::events::outbox::DeadReason::Observation.as_str()),
        "buried as observation_changed"
    );
    let mut buried: Vec<String> = dead.into_iter().map(|d| d.event_id).collect();
    buried.sort();
    old_grant.sort();
    assert_eq!(
        buried, old_grant,
        "only u1's changes from the old grant are buried"
    );
    delivery.abort();
}
