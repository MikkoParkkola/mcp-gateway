// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The listener map: two subscribers of one
//! per-user backend, and its shared listener, are three listeners with their
//! own entry, URI ledger and confirm clock.

use std::sync::{Arc, Weak};

use super::*;
use crate::backend::BackendRegistry;

fn offline(name: &str) -> Arc<crate::backend::Backend> {
    Arc::new(crate::backend::Backend::new(
        name,
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    ))
}

fn listeners() -> Arc<UpstreamListeners> {
    let registry = Arc::new(BackendRegistry::new());
    assert!(registry.register(offline("b")));
    UpstreamListeners::new(
        registry,
        Weak::new(),
        Arc::new(std::collections::BTreeSet::new),
    )
}

fn as_user(obs: &str) -> ListenerKey {
    ListenerKey {
        backend: "b".into(),
        obs: Some(obs.into()),
    }
}

fn watched(uri: &str) -> Interest {
    Interest::ResourceUpdated(uri.to_owned())
}

#[tokio::test]
async fn each_subscriber_of_a_backend_is_its_own_listener() {
    let l = listeners();
    let (p, q, shared) = (as_user("p"), as_user("q"), ListenerKey::shared("b"));
    for key in [&p, &q, &shared] {
        l.hold(key, &watched("file:///a")).expect("counted");
    }
    let map = l.backends.lock();
    assert_eq!(map.len(), 3, "one entry per key");
    let (ep, eq) = (&map[&p], &map[&q]);
    assert!(!Arc::ptr_eq(ep, eq));
    assert!(
        !Arc::ptr_eq(&ep.ledger(), &eq.ledger()),
        "ISO-T4c: one subscriber's legacy holders never keep another's"
    );
    assert!(!Arc::ptr_eq(&ep.ledger(), &map[&shared].ledger()));
    assert_eq!(ep.key, p);
    assert_eq!(ep.name, "b");
}

/// ISO-T4c: one subscriber's legacy unsubscribe leaves another's subscribe
/// owed. The session fills a ledger; none runs here, so each subscriber's
/// ledger is told its wanted URI directly.
#[tokio::test]
async fn one_subscribers_unsubscribe_keeps_anothers_subscribe() {
    let l = listeners();
    let (p, q) = (as_user("p"), as_user("q"));
    let uri = "file:///a";
    for key in [&p, &q] {
        l.hold(key, &watched(uri)).expect("counted");
    }
    let q_ledger = {
        let map = l.backends.lock();
        for key in [&p, &q] {
            map[key].ledger().lock().want(uri).expect("room");
        }
        map[&q].ledger()
    };
    l.remove(&p, &watched(uri));
    assert!(
        q_ledger
            .lock()
            .due(std::time::Instant::now())
            .contains(&(uri.to_owned(), true)),
        "q's subscribe is still owed after p unsubscribed"
    );
}

#[tokio::test]
async fn removing_one_subscribers_interest_leaves_the_others() {
    let l = listeners();
    let (p, q) = (as_user("p"), as_user("q"));
    l.hold(&p, &Interest::ToolsChanged).expect("counted");
    l.hold(&q, &Interest::ToolsChanged).expect("counted");
    l.remove(&p, &Interest::ToolsChanged);
    let map = l.backends.lock();
    assert!(
        !map.contains_key(&p),
        "p's last interest ended its listener"
    );
    assert!(map.contains_key(&q), "q's listener is untouched");
}

#[tokio::test]
async fn each_listener_has_its_own_confirm_clock() {
    let l = listeners();
    let (p, q) = (as_user("p"), as_user("q"));
    assert!(l.may_confirm(&p));
    assert!(!l.may_confirm(&p), "p's window is open");
    assert!(l.may_confirm(&q), "ISO-T4b: q's read is not held by p's");
    assert!(l.may_confirm(&ListenerKey::shared("b")));
}

/// A per-user key with no snapshot of its own admits without a confirming
/// read. That it never reads as the gateway is pinned end to end by ISO-T7
/// (`tests/per_subscriber_isolation.rs`, the `iso_t7_*` rows).
#[tokio::test]
async fn a_per_user_key_without_a_snapshot_admits() {
    let l = listeners();
    assert!(
        l.authorize_uri(&as_user("p"), "file:///x", Some(1))
            .await
            .is_ok()
    );
    assert!(
        l.confirmed.lock().is_empty(),
        "no confirming read was taken for it"
    );
}

#[test]
fn a_listener_key_debug_omits_the_observation() {
    let rendered = format!("{:?}", as_user("idp:secret-binding"));
    assert!(!rendered.contains("secret-binding"), "{rendered}");
    assert!(rendered.contains("per_user: true"), "{rendered}");
}

/// C9: a per-user listener logs that an error happened, never its text.
#[tokio::test]
async fn a_per_user_listener_withholds_error_text() {
    let l = listeners();
    l.hold(&as_user("p"), &Interest::ToolsChanged)
        .expect("counted");
    l.hold(&ListenerKey::shared("b"), &Interest::ToolsChanged)
        .expect("counted");
    let map = l.backends.lock();
    let echoed = "401: bad token eyJsecret";
    assert_eq!(map[&as_user("p")].error_text(&echoed), "withheld");
    assert_eq!(map[&ListenerKey::shared("b")].error_text(&echoed), echoed);
}

/// A5: a backend runs at most `MAX_PER_USER_LISTENERS` per-user listeners; a
/// new subscriber past it is refused, one already listening is not, and the
/// shared listener never counts.
#[tokio::test]
async fn a5_per_user_listeners_are_bounded_per_backend() {
    let l = listeners();
    for n in 0..MAX_PER_USER_LISTENERS {
        l.hold(&as_user(&format!("u{n}")), &Interest::ToolsChanged)
            .expect("counted");
    }
    assert!(l.over_budget(&as_user("new")), "one past the budget");
    assert!(
        !l.over_budget(&as_user("u0")),
        "an existing listener adds interest"
    );
    assert!(!l.over_budget(&ListenerKey::shared("b")));
    let other = ListenerKey {
        backend: "other".into(),
        obs: Some("new".into()),
    };
    assert!(!l.over_budget(&other), "per backend");
}

/// A parked key is counted against the same URI budget a running one is: past
/// it, `hold` refuses rather than dropping the URI.
#[tokio::test]
async fn a_parked_key_refuses_a_uri_past_the_budget() {
    let l = listeners();
    let p = as_user("p");
    for n in 0..crate::events::upstream_need::MAX_URIS {
        l.hold(&p, &watched(&format!("file:///{n}")))
            .expect("counted");
    }
    assert!(l.hold(&p, &watched("file:///over")).is_err());
    assert!(l.hold(&p, &Interest::ToolsChanged).is_ok(), "no URI budget");
}

/// ISO-T4a, map half: two subscribers' tools interest on one per-user backend
/// keeps two listener entries, so their coalescers, snapshots and tasks are
/// two. A key that ignored the observation would fold them into one.
#[tokio::test]
async fn iso_t4a_two_subscribers_tools_interest_keeps_two_listeners() {
    let l = listeners();
    let (p, q) = (as_user("p"), as_user("q"));
    l.hold(&p, &Interest::ToolsChanged).expect("counted");
    l.hold(&q, &Interest::ToolsChanged).expect("counted");
    let map = l.backends.lock();
    assert_eq!(map.len(), 2, "one listener per subscriber");
    assert!(!Arc::ptr_eq(&map[&p], &map[&q]), "no shared listener state");
}
