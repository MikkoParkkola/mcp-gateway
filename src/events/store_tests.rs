// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

const TAIL: TailPolicy = TailPolicy {
    ttl: Duration::from_secs(3600),
    max: 3,
    max_per_principal: 2,
};

fn sub(principal: &str, url: &str, now: DateTime<Utc>) -> Subscription {
    Subscription {
        v: 1,
        id: format!("sub_{principal}_{}", url.len()),
        principal: principal.into(),
        api_key_name: None,
        url: url.into(),
        name: "e".into(),
        arguments: serde_json::json!({}),
        secret: "whsec_x".into(),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + chrono::Duration::hours(1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
    }
}

#[test]
fn records_survive_reopen_and_secrets_stay_out_of_debug() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let s = sub("p", "https://h/a", now);
    store.upsert(s.clone(), true, now).expect("upsert");
    assert!(!format!("{s:?}").contains("whsec_x"));
    drop(store);
    let store = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert_eq!(store.live_count(Some("p"), now), 1);
    assert!(store.is_verified("p", "https://h/a", now, TAIL));
    assert!(
        !store.is_verified("q", "https://h/a", now, TAIL),
        "keyed by principal too"
    );
}

#[test]
fn tail_lives_for_its_ttl_and_is_capped_per_principal() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = Utc::now();
    let store = Store::open(dir.path(), t0, TAIL).expect("open");
    let urls = ["https://h/1", "https://h/22", "https://h/333"];
    for (n, url) in urls.iter().enumerate() {
        let at = t0 + chrono::Duration::seconds(i64::try_from(n).expect("small"));
        let s = sub("p", url, at);
        store.upsert(s.clone(), true, at).expect("upsert");
        store.remove(&s.id, at, TAIL).expect("remove");
    }
    let now = t0 + chrono::Duration::seconds(10);
    assert!(
        !store.is_verified("p", urls[0], now, TAIL),
        "oldest of three evicted at cap 2"
    );
    assert!(store.is_verified("p", urls[1], now, TAIL));
    assert!(store.is_verified("p", urls[2], now, TAIL));
    let late = t0 + chrono::Duration::hours(2);
    assert!(
        !store.is_verified("p", urls[2], late, TAIL),
        "past the tail TTL"
    );
}

#[test]
fn a_live_subscriptions_verification_is_never_evicted() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    store
        .upsert(sub("p", "https://live/xyz", now), true, now)
        .expect("live");
    for url in [
        "https://h/1",
        "https://h/22",
        "https://h/333",
        "https://h/4444",
    ] {
        let s = sub("p", url, now);
        store.upsert(s.clone(), true, now).expect("upsert");
        store.remove(&s.id, now, TAIL).expect("remove");
    }
    assert!(store.is_verified("p", "https://live/xyz", now, TAIL));
}
