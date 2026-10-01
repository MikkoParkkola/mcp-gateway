// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

const CAPS: Caps = Caps {
    per_principal: 100,
    global: 100,
};

fn grace() -> chrono::Duration {
    chrono::Duration::minutes(10)
}

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
    store
        .admit(s.clone(), true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("admitted");
    assert!(!format!("{s:?}").contains("whsec_x"));
    drop(store);
    let store = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert!(store.get(&s.id).is_some());
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
        store
            .admit(s.clone(), true, CAPS, grace(), at, TAIL)
            .expect("io")
            .expect("admitted");
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
        .admit(
            sub("p", "https://live/xyz", now),
            true,
            CAPS,
            grace(),
            now,
            TAIL,
        )
        .expect("io")
        .expect("live");
    for url in [
        "https://h/1",
        "https://h/22",
        "https://h/333",
        "https://h/4444",
    ] {
        let s = sub("p", url, now);
        store
            .admit(s.clone(), true, CAPS, grace(), now, TAIL)
            .expect("io")
            .expect("admitted");
        store.remove(&s.id, now, TAIL).expect("remove");
    }
    assert!(store.is_verified("p", "https://live/xyz", now, TAIL));
}

#[test]
fn caps_are_checked_with_the_commit_and_refresh_is_never_capped() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let caps = Caps {
        per_principal: 1,
        global: 2,
    };
    let first = sub("p", "https://h/1", now);
    store
        .admit(first.clone(), true, caps, grace(), now, TAIL)
        .expect("io")
        .expect("first");
    let second = sub("p", "https://h/22", now);
    assert_eq!(
        store
            .admit(second, true, caps, grace(), now, TAIL)
            .expect("io"),
        Err(CapHit::PerPrincipal(1))
    );
    store
        .admit(first, false, caps, grace(), now, TAIL)
        .expect("io")
        .expect("refresh at the cap");
    store
        .admit(sub("q", "https://h/1", now), true, caps, grace(), now, TAIL)
        .expect("io")
        .expect("q");
    assert_eq!(
        store
            .admit(sub("r", "https://h/1", now), true, caps, grace(), now, TAIL)
            .expect("io"),
        Err(CapHit::Global(2))
    );
}

#[test]
fn expired_rows_are_swept_on_admission_and_free_their_slot() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let caps = Caps {
        per_principal: 1,
        global: 1,
    };
    let mut old = sub("p", "https://h/1", now);
    old.expires_at = Some(now + chrono::Duration::seconds(1));
    store
        .admit(old.clone(), true, caps, grace(), now, TAIL)
        .expect("io")
        .expect("old");
    let later = now + chrono::Duration::seconds(5);
    store
        .admit(
            sub("p", "https://h/22", later),
            true,
            caps,
            grace(),
            later,
            TAIL,
        )
        .expect("io")
        .expect("the expired row no longer holds the slot");
    assert!(store.get(&old.id).is_none(), "swept from memory");
    assert!(
        !dir.path()
            .join("subs")
            .join(format!("{}.json", old.id))
            .exists(),
        "and disk"
    );
    assert!(
        store.is_verified("p", "https://h/1", later, TAIL),
        "its tail began at expiry"
    );
}

#[test]
fn rotation_keeps_the_stored_secret_as_previous() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let first = sub("p", "https://h/1", now);
    store
        .admit(first.clone(), true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("first");
    let mut rotated = first.clone();
    rotated.secret = "whsec_second".into();
    store
        .admit(rotated, false, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("rotated");
    let stored = store.get(&first.id).expect("row");
    assert_eq!(stored.secret, "whsec_second");
    assert_eq!(stored.previous_secret.as_deref(), Some("whsec_x"));
    assert_eq!(stored.previous_until, Some(now + grace()));
}

#[test]
fn unsubscribing_an_expired_row_does_not_restart_its_tail() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let mut old = sub("p", "https://h/1", now);
    old.expires_at = Some(now + chrono::Duration::seconds(1));
    store
        .admit(old.clone(), true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("old");
    let late = now + chrono::Duration::hours(2);
    assert!(
        !store.remove(&old.id, late, TAIL).expect("io"),
        "already swept"
    );
    assert!(
        !store.is_verified("p", "https://h/1", late, TAIL),
        "the tail began at expiry and has run out"
    );
}
