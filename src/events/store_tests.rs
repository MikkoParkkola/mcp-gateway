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
        api_key: None,
        credential_kind: None,
        credential_principal: None,
        read_key: None,
        binding: None,
        legacy_api_key_name: None,
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
    // The grace runs from the commit that rotated, not the request.
    assert_eq!(stored.previous_until, Some(stored.granted_at + grace()));
}

/// The rotation grace protects a live rotation only: an expired row's old
/// secret ends with the row and is never dual-signed for its successor.
#[test]
fn an_expired_rows_secret_is_not_carried_into_a_new_grace() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let mut first = sub("p", "https://h/1", now);
    first.expires_at = Some(now + chrono::Duration::seconds(1));
    store
        .admit(first.clone(), true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("first");
    let later = now + chrono::Duration::seconds(5);
    let mut renewed = sub("p", "https://h/1", later);
    renewed.secret = "whsec_second".into();
    store
        .admit(renewed, true, CAPS, grace(), later, TAIL)
        .expect("io")
        .expect("renewed");
    let stored = store.get(&first.id).expect("row");
    assert_eq!(stored.secret, "whsec_second");
    assert_eq!(stored.previous_secret, None, "the expired secret is gone");
    assert_eq!(stored.previous_until, None);
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

#[test]
fn a_skipped_challenge_without_a_usable_opt_in_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let s = sub("p", "https://h/1", now);
    assert_eq!(
        store
            .admit(s.clone(), false, CAPS, grace(), now, TAIL)
            .expect("io"),
        Err(CapHit::Unverified)
    );
    assert!(store.get(&s.id).is_none(), "nothing committed");
    store
        .admit(s, true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("a fresh opt-in commits");
}

#[test]
fn one_principals_churn_evicts_its_own_tail_before_anothers() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = Utc::now();
    let store = Store::open(dir.path(), t0, TAIL).expect("open");
    let cycle = |principal: &str, url: &str, secs: i64| {
        let at = t0 + chrono::Duration::seconds(secs);
        let s = sub(principal, url, at);
        store
            .admit(s.clone(), true, CAPS, grace(), at, TAIL)
            .expect("io")
            .expect("admitted");
        store.remove(&s.id, at, TAIL).expect("remove");
    };
    cycle("q", "https://h/1", 0);
    cycle("p", "https://h/22", 1);
    cycle("p", "https://h/333", 2);
    cycle("p", "https://h/4444", 3);
    let now = t0 + chrono::Duration::seconds(10);
    assert!(
        store.is_verified("q", "https://h/1", now, TAIL),
        "q's older tail survives"
    );
    assert!(
        !store.is_verified("p", "https://h/22", now, TAIL),
        "p's own oldest went"
    );
}

/// MIK-7805 AC2: the commit itself says whether it inserted or refreshed.
#[test]
fn admit_reports_inserted_then_refreshed() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let s = sub("p", "https://h/1", now);
    assert_eq!(
        store
            .admit(s.clone(), true, CAPS, grace(), now, TAIL)
            .expect("io"),
        Ok(Admission::Inserted)
    );
    assert_eq!(
        store.admit(s, false, CAPS, grace(), now, TAIL).expect("io"),
        Ok(Admission::Refreshed)
    );
}

/// MIK-7854.EVENTS.3: no build wrote a version 0 record, so one is skipped
/// on load like any version this build does not know.
#[test]
fn a_version_zero_record_is_not_loaded() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let s = sub("p", "https://h/a", now);
    store
        .admit(s.clone(), true, CAPS, grace(), now, TAIL)
        .expect("io")
        .expect("admitted");
    drop(store);
    let (subs, name) = (dir.path().join("subs"), format!("{}.json", s.id));
    let bytes = std::fs::read(subs.join(&name)).expect("record");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    value["v"] = serde_json::json!(0);
    write_record(&subs, &name, &value).expect("rewrite");
    let store = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert!(store.get(&s.id).is_none(), "a version 0 record is skipped");
}

/// MIK-7854.EVENTS.4: a verification tail over the cap in force is trimmed
/// before an admission may reuse it, on the same open store.
#[test]
fn an_over_cap_tail_is_trimmed_before_it_is_reused() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = Utc::now();
    let store = Store::open(dir.path(), t0, TAIL).expect("open");
    let urls = ["https://h/1", "https://h/22", "https://h/333"];
    for (n, url) in urls.iter().enumerate() {
        let at = t0 + chrono::Duration::seconds(i64::try_from(n).expect("small"));
        let s = sub("q", url, at);
        store
            .admit(s.clone(), true, CAPS, grace(), at, TAIL)
            .expect("io")
            .expect("admitted");
        store.remove(&s.id, at, TAIL).expect("remove");
    }
    let narrow = TailPolicy {
        max: 1,
        max_per_principal: 1,
        ..TAIL
    };
    let now = t0 + chrono::Duration::seconds(10);
    assert_eq!(
        store
            .admit(sub("q", urls[1], now), false, CAPS, grace(), now, narrow)
            .expect("io"),
        Err(CapHit::Unverified),
        "the older tail is past the narrowed cap"
    );
}

/// MIK-7854.EVENTS.4: subscriptions live at the request time but expired by
/// the commit are swept at the commit instant, so their tails are capped
/// before the opt-in is read.
#[test]
fn tails_of_rows_that_expire_before_the_commit_are_capped_first() {
    let dir = tempfile::tempdir().expect("dir");
    let real = Utc::now();
    let asked = real - chrono::Duration::hours(2);
    let long = TailPolicy {
        ttl: Duration::from_secs(24 * 3600),
        max: 1,
        max_per_principal: 1,
    };
    let store = Store::open(dir.path(), asked, long).expect("open");
    for (url, mins) in [("https://h/1", 10), ("https://h/22", 20)] {
        let s = Subscription {
            expires_at: Some(asked + chrono::Duration::minutes(mins)),
            ..sub("q", url, asked)
        };
        store
            .admit(s, true, CAPS, grace(), asked, long)
            .expect("io")
            .expect("admitted");
    }
    let again = sub("q", "https://h/1", asked);
    assert_eq!(
        store
            .admit(again, false, CAPS, grace(), asked, long)
            .expect("io"),
        Err(CapHit::Unverified),
        "both rows expired before the commit; the older tail is over the cap"
    );
}

/// MIK-7854.EVENTS.1: the grant becomes a time at the commit instant, not at
/// the request: a request stamped 2 h ago still commits a 1 h grant that is
/// live now, standing in for any wait before the store lock.
#[test]
fn the_grant_is_fixed_at_the_commit_instant() {
    let dir = tempfile::tempdir().expect("dir");
    let asked = Utc::now() - chrono::Duration::hours(2);
    let store = Store::open(dir.path(), asked, TAIL).expect("open");
    let s = sub("p", "https://h/a", asked);
    let grant = Grant {
        ttl: Some(chrono::Duration::hours(1)),
        until: None,
    };
    let (_, answered) = store
        .admit_granted(s.clone(), grant, true, (CAPS, grace(), TAIL), asked)
        .expect("io")
        .expect("admitted");
    let row = store.get(&s.id).expect("row");
    let expires = row.expires_at.expect("an expiry");
    assert_eq!(
        answered,
        Some(expires),
        "the answer is the committed expiry"
    );
    assert!(expires > Utc::now(), "live after the commit: {expires}");
    assert_eq!(expires - row.granted_at, chrono::Duration::hours(1));
}
