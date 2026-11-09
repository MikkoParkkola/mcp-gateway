// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! In-flight admission for a live owner, and the expiry sweep never evicting a live or settling entry.

use super::*;

/// Row 4a — a second caller arriving on a key whose reservation passed
/// `IN_FLIGHT_TIMEOUT` while its owner is still alive is told in-flight, not
/// admitted.
///
/// Admission is the whole of this row. `decide_check_plan`
/// (`src/idempotency.rs:246-258`) answers `CheckPlan::InFlight` for a live
/// owner and a dead one alike, so the *staleness* of the dead half is
/// deliberately unobservable here — reclaiming is the sweep's job, which is
/// row 4b. Both halves are asserted anyway, because what this row pins is that
/// ageing past the timeout readmits nobody.
#[test]
fn live_owner_past_the_timeout_is_told_in_flight() {
    let cache = Arc::new(IdempotencyCache::new());
    let _reservation = admit(&cache, "key-live-aged");

    assert!(
        cache.age_in_flight("key-live-aged", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)),
        "the seam must find the in-flight entry it is asked to age"
    );

    assert!(
        matches!(cache.check("key-live-aged"), CheckOutcome::InFlight),
        "a call still running past the timeout keeps its entry through \
         admission (ADR-012 A2): the second caller is told in-flight rather \
         than admitted against a key whose mutation is still running"
    );
    assert!(
        enforce(&cache, "key-live-aged", "backend:charge_card|{}").is_err(),
        "`enforce` must refuse the duplicate rather than mint a second \
         reservation for a key that is still owned"
    );

    // The never-readmit half: an aged entry whose owner is gone answers the
    // same way, because `decide_check_plan` maps `StaleInFlight` to
    // `CheckPlan::InFlight` too. Admission never trades staleness for a fresh
    // attempt; only the sweep acts on it.
    cache.mark_in_flight("key-dead-aged");
    assert!(cache.age_in_flight("key-dead-aged", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));
    assert!(
        matches!(cache.check("key-dead-aged"), CheckOutcome::InFlight),
        "an aged entry with no live owner is still not an invitation to re-run \
         the call at the admission surface: an admission that freed a key here \
         is the second execution on one key ADR-012 exists to stop"
    );
}

/// Row 4b — that same entry survives an explicit `evict_expired` sweep, and
/// an aged entry whose owner is gone does not.
///
/// A separate row because the sweep is the only public surface on which
/// staleness is observable at all: `evict_expired`
/// (`src/idempotency.rs:534`) retains on `!is_reclaimable(classify(entry))`,
/// the same predicate admission uses, so *"a call running past the timeout
/// keeps its entry through the background cleanup as well as through
/// admission"* (ADR-012 consequence 3).
///
/// Both halves are asserted, and that is what makes the row non-vacuous:
/// demanding survival of every aged in-flight entry would demand it of one
/// whose owner died too, removing the eviction consequence 3 depends on. The
/// requirement is that liveness decide the sweep, not that the sweep stop
/// deciding — the timeout then does what it was introduced for, *"reclaiming
/// entries whose owner is gone — and nothing else"*.
#[test]
fn a_live_reservation_survives_an_evict_expired_sweep() {
    let cache = Arc::new(IdempotencyCache::new());

    // Owned: `enforce` mints the token and the reservation holds it alive.
    let _live = admit(&cache, "key-live");
    // Ownerless by construction: `mark_in_flight` stores `Weak::new()`.
    cache.mark_in_flight("key-dead");

    let past_the_timeout = IN_FLIGHT_TIMEOUT + Duration::from_secs(1);
    assert!(cache.age_in_flight("key-live", past_the_timeout));
    assert!(cache.age_in_flight("key-dead", past_the_timeout));

    cache.evict_expired();

    assert!(
        matches!(cache.check("key-live"), CheckOutcome::InFlight),
        "the sweep must not reclaim a key whose call is still running: \
         evicting it readmits the next caller fresh against a mutation in \
         progress, which is the duplicate execution ADR-012 A2 closes"
    );
    assert!(
        matches!(cache.check("key-dead"), CheckOutcome::Proceed),
        "the sweep must still reclaim an aged entry whose owner is gone — \
         a liveness rule that retains everything past the timeout removes the \
         eviction consequence 3 depends on"
    );
}

/// Row 4c — a sweep landing while a reservation's settlement is in progress
/// does not evict its entry.
///
/// The race amendment A2 exists for, and the one rows 4a and 4b cannot state:
/// `Arc` drops the strong count to zero *before* running the inner value's
/// `Drop`, so `Weak::upgrade` returns `None` while the reservation is still
/// storing `Failed` (ADR-012:150-163). A liveness rule built on the
/// reservation's own refcount passes 4a and 4b and still loses the entry here,
/// admitting the next caller fresh against a key whose mutation may have
/// committed.
/// Stated as a one-sided invariant under arbitrary interleaving rather than a
/// single-shot failing test: the damage is the *transient* `Proceed` a
/// concurrent caller reads and acts on, and settlement re-inserts the entry
/// afterwards either way (`mark_completed_bound` inserts unconditionally), so
/// a post-hoc scan of the finished keys cannot fail. A checker thread reading
/// the published key while a sweeper runs is the only oracle. The read is
/// racy in one direction only, which is what makes it sound: a stale read can
/// name a key that has since settled, and a settled key answers `Completed`,
/// so the checker cannot false-positive.
#[test]
fn a_sweep_during_settlement_does_not_evict_the_entry() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const ROUNDS: usize = 500;
    const FINGERPRINT: &str = "backend:charge_card|{}";

    let cache = Arc::new(IdempotencyCache::new());
    let published: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let readmitted = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));

    let sweeper = {
        let cache = Arc::clone(&cache);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                cache.evict_expired();
            }
        })
    };
    let checker = {
        let cache = Arc::clone(&cache);
        let published = Arc::clone(&published);
        let readmitted = Arc::clone(&readmitted);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let key = published.lock().expect("published mutex poisoned").clone();
                if let Some(key) = key
                    && matches!(cache.check(&key), CheckOutcome::Proceed)
                {
                    readmitted.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };

    for round in 0..ROUNDS {
        let key = format!("key-settling-{round}");
        let outcome = enforce(&cache, &key, FINGERPRINT).expect("a fresh key is admitted");
        let GuardOutcome::Proceed(mut reservation) = outcome else {
            panic!("a fresh key must be admitted, not answered from the cache");
        };
        *published.lock().expect("published mutex poisoned") = Some(key.clone());
        // Aged so the sweeper actually considers the entry; the owner is alive,
        // so only the settlement window can make it look reclaimable.
        assert!(cache.age_in_flight(&key, IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));

        reservation.complete(&json!({"resultType": "complete", "content": []}));
        drop(reservation);

        *published.lock().expect("published mutex poisoned") = None;
    }

    done.store(true, Ordering::Relaxed);
    sweeper.join().expect("sweeper thread panicked");
    checker.join().expect("checker thread panicked");

    assert_eq!(
        readmitted.load(Ordering::Relaxed),
        0,
        "a sweep landing inside a reservation's settlement must not free its \
         key: every `Proceed` counted here is a caller told to run a mutation \
         whose first execution had already reached the backend (ADR-012 A2, \
         ADR-012:150-163)"
    );
}
