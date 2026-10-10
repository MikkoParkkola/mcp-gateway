// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 P2 (design v3, row 11): idle reclaim on a clock that reads before
//! 1970. Activity on such a clock cannot be dated, so the key waits for
//! renewal: the first readable reap gives it a full idle TTL (an ended
//! session a full END_GRACE) and keeps it; only a later reap reclaims it.
//! Nothing is reclaimed early once the clock reads, and nothing is held
//! forever.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{END_GRACE, IDLE_TTL, SessionLifecycle};

/// The real clock, read on this thread outside any forced-clock guard.
fn real_now() -> u64 {
    crate::clock::unix_secs().expect("the test host's clock reads")
}

/// A lifecycle that counts its cleanup handler's runs.
fn counted() -> (Arc<SessionLifecycle>, Arc<AtomicUsize>) {
    let lifecycle = Arc::new(SessionLifecycle::new());
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    lifecycle.register("count", move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    (lifecycle, fired)
}

/// T10a/T10c: a new key whose hold ends on an unreadable clock is not given
/// a deadline it cannot date. The first readable reap assigns it a full idle
/// TTL and keeps it, including at exactly that deadline; only a reap past it
/// reclaims the key. Mutant: the release stamped with the raw clock (or 0)
/// plus the TTL, so the first readable reap reclaims it.
#[test]
fn a_key_released_on_an_unreadable_clock_gets_a_full_idle_ttl_at_the_first_readable_reap() {
    let (lifecycle, fired) = counted();
    {
        let _clock = crate::clock::test_clock::before_epoch();
        drop(lifecycle.hold("caller"));
    }
    let first = real_now() + IDLE_TTL.as_secs() + 1;
    assert_eq!(
        lifecycle.reap(first),
        0,
        "reclaimed at the first readable reap after activity it could not date"
    );
    assert_eq!(
        lifecycle.reap(first + IDLE_TTL.as_secs()),
        0,
        "reclaimed at the deadline the first readable reap assigned"
    );
    assert_eq!(lifecycle.reap(first + IDLE_TTL.as_secs() + 1), 1);
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

/// T10b: activity on an unreadable clock proves an existing key live, so its
/// old deadline is not kept: the first readable reap renews it for a full
/// idle TTL. Mutant: the old deadline kept (or the raw clock's), so the key
/// is reclaimed at the first readable reap past it.
#[test]
fn activity_on_an_unreadable_clock_renews_an_existing_key_at_the_first_readable_reap() {
    let (lifecycle, fired) = counted();
    let old = real_now() + IDLE_TTL.as_secs();
    lifecycle.track("caller", old);
    {
        let _clock = crate::clock::test_clock::before_epoch();
        drop(lifecycle.hold("caller"));
    }
    let first = old + 1;
    assert_eq!(
        lifecycle.reap(first),
        0,
        "a key active since its old deadline was reclaimed on it"
    );
    assert_eq!(lifecycle.reap(first + IDLE_TTL.as_secs()), 0);
    assert_eq!(lifecycle.reap(first + IDLE_TTL.as_secs() + 1), 1);
    assert_eq!(fired.load(Ordering::SeqCst), 1);
}

/// T10d: a session that ends on an unreadable clock runs its end handlers
/// once at once, and its second pass waits a full END_GRACE from the first
/// readable reap, at exactly that boundary too. Mutant: the grace stamped
/// with the raw clock (or 0), so the second pass runs at the first readable
/// reap.
#[test]
fn a_session_ended_on_an_unreadable_clock_gets_a_full_grace_at_the_first_readable_reap() {
    let lifecycle = SessionLifecycle::new();
    let fired = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&fired);
    lifecycle.register_session_end("count", move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
    });
    {
        let _clock = crate::clock::test_clock::before_epoch();
        lifecycle.on_disconnect("ended");
    }
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "the first pass runs at once"
    );
    let first = real_now() + END_GRACE.as_secs() + 1;
    lifecycle.reap(first);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "the second pass ran at the first readable reap"
    );
    lifecycle.reap(first + END_GRACE.as_secs());
    assert_eq!(fired.load(Ordering::SeqCst), 1, "ran at the assigned grace");
    lifecycle.reap(first + END_GRACE.as_secs() + 1);
    assert_eq!(fired.load(Ordering::SeqCst), 2, "the second pass, once");
}
