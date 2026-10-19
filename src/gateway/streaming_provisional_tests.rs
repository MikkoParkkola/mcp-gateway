// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Provisional sessions (MIK-8504): minted, counted, promoted, reaped, capped.

use super::*;
use crate::config::StreamingConfig;
use crate::gateway::session_id::SessionId;

const HOUR: Duration = Duration::from_secs(3600);

fn mux() -> NotificationMultiplexer {
    NotificationMultiplexer::new(
        Arc::new(crate::backend::BackendRegistry::new()),
        StreamingConfig::default(),
    )
}

fn owner() -> SessionOwner {
    SessionOwner::Credential("alice".to_string())
}

fn live(m: &NotificationMultiplexer) -> usize {
    m.provisional_live.load(Ordering::SeqCst)
}

fn session(m: &NotificationMultiplexer, id: &SessionId) -> Arc<ClientSession> {
    Arc::clone(
        m.sessions
            .read()
            .get(id.expose_secret())
            .expect("in the store"),
    )
}

#[test]
fn a_sessionless_call_mints_a_counted_provisional_session() {
    let m = mux();
    let (id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    assert!(session(&m, &id).provisional.load(Ordering::SeqCst));
    assert_eq!(live(&m), 1);
}

#[test]
fn initialize_mints_an_ordinary_session_even_at_the_cap() {
    let m = mux();
    m.provisional_live
        .store(MAX_PROVISIONAL_SESSIONS, Ordering::SeqCst);
    let (id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Ordinary)
        .expect("initialize is never refused by the cap");
    assert!(!session(&m, &id).provisional.load(Ordering::SeqCst));
    assert_eq!(live(&m), MAX_PROVISIONAL_SESSIONS);
}

#[test]
fn at_the_cap_a_new_provisional_session_is_refused_and_nothing_is_inserted() {
    let m = mux();
    m.provisional_live
        .store(MAX_PROVISIONAL_SESSIONS - 1, Ordering::SeqCst);
    let (_id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("one below the cap admits");
    let before = m.session_count();
    assert!(
        m.open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
            .is_err()
    );
    assert_eq!(m.session_count(), before);
    assert_eq!(live(&m), MAX_PROVISIONAL_SESSIONS);
}

#[test]
fn at_the_cap_the_owner_still_resumes_its_session() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    m.provisional_live
        .store(MAX_PROVISIONAL_SESSIONS, Ordering::SeqCst);
    let (again, _hold) = m
        .open_request_session_scoped(
            Some(id.expose_secret()),
            &owner(),
            None,
            MintKind::Provisional,
        )
        .expect("a resume is never refused");
    assert_eq!(again.expose_secret(), id.expose_secret());
}

#[test]
fn presenting_the_id_again_promotes_it_once() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    assert_eq!(live(&m), 1, "counted until presented again");
    for _ in 0..2 {
        let (_, _hold) = m
            .open_request_session_scoped(
                Some(id.expose_secret()),
                &owner(),
                None,
                MintKind::Provisional,
            )
            .expect("resume");
    }
    assert!(!session(&m, &id).provisional.load(Ordering::SeqCst));
    assert_eq!(live(&m), 0);
}

#[test]
fn another_owner_presenting_the_id_neither_promotes_nor_resumes_it() {
    let m = mux();
    let (id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    let (other, _other_hold) = m
        .open_request_session_scoped(
            Some(id.expose_secret()),
            &SessionOwner::Credential("mallory".to_string()),
            None,
            MintKind::Provisional,
        )
        .expect("under the cap");
    assert_ne!(other.expose_secret(), id.expose_secret());
    assert!(session(&m, &id).provisional.load(Ordering::SeqCst));
    assert_eq!(live(&m), 2);
}

#[test]
fn a_provisional_session_is_reaped_after_the_short_limit_and_uncounted() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    let s = session(&m, &id);
    let now = *s.last_active.read();
    assert!(!NotificationMultiplexer::reapable(
        &s,
        now + PROVISIONAL_SESSION_TTL - Duration::from_millis(1),
        HOUR
    ));
    assert!(NotificationMultiplexer::reapable(
        &s,
        now + PROVISIONAL_SESSION_TTL,
        HOUR
    ));
    drop(s);
    m.remove_session(id.expose_secret());
    assert_eq!(live(&m), 0, "leaving the store uncounts it");
}

#[test]
fn a_provisional_session_with_a_request_in_flight_is_not_reaped() {
    let m = mux();
    let (id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    let s = session(&m, &id);
    let late = *s.last_active.read() + PROVISIONAL_SESSION_TTL * 2;
    // Past the provisional limit, and past a zero configured TTL that would
    // reap any idle session: the request in flight still keeps it.
    assert!(!NotificationMultiplexer::reapable(&s, late, Duration::ZERO));
}

#[test]
fn an_ordinary_session_keeps_the_configured_ttl() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Ordinary)
        .expect("ordinary");
    drop(hold);
    let s = session(&m, &id);
    let now = *s.last_active.read();
    assert!(!NotificationMultiplexer::reapable(
        &s,
        now + PROVISIONAL_SESSION_TTL,
        HOUR
    ));
    assert!(NotificationMultiplexer::reapable(&s, now + HOUR, HOUR));
}

#[test]
fn the_reaper_uncounts_what_it_reaps() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    // Under the provisional limit nothing goes.
    assert!(m.reap_expired_sessions(HOUR).is_empty());
    for s in m.sessions.read().values() {
        *s.last_active.write() = Instant::now() - PROVISIONAL_SESSION_TTL;
    }
    // The reaped id goes back to the lifecycle sweep, which ends every
    // per-session store keyed by it, as for an ordinary reap (R7).
    assert_eq!(
        m.reap_expired_sessions(HOUR),
        vec![id.expose_secret().to_string()]
    );
    assert_eq!(live(&m), 0);
}

/// R6: an id the store does not hold is a new insert and counts.
#[test]
fn an_unknown_id_at_the_cap_is_refused() {
    let m = mux();
    m.fill_provisional_cap_for_test();
    assert!(
        m.open_request_session_scoped(
            Some("no-such-session"),
            &owner(),
            None,
            MintKind::Provisional
        )
        .is_err()
    );
}

/// R9: removal, promotion and reaping each free one slot.
#[test]
fn removal_promotion_and_reaping_each_free_a_slot() {
    let m = mux();
    m.provisional_live
        .store(MAX_PROVISIONAL_SESSIONS - 3, Ordering::SeqCst);
    let mint = |m: &NotificationMultiplexer| {
        m.open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
            .map(|(id, _hold)| id)
    };
    let removed = mint(&m).expect("slot 1");
    let promoted = mint(&m).expect("slot 2");
    let reaped = mint(&m).expect("slot 3");
    assert!(mint(&m).is_err(), "full");
    m.remove_session(removed.expose_secret());
    assert!(m.touch_if_owned(promoted.expose_secret(), &owner()));
    *session(&m, &reaped).last_active.write() = Instant::now() - PROVISIONAL_SESSION_TTL;
    assert_eq!(m.reap_expired_sessions(HOUR).len(), 1);
    for slot in 0..3 {
        assert!(mint(&m).is_ok(), "freed slot {slot}");
    }
    assert!(mint(&m).is_err(), "full again");
}

/// R5: the count is checked and taken under the lock that inserts, so
/// racing admissions mint exactly the free slots.
#[test]
fn racing_admissions_mint_exactly_the_free_slots() {
    let m = mux();
    m.provisional_live
        .store(MAX_PROVISIONAL_SESSIONS - 5, Ordering::SeqCst);
    let admitted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..32 {
            scope.spawn(|| {
                if m.open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
                    .is_ok()
                {
                    admitted.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(admitted.load(Ordering::SeqCst), 5);
    assert_eq!(m.session_count(), 5);
    assert_eq!(live(&m), MAX_PROVISIONAL_SESSIONS);
}

/// R10: the direct route presenting the id adopts it.
#[test]
fn the_direct_route_presenting_the_id_promotes_it() {
    let m = mux();
    let (id, _hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    assert_eq!(live(&m), 1);
    assert!(m.touch_if_owned(id.expose_secret(), &owner()));
    assert!(!session(&m, &id).provisional.load(Ordering::SeqCst));
    assert_eq!(live(&m), 0);
}

/// R11: an open stream keeps a provisional session past the limit, with no
/// request in flight; once it closes the session goes.
#[test]
fn an_open_stream_keeps_a_provisional_session_past_the_limit() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    let s = session(&m, &id);
    let receiver = s.subscribe();
    let late = *s.last_active.read() + PROVISIONAL_SESSION_TTL * 2;
    drop(hold);
    assert!(!NotificationMultiplexer::reapable(&s, late, HOUR));
    drop(receiver);
    assert!(NotificationMultiplexer::reapable(&s, late, HOUR));
}

/// A request ending while the reaper looks keeps its adoption window: the
/// reaper reads what is in flight before the last-active time, and a hold's
/// drop writes the time before it lowers the count (review fix).
#[test]
fn a_request_ending_mid_sweep_is_not_reaped() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    let s = session(&m, &id);
    let late = *s.last_active.read() + PROVISIONAL_SESSION_TTL * 2;
    assert!(!NotificationMultiplexer::reapable_observed(
        &s,
        late,
        HOUR,
        || drop(hold)
    ));
}

/// A configured `session_ttl` shorter than the provisional limit shortens it
/// too: a provisional session never outlives an ordinary one (review G3).
#[test]
fn a_short_session_ttl_shortens_the_provisional_limit() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    let s = session(&m, &id);
    let short = Duration::from_secs(10);
    let now = *s.last_active.read();
    assert!(!NotificationMultiplexer::reapable(
        &s,
        now + short - Duration::from_millis(1),
        short
    ));
    assert!(NotificationMultiplexer::reapable(&s, now + short, short));
}

/// A zero `session_ttl` reaps an idle provisional session at once and frees
/// its slot (review round 3).
#[test]
fn a_zero_session_ttl_reaps_an_idle_provisional_session_and_frees_its_slot() {
    let m = mux();
    let (id, hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(hold);
    assert_eq!(live(&m), 1);
    assert_eq!(
        m.reap_expired_sessions(Duration::ZERO),
        vec![id.expose_secret().to_string()]
    );
    assert_eq!(live(&m), 0);
    assert_eq!(m.session_count(), 0);
}

/// A zero `session_ttl` still never reaps a provisional session under an
/// open stream or a running request (review round 3).
#[test]
fn a_zero_session_ttl_keeps_a_provisional_session_with_a_stream_or_a_request() {
    let m = mux();
    let (streamed, stream_hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    drop(stream_hold);
    let receiver = session(&m, &streamed).subscribe();
    let (_running, _request_hold) = m
        .open_request_session_scoped(None, &owner(), None, MintKind::Provisional)
        .expect("under the cap");
    assert!(m.reap_expired_sessions(Duration::ZERO).is_empty());
    assert_eq!(live(&m), 2);
    drop(receiver);
}
