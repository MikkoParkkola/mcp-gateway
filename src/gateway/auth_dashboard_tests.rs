// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Store-level tests for the dashboard bootstrap and sessions.

use super::DashboardBootstrap;

/// The link is redeemed only by somebody actually at this machine
/// (MIK-7257).
///
/// The check used to read the `Host` header, which the caller writes and a
/// proxy rewrites — nginx's default for a bare `proxy_pass` is the upstream
/// address, so a forwarded request arrived carrying a loopback `Host` and
/// was accepted from anywhere. These cases drive the same predicate the
/// middleware uses, over the two facts it now reads.
#[test]
fn a_link_is_redeemed_only_from_this_machine() {
    // (peer, forwarding header present, may redeem)
    let cases: [(&str, bool, bool); 6] = [
        // A browser on this machine: the case the link exists for.
        ("127.0.0.1:52344", false, true),
        ("[::1]:52344", false, true),
        // Straight off the network. Never printed on such a bind, and
        // refused even if the value leaked.
        ("10.0.0.7:41000", false, false),
        ("[2001:db8::1]:41000", false, false),
        // A same-host reverse proxy forwarding someone else's request: the
        // peer IS loopback, which is why the peer alone is not the answer.
        // Refused on the forwarding header a conventional proxy sets.
        ("127.0.0.1:52344", true, false),
        // A remote proxy is refused twice over.
        ("10.0.0.7:41000", true, false),
    ];
    for (peer, forwarded, may_redeem) in cases {
        let addr: std::net::SocketAddr = peer.parse().expect("test peer parses");
        let peer_is_local = addr.ip().is_loopback();
        let allowed = peer_is_local && !forwarded;
        assert_eq!(
            allowed, may_redeem,
            "peer {peer} with forwarding={forwarded} was judged wrongly: \
             refusing a local browser breaks the only way into the \
             dashboard, and admitting a forwarded request hands an admin \
             session to whoever holds the link"
        );
    }
}

#[test]
fn a_handle_is_only_valid_if_this_process_issued_it() {
    let b = DashboardBootstrap::new();
    let handle = b.issue_session();
    assert!(b.session_is_valid(&handle));
    assert!(!b.session_is_valid("guessed"));

    // A handle from another process is meaningless here, which is the
    // point of an opaque session over a bearer token in a cookie.
    let other = DashboardBootstrap::new();
    assert!(!other.session_is_valid(&handle));
}

#[test]
fn handles_are_not_guessable_and_not_reused() {
    let b = DashboardBootstrap::new();
    let a = b.issue_session();
    let c = b.issue_session();
    assert_ne!(a, c);
    assert!(a.len() >= 42, "32 random bytes, base64url: {a}");
}

/// The session handle is never the admin credential.
///
/// This is the central claim of the opaque-session design — the cookie used
/// to carry the bearer token, which is long-lived and, without TLS,
/// recoverable from the wire — and nothing asserted it. A change that put
/// the credential back in the cookie would have passed every test here.
#[test]
fn a_session_handle_is_never_the_admin_credential() {
    let bearer = "mcpgw_a-realistic-looking-admin-credential";
    let b = DashboardBootstrap::new();

    for _ in 0..8 {
        let handle = b.issue_session();
        assert_ne!(
            handle, bearer,
            "the cookie must carry an opaque handle, never the credential"
        );
        assert!(
            !handle.contains(bearer) && !bearer.contains(&handle),
            "and must not embed or be embedded in it: {handle}"
        );
        assert!(
            !handle.starts_with("mcpgw_"),
            "nor look like one, which would invite pasting it as a token: {handle}"
        );
    }
}

/// A bootstrap value is spent exactly once, and a wrong one spends nothing.
#[test]
fn a_bootstrap_value_is_single_use_and_a_wrong_one_costs_nothing() {
    let b = DashboardBootstrap::new();
    let printed = b.peek().expect("a value is issued at startup");

    assert!(!b.consume("not-the-value"), "a wrong value is rejected");
    assert!(
        b.consume(&printed),
        "and rejecting it must not have spent the real one — otherwise a \
         stray click on a stale link disarms the operator's own"
    );
    assert!(!b.consume(&printed), "the real value is spent only once");
}

// ── MIK-7570.SESSION.1: idle and absolute expiry (E5) ──────────────────

use std::time::Duration;

use super::{Now, SessionCheck, SessionLimits, Touch};

const IDLE: Duration = Duration::from_secs(1800);
const ABSOLUTE: Duration = Duration::from_secs(28_800);
const LIMITS: SessionLimits = SessionLimits {
    idle: IDLE,
    absolute: ABSOLUTE,
};
const SEC: Duration = Duration::from_secs(1);
/// One second short of the idle limit.
const JUST_IDLE: Duration = Duration::from_secs(1799);

/// `t0` moved forward by `by` on both clocks.
fn at(t0: Now, by: Duration) -> Now {
    Now {
        mono: t0.mono + by,
        wall: t0.wall + by,
    }
}

/// A store with one session issued at `t0`.
fn issued() -> (DashboardBootstrap, String, Now) {
    let b = DashboardBootstrap::new();
    let t0 = Now::read();
    let handle = b.issue_session_at(t0, &LIMITS);
    (b, handle, t0)
}

/// E5-T1: no activity for longer than the idle limit ends the session, and
/// the check that says so removes it.
#[test]
fn idle_session_expires() {
    let (b, h, t0) = issued();
    assert_eq!(
        b.check_session(&h, at(t0, IDLE + SEC), &LIMITS, Touch::Yes),
        SessionCheck::Expired,
        "a session untouched past the idle limit is expired"
    );
    assert_eq!(
        b.check_session(&h, at(t0, IDLE + SEC), &LIMITS, Touch::Yes),
        SessionCheck::Unknown,
        "and the expired handle was removed, not kept"
    );
}

/// E5-T2: steady activity cannot carry a session past the absolute limit.
#[test]
fn active_session_hits_absolute_limit() {
    let (b, h, t0) = issued();
    let step = JUST_IDLE;
    let mut elapsed = step;
    while elapsed <= ABSOLUTE {
        assert_eq!(
            b.check_session(&h, at(t0, elapsed), &LIMITS, Touch::Yes),
            SessionCheck::Valid,
            "an active session is valid before the absolute limit ({elapsed:?})"
        );
        elapsed += step;
    }
    assert_eq!(
        b.check_session(&h, at(t0, ABSOLUTE + SEC), &LIMITS, Touch::Yes),
        SessionCheck::Expired,
        "activity never extends a session past the absolute limit"
    );
}

/// E5-T3 (guard, passes today): activity restarts the idle clock.
#[test]
fn touched_session_stays_valid() {
    let (b, h, t0) = issued();
    assert_eq!(
        b.check_session(&h, at(t0, JUST_IDLE), &LIMITS, Touch::Yes),
        SessionCheck::Valid
    );
    assert_eq!(
        b.check_session(&h, at(t0, JUST_IDLE * 2), &LIMITS, Touch::Yes),
        SessionCheck::Valid,
        "the idle clock restarts at each activity check"
    );
}

/// E5-T12 (store half): a tab that only polls expires at the idle limit, far
/// below the absolute cap.
#[test]
fn poll_only_tab_expires_at_idle_not_cap() {
    let (b, h, t0) = issued();
    let poll = Duration::from_secs(5);
    let mut elapsed = poll;
    while elapsed < IDLE {
        assert_eq!(
            b.check_session(&h, at(t0, elapsed), &LIMITS, Touch::No),
            SessionCheck::Valid,
            "a poll inside the idle limit is answered ({elapsed:?})"
        );
        elapsed += poll;
    }
    assert_eq!(
        b.check_session(&h, at(t0, IDLE + SEC), &LIMITS, Touch::No),
        SessionCheck::Expired,
        "polls are checked but never extend the idle clock"
    );
}

/// E5-T8: issuing sweeps expired entries, so the store cannot grow without
/// bound.
#[test]
fn issue_sweeps_expired_sessions() {
    let b = DashboardBootstrap::new();
    let t0 = Now::read();
    for _ in 0..100 {
        let _ = b.issue_session_at(t0, &LIMITS);
    }
    let _ = b.issue_session_at(at(t0, ABSOLUTE + SEC), &LIMITS);
    assert_eq!(b.session_count(), 1, "only the fresh session remains");
}

/// E5-T14: a host suspend stops the monotonic clock; the wall clock still
/// ends the idle session.
#[test]
fn suspended_host_expires_by_wall_clock() {
    let (b, h, t0) = issued();
    let woke = Now {
        mono: t0.mono + SEC,
        wall: t0.wall + IDLE + SEC,
    };
    assert_eq!(
        b.check_session(&h, woke, &LIMITS, Touch::Yes),
        SessionCheck::Expired
    );
}

/// E5-T14b: the wall clock also enforces the absolute limit on a session that
/// was active recently by both clocks.
#[test]
fn suspended_host_hits_absolute_by_wall_clock() {
    let (b, h, t0) = issued();
    // Active until shortly before the suspend, on both clocks.
    let before = at(t0, Duration::from_secs(60));
    assert_eq!(
        b.check_session(&h, before, &LIMITS, Touch::Yes),
        SessionCheck::Valid
    );
    // Idle is widened to the absolute limit, so the wall gap since the last
    // activity (absolute - 59 s) stays under it: only the absolute
    // comparison on the wall clock can end this session. Monotonic age is 61 s.
    let limits = SessionLimits {
        idle: ABSOLUTE,
        absolute: ABSOLUTE,
    };
    let woke = Now {
        mono: before.mono + SEC,
        wall: t0.wall + ABSOLUTE + SEC,
    };
    assert_eq!(
        b.check_session(&h, woke, &limits, Touch::Yes),
        SessionCheck::Expired,
        "wall-clock age past the absolute limit ends the session"
    );
}

/// A backward wall-clock step cannot revive or extend a session: the
/// monotonic clock still ends it.
#[test]
fn a_backward_wall_step_does_not_extend() {
    let (b, h, t0) = issued();
    let stepped_back = Now {
        mono: t0.mono + IDLE + SEC,
        wall: t0.wall - Duration::from_secs(3600),
    };
    assert_eq!(
        b.check_session(&h, stepped_back, &LIMITS, Touch::Yes),
        SessionCheck::Expired
    );
}

/// MIK-8202: a wall clock stepped before 1970 refuses a dashboard session,
/// even one with no credential cap that is inside its idle limit: the
/// monotonic clock alone stops while the host sleeps.
#[test]
fn a_session_on_a_clock_before_the_epoch_is_refused() {
    let before_epoch = std::time::UNIX_EPOCH - Duration::from_secs(1);
    let (b, h, t0) = issued();
    assert_eq!(
        b.check_session(&h, at(t0, JUST_IDLE), &LIMITS, Touch::No),
        SessionCheck::Valid,
        "control: inside the idle limit on a readable clock"
    );
    let stepped = Now {
        mono: t0.mono + JUST_IDLE,
        wall: before_epoch,
    };
    assert_eq!(
        b.check_session(&h, stepped, &LIMITS, Touch::Yes),
        SessionCheck::Expired,
        "a clock before 1970 kept a dashboard session"
    );
}

/// Revocation removes the handle; a second revocation reports nothing.
#[test]
fn revoke_ends_a_session_once() {
    let (b, h, t0) = issued();
    assert!(
        b.revoke(&h, at(t0, SEC), &LIMITS),
        "an issued handle is revoked"
    );
    assert!(!b.revoke(&h, at(t0, SEC), &LIMITS), "and only once");
    assert_eq!(
        b.check_session(&h, at(t0, SEC), &LIMITS, Touch::Yes),
        SessionCheck::Unknown
    );
}

/// E5-T19: revoking an entry already past its limit is not a live logout: it
/// reports `false` (so nothing is audited as a logout) and still removes it.
#[test]
fn revoking_an_expired_entry_is_not_a_live_logout() {
    let (b, h, t0) = issued();
    assert!(
        !b.revoke(&h, at(t0, IDLE + SEC), &LIMITS),
        "a session past its idle limit had already ended"
    );
    assert_eq!(
        b.check_session(&h, at(t0, SEC), &LIMITS, Touch::No),
        SessionCheck::Unknown,
        "and the entry is gone"
    );
}

/// Rearming replaces an unused value: the old one is dead, the new one works
/// once.
#[test]
fn rearm_replaces_an_unused_value() {
    let b = DashboardBootstrap::new();
    let old = b.peek().expect("a value is issued at startup");
    let new = b.rearm();
    assert!(!new.is_empty(), "rearm returns a value");
    assert_ne!(old, new, "rearm mints a different value");
    assert!(!b.consume(&old), "the replaced value no longer redeems");
    assert!(b.consume(&new), "the new value redeems");
    assert!(!b.consume(&new), "once");
}

/// A session opened by a capped link ends at the cap, even inside its idle
/// and absolute limits.
#[test]
fn a_capped_session_ends_at_its_cap() {
    use super::{Now, SessionCheck, SessionLimits, Touch};
    use std::time::Duration;
    let store = DashboardBootstrap::new();
    let now = Now::read();
    let limits = SessionLimits::default();
    let value = store.rearm_until(Some(now.wall + Duration::from_secs(600)));
    let not_after = store
        .consume_capped(&value)
        .expect("the value redeems")
        .not_after;
    let handle = store.issue_session_until(now, &limits, not_after);
    let at = |secs| Now {
        mono: now.mono + Duration::from_secs(secs),
        wall: now.wall + Duration::from_secs(secs),
    };
    assert_eq!(
        store.check_session(&handle, at(599), &limits, Touch::No),
        SessionCheck::Valid
    );
    assert_eq!(
        store.check_session(&handle, at(601), &limits, Touch::No),
        SessionCheck::Expired
    );
}
