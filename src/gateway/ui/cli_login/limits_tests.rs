// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows L2.1-L2.6 and L2.9 of the CLI login test plan: each cap alone, with the
//! other counters empty, refused on both sides of its window's end.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::limits::{
    LOOKUP_WINDOW, LOOKUPS_PER_GATEWAY, LOOKUPS_PER_SESSION, Limits, MAX_TRACKED_KEYS, MINUTE,
    STARTS_PER_GATEWAY, STARTS_PER_PEER,
};

const JUST: Duration = Duration::from_secs(1);

fn peer(n: u32) -> IpAddr {
    IpAddr::from(n.to_be_bytes())
}

fn session(n: u32) -> String {
    format!("session-{n}")
}

/// L2.1: five starts per peer per minute; the refused sixth spends no
/// gateway slot.
#[test]
fn starts_five_per_peer_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for k in 1..=STARTS_PER_PEER {
        assert!(limits.admit_start(peer(1), t0), "start {k} of peer 1");
    }
    assert!(!limits.admit_start(peer(1), t0), "the 6th start of peer 1");
    for n in 2..=STARTS_PER_GATEWAY - STARTS_PER_PEER + 1 {
        assert!(
            limits.admit_start(peer(n), t0),
            "peer {n}: the refused 6th must not have spent a gateway slot"
        );
    }
    let fresh = Limits::new();
    for _ in 0..STARTS_PER_PEER {
        assert!(fresh.admit_start(peer(1), t0));
    }
    assert!(
        !fresh.admit_start(peer(1), t0 + MINUTE - JUST),
        "still inside the minute"
    );
    assert!(
        fresh.admit_start(peer(1), t0 + MINUTE),
        "the minute has passed"
    );
}

/// L2.2: a hundred starts per gateway per minute, each peer under its cap.
#[test]
fn starts_one_hundred_per_gateway_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for n in 1..=STARTS_PER_GATEWAY {
        assert!(limits.admit_start(peer(n), t0), "start from peer {n}");
    }
    assert!(!limits.admit_start(peer(1000), t0), "the 101st start");
    assert!(
        !limits.admit_start(peer(1001), t0 + MINUTE - JUST),
        "still inside the minute"
    );
    assert!(
        limits.admit_start(peer(1001), t0 + MINUTE),
        "the minute has passed"
    );
}

/// L2.3: five failed lookups per session per 600 s; other sessions go on.
#[test]
fn failed_lookups_five_per_session_per_600_seconds() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for k in 1..=LOOKUPS_PER_SESSION {
        assert!(
            limits.may_look_up(&session(1), t0),
            "lookup {k} of session 1"
        );
        limits.note_failed_lookup(&session(1), t0);
    }
    assert!(
        !limits.may_look_up(&session(1), t0),
        "session 1 after five failures"
    );
    for n in 2..=LOOKUPS_PER_GATEWAY - LOOKUPS_PER_SESSION + 1 {
        assert!(
            limits.may_look_up(&session(n), t0),
            "session {n} beside a blocked one"
        );
        limits.note_failed_lookup(&session(n), t0);
    }
    assert!(
        !limits.may_look_up(&session(1), t0 + LOOKUP_WINDOW - JUST),
        "inside 600 s"
    );
    assert!(
        limits.may_look_up(&session(1), t0 + LOOKUP_WINDOW),
        "600 s have passed"
    );
}

/// L2.4: a hundred failed lookups per gateway per 600 s.
#[test]
fn failed_lookups_one_hundred_per_gateway_per_600_seconds() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for n in 1..=LOOKUPS_PER_GATEWAY {
        assert!(limits.may_look_up(&session(n), t0), "session {n}");
        limits.note_failed_lookup(&session(n), t0);
    }
    assert!(
        !limits.may_look_up(&session(1000), t0),
        "a fresh session after 100 failures"
    );
    assert!(
        !limits.may_look_up(&session(1000), t0 + LOOKUP_WINDOW - JUST),
        "inside 600 s"
    );
    assert!(
        limits.may_look_up(&session(1000), t0 + LOOKUP_WINDOW),
        "600 s have passed"
    );
}

/// L2.5: five invalid polls per peer per minute; other peers go on.
#[test]
fn invalid_polls_five_per_peer_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for k in 1..=super::limits::INVALID_POLLS_PER_PEER {
        assert!(limits.may_poll(peer(1), t0), "poll {k} of peer 1");
        limits.note_invalid_poll(peer(1), t0);
    }
    assert!(
        !limits.may_poll(peer(1), t0),
        "peer 1 after five invalid polls"
    );
    for n in 2..=50 {
        assert!(
            limits.may_poll(peer(n), t0),
            "peer {n} beside a blocked one"
        );
        limits.note_invalid_poll(peer(n), t0);
    }
    assert!(
        !limits.may_poll(peer(1), t0 + MINUTE - JUST),
        "still inside the minute"
    );
    assert!(
        limits.may_poll(peer(1), t0 + MINUTE),
        "the minute has passed"
    );
}

/// L2.6: a hundred invalid polls per gateway per minute.
#[test]
fn invalid_polls_one_hundred_per_gateway_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for n in 1..=super::limits::INVALID_POLLS_PER_GATEWAY {
        assert!(limits.may_poll(peer(n), t0), "peer {n}");
        limits.note_invalid_poll(peer(n), t0);
    }
    assert!(
        !limits.may_poll(peer(1000), t0),
        "a fresh peer after 100 invalid polls"
    );
    assert!(
        !limits.may_poll(peer(1000), t0 + MINUTE - JUST),
        "still inside the minute"
    );
    assert!(
        limits.may_poll(peer(1000), t0 + MINUTE),
        "the minute has passed"
    );
}

/// L2.9: 300 peers over three minutes are all admitted and the per-peer map
/// never tracks more than its bound (idle keys are shed).
#[test]
fn limiter_storage_is_bounded() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for minute in 0..3_u32 {
        let now = t0 + MINUTE * minute;
        for k in 0..STARTS_PER_GATEWAY {
            let n = minute * STARTS_PER_GATEWAY + k + 1;
            assert!(
                limits.admit_start(peer(n), now),
                "peer {n} in minute {minute}"
            );
            assert!(
                limits.tracked_start_peers() <= MAX_TRACKED_KEYS,
                "tracked {} > bound after peer {n}",
                limits.tracked_start_peers()
            );
        }
    }
}
