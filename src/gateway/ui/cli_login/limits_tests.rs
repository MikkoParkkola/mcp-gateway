// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows L2.1-L2.6 and L2.9 of the CLI login test plan: each cap alone, with the
//! other counters empty, refused on both sides of its window's end.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::limits::Limits;

// The design's numbers, written out on purpose: a row
// that read the constant it checks would move with a changed constant and
// stay green.
const PER_KEY: u32 = 5;
const PER_GATEWAY: u32 = 100;
const MINUTE: Duration = Duration::from_secs(60);
const TEN_MINUTES: Duration = Duration::from_secs(600);
/// The per-key map's bound (a design choice: at least every gateway cap).
const KEY_BOUND: usize = 128;
// 59 s and 599 s below: a window's end less one second, written out like the rest.

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
    for k in 1..=PER_KEY {
        assert!(limits.admit_start(peer(1), t0), "start {k} of peer 1");
    }
    assert!(!limits.admit_start(peer(1), t0), "the 6th start of peer 1");
    for n in 2..=PER_GATEWAY - PER_KEY + 1 {
        assert!(
            limits.admit_start(peer(n), t0),
            "peer {n}: the refused 6th must not have spent a gateway slot"
        );
    }
    let fresh = Limits::new();
    for _ in 0..PER_KEY {
        assert!(fresh.admit_start(peer(1), t0));
    }
    assert!(
        !fresh.admit_start(peer(1), t0 + Duration::from_secs(59)),
        "still inside the minute"
    );
    assert!(
        fresh.admit_start(peer(1), t0 + MINUTE),
        "the minute has passed"
    );
}

/// L2.2: a hundred starts per gateway per minute, each peer under its cap;
/// a start the gateway refuses spends no peer slot.
#[test]
fn starts_one_hundred_per_gateway_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for n in 1..=PER_GATEWAY {
        assert!(limits.admit_start(peer(n), t0), "start from peer {n}");
    }
    assert!(!limits.admit_start(peer(1000), t0), "the 101st start");
    assert!(
        !limits.admit_start(peer(1001), t0 + Duration::from_secs(59)),
        "still inside the minute"
    );
    for k in 1..=PER_KEY {
        assert!(
            limits.admit_start(peer(1001), t0 + MINUTE),
            "start {k} of peer 1001 at 60 s: the gateway's refusal at 59 s spent no peer slot"
        );
    }
    assert!(
        !limits.admit_start(peer(1001), t0 + MINUTE),
        "the 6th start of peer 1001 at 60 s"
    );
}

/// L2.3: five failed lookups per session per 600 s; other sessions go on.
#[test]
fn failed_lookups_five_per_session_per_600_seconds() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for k in 1..=PER_KEY {
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
    for n in 2..=PER_GATEWAY - PER_KEY + 1 {
        assert!(
            limits.may_look_up(&session(n), t0),
            "session {n} beside a blocked one"
        );
        limits.note_failed_lookup(&session(n), t0);
    }
    assert!(
        !limits.may_look_up(&session(1), t0 + Duration::from_secs(599)),
        "inside 600 s"
    );
    assert!(
        limits.may_look_up(&session(1), t0 + TEN_MINUTES),
        "600 s have passed"
    );
}

/// L2.4: a hundred failed lookups per gateway per 600 s.
#[test]
fn failed_lookups_one_hundred_per_gateway_per_600_seconds() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for n in 1..=PER_GATEWAY {
        assert!(limits.may_look_up(&session(n), t0), "session {n}");
        limits.note_failed_lookup(&session(n), t0);
    }
    assert!(
        !limits.may_look_up(&session(1000), t0),
        "a fresh session after 100 failures"
    );
    assert!(
        !limits.may_look_up(&session(1000), t0 + Duration::from_secs(599)),
        "inside 600 s"
    );
    assert!(
        limits.may_look_up(&session(1000), t0 + TEN_MINUTES),
        "600 s have passed"
    );
}

/// L2.5: five invalid polls per peer per minute; other peers go on.
#[test]
fn invalid_polls_five_per_peer_per_minute() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for k in 1..=PER_KEY {
        assert!(limits.may_poll(peer(1), t0), "poll {k} of peer 1");
        limits.note_invalid_poll(peer(1), t0);
    }
    assert!(
        !limits.may_poll(peer(1), t0),
        "peer 1 after five invalid polls"
    );
    for n in 2..=PER_GATEWAY - PER_KEY + 1 {
        assert!(
            limits.may_poll(peer(n), t0),
            "peer {n} beside a blocked one"
        );
        limits.note_invalid_poll(peer(n), t0);
    }
    assert!(
        !limits.may_poll(peer(1), t0 + Duration::from_secs(59)),
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
    for n in 1..=PER_GATEWAY {
        assert!(limits.may_poll(peer(n), t0), "peer {n}");
        limits.note_invalid_poll(peer(n), t0);
    }
    assert!(
        !limits.may_poll(peer(1000), t0),
        "a fresh peer after 100 invalid polls"
    );
    assert!(
        !limits.may_poll(peer(1000), t0 + Duration::from_secs(59)),
        "still inside the minute"
    );
    assert!(
        limits.may_poll(peer(1000), t0 + MINUTE),
        "the minute has passed"
    );
}

/// A caller reads its time before the start lock, so two starts can be
/// counted out of order. A start counted earlier than one already held must
/// still leave the window when its time is up: then exactly one more start
/// fits under the cap, and a start the cap admits is counted.
#[test]
fn starts_counted_out_of_order_still_fill_the_cap() {
    let limits = Limits::new();
    let t0 = Instant::now();
    let later = t0 + Duration::from_secs(1);
    for k in 1..PER_KEY {
        assert!(limits.admit_start(peer(1), later), "start {k} of peer 1");
    }
    assert!(
        limits.admit_start(peer(1), t0),
        "the 5th start, counted after the others but timed before them"
    );
    // At 60 s the start timed t0 has left the window; the four timed 1 s
    // later have not, so one start fits, and it must be counted.
    assert!(
        limits.admit_start(peer(1), t0 + MINUTE),
        "one start fits once t0 leaves the window"
    );
    assert!(
        !limits.admit_start(peer(1), t0 + MINUTE),
        "the cap is full again: the admitted start was counted"
    );
}

/// L2.9: 300 keys over three windows are all admitted and no per-key map
/// (start peers, lookup sessions, invalid-poll peers) ever tracks more than
/// its bound: idle keys are shed.
#[test]
fn limiter_storage_is_bounded() {
    let limits = Limits::new();
    let t0 = Instant::now();
    for round in 0..3_u32 {
        let minute = t0 + MINUTE * round;
        let window = t0 + TEN_MINUTES * round;
        for k in 0..PER_GATEWAY {
            let n = round * PER_GATEWAY + k + 1;
            assert!(limits.admit_start(peer(n), minute), "start of peer {n}");
            assert!(limits.may_poll(peer(n), minute), "poll of peer {n}");
            limits.note_invalid_poll(peer(n), minute);
            assert!(
                limits.may_look_up(&session(n), window),
                "lookup of session {n}"
            );
            limits.note_failed_lookup(&session(n), window);
            let [starts, lookups, polls] = limits.tracked_keys();
            assert!(
                starts <= KEY_BOUND,
                "start peers: {starts} tracked after key {n}"
            );
            assert!(
                lookups <= KEY_BOUND,
                "lookup sessions: {lookups} tracked after key {n}"
            );
            assert!(
                polls <= KEY_BOUND,
                "invalid-poll peers: {polls} tracked after key {n}"
            );
        }
    }
}
