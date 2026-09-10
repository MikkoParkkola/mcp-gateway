// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Acceptance-criterion tests for MIK-7215.CONTROL.2 — firewall budgets keyed
//! on the principal over an explicit window.
//!
//! The requirement states the failure it exists to prevent: *"A per-session
//! budget under statelessness is an unlimited budget."* Every case here
//! therefore asserts a **refusal** or a **count that stops rising**, never that
//! a number came back. A budget that keeps returning numbers while its key
//! disappears is the shape of failure this file is written against.

use std::time::{Duration, Instant};

use mcp_gateway::security::firewall::principal_window::{PrincipalWindow, Usage};

const WINDOW: Duration = Duration::from_secs(60);

fn window() -> PrincipalWindow {
    PrincipalWindow::new(WINDOW)
}

#[test]
fn ac_control_2_a_budget_with_no_principal_is_unkeyed_not_zero() {
    // The whole criterion in one assertion. With no key, a counting budget has
    // two honest answers and one dishonest one. It may say "I cannot count";
    // it may not say "0 so far", because 0 is indistinguishable from a caller
    // who has spent nothing and every caller shares it.
    let window = window();
    assert_eq!(
        window.record(None, "srv:tool"),
        Usage::Unkeyed,
        "with no principal to key on the budget must report that it cannot \
         count, never a usage figure that reads as headroom"
    );
}

#[test]
fn ac_control_2_usage_accumulates_for_one_principal_within_the_window() {
    let window = window();
    let start = Instant::now();

    window.record_at(Some("principal:a"), "srv:tool", start);
    let second = window.record_at(
        Some("principal:a"),
        "srv:tool",
        start + Duration::from_secs(1),
    );

    assert_eq!(
        second,
        Usage::Counted {
            total: 2,
            distinct: 1
        },
        "two calls by one principal inside the window are two calls against \
         that principal's budget"
    );
}

#[test]
fn ac_control_2_two_principals_do_not_share_one_budget() {
    // A budget one caller can exhaust on another caller's behalf is not a
    // budget. This is the same defect as a single shared session bucket,
    // reached by a different route.
    let window = window();
    let start = Instant::now();

    window.record_at(Some("principal:a"), "srv:tool", start);
    window.record_at(Some("principal:a"), "srv:tool", start);

    assert_eq!(
        window.record_at(Some("principal:b"), "srv:tool", start),
        Usage::Counted {
            total: 1,
            distinct: 1
        },
        "a second principal's first call is its first call, whatever the first \
         principal has spent"
    );
}

#[test]
fn ac_control_2_the_window_is_explicit_and_observations_leave_it() {
    // "Over an explicit window" is the half of the requirement that keeps the
    // budget from becoming a lifetime quota. An observation older than the
    // window is not merely uncounted — it is gone.
    let window = window();
    let start = Instant::now();

    window.record_at(Some("principal:a"), "srv:tool", start);
    let later = window.record_at(
        Some("principal:a"),
        "srv:tool",
        start + WINDOW + Duration::from_secs(1),
    );

    assert_eq!(
        later,
        Usage::Counted {
            total: 1,
            distinct: 1
        },
        "the earlier call has left the window, so only the current one counts"
    );
}

#[test]
fn ac_control_2_an_empty_principal_string_is_not_a_principal() {
    // The dangerous near-miss: an empty string is a perfectly good map key, so
    // a budget handed one counts happily and pools every anonymous caller into
    // a single bucket. That bucket is exhausted by whoever calls most and is
    // shared by everyone — worse than no budget, because it reports success.
    let window = window();
    assert_eq!(
        window.record(Some(""), "srv:tool"),
        Usage::Unkeyed,
        "an empty principal is the absence of a principal, not a caller named \
         the empty string"
    );
}

#[test]
fn ac_control_2_expiry_reclaims_a_principal_with_no_live_observations() {
    // MIK-7215.CONTROL.4 in miniature: the state is reclaimed by the passage
    // of time, not by a disconnect that a stateless transport never delivers.
    let window = window();
    let start = Instant::now();

    window.record_at(Some("principal:a"), "srv:tool", start);
    assert_eq!(window.tracked_principals(), 1);

    window.expire_at(start + WINDOW + Duration::from_secs(1));

    assert_eq!(
        window.tracked_principals(),
        0,
        "a principal whose every observation has aged out holds no state; \
         nothing had to disconnect for that to be true"
    );
}
