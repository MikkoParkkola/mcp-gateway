// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T3 of the `MIK-7215.CONTROL.4` test plan: `reap` reports how many keys it
//! reclaimed.
//!
//! Kept in its own file on purpose. The other cases in the plan drive a handler
//! entry point that does not exist yet, so they share one compile error; this
//! case's red must be attributable to the `reap` signature alone.
//!
//! Plan: `docs/design/2026-09-08-control4-session-lifecycle-test-plan.md`.

use mcp_gateway::gateway::session_lifecycle::SessionLifecycle;

/// The count is the reclaimed keys, not the tracked ones: a key whose deadline
/// has not passed survives the sweep and must not be counted.
#[test]
fn reap_returns_the_number_of_keys_it_reclaimed() {
    // GIVEN: two keys already past their deadline and one that is not.
    let lifecycle = SessionLifecycle::new();
    lifecycle.track("expired-a", 100);
    lifecycle.track("expired-b", 100);
    lifecycle.track("still-live", 400);

    // WHEN: a sweep observes a clock past the first two deadlines only.
    let reclaimed = lifecycle.reap(300);

    // THEN: the return value names the two it removed, and the survivor stays.
    assert_eq!(
        reclaimed, 2,
        "reap must report the keys it reclaimed, not the keys it looked at"
    );
    assert_eq!(
        lifecycle.tracked_count(),
        1,
        "the key whose deadline has not passed must survive the sweep"
    );
}

/// A sweep that reclaims nothing reports zero rather than staying silent —
/// the caller logging a sweep needs to tell an idle sweep from a busy one.
#[test]
fn reap_returns_zero_when_no_deadline_has_passed() {
    // GIVEN: one key whose deadline is in the future.
    let lifecycle = SessionLifecycle::new();
    lifecycle.track("still-live", 400);

    // WHEN: a sweep observes a clock before that deadline.
    let reclaimed = lifecycle.reap(300);

    // THEN: zero reclaimed, and the key is untouched.
    assert_eq!(reclaimed, 0, "an idle sweep reclaims nothing and says so");
    assert_eq!(lifecycle.tracked_count(), 1);
}
