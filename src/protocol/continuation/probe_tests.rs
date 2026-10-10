// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8323 probe rows R7 and R10, plus the gate's no-open pin.

use serde_json::json;

use super::*;
use crate::protocol::continuation::{ContinuationState, now_unix_secs};
async fn mint_at(state: &ContinuationState, now: u64) -> String {
    let payload = state
        .begin_exchange(
            "srv".into(),
            None,
            "fp".into(),
            &crate::protocol::continuation::QuotaKey::for_test("fp"),
            "digest".into(),
            now,
        )
        .await
        .expect("a fresh state has a slot");
    state.keyring().mint(&payload).expect("the envelope seals")
}

/// R10: every real mint passes the four-character gate and is found. A
/// three-character decode (two nonce bits in the kid byte) misses most, so the
/// row needs many envelopes. One caller mints all 256, as one client running
/// many exchanges would: each exchange's slot is released before the next
/// mint (as a redeem would), so the caller stays under its 64-slot share
/// (MIK-8293) and the envelope still opens (`open` checks authenticity and
/// expiry, never the slot). The slot table is empty after every probe: the
/// probe opens envelopes, it never takes or keeps a slot.
#[tokio::test]
async fn r10_every_real_mint_passes_the_gate_and_is_found() {
    let state = ContinuationState::new();
    for n in 0..256 {
        let now = now_unix_secs();
        let payload = state
            .begin_exchange(
                "srv".into(),
                None,
                "fp".into(),
                &crate::protocol::continuation::QuotaKey::for_test("fp"),
                "digest".into(),
                now,
            )
            .await
            .unwrap_or_else(|| panic!("mint {n}: the caller is at its share"));
        let envelope = state.keyring().mint(&payload).expect("the envelope seals");
        assert!(
            state.in_flight().complete(&payload.hold_key, now).await,
            "setup: release"
        );
        assert!(
            framed(state.keyring(), &envelope),
            "mint {n} failed the gate"
        );
        let mut budget = ProbeBudget::new(PROBE_OPENS_PER_STEP);
        let wrapped = json!({ "x": format!("see {envelope}.") });
        assert_eq!(
            sealed_state_in(state.keyring(), &wrapped, &mut budget),
            Ok(true),
            "mint {n} was not found"
        );
        assert_eq!(budget.spent(), 1, "mint {n} cost more than one open");
        assert_eq!(
            state.in_flight().len(now_unix_secs()).await,
            0,
            "mint {n}: the probe took a slot"
        );
    }
}

/// R7: a foreign envelope (another keyring), an expired one of ours, and a
/// random string of envelope length and alphabet are ordinary data.
#[tokio::test]
async fn r7_foreign_expired_and_random_strings_are_not_ours() {
    let ours = ContinuationState::new();
    let foreign = mint_at(&ContinuationState::new(), now_unix_secs()).await;
    let expired = mint_at(&ours, 1_000).await;
    assert!(
        ours.keyring().open_now(&expired).is_err(),
        "setup: the old envelope must be expired"
    );
    let real = mint_at(&ours, now_unix_secs()).await;
    let random: String = real.chars().rev().collect();
    for (case, text) in [
        ("foreign", foreign),
        ("expired", expired),
        ("random", random),
    ] {
        let mut budget = ProbeBudget::new(PROBE_OPENS_PER_STEP);
        assert_eq!(
            sealed_state_in(ours.keyring(), &json!([text]), &mut budget),
            Ok(false),
            "{case} was taken for ours"
        );
    }
}

/// The gate opens nothing for a string that is too short, too long, or does
/// not start with our version and a held kid.
#[tokio::test]
async fn the_gate_rejects_without_opening() {
    let state = ContinuationState::new();
    let real = mint_at(&state, now_unix_secs()).await;
    // Byte 0 is 0x01, so the first character is always `A`; `B` makes it 0x04+.
    let wrong_version = format!("B{}", &real[1..]);
    let rejects = json!([
        &real[..MIN_ENVELOPE_LEN - 1],
        "A".repeat(MAX_ENVELOPE_LEN + 1),
        wrong_version,
        "just words, no envelope",
    ]);
    let mut budget = ProbeBudget::new(0);
    assert_eq!(
        sealed_state_in(state.keyring(), &rejects, &mut budget),
        Ok(false)
    );
    assert_eq!(budget.spent(), 0);
}

/// gpt c1, grok c2: under a clock that reads before 1970 (MIK-8202's
/// thread-local hook), the public probe refuses a live envelope instead of
/// passing it as "not ours" (fail closed).
#[tokio::test]
async fn an_unreadable_clock_refuses_rather_than_passing_an_envelope() {
    let state = ContinuationState::new();
    let real = mint_at(&state, now_unix_secs()).await;
    let _clock = crate::clock::test_clock::before_epoch();
    let mut budget = ProbeBudget::new(PROBE_OPENS_PER_STEP);
    assert_eq!(
        sealed_state_in(state.keyring(), &json!({ "x": real }), &mut budget),
        Err(ProbeRefusal::ClockUnreadable)
    );
}

/// gpt c2: the clock is read once per framed candidate and never for a value
/// with none.
#[tokio::test]
async fn the_clock_is_read_only_for_a_framed_candidate() {
    let state = ContinuationState::new();
    let real = mint_at(&state, now_unix_secs()).await;
    let reads = std::cell::Cell::new(0);
    let clock = || {
        reads.set(reads.get() + 1);
        Some(now_unix_secs())
    };
    let mut budget = ProbeBudget::new(PROBE_OPENS_PER_STEP);
    assert_eq!(
        scan(
            state.keyring(),
            // Envelope-sized, but `B` frames a wrong version: a gate reject.
            &json!(["just words", "B".repeat(MIN_ENVELOPE_LEN)]),
            &mut budget,
            &clock
        ),
        Ok(false)
    );
    assert_eq!(reads.get(), 0, "ordinary data read the clock");
    // gpt c3: two framed near-misses, then the live envelope: one read per
    // candidate, not one per scan.
    let mut misses: Vec<String> = (0..2)
        .map(|n| {
            let mut chars: Vec<char> = real.chars().collect();
            chars[30 + n] = if chars[30 + n] == 'A' { 'B' } else { 'A' };
            chars.into_iter().collect()
        })
        .collect();
    misses.push(real);
    assert_eq!(
        scan(state.keyring(), &json!(misses), &mut budget, &clock),
        Ok(true)
    );
    assert_eq!(reads.get(), 3, "three framed candidates, three reads");
}
