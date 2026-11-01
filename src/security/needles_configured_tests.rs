// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Configured `headers:` and `env:` credentials in the value set: held for
//! as long as they stay configured, counted from a reload that drops them,
//! never demoted by a send of the same bytes, and gated by length only when
//! the gateway inferred that they are secret.

use std::sync::Arc;
use std::time::Duration;

use super::tests::{logs, scrubbed};
use super::{MAX_NEEDLES, NeedleSet, Scrubbed};
use crate::config::configured_secrets::{ConfiguredSecret, ConfiguredSecrets, SecretOrigin};

const GRACE: Duration = Duration::from_secs(3_600);

/// Well past any grace.
const LONG_AFTER: Duration = Duration::from_secs(10 * 3_600);

fn explicit(field: &str, value: &str) -> ConfiguredSecret {
    ConfiguredSecret {
        field: field.to_owned(),
        value: value.to_owned(),
        origin: SecretOrigin::Explicit,
    }
}

fn inferred(field: &str, value: &str) -> ConfiguredSecret {
    ConfiguredSecret {
        origin: SecretOrigin::Inferred,
        ..explicit(field, value)
    }
}

fn redacted(needles: &NeedleSet, value: &str) -> bool {
    let (outcome, text) = scrubbed(needles, &format!("echo {value}"));
    outcome == Scrubbed::Redacted && !text.contains(value)
}

/// A configured value has no last send: it stays redacted long after any
/// grace, with no call ever sending it.
#[tokio::test(start_paused = true)]
async fn a_configured_value_never_retires() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![explicit("headers.A", "configured-token-1")]),
    );
    tokio::time::advance(LONG_AFTER).await;
    assert!(redacted(&needles, "configured-token-1"));
}

/// A value a reload no longer configures counts from that reload: an echo
/// just after the rotation is still removed, and it retires a grace later.
#[tokio::test(start_paused = true)]
async fn a_value_dropped_by_a_reload_retires_a_grace_later() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![explicit("env.K", "rotated-out-token")]),
    );
    tokio::time::advance(LONG_AFTER).await;
    assert!(
        redacted(&needles, "rotated-out-token"),
        "premise: the cached matcher holds it"
    );
    needles.pin_configured("b", &ConfiguredSecrets::default());
    tokio::time::advance(Duration::from_secs(3_599)).await;
    assert!(
        redacted(&needles, "rotated-out-token"),
        "dropped before its grace passed"
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(
        !redacted(&needles, "rotated-out-token"),
        "still held a grace after the reload dropped it"
    );
}

/// A `secrets:` send of a configured value renews it but never demotes it,
/// and a value sent before it was configured is promoted, never held twice.
#[tokio::test(start_paused = true)]
async fn a_send_of_a_configured_value_does_not_demote_it() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "shared-token-value");
    let set = ConfiguredSecrets::of(vec![explicit("headers.A", "shared-token-value")]);
    needles.pin_configured("b", &set);
    needles.insert("b", "shared-token-value");
    assert_eq!(format!("{needles:?}"), "NeedleSet(1 values)", "held twice");
    tokio::time::advance(LONG_AFTER).await;
    assert!(redacted(&needles, "shared-token-value"));
}

/// A value that had retired is back in the set once it is configured,
/// though the matcher cached while it was retired lacked it.
#[tokio::test(start_paused = true)]
async fn pinning_a_retired_value_matches_it_again() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "returning-token-1");
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(
        !redacted(&needles, "returning-token-1"),
        "premise: it retired"
    );
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![explicit("env.K", "returning-token-1")]),
    );
    assert!(redacted(&needles, "returning-token-1"));
}

/// Cost: a set of configured values compiles once and is reused across
/// calls and across a grace period (no expiry deadline for pinned values).
#[tokio::test(start_paused = true)]
async fn configured_values_reuse_one_matcher() {
    let needles = NeedleSet::with_grace(GRACE);
    let values: Vec<_> = (0..15)
        .map(|i| explicit(&format!("env.K{i}"), &format!("configured-value-{i:02}")))
        .collect();
    needles.pin_configured("b", &ConfiguredSecrets::of(values));
    let first = needles.snapshot();
    assert!(redacted(&needles, "configured-value-07"));
    tokio::time::advance(LONG_AFTER).await;
    assert!(
        Arc::ptr_eq(&first, &needles.snapshot()),
        "an all-configured set was rebuilt"
    );
}

/// The lead's thresholds: an inferred value under 8 bytes is left out and
/// its field named once; an 8-byte one is held; an explicit 1-byte value is
/// held, with the existing short-value warning naming its field.
#[tokio::test(start_paused = true)]
async fn only_an_inferred_value_is_gated_by_length() {
    let needles = NeedleSet::with_grace(GRACE);
    let set = ConfiguredSecrets::of(vec![
        inferred("env.SHORT", "7bytes!"),
        inferred("env.EIGHT", "8bytes!!"),
        explicit("env.ONE", "1"),
    ]);
    let log = logs(|| {
        needles.pin_configured("b", &set);
        needles.pin_configured("b", &set);
    });
    let (_, text) = scrubbed(&needles, "echo 7bytes! 8bytes!! 1");
    assert!(
        text.contains("7bytes!"),
        "a 7-byte inferred value was redacted: {text}"
    );
    assert!(
        !text.contains("8bytes!!"),
        "an 8-byte inferred value was not redacted: {text}"
    );
    assert!(
        !text.contains(" 1"),
        "a 1-byte explicit value was not redacted: {text}"
    );
    assert_eq!(
        log.matches("too short to be treated as a secret").count(),
        1,
        "{log}"
    );
    assert!(
        log.contains("env.SHORT") && log.contains("env.ONE"),
        "{log}"
    );
    assert!(!log.contains("7bytes!"), "a warning printed a value: {log}");
}

/// Overflow with configured and sent values mixed: past the bound the set
/// fails closed; once sent values retire there is room and answers flow.
#[tokio::test(start_paused = true)]
async fn overflow_recovers_with_configured_values_held() {
    let needles = NeedleSet::with_grace(GRACE);
    for i in 0..MAX_NEEDLES - 1 {
        needles.insert("b", &format!("sent-value-{i:05}"));
    }
    let set = ConfiguredSecrets::of(vec![
        explicit("headers.A", "configured-a-value"),
        explicit("headers.B", "configured-b-value"),
    ]);
    needles.pin_configured("b", &set);
    assert!(
        needles.overflowed(),
        "premise: the second configured value did not fit"
    );
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    needles.pin_configured("b", &set);
    assert!(!needles.overflowed(), "room after the sent values retired");
    assert!(redacted(&needles, "configured-a-value"));
    assert!(redacted(&needles, "configured-b-value"));
}

/// A configured value a full set refused stays owed: when retirement makes
/// room, the next unrelated send installs it before the refusal clears, so
/// answers never flow again with a configured credential missing.
#[tokio::test(start_paused = true)]
async fn an_unrelated_send_never_clears_overflow_past_an_owed_value() {
    let needles = NeedleSet::with_grace(GRACE);
    for i in 0..MAX_NEEDLES - 1 {
        needles.insert("b", &format!("sent-value-{i:05}"));
    }
    let set = ConfiguredSecrets::of(vec![
        explicit("headers.A", "configured-a-value"),
        explicit("headers.B", "configured-b-value"),
    ]);
    needles.pin_configured("b", &set);
    assert!(
        needles.overflowed(),
        "premise: one configured value did not fit"
    );
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    needles.insert("b", "unrelated-later-value");
    assert!(!needles.overflowed(), "room after the sent values retired");
    assert!(redacted(&needles, "configured-a-value"));
    assert!(
        redacted(&needles, "configured-b-value"),
        "the owed configured value was never installed"
    );
}
