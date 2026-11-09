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

/// A set no send reaches any more (a removed backend's) recovers once its
/// values retire: checking it settles it, with no further insert.
#[tokio::test(start_paused = true)]
async fn an_overflowed_set_with_no_sends_recovers_when_its_values_retire() {
    let needles = NeedleSet::with_grace(GRACE);
    for i in 0..=MAX_NEEDLES {
        needles.insert("b", &format!("sent-value-{i:05}"));
    }
    assert!(needles.overflowed(), "premise: the set refuses");
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(
        !needles.overflowed(),
        "a set whose values all retired still refuses"
    );
}

/// Configured values sit outside the bound on sent values: a backend whose
/// sends filled every slot still has each configured value held and
/// redacted, and the bound still refuses the next sent value.
#[tokio::test(start_paused = true)]
async fn configured_values_past_the_free_slots_are_all_held() {
    let needles = NeedleSet::with_grace(GRACE);
    for i in 0..MAX_NEEDLES {
        needles.insert("b", &format!("sent-value-{i:05}"));
    }
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![
            explicit("headers.A", "configured-a-value"),
            explicit("headers.B", "configured-b-value"),
            explicit("env.C", "configured-c-value"),
        ]),
    );
    assert!(
        !needles.overflowed(),
        "configured values overflowed the set"
    );
    for value in [
        "configured-a-value",
        "configured-b-value",
        "configured-c-value",
    ] {
        assert!(redacted(&needles, value), "{value} is not held");
    }
    needles.insert("b", "one-sent-value-too-many");
    assert!(
        needles.overflowed(),
        "the bound on sent values no longer holds"
    );
}

/// Reloads that each replace a backend's configured values demote the old
/// ones into the sent count: past the bound the set refuses, and it
/// recovers once they retire.
#[tokio::test(start_paused = true)]
async fn reloads_that_supersede_past_the_bound_refuse_until_they_retire() {
    let needles = NeedleSet::with_grace(GRACE);
    // 18 loads of 64 distinct values: 17 superseded loads, 1,088 demoted.
    for load in 0..18 {
        let set = ConfiguredSecrets::of(
            (0..64)
                .map(|i| {
                    explicit(
                        &format!("headers.K{i}"),
                        &format!("load-{load:02}-value-{i:02}"),
                    )
                })
                .collect(),
        );
        needles.pin_configured("b", &set);
    }
    assert!(
        needles.overflowed(),
        "1,088 superseded values held past the bound without a refusal"
    );
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(!needles.overflowed(), "the refusal outlived the grace");
    assert!(
        redacted(&needles, "load-17-value-00"),
        "the current load lost its values"
    );
}

/// Before a registration is decided only additions are made: the values the
/// instance still registered holds stay configured until the new one is in.
#[tokio::test(start_paused = true)]
async fn adding_a_record_before_registration_demotes_nothing() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![explicit("headers.A", "serving-instance-value")]),
    );
    let next = ConfiguredSecrets::of(vec![explicit("headers.A", "replacement-value")]);
    needles.add_configured("b", &next);
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(
        redacted(&needles, "serving-instance-value"),
        "a refused registration let the serving instance's value retire"
    );
    assert!(redacted(&needles, "replacement-value"));
    needles.pin_configured("b", &next);
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert!(
        !redacted(&needles, "serving-instance-value"),
        "the superseded value never started its grace"
    );
}

/// A value overlapping a marker (`prefix[redact`) beside a neighbour that
/// is removed: within one set the renderer writes the first marker that
/// forms no held value, so the answer is redacted and the value never
/// leaves.
#[tokio::test(start_paused = true)]
async fn a_value_overlapping_a_marker_is_never_formed_in_one_set() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![
            explicit("headers.A", "prefix[redact"),
            explicit("headers.B", "other-token-value"),
        ]),
    );
    let (outcome, text) = scrubbed(&needles, "prefixother-token-value");
    assert_eq!(outcome, Scrubbed::Redacted, "{text}");
    assert!(
        !text.contains("prefix[redact"),
        "a marker formed the value: {text}"
    );
}

/// A value learned at runtime (an injected one) that contains a marker:
/// within one set no marker that would form it is written, so it never
/// leaves.
#[tokio::test(start_paused = true)]
async fn a_runtime_value_holding_a_marker_is_never_formed_in_one_set() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "abc[redacted]xyz-token");
    needles.insert("b", "other-token-value");
    let (outcome, text) = scrubbed(&needles, "abcother-token-valuexyz-token");
    assert_eq!(outcome, Scrubbed::Redacted, "{text}");
    assert!(
        !text.contains("abc[redacted]xyz-token"),
        "a marker formed the value: {text}"
    );
}

/// Across sets: the first set finds nothing, the second's redaction forms
/// the first's value; the stored scrub's rescan refuses the answer.
#[tokio::test(start_paused = true)]
async fn a_stored_answer_where_one_set_forms_anothers_value_is_refused() {
    let first = Arc::new(NeedleSet::with_grace(GRACE));
    first.pin_configured(
        "a",
        &ConfiguredSecrets::of(vec![explicit("headers.A", "prefix[redact")]),
    );
    let second = Arc::new(NeedleSet::with_grace(GRACE));
    second.pin_configured(
        "b",
        &ConfiguredSecrets::of(vec![explicit("headers.B", "other-token-value")]),
    );
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({"text": "prefixother-token-value"}),
    );
    let outcome = super::scrub_stored(&[first, second], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(
        !wire.contains("prefix[redact"),
        "the formed value left: {wire}"
    );
}

/// A seal as the gateway writes it, signature `sig`.
fn provenance(sig: &str) -> serde_json::Value {
    serde_json::json!({ "receipt": { "tool": "t" }, "public_signature": { "payload": "p", "sig": sig } })
}

/// A stored answer sealed four ways (a tool result's own `_meta`, a task
/// wire's `result`, an array element, and a chain answer's steps carried as
/// JSON text), with `value` in its text and in the steps' text.
fn sealed_answer(value: &str) -> crate::protocol::JsonRpcResponse {
    let steps = serde_json::json!({ "results": [
        { "result": { "text": format!("step {value}"), "_meta": { "provenance": provenance("s") } } },
    ] });
    crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({
            "content": [{ "type": "text", "text": steps.to_string() }],
            "text": format!("answer {value}"),
            "_meta": { "provenance": provenance("s") },
            "result": { "_meta": { "provenance": provenance("s") } },
            "items": [[{ "_meta": { "provenance": provenance("s") } }]],
        }),
    )
}

fn holding(value: &str) -> Arc<NeedleSet> {
    let set = Arc::new(NeedleSet::with_grace(GRACE));
    set.pin_configured(
        "a",
        &ConfiguredSecrets::of(vec![explicit("headers.A", value)]),
    );
    set
}

/// A redaction drops every provenance seal in the stored answer, at any
/// depth, in arrays and inside JSON text, and keeps each receipt: the seals
/// were made over the unredacted bytes, and their payload carries those
/// bytes' digest.
#[tokio::test(start_paused = true)]
async fn a_redacted_stored_answer_keeps_no_seal_anywhere() {
    let mut answer = sealed_answer("held-secret-value");
    let outcome = super::scrub_stored(&[holding("held-secret-value")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Redacted, "{wire}");
    assert!(!wire.contains("held-secret-value"), "{wire}");
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
    assert_eq!(
        wire.matches("receipt").count(),
        4,
        "a receipt was dropped: {wire}"
    );
}

/// The scrub renames a key holding a marked value; a seal under a renamed
/// key is gone too, since the seals come off before the scrub.
#[tokio::test(start_paused = true)]
async fn a_seal_under_a_key_the_scrub_renames_is_dropped() {
    let mut answer = sealed_answer("plain-text");
    let outcome = super::scrub_stored(&[holding("provenance")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Redacted, "{wire}");
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
}

/// A held value inside a seal itself: nothing else is removed, but the seal
/// stays off and the answer counts as redacted.
#[tokio::test(start_paused = true)]
async fn a_seal_holding_a_held_value_is_dropped() {
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({ "text": "plain", "_meta": { "provenance": provenance("sig-held-secret-value") } }),
    );
    let outcome = super::scrub_stored(&[holding("held-secret-value")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_ne!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(!wire.contains("held-secret-value"), "{wire}");
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
    assert!(wire.contains("receipt"), "the receipt stays: {wire}");
}

/// Control: with no value held anywhere, the answer goes out byte-identical,
/// seals included, the ones in JSON text too.
#[tokio::test(start_paused = true)]
async fn a_stored_answer_keeps_its_seals_while_no_value_is_held() {
    let mut answer = sealed_answer("plain-text");
    let before = serde_json::to_string(&answer).expect("serializes");
    let outcome = super::scrub_stored(&[Arc::new(NeedleSet::with_grace(GRACE))], &mut answer);
    assert_eq!(outcome, Scrubbed::Clean);
    assert_eq!(serde_json::to_string(&answer).expect("serializes"), before);
}

/// A held value only in the stored text as written, gone once the strip
/// rewrites it compact: the stored answer is not put back, and the seal
/// stays off.
#[tokio::test(start_paused = true)]
async fn a_held_value_only_in_the_text_the_strip_rewrote_is_not_put_back() {
    let steps = "{\n  \"step\": \"held\",\n  \"_meta\": {\"provenance\": {\"receipt\": {}, \"public_signature\": {\"sig\": \"s\"}}}\n}";
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({ "content": [{ "type": "text", "text": steps }] }),
    );
    let outcome = super::scrub_stored(&[holding("\"step\": \"held\"")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_ne!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
    assert!(
        !wire.contains("\\\"step\\\": \\\"held\\\""),
        "the held value was put back: {wire}"
    );
}

/// Text shaped as JSON that names a seal but will not parse may still carry
/// it: a redacted answer holding one is refused.
#[tokio::test(start_paused = true)]
async fn a_redacted_answer_with_seal_text_that_will_not_parse_is_refused() {
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({
            "text": "answer held-secret-value",
            "content": [{ "type": "text", "text": "{\"_meta\": {\"provenance\": {\"public_signature\": \"p\"" }],
        }),
    );
    let outcome = super::scrub_stored(&[holding("held-secret-value")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(
        answer.result.is_none(),
        "a refused answer carries no result: {wire}"
    );
}

/// While any value is held, a stored answer goes out with no seal even when
/// the scrub removes nothing; its receipts stay.
#[tokio::test(start_paused = true)]
async fn a_stored_answer_is_unsealed_while_any_value_is_held() {
    let mut answer = sealed_answer("plain-text");
    let outcome = super::scrub_stored(&[holding("held-secret-value")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Clean, "{wire}");
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
    assert_eq!(
        wire.matches("receipt").count(),
        4,
        "a receipt was dropped: {wire}"
    );
    assert!(wire.contains("plain-text"), "nothing else changed: {wire}");
}

/// Seal text behind a prose prefix that will not parse: a redacted answer
/// holding it is refused.
#[tokio::test(start_paused = true)]
async fn a_redacted_answer_with_prose_led_seal_text_is_refused() {
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({
            "text": "answer held-secret-value",
            "note": "Result: {\"_meta\": {\"provenance\": {\"public_signature\": \"p\"",
        }),
    );
    let outcome = super::scrub_stored(&[holding("held-secret-value")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_eq!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(
        answer.result.is_none(),
        "a refused answer carries no result: {wire}"
    );
}

/// A held number inside a seal is never served: the seal is gone first.
#[tokio::test(start_paused = true)]
async fn a_held_number_inside_a_seal_is_not_served() {
    let mut answer = crate::protocol::JsonRpcResponse::success(
        crate::protocol::RequestId::Number(1),
        serde_json::json!({ "text": "plain", "_meta": { "provenance": {
            "receipt": { "tool": "t" }, "public_signature": { "n": 424_242 } } } }),
    );
    let outcome = super::scrub_stored(&[holding("424242")], &mut answer);
    let wire = serde_json::to_string(&answer).expect("serializes");
    assert_ne!(outcome, Scrubbed::Refuse, "{wire}");
    assert!(
        !wire.contains("424242"),
        "the held number was served: {wire}"
    );
    assert!(
        !wire.contains("public_signature"),
        "a seal was kept: {wire}"
    );
}
