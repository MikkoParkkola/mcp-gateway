// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The injected-value set's lifetime rules: a value stays redacted
//! for its grace after its last send, a rotation that outruns the grace
//! fails closed, and a retired value is no longer redacted (the documented
//! residual).

use std::time::Duration;

use serde_json::json;

use super::{NeedleSet, Scrubbed, ingress_scrub};
use crate::clock::test_clock::at_secs;
use crate::protocol::{JsonRpcMessage, JsonRpcResponse, RequestId};

const GRACE: Duration = Duration::from_secs(3_600);

/// Log lines written while `run` runs, as text (thread-scoped subscriber).
fn logs(run: impl FnOnce()) -> String {
    #[derive(Clone, Default)]
    struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("sink").extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    crate::test_log_capture::keep_interest_open();
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, run);
    let bytes = sink.0.lock().expect("sink").clone();
    String::from_utf8_lossy(&bytes).into_owned()
}
const T0: u64 = 1_800_000_000;

/// The text `needles` leaves of an answer whose result is `text`.
fn scrubbed(needles: &NeedleSet, text: &str) -> (Scrubbed, String) {
    let mut message = JsonRpcMessage::Response(JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"text": text}),
    ));
    let outcome = ingress_scrub(needles, &mut message);
    let JsonRpcMessage::Response(response) = message else {
        unreachable!("a response stays a response")
    };
    let result = response
        .result
        .map(|r| r["text"].to_string())
        .unwrap_or_default();
    (outcome, result)
}

/// A value inside its grace is redacted.
#[tokio::test(start_paused = true)]
async fn a_value_inside_its_grace_is_redacted() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    tokio::time::advance(GRACE).await;
    let (outcome, text) = scrubbed(&needles, "echo token-one-value");
    assert_eq!(outcome, Scrubbed::Redacted);
    assert!(!text.contains("token-one-value"), "{text}");
}

/// A retired value (past its grace since its last send) is no longer
/// redacted: the documented residual, pinned so a change to it is a choice.
#[tokio::test(start_paused = true)]
async fn a_retired_value_is_no_longer_redacted() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    let (outcome, text) = scrubbed(&needles, "echo token-one-value");
    assert_eq!(outcome, Scrubbed::Clean);
    assert!(text.contains("token-one-value"), "{text}");
}

/// A wall-clock jump of 48 h with no monotonic time elapsed retires
/// nothing: a value sent a minute ago is still redacted.
#[tokio::test(start_paused = true)]
async fn a_wall_clock_jump_does_not_retire_a_live_value() {
    let needles = NeedleSet::with_grace(GRACE);
    let wall = at_secs(T0);
    needles.insert("b", "token-one-value");
    tokio::time::advance(Duration::from_secs(60)).await;
    drop(wall);
    let _wall = at_secs(T0 + 48 * 3_600);
    let (outcome, text) = scrubbed(&needles, "echo token-one-value");
    assert_eq!(outcome, Scrubbed::Redacted, "{text}");
}

/// Rotation past 1,024 values, each retired before the next: traffic keeps
/// flowing and the newest value is redacted.
#[tokio::test(start_paused = true)]
async fn rotation_past_the_bound_with_the_grace_elapsed_keeps_answers_flowing() {
    let needles = NeedleSet::with_grace(GRACE);
    for step in 0..2_000_u64 {
        needles.insert("b", &format!("rotated-token-{step:05}"));
        tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    }
    needles.insert("b", "rotated-token-02000");
    assert!(
        !needles.overflowed(),
        "rotation slower than the grace overflowed"
    );
    let (outcome, text) = scrubbed(&needles, "echo rotated-token-02000");
    assert_eq!(outcome, Scrubbed::Redacted, "{text}");
}

/// Rotation faster than the grace fills the set with live values: the set
/// fails closed and every answer is refused, never a live value dropped.
#[test]
fn rotation_faster_than_the_grace_fails_closed() {
    let needles = NeedleSet::with_grace(GRACE);
    let logged = logs(|| {
        for step in 0..=super::MAX_NEEDLES {
            needles.insert("rotating-backend", &format!("fast-token-{step:05}"));
        }
    });
    assert!(
        logged.contains("rotating faster than the redaction grace allows")
            && logged.contains("rotating-backend"),
        "the warning does not name the cause and the backend: {logged}"
    );
    assert!(
        !logged.contains("fast-token-"),
        "the warning printed a value: {logged}"
    );
    assert!(
        needles.overflowed(),
        "a full set of live values did not fail closed"
    );
    let (outcome, _) = scrubbed(&needles, "echo fast-token-00000");
    assert_eq!(outcome, Scrubbed::Refuse);
}

/// The 1,024th distinct live value is still held and redacted; only the
/// next one closes the set.
#[test]
fn the_last_value_inside_the_bound_still_answers() {
    let needles = NeedleSet::with_grace(GRACE);
    for step in 0..super::MAX_NEEDLES {
        needles.insert("b", &format!("fill-token-{step:05}"));
    }
    assert!(!needles.overflowed());
    let (outcome, text) = scrubbed(&needles, "echo fill-token-01023");
    assert_eq!(outcome, Scrubbed::Redacted, "{text}");
}

/// T1.42: a value echoed percent-encoded, inside a URI or in plain text, is
/// redacted like the value itself.
#[test]
fn a_percent_encoded_echo_is_redacted() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "tok en/\u{fc}?=1");
    for echo in [
        "see https://x.invalid/cb?k=tok+en%2F%C3%BC%3F%3D1&n=2",
        "the key was tok+en%2F%C3%BC%3F%3D1",
    ] {
        let (outcome, text) = scrubbed(&needles, echo);
        assert_eq!(outcome, Scrubbed::Redacted, "{echo}");
        assert!(!text.contains("tok+en"), "{text}");
    }
}

/// DELTA-2: overlapping needles leave no fragment of either.
#[test]
fn overlapping_needles_leave_nothing() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "abcdef");
    needles.insert("b", "cdefgh");
    let (outcome, text) = scrubbed(&needles, "xabcdefghy");
    assert_eq!(outcome, Scrubbed::Redacted);
    assert!(
        !text.contains("ab") && !text.contains("gh") && text.contains('x') && text.contains('y'),
        "{text}"
    );
}

/// DELTA-3 (the gated part of T1.33): a string holding no needle is not
/// copied; its buffer is the one the answer arrived with.
#[test]
fn a_clean_string_is_not_copied() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    let mut message = JsonRpcMessage::Response(JsonRpcResponse::success(
        RequestId::Number(1),
        json!({"text": "nothing to see here"}),
    ));
    let before = match &message {
        JsonRpcMessage::Response(r) => r.result.as_ref().unwrap()["text"]
            .as_str()
            .unwrap()
            .as_ptr(),
        _ => unreachable!(),
    };
    assert_eq!(ingress_scrub(&needles, &mut message), Scrubbed::Clean);
    let JsonRpcMessage::Response(response) = message else {
        unreachable!()
    };
    let after = response.result.as_ref().unwrap()["text"]
        .as_str()
        .unwrap()
        .as_ptr();
    assert_eq!(before, after, "a clean string was rebuilt");
}

/// DELTA-2: a 16 MiB string of one matching character stays under the
/// output cap.
#[test]
fn a_long_run_of_a_short_needle_stays_under_the_cap() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "a");
    let long = "a".repeat(16 * 1024 * 1024);
    let (outcome, text) = scrubbed(&needles, &long);
    assert_eq!(outcome, Scrubbed::Redacted);
    assert!(
        text.len() < 64,
        "the output was not collapsed: {} bytes",
        text.len()
    );
}

/// T1.33 (a measurement, not a gate): scrub time against parse time for
/// 1 MiB and 16 MiB answers with 3, 64 and 1,024 needles, on clean text,
/// text with one echo, and an array of numbers beside all-digit and
/// scientific-notation needles. Run with `--ignored --nocapture`; the
/// lines are reported in the PR.
#[test]
#[ignore = "measurement: run by hand and report"]
fn cost_of_the_scrub_against_the_parse() {
    for size in [1024 * 1024, 16 * 1024 * 1024] {
        // 3: the smallest set holding the echoed value and both numbers.
        for count in [3_usize, 64, 1024] {
            let needles = NeedleSet::with_grace(GRACE);
            // `count` values in all: the two number needles are among them,
            // so 1,024 stays within the bound and measures redaction.
            for i in 0..count.saturating_sub(2) {
                needles.insert("b", &format!("needle-{i:05}-secret"));
            }
            needles.insert("b", "012345");
            needles.insert("b", "1.5e10");
            let clean = "x".repeat(size);
            let echo = format!("{}needle-00000-secret", "x".repeat(size - 19));
            let numbers = format!("[{}]", vec!["12345"; size / 6].join(","));
            for (kind, body) in [
                ("clean", json!({"text": clean}).to_string()),
                ("echo", json!({"text": echo}).to_string()),
                ("numbers", format!("{{\"n\":{numbers}}}")),
            ] {
                let started = std::time::Instant::now();
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                let parse = started.elapsed();
                let mut message = JsonRpcMessage::Response(JsonRpcResponse::success(
                    RequestId::Number(1),
                    parsed,
                ));
                let started = std::time::Instant::now();
                let outcome = ingress_scrub(&needles, &mut message);
                let scrub = started.elapsed();
                assert_ne!(
                    outcome,
                    Scrubbed::Refuse,
                    "the set overflowed: not a redaction cost"
                );
                println!(
                    "T1.33 size={size} needles={count} kind={kind} parse={parse:?} scrub={scrub:?} outcome={outcome:?}"
                );
            }
        }
    }
}

/// gpt G2: an `error.code` equal to a value by number, not only by text, is
/// refused on a response and on a retryable error, and the refusal keeps the
/// error retryable.
#[test]
fn an_error_code_equal_to_a_value_by_number_is_refused() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "0739154");
    let mut message = JsonRpcMessage::Response(JsonRpcResponse::error(
        Some(RequestId::Number(1)),
        739_154,
        "nope",
    ));
    assert_eq!(ingress_scrub(&needles, &mut message), Scrubbed::Refuse);
    let answer = super::scrub_answer(
        &needles,
        Err(crate::Error::JsonRpcRetryable {
            code: 739_154,
            message: "busy".to_owned(),
            status: 503,
            data: None,
        }),
    );
    let Err(crate::Error::JsonRpcRetryable {
        code,
        message,
        status,
        ..
    }) = answer
    else {
        panic!("not a retryable refusal: {answer:?}");
    };
    assert_eq!((code, status), (-32603, 503));
    assert!(!message.contains("739154"), "{message}");
}

/// gpt G3: the envelope's `jsonrpc` is normalised, so a value placed there
/// never passes.
#[test]
fn a_value_in_the_jsonrpc_field_is_normalised_away() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    let mut response = JsonRpcResponse::success(RequestId::Number(1), json!({}));
    response.jsonrpc = "token-one-value".to_owned();
    let mut message = JsonRpcMessage::Response(response);
    assert_eq!(ingress_scrub(&needles, &mut message), Scrubbed::Redacted);
    let JsonRpcMessage::Response(response) = message else {
        unreachable!()
    };
    assert_eq!(response.jsonrpc, "2.0");
}

/// gpt G5: a supported-version list holding a value is refused, never shown.
#[test]
fn a_supported_version_holding_a_value_is_refused() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    let answer = super::scrub_answer(
        &needles,
        Err(crate::Error::ProtocolVersionRejected {
            supported: vec!["2025-06-18".to_owned(), "token-one-value".to_owned()],
        }),
    );
    let text = format!("{answer:?}");
    assert!(!text.contains("token-one-value"), "{text}");
    assert!(
        matches!(answer, Err(crate::Error::JsonRpc { code: -32603, .. })),
        "{text}"
    );
}

/// kimi A-F1: the RFC 3986 spelling (space as `%20`) and lowercase hex are
/// matched as well as the form spelling.
#[test]
fn every_listed_percent_spelling_is_redacted() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "tok en/\u{fc}?=1");
    for echo in [
        "k=tok%20en%2F%C3%BC%3F%3D1",
        "k=tok%20en%2f%c3%bc%3f%3d1",
        "k=tok+en%2f%c3%bc%3f%3d1",
    ] {
        let (outcome, text) = scrubbed(&needles, echo);
        assert_eq!(outcome, Scrubbed::Redacted, "{echo}");
        assert!(!text.contains("tok"), "{echo} -> {text}");
    }
}

/// DELTA-11: the compiled set is reused but never stale: a value added after
/// a scrub is matched by the next one, and a cached build stops matching a
/// value once its grace passes.
#[tokio::test(start_paused = true)]
async fn the_cached_matcher_follows_inserts_and_retirement() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-one-value");
    assert_eq!(
        scrubbed(&needles, "echo token-one-value").0,
        Scrubbed::Redacted
    );
    needles.insert("b", "token-two-value");
    assert_eq!(
        scrubbed(&needles, "echo token-two-value").0,
        Scrubbed::Redacted
    );
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    let (outcome, text) = scrubbed(&needles, "echo token-one-value");
    assert_eq!(
        outcome,
        Scrubbed::Clean,
        "a retired value is still matched: {text}"
    );
}

/// A value sent again after it retired is matched again, though the build
/// cached while it was retired lacked it (review round 2).
#[tokio::test(start_paused = true)]
async fn a_value_renewed_after_it_retired_is_matched_again() {
    let needles = NeedleSet::with_grace(GRACE);
    needles.insert("b", "token-renewed-value");
    tokio::time::advance(GRACE + Duration::from_secs(1)).await;
    assert_eq!(
        scrubbed(&needles, "echo token-renewed-value").0,
        Scrubbed::Clean,
        "premise: the value retired and the empty build is cached"
    );
    needles.insert("b", "token-renewed-value");
    let (outcome, text) = scrubbed(&needles, "echo token-renewed-value");
    assert_eq!(
        outcome,
        Scrubbed::Redacted,
        "a renewed value is not matched: {text}"
    );
}
