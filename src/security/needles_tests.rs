// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The injected-value set's lifetime rules (MIK-9035): a value stays redacted
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
