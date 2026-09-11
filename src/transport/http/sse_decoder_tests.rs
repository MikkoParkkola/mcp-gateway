// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Properties the streaming SSE decoder must hold (`MIK-7272.SUB.2b` (d)).
//!
//! These fail today on the `unimplemented!()` bodies: they are the acceptance
//! criteria for the decoder, written before it.

use super::sse_decoder::{MAX_PENDING_SSE_BYTES, SseDecoder, SseEvent, decode_sse_exchange};
use crate::transport::notification_sink;

/// Decode a whole body in one push plus a finish.
fn decode_all(body: &[u8]) -> Vec<SseEvent> {
    let mut decoder = SseDecoder::new(MAX_PENDING_SSE_BYTES);
    let mut out = decoder.push(body).expect("whole-body push");
    out.extend(decoder.finish().expect("finish"));
    out
}

fn event(name: Option<&str>, data: &str) -> SseEvent {
    SseEvent {
        event: name.map(str::to_string),
        data: data.to_string(),
    }
}

/// P1: framing is independent of chunk boundaries.
///
/// Anchored, not merely differential: the unsplit decode must equal an
/// explicit expectation first, so a uniformly-lossy decoder cannot pass by
/// being equally wrong on both sides. The multi-byte emoji puts a split
/// inside a UTF-8 sequence at some offsets.
#[test]
fn every_chunk_boundary_decodes_identically() {
    let body = b"event: message\ndata: {\"ok\":\"\xf0\x9f\x9a\x80\"}\n\nevent: message\ndata: {\"id\":2}\n\n";
    let expected = vec![
        event(Some("message"), "{\"ok\":\"\u{1f680}\"}"),
        event(Some("message"), "{\"id\":2}"),
    ];
    assert_eq!(decode_all(body), expected, "unsplit baseline");

    for split in 0..=body.len() {
        let mut decoder = SseDecoder::new(MAX_PENDING_SSE_BYTES);
        let mut got = decoder.push(&body[..split]).expect("head");
        got.extend(decoder.push(&body[split..]).expect("tail"));
        got.extend(decoder.finish().expect("finish"));
        assert_eq!(got, expected, "split at byte {split}");
    }
}

/// P2: the bound covers only bytes not yet forming an event, so an arbitrarily
/// long stream of small events never trips it.
#[test]
fn a_long_stream_of_small_events_never_exceeds_the_pending_bound() {
    let mut decoder = SseDecoder::new(256);
    for i in 0..5_000 {
        let chunk = format!("data: {{\"id\":{i}}}\n\n");
        let events = decoder.push(chunk.as_bytes()).expect("small event");
        assert_eq!(events, vec![event(None, &format!("{{\"id\":{i}}}"))]);
    }
}

/// P2: an unterminated tail past the bound fails during `push` -- before the
/// stream ends -- rather than being discovered only at `finish`.
#[test]
fn an_unterminated_block_past_the_bound_fails_in_push() {
    let mut decoder = SseDecoder::new(64);
    let coalesced = format!("data: {}", "x".repeat(4096));
    assert!(
        decoder.push(coalesced.as_bytes()).is_err(),
        "oversized pending block must fail in push, not finish"
    );
}

/// P2: the bound covers the whole retained event, not just the undrained
/// tail. Every completed `data:` line leaves the byte buffer and joins the
/// pending event, so a flood of short lines with no blank line would grow
/// without limit under a tail-only bound -- memory exhaustion, no error.
#[test]
fn many_short_data_lines_without_a_blank_line_exceed_the_bound() {
    let mut decoder = SseDecoder::new(4096);
    let line = format!("data: {}\n", "z".repeat(64));
    let mut rejected = false;
    for _ in 0..512 {
        match decoder.push(line.as_bytes()) {
            Ok(events) => assert!(events.is_empty(), "no blank line, so no event completes"),
            Err(_) => {
                rejected = true;
                break;
            }
        }
    }
    assert!(
        rejected,
        "an unterminated event grown past the bound by many short lines must fail in push"
    );
}

/// P3: a legitimately large tool result decodes. The bound under test is the
/// production constant, not a literal, so this proves something about ship.
#[test]
fn a_tool_result_far_larger_than_a_chunk_decodes() {
    let payload = "y".repeat(256 * 1024);
    let body = format!("event: message\ndata: {{\"text\":\"{payload}\"}}\n\n");
    assert!(
        body.len() < MAX_PENDING_SSE_BYTES,
        "fixture within the bound"
    );

    let mut decoder = SseDecoder::new(MAX_PENDING_SSE_BYTES);
    let mut got = Vec::new();
    for chunk in body.as_bytes().chunks(8192) {
        got.extend(decoder.push(chunk).expect("chunk"));
    }
    got.extend(decoder.finish().expect("finish"));
    assert_eq!(
        got,
        vec![event(
            Some("message"),
            &format!("{{\"text\":\"{payload}\"}}")
        )]
    );
}

/// P4: all three line terminators frame events.
///
/// LF and CRLF already work in the buffered path (`str::lines()` strips a
/// trailing `\r`); they are regression guards. **Bare CR is the real defect**
/// -- such a stream never dispatches today.
#[test]
fn lf_crlf_and_bare_cr_all_frame_events() {
    let expected = vec![event(Some("message"), "{\"id\":1}")];
    for (label, body) in [
        ("lf", "event: message\ndata: {\"id\":1}\n\n".to_string()),
        (
            "crlf",
            "event: message\r\ndata: {\"id\":1}\r\n\r\n".to_string(),
        ),
        ("cr", "event: message\rdata: {\"id\":1}\r\r".to_string()),
    ] {
        assert_eq!(decode_all(body.as_bytes()), expected, "terminator: {label}");
    }
}

/// P5: repeated `data:` fields join with a single `\n`, and exactly one
/// leading space is stripped -- not `trim`, so inner whitespace survives.
#[test]
fn multiple_data_fields_join_with_newlines() {
    let body = b"event: message\ndata: {\"a\":1,\ndata:  \"b\":2}\n\n";
    assert_eq!(
        decode_all(body),
        vec![event(Some("message"), "{\"a\":1,\n \"b\":2}")]
    );
}

/// P6: keep-alive noise is skipped, not turned into a transport error. An
/// empty `data:` is the killer today -- `serde_json::from_str("")` errors and
/// the whole exchange fails.
#[test]
fn comments_and_empty_data_are_skipped_not_errors() {
    let body = b": ping\n\ndata:\n\nevent: message\ndata: {\"id\":7}\n\n: keep-alive\n\n";
    assert_eq!(decode_all(body), vec![event(Some("message"), "{\"id\":7}")]);
}

/// P6: an unterminated final block still decodes, matching `str::lines()`.
#[test]
fn finish_flushes_a_block_with_no_trailing_blank_line() {
    let body = b"event: message\ndata: {\"id\":9}\n";
    assert_eq!(decode_all(body), vec![event(Some("message"), "{\"id\":9}")]);
}

/// P7: a stream that ends mid-exchange still surfaces the block that never
/// got its blank line. `finish` flushing it is not enough -- the driver has to
/// call `finish` rather than drop the tail on EOF.
#[tokio::test]
async fn a_stream_ending_without_a_blank_line_still_yields_its_response() {
    let body = futures::stream::iter(vec![Ok(bytes::Bytes::from_static(
        b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n",
    ))]);
    let response = decode_sse_exchange(body)
        .await
        .expect("the flushed final block is the response");
    assert!(response.result.is_some());
}

/// P7, converse: the response frame ends the call immediately. A stream held
/// open forever after it must not keep the caller waiting for EOF.
#[tokio::test]
async fn the_response_frame_completes_the_call_without_waiting_for_close() {
    let body = futures::stream::unfold(0usize, |step| async move {
        match step {
            0 => Some((
                Ok(bytes::Bytes::from_static(
                    b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
                )),
                1,
            )),
            // Open forever: no further chunk, no close.
            _ => std::future::pending().await,
        }
    });

    let response =
        tokio::time::timeout(std::time::Duration::from_secs(5), decode_sse_exchange(body))
            .await
            .expect("the response frame must return at once, not on stream close")
            .expect("a response");
    assert!(response.result.is_some());
}

/// P7: a notification is observable while the response frame is still
/// outstanding. A decoder that buffers the body and decodes at the end cannot
/// pass; the timeout makes that a failure rather than a hang.
#[tokio::test]
async fn a_notification_arrives_before_the_response_frame() {
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let stream_gate = std::sync::Arc::clone(&gate);
    let body = futures::stream::unfold(0usize, move |step| {
        let gate = std::sync::Arc::clone(&stream_gate);
        async move {
            match step {
                0 => Some((
                    Ok(bytes::Bytes::from_static(
                        b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n",
                    )),
                    1,
                )),
                1 => {
                    let _permit = gate.acquire().await.expect("gate");
                    Some((
                        Ok(bytes::Bytes::from_static(
                            b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
                        )),
                        2,
                    ))
                }
                _ => None,
            }
        }
    });

    let (scoped, mut rx) = notification_sink::scope(decode_sse_exchange(body));
    tokio::pin!(scoped);

    let early = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::select! {
            received = rx.recv() => received,
            _ = &mut scoped => panic!(
                "notification not observable before the response frame -- batched read"
            ),
        }
    })
    .await
    .expect("the notification must surface before the gate is released");

    assert_eq!(
        early.expect("a notification").method,
        "notifications/progress"
    );
    gate.add_permits(1);
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), scoped)
        .await
        .expect("the exchange must finish once the response chunk is released")
        .expect("a response");
    assert!(response.result.is_some());
}
