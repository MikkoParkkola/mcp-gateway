// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C0 T4: reading an `Events` stream must tell "nothing yet" from "the
//! stream ended". Every read is the public `Events::next()` under a
//! paused clock, so the `ARRIVAL` deadline inside `next()` passes by
//! auto-advance, with no wall-clock wait and no substituted deadline.

use std::convert::Infallible;

use axum::body::{Body, Bytes};
use serde_json::json;

use super::{EventOutcome, Events, spawn_relay};

fn events(body: Body) -> Events {
    Events {
        stream: Box::pin(body.into_data_stream()),
        buffer: String::new(),
    }
}

#[tokio::test(start_paused = true)]
async fn pending_and_empty_reads_are_distinguishable() {
    // Control: a body carrying one SSE data block reads as that event.
    let data = Body::from_stream(futures::stream::once(async {
        Ok::<_, Infallible>(Bytes::from_static(b"data: {\"method\":\"x\"}\n\n"))
    }));
    assert_eq!(
        events(data).next().await,
        EventOutcome::Event(json!({ "method": "x" })),
        "premise: the data control body parses as one event"
    );

    // A body that never yields: `next()` reads until its deadline passes.
    let pending = Body::from_stream(futures::stream::pending::<Result<Bytes, Infallible>>());
    let pending_observation = events(pending).next().await;

    // A body that has already ended.
    let empty_observation = events(Body::empty()).next().await;

    assert_eq!(
        pending_observation,
        EventOutcome::Timeout,
        "own T4: a pending read is a timeout, never the end of the stream"
    );
    assert_eq!(
        empty_observation,
        EventOutcome::Eof,
        "own T4: an ended stream is eof, never a timeout"
    );
    assert_ne!(
        pending_observation, empty_observation,
        "own T4: a pending read and an ended stream must be distinguishable"
    );
}

fn failing_body() -> Body {
    Body::from_stream(futures::stream::once(async {
        Err::<Bytes, std::io::Error>(std::io::Error::other("connection reset"))
    }))
}

#[tokio::test(start_paused = true)]
async fn error_body_reads_as_error_not_eof() {
    match events(failing_body()).next().await {
        EventOutcome::Error(error) => {
            assert!(
                error.contains("connection reset"),
                "own T4: the actual body error is carried: {error}"
            );
        }
        other => panic!("own T4: a failing body must read as an error, not {other:?}"),
    }
}

#[tokio::test]
async fn relay_error_terminal_is_sticky() {
    let mut relay = spawn_relay(events(failing_body()));
    let first = relay.recv().await;
    match &first {
        EventOutcome::Error(error) => {
            assert!(
                error.contains("connection reset"),
                "own T4: the relay forwards the actual body error: {error}"
            );
        }
        other => panic!("own T4: a failing body must relay as an error, not {other:?}"),
    }
    assert_eq!(
        relay.recv().await,
        first,
        "own T4: a relay error terminal is re-observed identically"
    );
}

#[tokio::test]
async fn relay_eof_terminal_is_sticky() {
    let mut relay = spawn_relay(events(Body::empty()));
    assert_eq!(
        relay.recv().await,
        EventOutcome::Eof,
        "own T4: an ended body relays as eof"
    );
    assert_eq!(
        relay.recv().await,
        EventOutcome::Eof,
        "own T4: a relay eof terminal is re-observed identically"
    );
}
