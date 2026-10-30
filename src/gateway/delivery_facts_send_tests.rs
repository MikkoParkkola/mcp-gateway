// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a delivery knows about its sends: a send counted on entry stays
//! counted unless it returned an error that proves nothing left, and a key is
//! released only when no counted send remains.

use futures::FutureExt;

use super::{
    ResponseEffect, counted_send, raise, refused_before_send, refused_before_send_seen, scope,
    unsent,
};
use crate::Error;

fn config() -> Error {
    Error::Config("a secret rule cannot be applied".into())
}

fn connect() -> Error {
    Error::TransportConnect("refused".into())
}

fn lost() -> Error {
    Error::Transport("connection reset".into())
}

/// Outside a delivery cell, `unsent` is today's rule: the error's own
/// pre-dispatch verdict, nothing more (no production settlement runs there).
#[test]
fn outside_a_cell_unsent_is_the_errors_own_verdict() {
    for error in [config(), connect(), lost()] {
        assert_eq!(unsent(&error), error.is_pre_dispatch(), "{error:?}");
    }
    assert!(!refused_before_send_seen());
}

/// A refusal the send recorded makes a non-pre-dispatch error unsent.
#[tokio::test]
async fn a_send_recorded_refusal_is_unsent() {
    scope(async {
        assert!(
            !unsent(&config()),
            "premise: Config alone may have been sent"
        );
        let error = refused_before_send(config());
        assert!(refused_before_send_seen());
        assert!(unsent(&error), "a refusal before the send read as sent");
    })
    .await;
}

/// R5b: the Refused effect alone (raised after a send, by a response gate)
/// is not the fact: a later error still reads as possibly sent.
#[tokio::test]
async fn the_refused_effect_alone_is_not_a_refusal_before_the_send() {
    scope(async {
        raise(ResponseEffect::Refused);
        assert!(!unsent(&lost()));
        assert!(!unsent(&config()));
    })
    .await;
}

/// R17 (unit): one send that never connected is taken back: unsent.
#[tokio::test]
async fn a_lone_send_that_never_connected_is_unsent() {
    scope(async {
        let returned = counted_send(async { Err::<(), _>(connect()) }).await;
        assert!(unsent(&returned.expect_err("the send failed")));
    })
    .await;
}

/// R16 (unit): a send that may have arrived stays counted when a later
/// attempt never connects: the delivery keeps its key.
#[tokio::test]
async fn an_earlier_send_survives_a_later_one_that_never_connected() {
    scope(async {
        let _ = counted_send(async { Err::<(), _>(lost()) }).await;
        let returned = counted_send(async { Err::<(), _>(connect()) }).await;
        assert!(!unsent(&returned.expect_err("the send failed")));
    })
    .await;
}

/// R15 (unit): a send dropped before it returned (a timeout, a cancel) stays
/// counted, so a later refusal before another send does not release the key.
#[tokio::test]
async fn a_dropped_send_stays_counted() {
    scope(async {
        let pending = counted_send(std::future::pending::<crate::Result<()>>());
        assert!(
            pending.now_or_never().is_none(),
            "premise: polled once, then dropped"
        );
        let error = refused_before_send(config());
        assert!(!unsent(&error), "a dropped send was forgotten");
    })
    .await;
}

/// R13 (unit): a send that was answered also stays counted.
#[tokio::test]
async fn an_answered_send_stays_counted() {
    scope(async {
        let _ = counted_send(async { Ok::<(), Error>(()) }).await;
        assert!(!unsent(&refused_before_send(config())));
        assert!(!unsent(&connect()));
    })
    .await;
}
