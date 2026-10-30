// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test plan row 27: a timed send dropped mid-flight while its call goes on
//! to write its record.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use super::{Attempts, send_timed};
use crate::counters::{Call, CounterStore, End, Label, Tally, Window};
use crate::gateway::with_dispatch_scope;
use crate::gateway::send_timer_seam as seam;
use crate::protocol::JsonRpcResponse;
use crate::transport::{ResendPermission, Transport};

/// A backend that takes every request and never answers.
struct Hung;

#[async_trait::async_trait]
impl Transport for Hung {
    async fn request(&self, _method: &str, _params: Option<Value>) -> crate::Result<JsonRpcResponse> {
        std::future::pending().await
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// The send loses a select inside the call's scope: the call still records,
/// with one sample noted Cancelled and counted failed.
/// Mutant: `SendTimer`'s `Drop` notes nothing.
#[tokio::test]
async fn dropped_send_notes_cancelled() {
    seam::inject(Duration::from_millis(7));
    let ((), notes) = with_dispatch_scope(async {
        let send = send_timed(
            Arc::new(Hung),
            "tools/call".to_owned(),
            (None, Vec::new()),
            None,
            ResendPermission::Denied,
            Attempts::WithRetry,
        );
        tokio::select! {
            biased;
            answered = send => panic!("a hung backend answered: {answered:?}"),
            () = tokio::task::yield_now() => {}
        }
    })
    .await;
    seam::clear();
    let sample = notes.backend_sample();
    assert_eq!(sample, Some((Duration::from_millis(7), End::Cancelled)));
    let now = crate::clock::unix_secs().expect("a readable clock");
    let store = CounterStore::new(now);
    let call = Call {
        caller: "key:a",
        server: Label::Known("alpha"),
        tool: Label::Known("t"),
        tally: Tally::default(),
    };
    store.record_timed(&call, now, &chrono::Utc, sample);
    let view = store.latency_series(Some("alpha"), Window::Day, false, now, &chrono::Utc);
    let [point] = view.points.as_slice() else {
        panic!("one latency slot: {:?}", view.points);
    };
    assert_eq!((point.calls, point.failed, point.timed_out), (1, 1, 0));
}
