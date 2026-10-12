// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! The stdio end of [`ClientChannel`]: ask the client that spawned us, over
//! the same two pipes it already talks on.
//!
//! Design: `docs/design/2026-09-13-mik-7387-stdio-concurrent-dispatch.md`.
//!
//! Two halves that only work together. A request goes out through the single
//! writer task that owns stdout — nothing else may write there, or two
//! concurrent outbound frames interleave mid-line. The reply comes back up the
//! same stdin the serve loop is reading, so the loop classifies it and routes
//! it here rather than dispatching it as a request.

use dashmap::DashMap;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::gateway::outbound::{OutboundFrame, StdioReads};
use crate::transport::PendingRequestGuard;

/// A [`ClientChannel`] over the stdio pipes.
pub(crate) struct StdioClientChannel {
    /// Outbound requests awaiting a reply, keyed by the id we minted.
    pending: DashMap<String, oneshot::Sender<Value>>,
    /// The only handle to stdout. Frames are queued, never written here.
    writer: mpsc::Sender<OutboundFrame>,
    /// The cross-tenant read judge every bridged request passes (MIN.2).
    reads: StdioReads,
    /// Set once the client is gone, and never cleared.
    closed: AtomicBool,
}

impl StdioClientChannel {
    /// Build a channel that queues its frames on `writer`.
    pub(crate) fn new(writer: mpsc::Sender<OutboundFrame>, reads: StdioReads) -> Self {
        Self {
            pending: DashMap::new(),
            writer,
            reads,
            closed: AtomicBool::new(false),
        }
    }

    /// The id an inbound frame replies to, if it is a reply at all.
    ///
    /// A reply carries an `id` and no `method`: a frame with both is a request
    /// the client is making of us, and dispatching a reply as a request is the
    /// failure this predicate exists to prevent. Ids are normalised to the
    /// `String` the map is keyed by, because a client may echo our string id
    /// as a JSON number.
    pub(crate) fn reply_id(frame: &Value) -> Option<String> {
        if frame.get("method").is_some() {
            return None;
        }
        match frame.get("id")? {
            Value::String(id) => Some(id.clone()),
            Value::Number(id) => Some(id.to_string()),
            _ => None,
        }
    }

    /// Hand `frame` to whatever is waiting on `id`.
    ///
    /// `false` when nothing waits — the expected cause is a late answer to a
    /// prompt that already timed out, which is not an error.
    pub(crate) fn resolve(&self, id: &str, frame: Value) -> bool {
        match self.pending.remove(id) {
            Some((_, tx)) => tx.send(frame).is_ok(),
            None => false,
        }
    }

    /// Fail every outstanding prompt, because the client is gone.
    ///
    /// Dropping the senders wakes each waiting `send_request` with a closed
    /// receiver, which is the same signal a vanished HTTP session produces
    /// (`src/gateway/proxy.rs:523`) and lands as [`DeliveryError::TimedOut`].
    ///
    /// Terminal: the flag is set before the map is cleared, so a prompt that
    /// registers during the EOF drain sees it and fails fast. Clearing alone
    /// would let that prompt wait out the bridge's full timeout inside the
    /// bounded drain, which is the response loss the drain exists to prevent.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.pending.clear();
    }
}

#[async_trait::async_trait]
impl ClientChannel for StdioClientChannel {
    async fn send_request(
        &self,
        session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, DeliveryError> {
        self.send_request_committing(session_id, id, method, params, None)
            .await
    }

    async fn send_request_committing(
        &self,
        _session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
        commit: Option<crate::gateway::input_bridge::DeliveryCommit>,
    ) -> Result<Value, DeliveryError> {
        // Registered before the frame goes out: a client fast enough to answer
        // between the write and the registration would find no receiver.
        let (tx, rx) = oneshot::channel();
        self.pending.insert(id.to_string(), tx);
        // Held across the await. `InputBridge::ask` wraps this call in a
        // timeout and abandons the future on expiry, so neither the success
        // nor the error path below runs; without the guard the entry leaks for
        // the life of the session.
        let _cleanup = PendingRequestGuard::new(&self.pending, id);

        // Checked after registration, never before: `close` sets the flag and
        // then clears the map, so a registration that survives the clear is
        // one whose check has not run yet. Reading the flag here catches both
        // orders; reading it first would race with the clear and leave an
        // entry nothing will ever resolve.
        if self.closed.load(Ordering::SeqCst) {
            return Err(DeliveryError::NoSession);
        }

        let mut frame = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        // Absent params stays absent: an empty object is a params member the
        // bridge did not send, and the client cannot tell the two apart.
        if let Some(params) = params {
            frame["params"] = params;
        }

        // Capacity first, commit second. The queue is bounded, so `send`
        // parks when it is full, and `close` runs inside that park: the flag
        // goes up and the map is cleared, and a plain `send` would then
        // commit the frame to a channel that is already terminal — a prompt
        // nothing can answer, reported to the caller as a timeout. Reserving
        // moves the park ahead of the commit, so the flag below is read with
        // capacity already in hand and the permit is dropped unused when the
        // session went away while we waited.
        let Ok(permit) = self.writer.reserve().await else {
            // The writer task is gone, so stdout is closed and nothing we
            // queue can reach anyone.
            return Err(DeliveryError::NoSession);
        };
        if self.closed.load(Ordering::SeqCst) {
            return Err(DeliveryError::NoSession);
        }
        // MIN.2: judged for the stdio client; a withheld prompt reaches no one.
        let Some(frame) = self.reads.request(frame).await else {
            return Err(DeliveryError::NoSession);
        };
        // MIK-7887.RECEIPT.3: committed by the writer once stdout took the
        // frame, not here, so a writer that dies first delivered nothing and a
        // wait cancelled after the write keeps it.
        permit.send(frame.committing_on_write(commit));
        debug!(%id, %method, "stdio: sent bridged request to the client");

        // A dropped sender means the entry went away without an answer, which
        // is what the bridge's own timeout arm means by `TimedOut`.
        rx.await.map_err(|_| DeliveryError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The read judge of a gateway with the verdict off.
    fn plain_reads() -> StdioReads {
        StdioReads::new(
            None,
            std::sync::Arc::new(crate::gateway::outbound::RejectionAudit::new(None, 1)),
            None,
        )
    }

    #[test]
    fn a_frame_with_a_method_is_a_request_not_a_reply() {
        // A server-to-client request echoed back, or the client's own call:
        // both carry `method`, and neither answers anything of ours.
        let frame = json!({"jsonrpc": "2.0", "id": "elicit-1", "method": "ping"});
        assert_eq!(StdioClientChannel::reply_id(&frame), None);
    }

    #[test]
    fn a_numeric_id_normalises_to_the_key_the_map_uses() {
        let frame = json!({"jsonrpc": "2.0", "id": 7, "result": {}});
        assert_eq!(
            StdioClientChannel::reply_id(&frame),
            Some("7".to_string()),
            "a client may echo an id as a number; the map is keyed by String"
        );
    }

    #[tokio::test]
    async fn a_reply_reaches_the_request_that_is_waiting_for_it() {
        let (tx, mut rx) = mpsc::channel(16);
        let channel = std::sync::Arc::new(StdioClientChannel::new(tx, plain_reads()));

        let asking = tokio::spawn({
            let channel = std::sync::Arc::clone(&channel);
            async move {
                channel
                    .send_request("stdio", "elicit-1", "elicitation/create", None)
                    .await
            }
        });

        let sent = rx
            .recv()
            .await
            .expect("the request was never queued")
            .stdio_value()
            .map(std::borrow::Cow::into_owned)
            .expect("a request writes a value");
        assert_eq!(
            sent.get("method").and_then(Value::as_str),
            Some("elicitation/create")
        );
        assert!(
            channel.resolve(
                "elicit-1",
                json!({"jsonrpc": "2.0", "id": "elicit-1", "result": {"action": "accept"}})
            ),
            "nothing was waiting on the id the request went out with"
        );

        let answer = asking.await.expect("task panicked").expect("no answer");
        assert_eq!(
            answer.pointer("/result/action").and_then(Value::as_str),
            Some("accept"),
            "the raw reply frame is what the bridge projects; it must arrive whole"
        );
    }

    #[tokio::test]
    async fn a_send_parked_on_a_full_queue_refuses_once_close_wins_the_race() {
        // The queue is bounded, so a producer can park inside `send`. `close`
        // runs in that gap: it raises the flag and clears the map, and the
        // frame would otherwise still be committed to a channel that is
        // already terminal — a prompt the client can never answer, reported
        // to the caller as a timeout rather than a dead session.
        let (tx, mut rx) = mpsc::channel(1);
        let channel = std::sync::Arc::new(StdioClientChannel::new(tx.clone(), plain_reads()));
        tx.send(OutboundFrame::gateway_stdio(json!({"filler": true})))
            .await
            .expect("the empty queue took the filler");

        let asking = tokio::spawn({
            let channel = std::sync::Arc::clone(&channel);
            async move {
                channel
                    .send_request("stdio", "elicit-1", "elicitation/create", None)
                    .await
            }
        });
        // Let the task register its entry and reach the park on the full queue.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }

        channel.close();
        let filler = rx
            .recv()
            .await
            .expect("the filler was queued")
            .stdio_value()
            .map(std::borrow::Cow::into_owned)
            .expect("the filler writes a value");
        assert!(
            filler.get("filler").is_some(),
            "the filler is what freed the capacity the parked send was waiting for"
        );

        let outcome = asking.await.expect("task panicked");
        assert!(
            matches!(outcome, Err(DeliveryError::NoSession)),
            "close won the race, so the caller is told the session is gone, not that it timed out: {outcome:?}"
        );
        assert!(
            rx.try_recv().is_err(),
            "no frame may be written after close: the client can never answer it"
        );
    }

    /// A commit that counts how often it ran.
    fn counting_commit() -> (
        crate::gateway::input_bridge::DeliveryCommit,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = std::sync::Arc::clone(&runs);
        let commit = crate::gateway::input_bridge::DeliveryCommit::new(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        (commit, runs)
    }

    /// MIK-7887.RECEIPT.3: a queued frame is not delivered. The commit runs
    /// when the writer reports stdout took the frame, once, and survives the
    /// caller abandoning its wait.
    #[tokio::test]
    async fn a_delivery_commits_when_stdout_takes_the_frame_not_when_queued() {
        use std::sync::atomic::Ordering;
        let (tx, mut rx) = mpsc::channel(16);
        let channel = StdioClientChannel::new(tx, plain_reads());
        let (commit, runs) = counting_commit();
        // The wait is abandoned right after the frame is queued.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            channel.send_request_committing(
                "stdio",
                "elicit-7",
                "elicitation/create",
                None,
                Some(commit),
            ),
        )
        .await;
        assert!(outcome.is_err(), "no reply came");
        let frame = rx.recv().await.expect("the request was queued");
        assert_eq!(runs.load(Ordering::SeqCst), 0, "queued is not delivered");
        frame.stdio_written();
        frame.stdio_written();
        assert_eq!(
            runs.load(Ordering::SeqCst),
            1,
            "written once, committed once"
        );
    }

    /// MIK-7887.RECEIPT.3: a closed session commits nothing.
    #[tokio::test]
    async fn a_closed_session_commits_no_delivery() {
        use std::sync::atomic::Ordering;
        let (tx, mut rx) = mpsc::channel(16);
        let channel = StdioClientChannel::new(tx, plain_reads());
        channel.close();
        let (commit, runs) = counting_commit();
        let sent = channel
            .send_request_committing(
                "stdio",
                "elicit-8",
                "elicitation/create",
                None,
                Some(commit),
            )
            .await;
        assert!(matches!(sent, Err(DeliveryError::NoSession)), "{sent:?}");
        assert!(rx.try_recv().is_err(), "nothing was queued");
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn an_abandoned_request_strands_no_entry() {
        // The cancellation contract on `ClientChannel::send_request`: an outer
        // timeout drops the future, and neither the success nor the error path
        // runs. Without the guard the entry outlives the prompt.
        let (tx, _rx) = mpsc::channel(16);
        let channel = StdioClientChannel::new(tx, plain_reads());

        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            channel.send_request("stdio", "elicit-2", "elicitation/create", None),
        )
        .await;

        assert!(outcome.is_err(), "the prompt was answered; it must not be");
        assert!(
            channel.pending.is_empty(),
            "the abandoned prompt left its pending entry behind"
        );
    }

    #[tokio::test]
    async fn close_wakes_every_outstanding_prompt() {
        let (tx, mut rx) = mpsc::channel(16);
        let channel = std::sync::Arc::new(StdioClientChannel::new(tx, plain_reads()));

        let asking = tokio::spawn({
            let channel = std::sync::Arc::clone(&channel);
            async move {
                channel
                    .send_request("stdio", "elicit-3", "elicitation/create", None)
                    .await
            }
        });
        rx.recv().await.expect("the request was never queued");

        channel.close();

        let outcome = asking.await.expect("task panicked");
        assert!(
            matches!(outcome, Err(DeliveryError::TimedOut)),
            "a prompt outstanding when the client vanishes must not hang: {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_prompt_raised_after_close_fails_instead_of_waiting() {
        // The EOF drain is bounded and runs after `close`. A dispatch that
        // reaches its bridged question inside that window must not register an
        // entry nothing can resolve and then wait out the bridge's timeout —
        // that spends the drain and loses the response it was drained for.
        let (tx, _rx) = mpsc::channel(16);
        let channel = StdioClientChannel::new(tx, plain_reads());
        channel.close();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            channel.send_request("stdio", "elicit-4", "elicitation/create", None),
        )
        .await
        .expect("the prompt waited for a client that is gone");

        assert!(
            matches!(outcome, Err(DeliveryError::NoSession)),
            "a prompt raised after the client is gone must fail fast: {outcome:?}"
        );
        assert!(
            channel.pending.is_empty(),
            "the refused prompt left its pending entry behind"
        );
    }

    /// MIK-7324.COV.3: an id that is neither a string nor a number names no
    /// request of ours, so the frame is not a reply.
    #[test]
    fn an_id_that_is_neither_string_nor_number_is_not_a_reply() {
        for id in [json!(true), json!(null), json!({"k": 1}), json!([1])] {
            let frame = json!({"jsonrpc": "2.0", "id": id, "result": {}});
            assert_eq!(StdioClientChannel::reply_id(&frame), None, "{frame}");
        }
    }

    /// A late answer for a prompt nobody waits on any more resolves nothing
    /// and is not an error.
    #[test]
    fn resolving_an_id_nothing_waits_on_returns_false() {
        let (tx, _rx) = mpsc::channel(1);
        let channel = StdioClientChannel::new(tx, plain_reads());
        assert!(!channel.resolve("elicit-gone", json!({"result": {}})));
    }

    /// MIK-7324.COV.3 (C6 stdio 6): any `method` member makes the frame a
    /// request, whatever its type, so a null method with an id is no reply.
    #[test]
    fn a_frame_with_a_null_method_is_not_a_reply() {
        let frame = json!({"jsonrpc": "2.0", "id": "elicit-1", "method": null});
        assert_eq!(StdioClientChannel::reply_id(&frame), None, "{frame}");
    }

    /// MIK-7324.COV.3 (C6 stdio 8): a reply naming an id nobody waits on is
    /// never handed to a different request that is waiting.
    #[test]
    fn a_reply_for_another_id_leaves_the_waiting_request_pending() {
        let (tx, _rx) = mpsc::channel(1);
        let channel = StdioClientChannel::new(tx, plain_reads());
        let (waiter, mut answer) = oneshot::channel();
        channel.pending.insert("elicit-1".to_string(), waiter);
        assert!(
            !channel.resolve("elicit-other", json!({"result": {}})),
            "a reply for an unknown id resolved something"
        );
        assert!(
            channel.pending.contains_key("elicit-1"),
            "the waiting request lost its pending entry to another id's reply"
        );
        assert!(
            answer.try_recv().is_err(),
            "the waiting request received another id's reply"
        );
    }
}
