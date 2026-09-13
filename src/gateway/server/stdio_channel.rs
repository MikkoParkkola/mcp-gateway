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
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::gateway::input_bridge::{ClientChannel, DeliveryError};
use crate::transport::PendingRequestGuard;

/// A [`ClientChannel`] over the stdio pipes.
pub(crate) struct StdioClientChannel {
    /// Outbound requests awaiting a reply, keyed by the id we minted.
    pending: DashMap<String, oneshot::Sender<Value>>,
    /// The only handle to stdout. Frames are queued, never written here.
    writer: mpsc::UnboundedSender<Value>,
}

impl StdioClientChannel {
    /// Build a channel that queues its frames on `writer`.
    pub(crate) fn new(writer: mpsc::UnboundedSender<Value>) -> Self {
        Self {
            pending: DashMap::new(),
            writer,
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
    pub(crate) fn close(&self) {
        self.pending.clear();
    }
}

#[async_trait::async_trait]
impl ClientChannel for StdioClientChannel {
    async fn send_request(
        &self,
        _session_id: &str,
        id: &str,
        method: &str,
        params: Option<Value>,
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

        let mut frame = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        // Absent params stays absent: an empty object is a params member the
        // bridge did not send, and the client cannot tell the two apart.
        if let Some(params) = params {
            frame["params"] = params;
        }

        if self.writer.send(frame).is_err() {
            // The writer task is gone, so stdout is closed and nothing we
            // queue can reach anyone.
            return Err(DeliveryError::NoSession);
        }
        debug!(%id, %method, "stdio: sent bridged request to the client");

        // A dropped sender means the entry went away without an answer, which
        // is what the bridge's own timeout arm means by `TimedOut`.
        rx.await.map_err(|_| DeliveryError::TimedOut)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let (tx, mut rx) = mpsc::unbounded_channel();
        let channel = std::sync::Arc::new(StdioClientChannel::new(tx));

        let asking = tokio::spawn({
            let channel = std::sync::Arc::clone(&channel);
            async move {
                channel
                    .send_request("stdio", "elicit-1", "elicitation/create", None)
                    .await
            }
        });

        let sent = rx.recv().await.expect("the request was never queued");
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
    async fn an_abandoned_request_strands_no_entry() {
        // The cancellation contract on `ClientChannel::send_request`: an outer
        // timeout drops the future, and neither the success nor the error path
        // runs. Without the guard the entry outlives the prompt.
        let (tx, _rx) = mpsc::unbounded_channel();
        let channel = StdioClientChannel::new(tx);

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
        let (tx, mut rx) = mpsc::unbounded_channel();
        let channel = std::sync::Arc::new(StdioClientChannel::new(tx));

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
}
