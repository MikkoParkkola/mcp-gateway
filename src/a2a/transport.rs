// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The A2A agent as a backend [`Transport`].
//!
//! A `Transport`, not a separate provider path: every backend call already runs
//! through `Backend` and the invoke funnel (tool policy, firewall, budgets,
//! audit, relay detection, response gates), so an agent reached this way is
//! governed exactly like any tool backend without a second set of gates.
//!
//! What it answers, as a legacy-era MCP peer offering one tool:
//! `initialize` (synthetic), `ping` (a live card fetch), `tools/list` (the card
//! as one tool) and `tools/call` (one `SendMessage`). Everything else is
//! `-32601`, `server/discover` included, so the era probe settles on legacy.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::sync::watch;

use super::client::{A2aClient, Endpoint, Reply};
use super::delegation::{
    CancelGuard, Canceller, PARKED_TTL, ParkRefused, Parked, Pending, SWEEP_EVERY,
};
use super::translator::{
    TOOL_NAME, card_to_tool, error_result, reply_to_result, status_text, task_to_result,
};
use super::types::{AgentCard, Message, SendMessageResponse, Task, TaskState};
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::security::ssrf::DestinationPolicy;
use crate::transport::Transport;
use crate::{Error, Result};

/// The MCP revision the synthetic `initialize` reports: the legacy one, since
/// this peer has no modern `_meta` channel.
const REPORTED_PROTOCOL_VERSION: &str = "2025-06-18";

/// The key the agent's question travels under in `inputRequests`.
const ASK_KEY: &str = "a2a_reply";
/// First and longest wait between `GetTask` polls of an unfinished task. The
/// first is short: the send returns as soon as the task exists, so a quick
/// agent's answer is usually one poll away.
const FIRST_POLL: Duration = Duration::from_millis(250);
const LONGEST_POLL: Duration = Duration::from_secs(5);
/// How long `close` waits for the cancels it sent.
const CLOSE_SETTLE: Duration = Duration::from_secs(5);

pub(crate) struct A2aTransport {
    client: A2aClient,
    endpoint: Endpoint,
    card: AgentCard,
    /// `true` once closed. Every in-flight call watches it, so `close` aborts
    /// a pending HTTP request instead of letting it run to the timeout.
    closed: watch::Sender<bool>,
    /// Questions waiting on their caller; each owns its agent task.
    parked: Parked,
    /// Sends the `CancelTask`s of abandoned tasks, bounded.
    canceller: Canceller,
    /// The backend timeout: bounds a whole delegation, send plus polls.
    timeout: Duration,
}

impl A2aTransport {
    /// Check the configured address, build the guarded client, read the card
    /// and choose its endpoint. Fails like any backend that cannot initialise.
    pub(crate) async fn start(
        a2a_url: &str,
        card_path: Option<&str>,
        headers: &HashMap<String, String>,
        timeout: Duration,
        destination: DestinationPolicy,
    ) -> Result<Arc<Self>> {
        let origin = url::Url::parse(a2a_url).map_err(|e| {
            Error::Config(format!(
                "a2a_url {} is not a URL: {e}",
                crate::security::diagnostic_url(a2a_url)
            ))
        })?;
        destination.check_literal(&origin)?;
        let http = crate::transport::guarded_client(
            origin,
            timeout,
            destination,
            Arc::new(AtomicU64::new(0)),
        )?;
        let headers = headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let client = A2aClient::new(a2a_url, card_path, headers, http)?;
        let card = client.fetch_card().await?;
        let endpoint = client.endpoint(&card)?;
        let canceller = Canceller::new(client.clone(), endpoint.clone());
        let transport = Arc::new(Self {
            client,
            endpoint,
            canceller,
            card,
            closed: watch::channel(false).0,
            parked: Parked::new(PARKED_TTL),
            timeout,
        });
        transport.spawn_sweeper();
        Ok(transport)
    }

    /// Cancel the task of every question left unanswered past its TTL. Holds
    /// the transport weakly and stops when it closes or is dropped.
    fn spawn_sweeper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let mut closed = self.closed.subscribe();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            loop {
                tokio::select! {
                    _ = closed.wait_for(|closed| *closed) => return,
                    _ = tick.tick() => {}
                }
                let Some(transport) = weak.upgrade() else {
                    return;
                };
                transport.sweep(std::time::Instant::now());
            }
        });
    }

    /// Cancel the task of every question expired at `now`.
    fn sweep(&self, now: std::time::Instant) {
        for pending in self.parked.drain_expired(now) {
            self.cancel(pending);
        }
    }

    /// One best-effort `CancelTask` for a parked task.
    fn cancel(&self, pending: Pending) {
        self.canceller.spawn(pending.task_id, pending.headers);
    }

    /// Run `call` unless the transport is, or becomes, closed.
    async fn unless_closed<T>(&self, call: impl Future<Output = Result<T>>) -> Result<T> {
        let mut closed = self.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|closed| *closed) => {
                Err(Error::Transport("A2A backend closed".into()))
            }
            outcome = call => outcome,
        }
    }

    async fn dispatch(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let id = RequestId::Number(0);
        match method {
            "initialize" => Ok(JsonRpcResponse::success(
                id,
                json!({
                    "protocolVersion": REPORTED_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": self.card.name,
                        "version": self.card.version.as_deref().unwrap_or("unknown"),
                    },
                }),
            )),
            "ping" => {
                self.unless_closed(self.client.fetch_card()).await?;
                Ok(JsonRpcResponse::success(id, json!({})))
            }
            "tools/list" => {
                let card = self.unless_closed(self.client.fetch_card()).await?;
                Ok(JsonRpcResponse::success(
                    id,
                    json!({"tools": [card_to_tool(&card)]}),
                ))
            }
            "tools/call" => {
                self.call_tool(id, params.as_ref(), extra_headers, identity)
                    .await
            }
            other => Ok(JsonRpcResponse::error(
                Some(id),
                -32601,
                format!("Method not found: an A2A agent does not answer `{other}`"),
            )),
        }
    }

    async fn call_tool(
        &self,
        id: RequestId,
        params: Option<&Value>,
        extra_headers: &[(String, String)],
        identity: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let invalid =
            |message: String| Ok(JsonRpcResponse::error(Some(id.clone()), -32602, message));
        let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
        if name != Some(TOOL_NAME) {
            return invalid(format!(
                "Unknown tool {name:?}: an A2A agent offers only `{TOOL_NAME}`"
            ));
        }
        // A retry answering the agent's question continues that agent task.
        if let Some(state) = params.and_then(|p| p.get("requestState")) {
            let Some(token) = state.as_str() else {
                return invalid("requestState must be a string".into());
            };
            return self
                .resume(id.clone(), token, params, extra_headers, identity)
                .await;
        }
        let Some(text) = params
            .and_then(|p| p.pointer("/arguments/message"))
            .and_then(Value::as_str)
        else {
            return invalid(format!(
                "`{TOOL_NAME}` requires a `message` string argument"
            ));
        };
        let mut guard = CancelGuard::new(self.canceller.clone(), extra_headers.to_vec());
        self.delegate(
            id,
            Message::user_text(text),
            extra_headers,
            identity,
            &mut guard,
        )
        .await
    }

    /// Redeem a parked question and act on the caller's answer.
    async fn resume(
        &self,
        id: RequestId,
        token: &str,
        params: Option<&Value>,
        extra_headers: &[(String, String)],
        identity: Option<&str>,
    ) -> Result<JsonRpcResponse> {
        let pending = match self.parked.take(token, identity, std::time::Instant::now()) {
            Ok(pending) => pending,
            Err((_, expired)) => {
                if let Some(expired) = expired {
                    self.cancel(expired);
                }
                // One answer whether the token was never issued, already used,
                // expired or another caller's: a caller cannot probe which, and
                // nothing reached the agent.
                return Ok(JsonRpcResponse::error(
                    Some(id),
                    -32602,
                    "requestState does not name a question waiting for this caller",
                ));
            }
        };
        // The map no longer owns the task; this guard does, from here on, so
        // a retry abandoned midway still cancels it.
        let mut guard = CancelGuard::new(self.canceller.clone(), extra_headers.to_vec());
        guard.arm(&pending.task_id);
        let answer = params.and_then(|p| p.pointer(&format!("/inputResponses/{ASK_KEY}")));
        let accepted = answer
            .filter(|answer| answer.get("action").and_then(Value::as_str) == Some("accept"))
            .and_then(|answer| answer.pointer("/content/reply"))
            .and_then(Value::as_str);
        let Some(reply) = accepted else {
            // Declined, canceled, or no usable answer: the agent's task ends.
            let canceled = self
                .unless_closed(self.client.cancel_task(
                    &self.endpoint,
                    &pending.task_id,
                    extra_headers,
                ))
                .await;
            // Only an answer the agent gave releases the guard; otherwise it
            // asks once more as it drops.
            if matches!(canceled, Ok(Reply::Answer(_))) {
                guard.disarm();
            }
            return Ok(JsonRpcResponse::success(
                id,
                error_result(
                    "the request for input was declined; cancellation of the agent's task was \
                     requested",
                ),
            ));
        };
        let mut message = Message::user_text(reply);
        message.task_id = Some(pending.task_id);
        message.context_id = pending.context_id;
        self.delegate(id, message, extra_headers, identity, &mut guard)
            .await
    }

    /// Send `message` and follow the agent's task to an answer, a question or
    /// the deadline. The caller's `guard` owns the task: armed already when
    /// the message continues a known task, armed as soon as a new task is
    /// named, and dropped with the caller's future if this one is abandoned.
    async fn delegate(
        &self,
        id: RequestId,
        message: Message,
        extra_headers: &[(String, String)],
        identity: Option<&str>,
        guard: &mut CancelGuard,
    ) -> Result<JsonRpcResponse> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        // Before the agent names a new task nothing can cancel it, so a
        // failure here says the remote outcome is not known.
        let sent = self
            .within(
                deadline,
                self.client
                    .send_message(&self.endpoint, message, extra_headers),
            )
            .await
            .map_err(|error| {
                Error::Transport(format!(
                    "{error}; whether the A2A agent started the task is not known"
                ))
            })?;
        let mut task = match sent {
            // A known task is canceled by the guard; a new one was never named.
            None if guard.is_armed() => return Ok(self.timed_out(id)),
            None => {
                return Ok(JsonRpcResponse::success(
                    id,
                    error_result(&format!(
                        "the A2A agent did not answer within the backend timeout ({}s); whether \
                         it started the task is not known",
                        self.timeout.as_secs()
                    )),
                ));
            }
            Some(Reply::AgentError { code, message }) => {
                return Ok(agent_error(id, code, &message));
            }
            Some(Reply::Answer(reply)) => match *reply {
                SendMessageResponse {
                    task: Some(task), ..
                } => task,
                answer => {
                    guard.disarm();
                    return Ok(JsonRpcResponse::success(id, reply_to_result(&answer)));
                }
            },
        };
        let mut wait = FIRST_POLL;
        loop {
            let state = task.status.state;
            if state.is_terminal() {
                guard.disarm();
                return Ok(JsonRpcResponse::success(id, task_to_result(&task)));
            }
            if state.is_interrupted() {
                guard.disarm();
                return Ok(self.ask(id, task, extra_headers, identity));
            }
            guard.arm(&task.id);
            // Sleep no further than the deadline, and bound the poll by it.
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(self.timed_out(id));
            }
            self.unless_closed(async {
                tokio::time::sleep(wait.min(remaining)).await;
                Ok(())
            })
            .await?;
            wait = (wait * 2).min(LONGEST_POLL);
            let polled = self
                .within(
                    deadline,
                    self.client
                        .get_task(&self.endpoint, &task.id, extra_headers),
                )
                .await?;
            task = match polled {
                None => return Ok(self.timed_out(id)),
                Some(Reply::Answer(task)) => task,
                Some(Reply::AgentError { code, message }) => {
                    return Ok(agent_error(id, code, &message));
                }
            };
        }
    }

    /// `call`, unless the transport closes (`Err`) or `deadline` passes first
    /// (`Ok(None)`).
    async fn within<T>(
        &self,
        deadline: tokio::time::Instant,
        call: impl Future<Output = Result<T>>,
    ) -> Result<Option<T>> {
        match tokio::time::timeout_at(deadline, self.unless_closed(call)).await {
            Ok(outcome) => outcome.map(Some),
            Err(_) => Ok(None),
        }
    }

    /// The answer when the deadline passes. The caller's guard, still armed,
    /// requests the task's cancellation as it drops.
    fn timed_out(&self, id: RequestId) -> JsonRpcResponse {
        JsonRpcResponse::success(
            id,
            error_result(&format!(
                "the A2A agent did not finish within the backend timeout ({}s); cancellation of \
                 its task was requested",
                self.timeout.as_secs()
            )),
        )
    }

    /// The agent's question as an MCP input round. Its task is parked under an
    /// opaque token only this caller can redeem.
    fn ask(
        &self,
        id: RequestId,
        task: Task,
        extra_headers: &[(String, String)],
        identity: Option<&str>,
    ) -> JsonRpcResponse {
        let mut question = status_text(task.status.message.as_ref());
        if task.status.state == TaskState::AuthRequired {
            question = format!("The agent needs authorization: {question}");
        }
        let token = match self.parked.park(
            task.id.clone(),
            task.context_id.clone(),
            identity,
            extra_headers.to_vec(),
            std::time::Instant::now(),
            self.canceller.hold(),
        ) {
            Ok(token) => token,
            Err(refused) => {
                self.canceller.spawn(task.id, extra_headers.to_vec());
                let why = match refused {
                    ParkRefused::Full => "too many unanswered agent questions",
                    ParkRefused::Closed => "the A2A backend is closing",
                };
                return JsonRpcResponse::success(
                    id,
                    error_result(&format!(
                        "{why}; cancellation of the agent's task was requested"
                    )),
                );
            }
        };
        JsonRpcResponse::success(
            id,
            json!({
                "resultType": "input_required",
                "inputRequests": {
                    ASK_KEY: {
                        "method": "elicitation/create",
                        "params": {
                            "message": question,
                            "requestedSchema": {
                                "type": "object",
                                "properties": {"reply": {"type": "string"}},
                                "required": ["reply"],
                            },
                        },
                    },
                },
                "requestState": token,
            }),
        )
    }
}

/// The agent's own JSON-RPC error, passed on as the agent's.
fn agent_error(id: RequestId, code: i32, message: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(Some(id), code, format!("A2A agent error: {message}"))
}

#[async_trait]
impl Transport for A2aTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse> {
        self.dispatch(method, params, &[], None).await
    }

    /// Per-request headers (a propagated end-user credential) go on this one
    /// request and are never stored: tenant isolation (IDP.3).
    async fn request_with_headers(
        &self,
        method: &str,
        params: Option<Value>,
        extra_headers: &[(String, String)],
        identity_key: Option<&str>,
        _resend: crate::transport::ResendPermission,
    ) -> Result<JsonRpcResponse> {
        self.dispatch(method, params, extra_headers, identity_key)
            .await
    }

    fn carries_identity_headers(&self) -> bool {
        true
    }

    /// A2A has no notification channel.
    async fn notify(&self, _method: &str, _params: Option<Value>) -> Result<()> {
        Ok(())
    }

    fn is_connected(&self) -> bool {
        !*self.closed.borrow()
    }

    async fn close(&self) -> Result<()> {
        self.closed.send_replace(true);
        // Closed under the map's lock: a call parking concurrently either
        // lands before this drain or is refused and cancels its own task.
        for pending in self.parked.close() {
            self.cancel(pending);
        }
        // The cancels are sent before `close` returns, so a shutdown that
        // follows does not abort them; bounded below the lifecycle's close
        // stage.
        self.canceller.settle(CLOSE_SETTLE).await;
        Ok(())
    }
}

impl Drop for A2aTransport {
    /// A transport dropped without `close` (a failed start, a replaced
    /// backend) still cancels the tasks of its waiting questions.
    fn drop(&mut self) {
        for pending in self.parked.close() {
            self.cancel(pending);
        }
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
