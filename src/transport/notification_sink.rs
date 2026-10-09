// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Request-scoped sink for a backend's notifications (`MIK-7272.SUB.2b`).
//!
//! A task-local rather than a registry keyed by progress token, for two
//! reasons. The invocation funnel between the router and the transport cannot
//! be widened -- `Transport::request` returns a bare `JsonRpcResponse` -- and no
//! channel exists from `AppState` down to a live transport: the `attach_era`
//! collaborator is built per backend inside the lifecycle, not threaded from
//! the gateway.
//!
//! The task-local also *is* the request scoping: two concurrent POSTs are two
//! tasks, so a notification can only ever be appended to the sink of the call
//! that provoked it. Nothing propagates across `tokio::spawn`, and nothing
//! between the router and the per-call transport code spawns.
//!
//! The payload is a **bounded channel, not a buffer** (ADR-014 §1). A `Vec`
//! drained after the future resolves preserves wire ordering but cannot
//! deliver a notification while the call that raised it is still in flight,
//! which is the whole requirement. [`scope`] therefore hands the receiving end
//! back to the caller so a consumer can drain it *concurrently* with the
//! request.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tokio::sync::mpsc;

use std::sync::Arc;

use crate::gateway::outbound::{OutboundFrame, StreamJudge};
use crate::protocol::{JsonRpcNotification, LoggingLevel};

/// Notifications one in-flight request may have outstanding before the sink
/// starts shedding them (ADR-014 §5 overflow policy).
const REQUEST_NOTIFICATION_DEPTH: usize = 64;

tokio::task_local! {
    static SINK: Sink;
    /// Minted-to-caller progress tokens for the requests this scope issued.
    ///
    /// A `Vec` rather than a single slot: one client request may dispatch
    /// several backend calls -- a JSON-RPC batch, or a meta-tool that fans out
    /// -- and each gets its own mint. Lookup is linear over a list whose length
    /// is the number of progress-bearing calls in one request.
    static TRANSLATIONS: RefCell<Vec<(String, Value)>>;
    /// The minimum severity this request asked to be told about (ADR-014 §4).
    ///
    /// `None` -- the seeded value -- is not "everything": it is *silence*. A
    /// request that declared no level gets no `notifications/message` at all,
    /// whoever raised them. Set once per request from the `_meta` key, after
    /// the body has been classified.
    static LEVEL: RefCell<Option<LoggingLevel>>;
}

/// The content screen a scope's notifications pass before they are queued:
/// a backend's mid-call text meets the response firewall as an answer does
/// (MIK-8161). The gateway supplies it; this layer only calls it.
pub(crate) trait NotificationScreen: Send + Sync {
    /// Screen `notification` in place; `false` withholds it.
    fn admit(&self, notification: &mut JsonRpcNotification) -> bool;

    /// Label later verdicts with the caller and session the dispatch has
    /// since authenticated (a scope opens before it knows them).
    fn bind(&self, _caller: &str, _session_id: &str) {}
}

/// A scope's screen. `None` only where nothing reaches a client (a test, or
/// a site that discards what it collects): every scope constructor takes one,
/// so no route opens a sink without deciding.
pub(crate) type Screen = Option<Arc<dyn NotificationScreen>>;

/// Where a scope's notifications go, and the screen they pass first.
#[derive(Clone)]
struct Sink {
    out: Out,
    screen: Screen,
}

/// `Raw` hands notifications on unjudged: tests, stdio, and the `Discard`
/// sites that drop them unread. `Judged` is a POST stream that writes them to
/// a caller, so each is judged here, at the one funnel, before it is queued
/// (`MIK-7116.MIN.2`, design §4.3).
#[derive(Clone)]
enum Out {
    Raw(mpsc::Sender<JsonRpcNotification>),
    Judged(mpsc::Sender<OutboundFrame>, Arc<StreamJudge>),
}

/// Notifications dropped because a request's sink was full. Monotonic for the
/// life of the process; overflow is a symptom worth seeing in aggregate.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Install a fresh sink around `fut` and hand back its receiving end.
///
/// The returned future owns the sending end, so the receiver observes close
/// exactly when the request finishes. Drain the receiver concurrently with
/// polling the future -- that concurrency is what makes a notification
/// reachable while its call is still running.
pub(crate) fn scope<F: Future>(
    screen: Screen,
    fut: F,
) -> (
    impl Future<Output = F::Output>,
    mpsc::Receiver<JsonRpcNotification>,
) {
    let (tx, rx) = mpsc::channel(REQUEST_NOTIFICATION_DEPTH);
    (
        scoped(
            Sink {
                out: Out::Raw(tx),
                screen,
            },
            fut,
        ),
        rx,
    )
}

/// [`scope`] for a stream that writes to a caller: every notification is
/// judged by `judge` as it is queued, and the receiver yields judged frames.
pub(crate) fn scope_judged<F: Future>(
    screen: Screen,
    fut: F,
    judge: Arc<StreamJudge>,
) -> (
    impl Future<Output = F::Output>,
    mpsc::Receiver<OutboundFrame>,
) {
    let (tx, rx) = mpsc::channel(REQUEST_NOTIFICATION_DEPTH);
    (
        scoped(
            Sink {
                out: Out::Judged(tx, judge),
                screen,
            },
            fut,
        ),
        rx,
    )
}

fn scoped<F: Future>(sink: Sink, fut: F) -> impl Future<Output = F::Output> {
    LEVEL.scope(
        RefCell::new(None),
        TRANSLATIONS.scope(RefCell::new(Vec::new()), SINK.scope(sink, fut)),
    )
}

/// Bind the caller this request's stream writes to, once the dispatch knows
/// who is asking. A no-op outside a judged scope.
pub(crate) fn bind_reader(key: impl FnOnce() -> String) {
    let _ = SINK.try_with(|sink| {
        if let Out::Judged(_, judge) = &sink.out
            && judge.judges()
        {
            judge.bind(key());
        }
    });
}

/// Bind this request's screen to the caller and session the dispatch
/// authenticated, once it knows them. A no-op outside a screened scope.
pub(crate) fn bind_screen(caller: &str, session_id: &str) {
    let _ = SINK.try_with(|sink| {
        if let Some(screen) = &sink.screen {
            screen.bind(caller, session_id);
        }
    });
}

/// Run `fut` under a sink, draining alongside it, and yield its output with
/// everything the backend published while it ran.
///
/// The drain runs concurrently rather than after, so this is a convenience
/// over [`scope`] for callers that have nowhere to stream to -- not a return
/// to collect-then-emit.
pub(crate) async fn collect<F: Future>(
    screen: Screen,
    fut: F,
) -> (F::Output, Vec<JsonRpcNotification>) {
    let (scoped, mut rx) = scope(screen, fut);
    let mut drained = Vec::new();
    tokio::pin!(scoped);
    let out = loop {
        tokio::select! {
            Some(notification) = rx.recv() => drained.push(notification),
            out = &mut scoped => break out,
        }
    };
    while let Ok(notification) = rx.try_recv() {
        drained.push(notification);
    }
    (out, drained)
}

/// Publish notifications to the in-flight request's sink. A no-op outside one,
/// which covers every backend call that did not arrive on `POST /mcp` --
/// health probes, warm-up handshakes and the reaper all run outside a scope.
///
/// Never blocks and never awaits: a full sink drops and counts, because
/// stalling a backend response to buffer a progress update inverts the
/// priority the notification exists to serve.
pub(crate) fn publish(notifications: Vec<JsonRpcNotification>) {
    if notifications.is_empty() {
        return;
    }
    let _ = SINK.try_with(|tx| {
        for mut notification in notifications {
            if !passes_level_filter(&notification) {
                continue;
            }
            // Screened as the backend sent it, before the caller's own token
            // is put back: the screen judges backend text, not the caller's.
            if !admitted(tx, &mut notification) {
                continue;
            }
            translate_back(&mut notification);
            send_or_count(tx, notification);
        }
    });
}

/// Hand one notification to a sink, counting it against the overflow total if
/// the sink is full.
///
/// Both delivery paths route through here -- the batched `publish` and the
/// streaming `DeliveryHandle` -- so a drop is counted the same way whichever
/// one shed it. Two copies of this accounting is how one path's overflow
/// becomes invisible in the number the other path maintains.
fn send_or_count(sink: &Sink, notification: JsonRpcNotification) {
    let sent = match &sink.out {
        Out::Raw(tx) => tx.try_send(notification).is_ok(),
        // A withheld notification is not queued; its rejection is audited.
        Out::Judged(tx, judge) => judge
            .judge(notification)
            .is_none_or(|frame| tx.try_send(frame).is_ok()),
    };
    if !sent {
        let total = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::warn!(
            dropped_total = total,
            capacity = REQUEST_NOTIFICATION_DEPTH,
            "request notification sink full; dropping notification"
        );
    }
}

/// Whether `sink`'s screen admits `notification` (a screened-out one is
/// withheld, not shed: it is not counted as overflow).
fn admitted(sink: &Sink, notification: &mut JsonRpcNotification) -> bool {
    sink.screen
        .as_ref()
        .is_none_or(|screen| screen.admit(notification))
}

/// Where one in-flight request's notifications go, in a form that survives
/// leaving the task that owns them.
///
/// `publish` reaches the caller through task-locals, which is enough when the
/// payload is carried back to the caller's own task. It is not enough when the
/// frame must be delivered the moment it is read -- the reader task of a
/// subprocess backend has neither task-local in scope, so publishing there
/// silently drops. Capturing both halves on the caller's task and carrying
/// them to the reader is what makes a mid-call notification reachable.
///
/// Both halves are load-bearing. The sender is where the frame goes; the
/// caller's own progress token is what the frame must carry, because
/// `translate_back` resolves that from `TRANSLATIONS` -- the very task-local
/// this handle exists to escape. A handle carrying only a sender arrives on
/// time with the wrong token on it, and a caller correlating on its own token
/// sees nothing (ADR-014 §2).
#[derive(Clone)]
pub(crate) struct DeliveryHandle {
    sink: Option<Sink>,
    client_token: Option<Value>,
}

impl DeliveryHandle {
    /// Snapshot this task's sink and the caller token `minted` maps to.
    ///
    /// Call it on the caller's task. Anywhere else both halves come back
    /// `None`, and the handle still registers: the notification is then
    /// recognised as owned and dropped deliberately rather than logged as a
    /// stray from nowhere.
    pub(crate) fn capture(minted: &str) -> Self {
        Self {
            sink: SINK.try_with(Clone::clone).ok(),
            client_token: TRANSLATIONS
                .try_with(|cell| {
                    cell.borrow()
                        .iter()
                        .find(|(m, _)| m == minted)
                        .map(|(_, client)| client.clone())
                })
                .ok()
                .flatten(),
        }
    }

    /// Deliver one notification now, restoring the caller's token first.
    ///
    /// No level filter: `passes_level_filter` admits every method that is not
    /// `notifications/message`, so a progress frame never meets it and
    /// snapshotting `LEVEL` alongside the sender would be dead weight.
    pub(crate) fn deliver(&self, mut notification: JsonRpcNotification) {
        let Some(sink) = self.sink.as_ref() else {
            return;
        };
        if !admitted(sink, &mut notification) {
            return;
        }
        if let Some(client) = self.client_token.clone()
            && notification.method == "notifications/progress"
            && let Some(Value::Object(params)) = notification.params.as_mut()
        {
            params.insert("progressToken".to_string(), client);
        }
        send_or_count(sink, notification);
    }
}

/// Record the minimum severity this request declared (ADR-014 §4).
///
/// Called once per request, from the point where the body has been classified
/// -- both transports classify, so both call it and neither gets a second
/// policy. An unparseable declaration is treated as *absent* rather than
/// refused: the field is optional and §4 already gives absence a defined
/// meaning, so a typo silences this request's messages instead of failing a
/// tool call that has nothing to do with logging.
///
/// Absence overwrites. A stdio JSON-RPC batch dispatches every item inside one
/// scope, so the slot outlives the item that set it; leaving it untouched would
/// hand an item that declared nothing the level its predecessor declared. The
/// case §4's absence-is-silence stops holding for is exactly that one -- an
/// undeclared item following a declared one -- not every item after the first.
///
/// A no-op outside a request scope, which is every backend call with no client
/// behind it.
pub(crate) fn set_request_log_level(declared: Option<&str>) {
    let parsed = declared.and_then(|declared| {
        let parsed =
            serde_json::from_value::<LoggingLevel>(Value::String(declared.to_owned())).ok();
        if parsed.is_none() {
            tracing::debug!(
                declared,
                "request declared an unknown log level; treating it as undeclared"
            );
        }
        parsed
    });
    let _ = LEVEL.try_with(|slot| *slot.borrow_mut() = parsed);
}

/// Raise a gateway-generated `notifications/message` on the in-flight
/// request's stream (ADR-014 §3).
///
/// Per-site and additive: the caller keeps its `tracing` line, because the two
/// have different audiences -- the operator's log records every request, this
/// records only the one the caller asked to be told about. There is
/// deliberately no `tracing_subscriber::Layer` behind it; a layer would have to
/// reconstruct the request scope from a span, and §3 rejects that.
///
/// The payload is MCP's own logging shape: `level`, `logger`, `data`.
///
/// `data` is built only when the request declared a level at or below `level`:
/// most callers declare none, and building a notification `publish` would drop
/// cost every `tools/call` (NFR.WORKLOAD.1). `publish` still applies the full
/// filter; this check can only skip what it would drop.
pub(crate) fn emit_log(level: LoggingLevel, logger: &str, data: impl FnOnce() -> Value) {
    if !declared_level_admits(level) {
        return;
    }
    publish(vec![JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/message".to_string(),
        params: Some(json!({ "level": level, "logger": logger, "data": data() })),
    }]);
}

/// One filter, both producers (ADR-014 §4): a relayed `notifications/message`
/// and one the gateway raised itself are judged by the same rule, because a
/// caller that asked for `error` does not care which side of the gateway a
/// `debug` line came from.
///
/// `notifications/progress` is never filtered -- it carries no level, so there
/// is nothing to judge it against.
///
/// Fails closed twice over: no declared level drops, and a message whose own
/// level cannot be parsed drops too. Waving through a message that cannot be
/// measured against the policy the caller asked for is the one outcome the
/// policy exists to prevent.
fn passes_level_filter(notification: &JsonRpcNotification) -> bool {
    if notification.method != "notifications/message" {
        return true;
    }
    // Checked before parsing: most requests declare nothing, and silence
    // needs no parse.
    if !LEVEL
        .try_with(|slot| slot.borrow().is_some())
        .unwrap_or(false)
    {
        return false;
    }
    let raised = notification
        .params
        .as_ref()
        .and_then(|params| params.get("level"))
        .and_then(|level| serde_json::from_value::<LoggingLevel>(level.clone()).ok());
    let Some(raised) = raised else {
        tracing::debug!("notifications/message carries no level this request can judge; dropping");
        return false;
    };
    declared_level_admits(raised)
}

/// The delivery rule for one `raised` level, shared by `publish`'s filter and
/// `emit_log`'s early return so the two cannot disagree: no declared level is
/// silence, otherwise `raised >= declared`.
fn declared_level_admits(raised: LoggingLevel) -> bool {
    LEVEL
        .try_with(|slot| slot.borrow().is_some_and(|declared| raised >= declared))
        .unwrap_or(false)
}

/// Substitute a gateway-owned progress token for the caller's, recording the
/// pair so [`translate_back`] can restore it on the way out.
///
/// `None` outside a request scope, which is the whole of the pass-through
/// policy: health probes, warm-up handshakes and the reaper dispatch backend
/// calls with no client behind them, and their `_meta` must travel unchanged.
///
/// The mint is `gw-<uuid>`: a `String` by construction, so it can never alias
/// a numeric caller token, collide with a concurrent call's token, or be
/// reused by a later one (ADR-014 section 2 records all three as defects of
/// keying on the caller's value).
pub(crate) fn mint_progress_token(client: &Value) -> Option<String> {
    TRANSLATIONS
        .try_with(|cell| {
            let minted = format!("gw-{}", uuid::Uuid::new_v4());
            cell.borrow_mut().push((minted.clone(), client.clone()));
            minted
        })
        .ok()
}

/// Restore the caller's own progress token on a notification travelling back.
///
/// The caller's token is stored and returned as a `Value`, never a `String`:
/// a client that sent `7` is entitled to see `7`, not `"7"`.
///
/// A notification whose token matches no mint is **forwarded unchanged**. It
/// is not necessarily a leak -- a backend may report progress for work the
/// gateway never minted for -- and dropping it would discard a frame the
/// client is entitled to. The miss is logged so a genuine mint leak is
/// visible in logs rather than only in client behaviour.
pub(crate) fn translate_back(notification: &mut JsonRpcNotification) {
    // Only progress frames carry a token this store can own. Another
    // notification method is free to use a `progressToken` param of its own
    // meaning, and rewriting it -- or logging it as a miss -- would be this
    // gateway reading someone else's field.
    if notification.method != "notifications/progress" {
        return;
    }
    let Some(token) = notification
        .params
        .as_ref()
        .and_then(|p| p.get("progressToken"))
    else {
        return;
    };
    let Some(minted) = token.as_str().map(str::to_string) else {
        // Only a minted token is ever a string of ours; a numeric token on the
        // wire cannot have come from this gateway. Owned so the read of
        // `params` ends before the write below.
        return;
    };

    let client = TRANSLATIONS
        .try_with(|cell| {
            cell.borrow()
                .iter()
                .find(|(m, _)| *m == minted)
                .map(|(_, client)| client.clone())
        })
        .ok()
        .flatten();

    let Some(client) = client else {
        // ci-allow-secret-log: an MCP progress token is a caller-chosen correlation id, not a credential; the value is what makes the miss attributable
        tracing::debug!(
            method = %notification.method,
            token = %minted,
            "progress notification carries a token this request never minted; forwarding unchanged"
        );
        return;
    };
    if let Some(Value::Object(params)) = notification.params.as_mut() {
        params.insert("progressToken".to_string(), client);
    }
}

#[cfg(test)]
#[path = "notification_sink_tests.rs"]
mod tests;
