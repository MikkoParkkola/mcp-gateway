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

use crate::protocol::{JsonRpcNotification, LoggingLevel};

/// Notifications one in-flight request may have outstanding before the sink
/// starts shedding them (ADR-014 §5 overflow policy).
const REQUEST_NOTIFICATION_DEPTH: usize = 64;

tokio::task_local! {
    static SINK: mpsc::Sender<JsonRpcNotification>;
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
    fut: F,
) -> (
    impl Future<Output = F::Output>,
    mpsc::Receiver<JsonRpcNotification>,
) {
    let (tx, rx) = mpsc::channel(REQUEST_NOTIFICATION_DEPTH);
    (
        LEVEL.scope(
            RefCell::new(None),
            TRANSLATIONS.scope(RefCell::new(Vec::new()), SINK.scope(tx, fut)),
        ),
        rx,
    )
}

/// Run `fut` under a sink, draining alongside it, and yield its output with
/// everything the backend published while it ran.
///
/// The drain runs concurrently rather than after, so this is a convenience
/// over [`scope`] for callers that have nowhere to stream to -- not a return
/// to collect-then-emit.
pub(crate) async fn collect<F: Future>(fut: F) -> (F::Output, Vec<JsonRpcNotification>) {
    let (scoped, mut rx) = scope(fut);
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
            translate_back(&mut notification);
            if tx.try_send(notification).is_err() {
                let total = DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    dropped_total = total,
                    capacity = REQUEST_NOTIFICATION_DEPTH,
                    "request notification sink full; dropping notification"
                );
            }
        }
    });
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
/// hand an item that declared nothing the level its predecessor declared, and
/// §4's absence-is-silence would stop holding for every item after the first.
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
pub(crate) fn emit_log(level: LoggingLevel, logger: &str, data: &Value) {
    publish(vec![JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: "notifications/message".to_string(),
        params: Some(json!({ "level": level, "logger": logger, "data": data })),
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
    let Ok(Some(declared)) = LEVEL.try_with(|slot| *slot.borrow()) else {
        return false;
    };
    let raised = notification
        .params
        .as_ref()
        .and_then(|params| params.get("level"))
        .and_then(|level| serde_json::from_value::<LoggingLevel>(level.clone()).ok());
    let Some(raised) = raised else {
        tracing::debug!("notifications/message carries no level this request can judge; dropping");
        return false;
    };
    raised >= declared
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
mod tests {
    use super::*;

    fn note(method: &str) -> JsonRpcNotification {
        JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: None,
        }
    }

    #[tokio::test]
    async fn publish_outside_a_scope_is_dropped_not_panicked() {
        publish(vec![note("notifications/progress")]);
    }

    /// Everything the level filter has to decide, on one axis: only the method
    /// carrying a level is judged, and only against the level the request
    /// declared.
    #[tokio::test]
    async fn the_level_filter_judges_messages_and_nothing_else() {
        let levelled = |level: &str| JsonRpcNotification {
            params: Some(json!({ "level": level, "data": "x" })),
            ..note("notifications/message")
        };

        let ((), delivered) = collect(async {
            set_request_log_level(Some("notice"));
            publish(vec![
                note("notifications/progress"),
                levelled("debug"),
                levelled("notice"),
                levelled("error"),
                note("notifications/message"),
            ]);
        })
        .await;

        assert_eq!(
            delivered
                .iter()
                .map(|n| n
                    .params
                    .as_ref()
                    .map_or("-", |p| p["level"].as_str().unwrap_or("-")))
                .collect::<Vec<_>>(),
            vec!["-", "notice", "error"],
            "progress passes unjudged, `debug` is below the declared level, and a \
             message carrying no level at all cannot be judged so it does not pass"
        );
    }

    /// A stdio batch dispatches every item inside one scope, so the slot one
    /// item writes is still there for the next. The item that declares nothing
    /// must be silent on its own account, not on its predecessor's.
    #[tokio::test]
    async fn a_second_declaration_of_nothing_clears_the_first() {
        let ((), delivered) = collect(async {
            set_request_log_level(Some("debug"));
            set_request_log_level(None);
            publish(vec![JsonRpcNotification {
                params: Some(json!({ "level": "error", "data": "x" })),
                ..note("notifications/message")
            }]);
        })
        .await;

        assert!(
            delivered.is_empty(),
            "the second item declared no level, so nothing it produced may pass: {delivered:?}"
        );
    }

    /// `DROPPED` is process-wide, so the two rows that read it cannot observe
    /// it concurrently: one reads a baseline, the other floods the sink, and
    /// whichever interleaving the harness picks decides whether the baseline
    /// is still true when it is asserted against. The counter is deliberately
    /// global -- it is an operator-facing total, not a per-request one -- so
    /// the rows take turns rather than the counter being made per-scope. The
    /// guard is held across the scope's awaits, so the lock has to be the
    /// async one.
    async fn drop_counter_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await
    }

    /// Overflow and policy are different facts about a request. A message the
    /// filter drops must not read as sink pressure on a 64-deep channel.
    #[tokio::test]
    async fn a_policy_drop_is_not_counted_as_an_overflow() {
        let _serialised = drop_counter_lock().await;
        let before = DROPPED.load(Ordering::Relaxed);

        let ((), delivered) = collect(async {
            publish(vec![JsonRpcNotification {
                params: Some(json!({ "level": "error" })),
                ..note("notifications/message")
            }]);
        })
        .await;

        assert!(delivered.is_empty(), "no level was declared, so: silence");
        assert_eq!(DROPPED.load(Ordering::Relaxed), before);
    }

    /// S-03 in miniature: the isolation is structural, so two concurrent
    /// scopes cannot see each other's notifications even under the same
    /// progress token.
    #[tokio::test]
    async fn concurrent_scopes_do_not_cross() {
        let left = collect(async {
            publish(vec![note("left")]);
            tokio::task::yield_now().await;
        });
        let right = collect(async {
            publish(vec![note("right")]);
            tokio::task::yield_now().await;
        });
        let ((), l) = tokio::spawn(left).await.unwrap();
        let ((), r) = tokio::spawn(right).await.unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].method, "left");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].method, "right");
    }

    /// The liveness property the `Vec` payload could not offer: a notification
    /// is readable while the future that raised it is still pending.
    #[tokio::test]
    async fn a_notification_is_readable_before_its_request_finishes() {
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let backend_gate = std::sync::Arc::clone(&gate);
        let (scoped, mut rx) = scope(async move {
            publish(vec![note("notifications/progress")]);
            let _permit = backend_gate.acquire().await.unwrap();
            "result"
        });
        tokio::pin!(scoped);

        let early = tokio::select! {
            received = rx.recv() => received,
            _ = &mut scoped => panic!("the request resolved before the gate was released"),
        };

        assert_eq!(early.unwrap().method, "notifications/progress");
        gate.add_permits(1);
        assert_eq!(scoped.await, "result");
    }

    /// ADR-014 §5: past capacity the sink sheds rather than stalling the call.
    #[tokio::test]
    async fn an_overfull_sink_drops_and_counts_instead_of_blocking() {
        let _serialised = drop_counter_lock().await;
        let before = DROPPED.load(Ordering::Relaxed);
        let ((), drained) = collect(async {
            publish(
                (0..REQUEST_NOTIFICATION_DEPTH + 8)
                    .map(|_| note("flood"))
                    .collect(),
            );
        })
        .await;

        assert_eq!(drained.len(), REQUEST_NOTIFICATION_DEPTH);
        assert_eq!(DROPPED.load(Ordering::Relaxed) - before, 8);
    }

    fn progress(token: &Value) -> JsonRpcNotification {
        JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "notifications/progress".to_string(),
            params: Some(serde_json::json!({ "progressToken": token, "progress": 1 })),
        }
    }

    fn token_of(notification: &JsonRpcNotification) -> Value {
        notification.params.as_ref().unwrap()["progressToken"].clone()
    }

    /// A `progressToken` on another method belongs to that method. Even a
    /// value this store would match is left alone, so the gate is asserted
    /// with a real mint rather than a stranger's string.
    #[tokio::test]
    async fn a_token_on_another_notification_method_is_not_rewritten() {
        let ((), drained) = collect(async {
            // The level filter is not the subject of this row -- translation
            // is -- so the request declares a level and the frame carries one,
            // and the only thing left to fail is the rewrite.
            set_request_log_level(Some("debug"));
            let minted = mint_progress_token(&serde_json::json!(7)).expect("inside a scope");
            let mut other = progress(&Value::String(minted.clone()));
            other.method = "notifications/message".to_string();
            if let Some(Value::Object(params)) = other.params.as_mut() {
                params.insert("level".to_string(), json!("info"));
            }
            publish(vec![other]);
        })
        .await;

        assert_eq!(drained.len(), 1);
        assert!(
            token_of(&drained[0]).as_str().unwrap().starts_with("gw-"),
            "a non-progress notification was translated: {:?}",
            token_of(&drained[0])
        );
    }

    /// Every backend call that did not arrive on `POST /mcp` runs outside a
    /// scope, and must hand the backend the caller's `_meta` untouched.
    #[tokio::test]
    async fn mint_outside_a_scope_is_none() {
        assert_eq!(mint_progress_token(&serde_json::json!("tok")), None);
    }

    /// The reason the store holds a `Value` and not a `String`: a client that
    /// sent the JSON number `7` must not get the string `"7"` back.
    #[tokio::test]
    async fn a_numeric_caller_token_comes_back_numeric() {
        let ((), drained) = collect(async {
            let minted = mint_progress_token(&serde_json::json!(7)).expect("inside a scope");
            assert!(minted.starts_with("gw-"), "mint was {minted}");
            publish(vec![progress(&Value::String(minted))]);
        })
        .await;

        assert_eq!(drained.len(), 1);
        assert_eq!(token_of(&drained[0]), serde_json::json!(7));
    }

    /// A backend may report progress for work this gateway never minted for.
    /// That frame is the client's to see, so a miss forwards rather than drops.
    #[tokio::test]
    async fn an_unminted_token_is_forwarded_unchanged() {
        let ((), drained) = collect(async {
            publish(vec![progress(&serde_json::json!("gw-not-ours"))]);
        })
        .await;

        assert_eq!(drained.len(), 1);
        assert_eq!(token_of(&drained[0]), serde_json::json!("gw-not-ours"));
    }

    /// One client request can dispatch several backend calls, so a scope holds
    /// a list of mints rather than a single slot -- and each notification must
    /// find its own caller's token.
    #[tokio::test]
    async fn two_mints_in_one_scope_each_translate_to_their_own_caller() {
        let ((), drained) = collect(async {
            let first = mint_progress_token(&serde_json::json!(7)).expect("inside a scope");
            let second = mint_progress_token(&serde_json::json!("seven")).expect("inside a scope");
            assert_ne!(first, second, "two calls must not share a mint");
            publish(vec![
                progress(&Value::String(second)),
                progress(&Value::String(first)),
            ]);
        })
        .await;

        assert_eq!(drained.len(), 2);
        assert_eq!(token_of(&drained[0]), serde_json::json!("seven"));
        assert_eq!(token_of(&drained[1]), serde_json::json!(7));
    }
}
