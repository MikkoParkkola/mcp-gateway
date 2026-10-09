// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

fn note(method: &str) -> JsonRpcNotification {
    JsonRpcNotification {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params: None,
    }
}

/// Raise `info` through `emit_log` under `declared`, returning how often
/// the payload was built and what was delivered.
async fn emit_info(declared: Option<&str>) -> (usize, Vec<JsonRpcNotification>) {
    let built = std::cell::Cell::new(0);
    let ((), delivered) = collect(None, async {
        set_request_log_level(declared);
        emit_log(LoggingLevel::Info, "gateway.invoke", || {
            built.set(built.get() + 1);
            json!({ "message": "tool invoked" })
        });
    })
    .await;
    (built.get(), delivered)
}

/// L1: outside a request scope nothing can be delivered, so nothing is built.
#[test]
fn emit_log_outside_a_scope_never_builds_the_payload() {
    let mut built = false;
    emit_log(LoggingLevel::Error, "gateway.invoke", || {
        built = true;
        Value::Null
    });
    assert!(!built);
}

/// L2 and L3: silence, and a level above the raised one, both skip the build.
#[tokio::test]
async fn emit_log_builds_nothing_the_filter_would_drop() {
    for declared in [None, Some("error")] {
        let (built, delivered) = emit_info(declared).await;
        assert_eq!(built, 0, "declared {declared:?}");
        assert!(delivered.is_empty(), "declared {declared:?}");
    }
}

/// L4 and L5: at or below the raised level, the payload is built once and
/// delivered; `debug` pins the comparison as `>=`, not equality.
#[tokio::test]
async fn emit_log_builds_and_delivers_at_or_below_the_raised_level() {
    for declared in ["info", "debug"] {
        let (built, delivered) = emit_info(Some(declared)).await;
        assert_eq!(built, 1, "declared {declared}");
        assert_eq!(delivered.len(), 1, "declared {declared}");
        assert_eq!(
            delivered[0].params.as_ref().unwrap()["data"]["message"],
            "tool invoked"
        );
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

    let ((), delivered) = collect(None, async {
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
    let ((), delivered) = collect(None, async {
        set_request_log_level(Some("debug"));
        publish(vec![JsonRpcNotification {
            params: Some(json!({ "level": "error", "data": "first" })),
            ..note("notifications/message")
        }]);
        set_request_log_level(None);
        publish(vec![JsonRpcNotification {
            params: Some(json!({ "level": "error", "data": "second" })),
            ..note("notifications/message")
        }]);
    })
    .await;

    // Both halves are asserted by one vector: an empty one would mean the
    // declaration never wrote, and a two-element one would mean the absence
    // did not clear it.
    assert_eq!(
        delivered
            .iter()
            .map(|n| n
                .params
                .as_ref()
                .map_or("-", |p| p["data"].as_str().unwrap_or("-")))
            .collect::<Vec<_>>(),
        vec!["first"],
        "the first item declared `debug` so its message passes; the second declared \
         nothing, so nothing it produced may: {delivered:?}"
    );
}

/// A serialised observation of the process-wide `DROPPED` counter.
///
/// `DROPPED` is global -- it is an operator-facing total, not a per-request
/// one -- so the rows that read it cannot observe it concurrently: one
/// reads a baseline, the other floods the sink, and whichever interleaving
/// the harness picks decides whether the baseline is still true when it is
/// asserted against. The rows take turns rather than the counter being made
/// per-scope.
///
/// Taking the lock and reading the baseline are one step here rather than
/// two lines a row has to remember in the right order. The guard is held
/// across the scope's awaits, so the lock has to be the async one, and it
/// lives for as long as the observation does.
///
/// This makes the correct pattern the easy one, not the only one: `DROPPED`
/// is still in scope for this module, so a row that loads it directly is
/// still a row that races. What it removes is the silent half-use -- a
/// baseline without the lock, or a lock without a baseline.
struct DropCounter {
    _serialised: tokio::sync::MutexGuard<'static, ()>,
    before: u64,
}

impl DropCounter {
    /// Start observing: take the turn, then read the baseline under it.
    async fn observe() -> Self {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        let serialised = LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        Self {
            _serialised: serialised,
            before: DROPPED.load(Ordering::Relaxed),
        }
    }

    /// How many notifications the sink has shed since the observation began.
    fn shed(&self) -> u64 {
        DROPPED.load(Ordering::Relaxed) - self.before
    }
}

/// Overflow and policy are different facts about a request. A message the
/// filter drops must not read as sink pressure on a 64-deep channel.
#[tokio::test]
async fn a_policy_drop_is_not_counted_as_an_overflow() {
    let dropped = DropCounter::observe().await;

    let ((), delivered) = collect(None, async {
        publish(vec![JsonRpcNotification {
            params: Some(json!({ "level": "error" })),
            ..note("notifications/message")
        }]);
    })
    .await;

    assert!(delivered.is_empty(), "no level was declared, so: silence");
    assert_eq!(dropped.shed(), 0, "a policy drop is not sink pressure");
}

/// S-03 in miniature: the isolation is structural, so two concurrent
/// scopes cannot see each other's notifications even under the same
/// progress token.
#[tokio::test]
async fn concurrent_scopes_do_not_cross() {
    let left = collect(None, async {
        publish(vec![note("left")]);
        tokio::task::yield_now().await;
    });
    let right = collect(None, async {
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
    let (scoped, mut rx) = scope(None, async move {
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
    let dropped = DropCounter::observe().await;
    let ((), drained) = collect(None, async {
        publish(
            (0..REQUEST_NOTIFICATION_DEPTH + 8)
                .map(|_| note("flood"))
                .collect(),
        );
    })
    .await;

    assert_eq!(drained.len(), REQUEST_NOTIFICATION_DEPTH);
    assert_eq!(dropped.shed(), 8);
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
    let ((), drained) = collect(None, async {
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
    let ((), drained) = collect(None, async {
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
    let ((), drained) = collect(None, async {
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
    let ((), drained) = collect(None, async {
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
