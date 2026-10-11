// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A sealed question's in-flight slot, owned by the copies of its answer
//! (MIK-8176, family continuation-slot-release).
//!
//! Every mint registers a hold in the request scope its route opened at its
//! outermost boundary. The answer that becomes an HTTP response carries the
//! holds whose envelope it contains ([`carried`]), and the JSON reply hands
//! them off once its delivery record is written ([`hand_off`]). A hold whose
//! last copy goes without ever being handed off gives its slot back.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tracing::warn;

use crate::protocol::continuation::ContinuationState;

/// One minted slot, shared (behind an `Arc`) by every copy of the answer
/// that carries it. The slot's fate follows its last clone.
pub(crate) struct SealedHold {
    continuation: Arc<ContinuationState>,
    hold_key: String,
    /// The envelope the mint sealed, so a carrier can be recognised.
    envelope: String,
    /// Set once any copy reaches a transport; the slot then lives until
    /// redeemed or expired.
    handed_off: AtomicBool,
}

impl Drop for SealedHold {
    fn drop(&mut self) {
        if self.handed_off.load(Ordering::Acquire) {
            return;
        }
        self.continuation
            .hold_counts()
            .unhanded_drops
            .fetch_add(1, Ordering::Relaxed);
        release(&self.continuation, &self.hold_key);
    }
}

/// Give `key`'s slot back without awaiting: in place when the table is free,
/// else on the runtime, else (no runtime) at expiry. Never panics.
fn release(continuation: &Arc<ContinuationState>, key: &str) {
    if continuation.in_flight().try_complete(key).is_some() {
        return;
    }
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let (continuation, key) = (Arc::clone(continuation), key.to_owned());
        runtime.spawn(async move {
            // Retention: completing only frees the slot, so a clock before
            // 1970 dates nothing here (MIK-8202).
            let now = crate::clock::unix_secs().unwrap_or(0);
            continuation.in_flight().complete(&key, now).await;
        });
    }
}

/// The holds minted while one request is served.
struct Holds {
    held: Mutex<Vec<Arc<SealedHold>>>,
}

tokio::task_local! {
    /// The open request's holds, owned by the outermost opener.
    static HOLDS: Arc<Holds>;
}

/// Run `future` inside a request scope, collecting the holds its mints take.
/// Inside an open scope this adds nothing: the outermost boundary owns them.
pub(crate) async fn scoped<F: Future>(future: F) -> F::Output {
    if HOLDS.try_with(|_| ()).is_ok() {
        return future.await;
    }
    let holds = Arc::new(Holds {
        held: Mutex::default(),
    });
    HOLDS.scope(holds, future).await
}

/// Register the slot `hold_key` a mint took from `continuation` and sealed
/// into `envelope`.
///
/// A mint with no open scope registers nothing, so nothing can release its
/// slot early: it waits for expiry, as every slot did before. Counted and
/// warned; the slot-release matrix asserts no route's cell mints unscoped,
/// so a route or a spawn that drops the scope fails CI there.
pub(crate) fn register(continuation: &Arc<ContinuationState>, hold_key: &str, envelope: &str) {
    let counts = continuation.hold_counts();
    let scoped = HOLDS
        .try_with(|holds| {
            let hold = Arc::new(SealedHold {
                continuation: Arc::clone(continuation),
                hold_key: hold_key.to_owned(),
                envelope: envelope.to_owned(),
                handed_off: AtomicBool::new(false),
            });
            holds
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(hold);
        })
        .is_ok();
    if scoped {
        counts.registered.fetch_add(1, Ordering::Relaxed);
    } else {
        counts.unscoped.fetch_add(1, Ordering::Relaxed);
        // Exported, so a production route that misses its scope shows to the
        // operator: nonzero means some slots only ever expire.
        telemetry_metrics::counter!("mcp_continuation_unscoped_mint_total").increment(1);
        warn!("A continuation slot was minted outside any request scope");
    }
}

/// The holds an HTTP answer carries: a response extension, handed off by the
/// JSON reply once its delivery record is written. A replacer that builds a
/// new response drops it, so those holds release with their scope.
#[derive(Clone, Default)]
pub(crate) struct CarriedHolds(Vec<Arc<SealedHold>>);

impl CarriedHolds {
    /// No holds: a frame that carries no sealed question.
    pub(crate) const fn none() -> Self {
        Self(Vec::new())
    }
}

impl std::fmt::Debug for CarriedHolds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CarriedHolds({})", self.0.len())
    }
}

/// The open scope's holds whose envelope `answer` carries: anywhere in a
/// string (an envelope text-wrapped by `gateway_invoke`), or as a top-level
/// `requestState` that opens to the same slot (a chain's re-seal).
pub(crate) fn carried(answer: &Value) -> CarriedHolds {
    let held = HOLDS
        .try_with(|holds| {
            holds
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
        .unwrap_or_default();
    if held.is_empty() {
        return CarriedHolds::default();
    }
    carried_from(&CarriedHolds(held), answer)
}

/// The holds in `holds` whose envelope `value` still carries: the same test
/// `carried` applies to the open scope, applied to holds a retained copy owns
/// (a stored result re-filtered against what the store actually committed).
pub(crate) fn carried_from(holds: &CarriedHolds, value: &Value) -> CarriedHolds {
    let reseal = value.get("requestState").and_then(Value::as_str);
    CarriedHolds(
        holds
            .0
            .iter()
            .filter(|hold| contains(value, &hold.envelope) || reopens(hold, reseal))
            .cloned()
            .collect(),
    )
}

/// Whether any string in `value` contains `needle`.
fn contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(items) => items.iter().any(|item| contains(item, needle)),
        Value::Object(fields) => fields.values().any(|field| contains(field, needle)),
        _ => false,
    }
}

/// Whether `token` opens, under `hold`'s keyring, to `hold`'s own slot.
/// On a clock before 1970 nothing can be opened, so any resealed token keeps
/// the hold: a hold only reserves its slot until it expires, while dropping
/// it would free a slot the answer may still carry (MIK-8202).
fn reopens(hold: &SealedHold, token: Option<&str>) -> bool {
    let Ok(now) = crate::clock::unix_secs() else {
        return token.is_some();
    };
    token.is_some_and(|token| {
        hold.continuation
            .keyring()
            .open(token, now)
            .is_ok_and(|payload| payload.hold_key == hold.hold_key)
    })
}

/// Put a retained copy's holds into the open scope, so the reader's route
/// treats them as its own mints: `carried` finds them in the answer it builds
/// and its transport hands them off. Outside a scope this drops the reader's
/// clones only; the retained copy's own clones keep the slot.
pub(crate) fn adopt(holds: CarriedHolds) {
    let _ = HOLDS.try_with(|scope| {
        scope
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend(holds.0);
    });
}

/// Hand `holds` off to the transport: their slots now live until redeemed or
/// expired. The one place a hold is disarmed.
pub(crate) fn hand_off(holds: &CarriedHolds) {
    for hold in &holds.0 {
        hold.handed_off.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;
    use serde_json::json;

    use super::{
        Arc, CarriedHolds, ContinuationState, Ordering, carried, hand_off, register, scoped,
    };

    /// Registered, unscoped and dropped-without-handoff counts.
    fn counts(continuation: &ContinuationState) -> [u64; 3] {
        let counts = continuation.hold_counts();
        [
            counts.registered.load(Ordering::Relaxed),
            counts.unscoped.load(Ordering::Relaxed),
            counts.unhanded_drops.load(Ordering::Relaxed),
        ]
    }

    /// A slot really held, as a mint takes it.
    async fn slot(continuation: &ContinuationState) -> String {
        let now = crate::protocol::continuation::now_unix_secs();
        let payload = continuation
            .begin_exchange(
                "alpha".into(),
                None,
                "fp".into(),
                &crate::protocol::continuation::QuotaKey::for_test("fp"),
                "digest".into(),
                now,
            )
            .await
            .expect("a fresh state has a slot");
        payload.hold_key
    }

    async fn held(continuation: &ContinuationState) -> usize {
        let now = crate::protocol::continuation::now_unix_secs();
        continuation.in_flight().len(now).await
    }

    /// A nested scope adds nothing: the outermost opener owns the holds, so
    /// an inner scope ending cannot drop them early; the outer one's end does.
    #[tokio::test]
    async fn an_inner_scope_does_not_own_the_holds() {
        let continuation = Arc::new(ContinuationState::new());
        let key = slot(&continuation).await;
        scoped(async {
            scoped(async {
                register(&continuation, &key, "env");
            })
            .await;
            assert_eq!(
                counts(&continuation),
                [1, 0, 0],
                "the inner scope dropped it"
            );
        })
        .await;
        assert_eq!(counts(&continuation), [1, 0, 1]);
        assert_eq!(
            held(&continuation).await,
            0,
            "the outer scope's end gives the never-handed-off slot back"
        );
    }

    /// A request dropped mid-flight drops every hold it registered.
    #[tokio::test]
    async fn a_cancelled_request_drops_its_holds() {
        let continuation = Arc::new(ContinuationState::new());
        let mut request = Box::pin(scoped(async {
            register(&continuation, "k1", "env-1");
            register(&continuation, "k2", "env-2");
            std::future::pending::<()>().await;
        }));
        assert!((&mut request).now_or_never().is_none());
        assert_eq!(counts(&continuation), [2, 0, 0]);
        drop(request);
        assert_eq!(counts(&continuation), [2, 0, 2]);
    }

    /// A mint outside any scope is counted and holds nothing, so nothing can
    /// release its slot early.
    #[test]
    fn an_unscoped_mint_is_counted_not_held() {
        let continuation = Arc::new(ContinuationState::new());
        register(&continuation, "k", "env");
        assert_eq!(counts(&continuation), [0, 1, 0]);
    }

    /// Under `Release`, a hold never handed off gives its slot back; one
    /// handed off keeps it, whatever the scope does after.
    #[tokio::test]
    async fn release_frees_only_what_was_never_handed_off() {
        let continuation = Arc::new(ContinuationState::new());
        let (kept, freed) = (slot(&continuation).await, slot(&continuation).await);
        scoped(async {
            register(&continuation, &kept, "env-kept");
            register(&continuation, &freed, "env-freed");
            hand_off(&carried(&json!({"content": [{"text": "see env-kept"}]})));
        })
        .await;
        assert_eq!(
            held(&continuation).await,
            1,
            "only the handed-off slot stays"
        );
        let now = crate::protocol::continuation::now_unix_secs();
        assert_eq!(
            continuation.in_flight().route(&kept, now).await,
            crate::protocol::continuation::Routing::Here
        );
    }

    /// An answer carries a hold by its envelope anywhere in a string; one
    /// that does not name it carries nothing.
    #[tokio::test]
    async fn carried_finds_the_envelope_in_any_string() {
        let continuation = Arc::new(ContinuationState::new());
        scoped(async {
            register(&continuation, "k", "env-123");
            assert_eq!(carried(&json!({"a": [{"b": "x env-123 y"}]})).0.len(), 1);
            assert_eq!(
                carried(&json!({"error": {"message": "refused"}})).0.len(),
                0
            );
        })
        .await;
    }

    /// The bridge: holds an answer carries outlive the scope that minted them
    /// (the reply is finalized after it ends). Not handed off (finalization
    /// cancelled or replaced) they give the slot back; handed off, they keep it.
    #[tokio::test]
    async fn carried_holds_outlive_their_scope_until_handed_off_or_dropped() {
        let continuation = Arc::new(ContinuationState::new());
        let (sent, lost) = (slot(&continuation).await, slot(&continuation).await);
        let (delivered, cancelled) = scoped(async {
            register(&continuation, &sent, "env-sent");
            register(&continuation, &lost, "env-lost");
            (
                carried(&json!({"requestState": "env-sent"})),
                carried(&json!({"requestState": "env-lost"})),
            )
        })
        .await;
        assert_eq!(
            held(&continuation).await,
            2,
            "carried holds survive the scope"
        );
        drop(cancelled);
        assert_eq!(held(&continuation).await, 1, "a dropped carrier releases");
        hand_off(&delivered);
        drop(delivered);
        assert_eq!(
            held(&continuation).await,
            1,
            "a handed-off carrier keeps its slot"
        );
    }

    /// A `Release` request dropped mid-flight gives back every real slot it
    /// registered.
    #[tokio::test]
    async fn a_cancelled_release_request_gives_its_slots_back() {
        let continuation = Arc::new(ContinuationState::new());
        let (one, two) = (slot(&continuation).await, slot(&continuation).await);
        let mut request = Box::pin(scoped(async {
            register(&continuation, &one, "env-1");
            register(&continuation, &two, "env-2");
            std::future::pending::<()>().await;
        }));
        assert!((&mut request).now_or_never().is_none());
        assert_eq!(held(&continuation).await, 2);
        drop(request);
        assert_eq!(held(&continuation).await, 0);
    }

    /// The direct route renders its answer as a whole JSON-RPC document. A
    /// state re-sealed over the same slot (a different envelope) sits in its
    /// `result`, and `to_http` must still carry the hold (agy F2 on #3645).
    #[tokio::test]
    async fn a_direct_answer_carries_a_reseal_of_its_slot() {
        let continuation = Arc::new(ContinuationState::new());
        let now = crate::protocol::continuation::now_unix_secs();
        let payload = continuation
            .begin_exchange(
                "alpha".into(),
                None,
                "fp".into(),
                &crate::protocol::continuation::QuotaKey::for_test("fp"),
                "digest".into(),
                now,
            )
            .await
            .expect("a fresh state has a slot");
        let minted = continuation.keyring().mint(&payload).expect("mint");
        let resealed = continuation.keyring().mint(&payload).expect("reseal");
        assert_ne!(minted, resealed, "a reseal is a different envelope");
        let carried = scoped(async {
            register(&continuation, &payload.hold_key, &minted);
            let body = json!({"jsonrpc": "2.0", "id": 1,
                              "result": {"resultType": "input_required", "requestState": resealed}});
            let frame = crate::gateway::outbound::answer_value(None, None, body, None, None);
            let response =
                crate::gateway::outbound::to_http(frame, axum::http::StatusCode::OK, "");
            response
                .extensions()
                .get::<CarriedHolds>()
                .map_or(0, |holds| holds.0.len())
        })
        .await;
        assert_eq!(
            carried, 1,
            "the reseal in the result carries its slot's hold"
        );
    }

    /// MIK-8202: on a clock before 1970 a reseal cannot be opened, so it
    /// keeps its hold instead of freeing a slot the answer may still carry.
    #[tokio::test]
    async fn a_reseal_on_a_clock_before_the_epoch_keeps_its_hold() {
        let continuation = Arc::new(ContinuationState::new());
        let now = crate::protocol::continuation::now_unix_secs();
        let payload = continuation
            .begin_exchange(
                "alpha".into(),
                None,
                "fp".into(),
                &crate::protocol::continuation::QuotaKey::for_test("fp"),
                "digest".into(),
                now,
            )
            .await
            .expect("a fresh state has a slot");
        let minted = continuation.keyring().mint(&payload).expect("mint");
        let resealed = continuation.keyring().mint(&payload).expect("reseal");
        let kept = scoped(async {
            register(&continuation, &payload.hold_key, &minted);
            let _clock = crate::clock::test_clock::before_epoch();
            carried(&json!({"requestState": resealed})).0.len()
        })
        .await;
        assert_eq!(
            kept, 1,
            "an unreadable clock dropped a resealed slot's hold"
        );
    }
}

mod held;
pub(crate) use held::{Held, HoldSink};

#[cfg(test)]
#[path = "sealed_hold_guards.rs"]
mod guards;
