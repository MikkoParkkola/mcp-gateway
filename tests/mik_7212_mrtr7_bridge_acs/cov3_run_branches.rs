// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7324.COV.3: the branches of `InputBridge::run` the rows above do not
//! reach. The deadline is checked again at the top of every later round, and
//! a gate refusal that is not a challenge refusal passes through unchanged on
//! both gate calls.

use super::*;

/// A backend that answers each retry with another ask, after a delay.
struct SlowBackend {
    delay: Duration,
    calls: Mutex<u32>,
}

#[async_trait::async_trait]
impl BackendInvoker for SlowBackend {
    async fn invoke(&self, _retry_params: Value) -> Result<Value, BridgeError> {
        *self.calls.lock().expect("calls") += 1;
        tokio::time::sleep(self.delay).await;
        Ok(asking(&[("k", ask("again?"))]))
    }
}

/// A gate that admits the first `admitted` challenges, then refuses with
/// `refusal`.
struct CountingGate {
    admitted: usize,
    seen: Mutex<usize>,
    refusal: fn() -> BridgeError,
}

impl ChallengeGate for CountingGate {
    fn admit(&self, _challenge: &Value) -> Result<(), BridgeError> {
        let mut seen = self.seen.lock().expect("seen");
        *seen += 1;
        if *seen > self.admitted {
            return Err((self.refusal)());
        }
        Ok(())
    }
}

/// The aggregate budget is checked again at the top of a later round: a
/// backend slower than the whole budget ends the exchange there, before the
/// client is asked a second time.
#[tokio::test]
async fn a_round_that_starts_past_the_aggregate_budget_ends_on_the_deadline() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(accepts(3, &content));
    let backend = SlowBackend {
        delay: Duration::from_millis(200),
        calls: Mutex::new(0),
    };
    let records = Records::default();
    let bounds = BridgeBounds {
        aggregate: Duration::from_millis(100),
        per_prompt: Duration::from_millis(50),
        ..BridgeBounds::DEFAULT
    };

    let outcome = InputBridge {
        channel: &client,
        backend: &backend,
        gate: &OpenChallengeGate,
        observer: &records,
        bounds,
    }
    .run(
        SESSION,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert_eq!(outcome, Err(BridgeError::Deadline));
    assert_eq!(
        *backend.calls.lock().unwrap(),
        1,
        "one retry, then the deadline"
    );
    assert_eq!(client.frames().len(), 1, "the second round never asked");
}

/// A gate refusal other than a challenge refusal reaches the caller as the
/// gate raised it; only a challenge refusal is rebuilt with `dispatched`.
#[tokio::test]
async fn a_round_gate_refusal_of_another_kind_passes_through_unchanged() {
    let client = FakeClient::mute();
    let backend = FakeBackend::never();
    let gate = CountingGate {
        admitted: 0,
        seen: Mutex::new(0),
        refusal: || BridgeError::RequestBudgetExhausted,
    };
    let records = Records::default();

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert_eq!(outcome, Err(BridgeError::RequestBudgetExhausted));
    assert!(client.frames().is_empty(), "a refused round asks no one");
    assert!(
        backend.calls().is_empty(),
        "a refused round retries nothing"
    );
}

/// The same holds on the gate call for the round handed back: a refusal of
/// another kind is not rebuilt as a challenge refusal.
#[tokio::test]
async fn a_handed_back_gate_refusal_of_another_kind_passes_through_unchanged() {
    let content = json!({"branch": "main"});
    let client = FakeClient::new(accepts(6, &content));
    let backend = FakeBackend::new(vec![asking(&[("k", ask("again?"))]); 6]);
    let rounds = usize::try_from(BridgeBounds::DEFAULT.rounds).unwrap();
    let gate = CountingGate {
        admitted: rounds,
        seen: Mutex::new(0),
        refusal: || BridgeError::NeverReached,
    };
    let records = Records::default();

    let outcome = bridge_gated(
        &client,
        &backend,
        &gate,
        &records,
        declared_all(),
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert_eq!(outcome, Err(BridgeError::NeverReached));
    assert_eq!(
        backend.calls().len(),
        rounds,
        "every asked round was retried"
    );
    assert_eq!(
        *gate.seen.lock().unwrap(),
        rounds + 1,
        "the handed-back round was gated"
    );
}
