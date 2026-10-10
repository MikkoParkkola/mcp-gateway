// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.7b: the bounds, the batch, and the projection.

use super::*;

// ── MRTR.7b — the bounds, the batch, and the projection ──────────────────────

/// Row 318 — a backend that keeps asking is cut off after three retries, and
/// its neighbour that asks exactly three times still completes.
///
/// Both halves, in one test, because neither is worth much alone. The failing
/// half passes against a bridge that cuts off at two retries, and the
/// completing half passes against a bridge with no bound at all; only the pair
/// pins the boundary to the one value that satisfies both. The count asserted
/// is retries — the invocation that produced `first` happened before the bridge
/// was entered, so `rounds: 3` is three calls through this backend and four
/// backend invocations in total.
#[tokio::test]
async fn ac_mrtr_7b_the_retry_bound_cuts_off_after_three_retries() {
    let content = json!({"branch": "main"});

    // The half that must be cut off: every retry asks again.
    let client = FakeClient::new(accepts(6, &content));
    let backend = FakeBackend::new(vec![asking(&[("k", ask("again?"))]); 6]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    // #569: the error carries the backend's last round (not `first?`) to resume.
    let last = Some(Box::new(asking(&[("k", ask("again?"))])));
    assert_eq!(
        outcome,
        Err(BridgeError::RoundsExhausted { last }),
        "a backend that never stops asking must be cut off by the retry bound"
    );
    let calls = backend.calls().len();
    assert_eq!(calls, 3, "expected three retries");

    // The neighbour: three asks in total, answered on the fourth invocation.
    let client = FakeClient::new(accepts(3, &content));
    let backend = FakeBackend::new(vec![
        asking(&[("k", ask("second?"))]),
        asking(&[("k", ask("third?"))]),
        completed(),
    ]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "a backend that asks exactly three times must complete: {outcome:?}"
    );
    assert_eq!(
        backend.calls().len(),
        3,
        "the last retry is the one that completes, not one over the bound"
    );
}

/// Row 319 — the request budget is spent before a batch is sent, not while it
/// is being sent.
///
/// `client.frames().len()` is the assertion that separates the two readings. A
/// bridge checking the budget after each send stops partway through the
/// offending batch and still reports `RequestBudgetExhausted`, so an assertion
/// on the error alone passes it; only the frame count says whether the three
/// requests that could never have been afforded were put to a person anyway.
/// The neighbour spends the budget exactly and must be sent whole.
#[tokio::test]
async fn ac_mrtr_7b_the_request_budget_is_checked_before_a_batch_is_sent() {
    let content = json!({"ok": true});
    let five = [
        ("a", ask("a?")),
        ("b", ask("b?")),
        ("c", ask("c?")),
        ("d", ask("d?")),
        ("e", ask("e?")),
    ];

    // Five, then six: the second batch cannot fit in the eight that remain.
    let client = FakeClient::new(accepts(11, &content));
    let backend = FakeBackend::new(vec![asking(&[
        ("f", ask("f?")),
        ("g", ask("g?")),
        ("h", ask("h?")),
        ("i", ask("i?")),
        ("j", ask("j?")),
        ("k", ask("k?")),
    ])]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&five),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::RequestBudgetExhausted),
        "a batch that cannot fit the budget must fail the call"
    );
    assert_eq!(
        client.frames().len(),
        5,
        "not one request of the unaffordable batch may be put to the client"
    );

    // The neighbour: five then three is exactly eight, and all eight are sent.
    let client = FakeClient::new(accepts(8, &content));
    let backend = FakeBackend::new(vec![
        asking(&[("f", ask("f?")), ("g", ask("g?")), ("h", ask("h?"))]),
        completed(),
    ]);
    let records = Records::default();
    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&five),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "eight requests exactly is inside the budget: {outcome:?}"
    );
    assert_eq!(
        client.frames().len(),
        8,
        "a batch that fits must be sent in full"
    );
}

/// Row 320 — a prompt nobody answers, while the aggregate budget is still
/// live, ends the CALL and names the key the bridge was waiting on.
///
/// INVERTED 2026-09-08 on `R8a`. This row previously asserted the opposite: the
/// round was abandoned and the remaining rounds ran. What made that reading
/// untenable is the retry it produced — a bare `continue` at the timeout site
/// handed the backend the same call with `k1` simply MISSING and no error
/// anywhere, so a client that stops answering is indistinguishable from a
/// question the backend never asked. `R8a` splits the silence by which bound
/// bound it: with `left > per_prompt` the budget is still live, so the failure
/// belongs to the prompt and is attributed to its key.
///
/// On tokio's paused clock: both bounds are timers, so the clock jumps to
/// whichever fires first and the test runs at once. Which arm fired is read
/// from the outcome: the per-prompt bound ends the call as `k1`'s delivery
/// failure, the aggregate as `Deadline` (MIK-8222). The aggregate is far past
/// the per-prompt bound, so only a bridge that skipped it reaches the
/// aggregate.
#[tokio::test(start_paused = true)]
async fn ac_mrtr_7b_an_unanswered_prompt_inside_a_live_budget_ends_the_call() {
    let bounds = BridgeBounds {
        aggregate: Duration::from_secs(60),
        per_prompt: Duration::from_millis(60),
        ..BridgeBounds::DEFAULT
    };
    let client = FakeClient::new(vec![Reply::Silent]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        bounds.aggregate * 2,
        bridge_with(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", ask("first?"))]),
            bounds,
        ),
    )
    .await
    .expect(
        "a bridge with no bound at all waits on the fixture's own 86_400s silence, \
             which is a hung suite rather than a failing row",
    );
    let elapsed = started.elapsed();

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::TimedOut,
        }),
        "an unanswered prompt inside a live budget must end the call as that prompt's \
         delivery failure, naming `k1`: a bridge that skips the prompt instead retries the \
         backend with the key missing, which reads to the backend as a question nobody asked"
    );
    assert!(
        elapsed >= bounds.per_prompt,
        "the wait must be ended by the per-prompt bound, not sooner: waited {elapsed:?}"
    );
    assert!(
        backend.calls().is_empty(),
        "a call ended by its own prompt must not retry the backend at all: {} retries",
        backend.calls().len()
    );
}

/// Row 320a — the same silence, when the AGGREGATE remainder is what bounds the
/// wait, is the budget's failure and not the prompt's.
///
/// The discriminator `R8a` spells is `left <= per_prompt`, and this row is the
/// only one that can observe it. Making `aggregate` equal to `per_prompt` puts
/// the very first prompt on that side of it: no round has run, so `left` is the
/// whole budget and the whole budget is the shorter of the two.
///
/// Two wrong implementations fail here and pass row 320. One that returns
/// `Delivery`/`TimedOut` for every timeout attributes an expired budget to
/// whichever prompt happened to be in flight — the key names an owner, and that
/// owner did nothing wrong. One that keeps the bare `continue` never fails at
/// all: it skips the prompt, retries a backend that answers, and the call
/// succeeds while its budget is gone.
#[tokio::test]
async fn ac_mrtr_7b_a_wait_bounded_by_the_aggregate_remainder_is_a_deadline() {
    let bounds = BridgeBounds {
        aggregate: Duration::from_millis(60),
        per_prompt: Duration::from_millis(60),
        ..BridgeBounds::DEFAULT
    };
    let client = FakeClient::new(vec![Reply::Silent]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        bridge_with(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", ask("first?"))]),
            bounds,
        ),
    )
    .await
    .expect("the bridge's own bound must end the wait, not the suite's outer timeout");

    assert_eq!(
        outcome,
        Err(BridgeError::Deadline),
        "a wait the aggregate remainder bounded must end the call as a deadline: attributing \
         an expired budget to `k1` blames the prompt for a bound it never reached"
    );
    assert!(
        backend.calls().is_empty(),
        "a call ended by its budget must not retry the backend: {} retries",
        backend.calls().len()
    );
}

/// Row 321 — rounds each answered inside the per-prompt bound are still ended
/// by the aggregate deadline.
///
/// The only row that can observe the aggregate bound at all. A single
/// unanswered prompt is abandoned at the per-prompt bound and can never reach
/// it, so unless several answered rounds are driven the aggregate is a number
/// no test touches. Each reply lands comfortably inside `per_prompt`; their sum
/// passes `aggregate`, and the call must end on the budget rather than on any
/// one prompt.
#[tokio::test]
async fn ac_mrtr_7b_answered_rounds_are_ended_by_the_aggregate_deadline() {
    let bounds = BridgeBounds {
        rounds: 12,
        requests: 20,
        aggregate: Duration::from_millis(500),
        per_prompt: Duration::from_millis(200),
    };
    let envelope =
        json!({"jsonrpc": "2.0", "result": {"action": "accept", "content": {"ok": true}}});
    let client = FakeClient::new(
        (0..12)
            .map(|_| Reply::After(Duration::from_millis(50), envelope.clone()))
            .collect(),
    );
    let backend = FakeBackend::new(vec![asking(&[("k", ask("again?"))]); 12]);
    let records = Records::default();

    let outcome = bridge_with(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k", ask("first?"))]),
        bounds,
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Deadline),
        "the aggregate budget must end a call whose rounds each answer in time"
    );
    assert!(
        backend.calls().len() >= 2,
        "the deadline must be reached across several answered rounds, not on one prompt: {} retries",
        backend.calls().len()
    );
    assert!(
        backend
            .calls()
            .iter()
            .any(|retry| retry.pointer("/inputResponses/k").is_some()),
        "a retry must carry the answer it collected, looked up structurally rather than as a \
         substring: the key `k` also appears in the question this retry echoes, so a text \
         search passes against a bridge that timed every prompt out and filed nothing"
    );
}

/// Row 322 — three questions in one batch, all answered, produce one retry
/// carrying three answers, each under the key that asked it.
///
/// The row no other 7b row implies. A bridge that resolves on the first answer
/// and retries immediately satisfies every bound row, every projection row and
/// every refusal row, because none of them names a batch that succeeds. The
/// answers are echoed rather than scripted positionally: prompt order within a
/// batch is unspecified, so a positional script would assert the order the
/// implementation happened to choose, and each answer has to be derivable from
/// its own question instead.
#[tokio::test]
async fn ac_mrtr_7b_a_batch_of_three_answers_arrives_in_one_retry() {
    let client = FakeClient::new(vec![Reply::Echo, Reply::Echo, Reply::Echo]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[
            ("one", ask("one?")),
            ("two", ask("two?")),
            ("three", ask("three?")),
        ]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "an answered batch must complete: {outcome:?}"
    );
    let calls = backend.calls();
    assert_eq!(
        calls.len(),
        1,
        "one batch, one retry — not one retry per answer"
    );
    for (key, message) in [("one", "one?"), ("two", "two?"), ("three", "three?")] {
        assert_eq!(
            calls[0].pointer(&format!("/inputResponses/{key}/echo/message")),
            Some(&json!(message)),
            "the answer filed under {key} must be the one that key's question drew"
        );
    }
    assert_eq!(
        calls[0]
            .pointer("/inputResponses")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(3),
        "three questions must produce three answers and nothing else"
    );
}

/// Row 327 — a cancel, an unrecognised action and a reply with no member each
/// fail as themselves, and none of them reaches the backend.
///
/// Three cases in one test because what the row asserts is that they stay
/// distinct: each alone passes against a bridge that collapses every non-accept
/// onto one error. The dangerous arm is the unmatched one — an `action` the
/// bridge cannot name, falling through to the accept path, forwards a body
/// nobody agreed to — so `UnknownAction` is asserted apart from `Declined`
/// rather than merged with it. `FakeBackend::never` makes the no-retry half a
/// fact about the fixture rather than a count that happens to be zero.
#[tokio::test]
async fn ac_mrtr_7b_cancel_unnamed_action_and_no_member_fail_distinguishably() {
    let cases: Vec<(&str, Reply, DeliveryError)> = vec![
        (
            "a cancel",
            result(&json!({"action": "cancel"})),
            DeliveryError::Declined {
                action: "cancel".to_string(),
            },
        ),
        (
            "an action outside the declared set",
            result(&json!({"action": "teleport"})),
            DeliveryError::UnknownAction {
                action: "teleport".to_string(),
            },
        ),
        (
            "a reply carrying neither result nor error",
            Reply::Now(json!({"jsonrpc": "2.0"})),
            DeliveryError::NoReplyMember,
        ),
    ];

    for (name, reply, expected) in cases {
        let client = FakeClient::new(vec![reply]);
        let backend = FakeBackend::never();
        let records = Records::default();

        let outcome = bridge(
            &client,
            &backend,
            &records,
            declared_all(),
            None,
            &interim(&[("k1", ask("Which branch?"))]),
        )
        .await;

        assert_eq!(
            outcome,
            Err(BridgeError::Delivery {
                key: "k1".to_string(),
                error: expected,
            }),
            "{name} must fail as itself"
        );
        assert!(
            backend.calls().is_empty(),
            "{name} must not re-invoke the backend"
        );
    }
}

/// MIK-7388 (`InputBridge::project`) — an `action` member in a reply to a kind
/// that has no actions is data, not a verdict.
///
/// `action` is elicitation's word. A `sampling/createMessage` result answers
/// with `role`/`content`/`model`/`stopReason`, and a client that also spells an
/// `action` field — an extension, a shared reply builder, a proxy — had its
/// answer read as an elicitation accept: the projection returned `content`
/// alone and `role`, `model` and `stopReason` never reached the backend. The
/// backend is owed the answer it was given, whole.
#[tokio::test]
async fn mik_7388_an_action_member_does_not_reshape_a_sampling_answer() {
    let answer = json!({
        "role": "assistant",
        "content": {"type": "text", "text": "hello"},
        "model": "some-model",
        "stopReason": "endTurn",
        "action": "accept",
    });
    let client = FakeClient::new(vec![result(&answer)]);
    let backend = FakeBackend::new(vec![completed()]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[(
            "k1",
            entry(
                "sampling/createMessage",
                &json!({"messages": [], "maxTokens": 8}),
            ),
        )]),
    )
    .await;

    assert!(outcome.is_ok(), "sampling round failed: {outcome:?}");
    assert_eq!(
        backend.calls()[0].pointer("/inputResponses/k1"),
        Some(&answer),
        "a sampling answer must reach the backend whole, action member and all"
    );
}

/// MIK-7388 (`InputBridge::project`) — an elicitation reply with no `action`
/// fails as malformed rather than being filed as it stands.
///
/// The other half of the same kind-blindness. `action` is required of an
/// elicitation reply, so one that omits it is unreadable — and filing it whole
/// hands the backend `{"content": …}` where an accept hands it `…`, the same
/// answer at two nesting depths depending on what the client forgot. A shape
/// the gateway cannot read is a delivery failure, and it is already spelled
/// `Malformed`.
#[tokio::test]
async fn mik_7388_an_elicitation_reply_without_an_action_fails_as_malformed() {
    let client = FakeClient::new(vec![result(&json!({"content": {"branch": "main"}}))]);
    let backend = FakeBackend::never();
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", ask("Which branch?"))]),
    )
    .await;

    assert_eq!(
        outcome,
        Err(BridgeError::Delivery {
            key: "k1".to_string(),
            error: DeliveryError::Malformed,
        }),
        "an elicitation reply with no action must fail as malformed"
    );
    assert!(
        backend.calls().is_empty(),
        "backend must not be retried for an unreadable elicitation reply"
    );
}

/// Row 328 — *each* bridged round is counted with `phase="bridge"`, and no part
/// of what a person answered appears in any record.
///
/// The counter's name is not asserted, because no name exists to assert:
/// `NFR.OBS.4` is recorded as having no design and no counters
/// (`docs/internal/requirements/RELEASE-4.0.0-cluster-a-readiness.md:44`), so a literal
/// here would be this test inventing the contract it claims to check. The two
/// halves the row does name are both asserted, and each is written so that the
/// cheapest wrong implementation fails it.
///
/// Three rounds rather than one, because "each round" is the half a single
/// successful round cannot observe: a counter emitted once per *call* carries
/// `phase="bridge"` and satisfies a one-round row completely, while losing
/// exactly the per-round resolution the requirement is about. Three answered
/// rounds demand at least three bridge-phase records, which no once-per-call
/// counter can produce.
///
/// The absence is the half that rots — a label added later to carry "what was
/// answered" breaks nothing and fails nothing — so it is asserted against the
/// captured records rather than by reading the emit sites, over every counter
/// name and every label key and value. Each round answers with its own
/// sentinel, so a bridge that leaks only the last answer, or only the first,
/// is caught rather than sampled.
#[tokio::test]
async fn ac_mrtr_7ab_a_bridged_round_is_counted_without_the_answer_body() {
    const SENTINELS: [&str; 3] = [
        "sentinel-answer-body-mrtr7-one",
        "sentinel-answer-body-mrtr7-two",
        "sentinel-answer-body-mrtr7-three",
    ];

    let client = FakeClient::new(
        SENTINELS
            .iter()
            .map(|sentinel| accepted(&json!({"branch": sentinel})))
            .collect(),
    );
    let backend = FakeBackend::new(vec![
        asking(&[("k2", ask("Which remote?"))]),
        asking(&[("k3", ask("Which tag?"))]),
        completed(),
    ]);
    let records = Records::default();

    let outcome = bridge(
        &client,
        &backend,
        &records,
        declared_all(),
        None,
        &interim(&[("k1", ask("Which branch?"))]),
    )
    .await;

    assert!(
        outcome.is_ok(),
        "the three rounds must complete: {outcome:?}"
    );
    let observed = records.all();
    let bridged = observed
        .iter()
        .filter(|record| record.labels.get("phase").map(String::as_str) == Some("bridge"))
        .count();
    assert!(
        bridged >= SENTINELS.len(),
        "each of the {} bridged rounds must be counted with phase=\"bridge\", and {bridged} \
         record(s) carry it: a counter emitted once per call passes the same row driven \
         through a single round",
        SENTINELS.len()
    );
    for record in &observed {
        for sentinel in SENTINELS {
            assert!(
                !record.counter.contains(sentinel),
                "an answer body must not reach a counter name: {:?}",
                record.counter
            );
            for (key, value) in &record.labels {
                assert!(
                    !key.contains(sentinel) && !value.contains(sentinel),
                    "an answer body must not reach a label: {key}={value}"
                );
            }
        }
    }
}

/// The control for rows 318-321: the fixture those rows retry with is the shape
/// the parser actually reads.
///
/// Every multi-round row drives its later rounds through [`asking`], and a
/// bridge is observable as looping only if the parser classifies what the
/// backend returned as another question. A fixture the parser refuses to
/// classify is indistinguishable, from outside, from a bridge that never loops:
/// both end the call after one round, and the row would then be failing for a
/// reason that has nothing to do with the bound it names. This asserts the
/// fixture rather than the bridge, so unlike its neighbours it may legitimately
/// pass while the bridge is still a stub.
///
/// Asserted against [`interim`] rather than against written-out literals: the
/// two fixtures agreeing is the property, and a literal restates one of them
/// where a later edit could move the other. Field by field because
/// `InputRequired` carries no `PartialEq`, and deriving one on a shipped type
/// to shorten a test is a production change this row does not need.
#[test]
fn ac_mrtr_7b_the_asking_fixture_is_what_the_parser_reads() {
    let expected = interim(&[("k1", ask("Which branch?"))]);
    let parsed = InputRequired::from_result(&asking(&[("k1", ask("Which branch?"))]))
        .expect("the retry fixture must parse as an unfinished round");

    assert_eq!(
        parsed.requests, expected.requests,
        "the wire fixture must parse to the entries the struct fixture states"
    );
    assert_eq!(
        parsed.request_state, expected.request_state,
        "the wire fixture must carry the state a retry has to echo back"
    );
}

/// A control, not an acceptance row: it proves `declared_all` declares.
///
/// The `_meta` keys are reverse-DNS, and a fixture writing the bare names is
/// read as a shape carrying no declaration at all — so every capability row
/// would gate on `Declared::NONE` and pass whatever the bridge did with the
/// permission it was never given. Asserting the fixture against the parser is
/// what stops that from being reintroduced silently; the row tests cannot see
/// it, because a client that declared nothing is a state they are allowed to
/// encounter.
#[test]
fn ac_mrtr_7a_the_capability_fixture_declares_what_it_names() {
    let all = declared_all();
    for capability in ["sampling", "roots", "elicitation"] {
        assert!(
            all.has(capability),
            "the fixture claiming every capability must declare {capability}, \
             or every capability row gates on a client that declared nothing"
        );
    }
}

/// The null channel refuses every admitted method, and says why in one way.
///
/// `NoClientChannel` is what a transport with no server-to-client path carries
/// on the caller context, and a null object that answered anything other than
/// `NoSession` — or answered it for only some of the closed method set — would
/// be a fail-open dressed as a default. The loop runs over `ServerRequestKind::ALL`
/// so a fourth kind cannot arrive unrefused.
#[tokio::test]
async fn ac_mrtr_7a_the_null_channel_refuses_every_admitted_method() {
    for kind in ServerRequestKind::ALL {
        let refusal = NoClientChannel
            .send_request("session-1", "bridge-1", kind.method(), Some(json!({})))
            .await;

        assert_eq!(
            refusal,
            Err(DeliveryError::NoSession),
            "the null channel must refuse {} with NoSession, not answer it",
            kind.method()
        );
    }
}
