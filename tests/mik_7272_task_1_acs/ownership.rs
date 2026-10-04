// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use serde_json::{Value, json};

use mcp_gateway::gateway::test_helpers::AppState;

use super::fixture;
use super::http::{
    SUBSCRIPTION_CAPACITY, modern, poll_unattributed_until_terminal, post_against,
    post_answer_against, post_unattributed, public_mcp_auth, send, state, state_from,
    state_holding, state_over, state_public_mcp, task_id_of, task_invoke,
};

/// An id nothing ever created: the negative control every "indistinguishable
/// from no task" comparison is made against, and still a control.
const FABRICATED_ID: &str = "task-11111111-1111-4111-8111-111111111111";
/// A SECOND id nothing ever created, used only where a create is expected to
/// be REFUSED and there is therefore no real id to name. Distinct from
/// `FABRICATED_ID` so the byte-identity comparison is never run against
/// itself. It is no longer a fallback for a create that was supposed to
/// succeed: those now panic instead, so an ownership row can never pass on
/// two unrelated refusals agreeing.
const UNDISPATCHED_ID: &str = "task-22222222-2222-4222-8222-222222222222";

/// The gateway's answer with the request id blanked, so two answers to two
/// different task ids can be compared for byte-identity. Blanking only what
/// MUST differ is the point: anything else that differs is the disclosure
/// the criterion forbids.
fn shape(mut body: Value) -> String {
    if let Some(obj) = body.as_object_mut() {
        obj.insert("id".into(), json!(0));
    }
    body.to_string()
}

// =======================================================================
// MIK-7272.TASK.1.11 — a retrieval naming another principal's task is
// answered as not-found, identically to an id that never existed.
// =======================================================================

/// A's task is real: the create is asserted, not hoped for. That is what
/// makes the byte-identity comparison a comparison — B is answered about an
/// id that DOES resolve for someone, and about one that resolves for
/// nobody, and the two answers must be the same.
///
/// The dispatch count is the ownership control. A create runs the backend
/// once; two retrievals by a principal who owns nothing must run it zero
/// more times. A gateway that dispatched on read would leak the task's
/// existence through the backend even while answering not-found.
#[tokio::test]
async fn ac_task_1_11_another_principals_task_is_indistinguishable_from_no_task() {
    let fixture = state().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(20, "mik-7272-task-1-11-create"),
    )
    .await;
    let task_id = task_id_of(&created);
    fixture.backend.wait_for_calls(1).await;

    let (_, foreign) = post_against(
        Arc::clone(&fixture.state),
        "key-b",
        modern(21, "tasks/get", json!({ "taskId": task_id }), true),
    )
    .await;
    let (_, absent) = post_against(
        Arc::clone(&fixture.state),
        "key-b",
        modern(22, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
    )
    .await;

    assert_eq!(
        shape(foreign),
        shape(absent),
        "B's view of A's task is byte-identical to B's view of an id that never existed"
    );
    assert_eq!(
        fixture.backend.calls(),
        1,
        "a retrieval dispatches nothing: the only backend run is A's create"
    );
}

// =======================================================================
// MIK-7272.TASK.1.12 — subscription admission enforces the same ownership
// check, and refuses indistinguishably from an id that never existed.
// =======================================================================

/// VACUOUS UNTIL SUB.2 LANDS in one specific respect, and this is the row
/// the design singles out for it: what must be true before the comparison
/// carries the criterion is that `subscriptions/listen` really admits a
/// stream for a `taskId` its caller owns. That half is now an assertion
/// rather than a comment — and the task it names is a real durable one, so
/// the admission is admission of something. Until the stream carries task
/// notifications, a green here is coverage of the ownership check only, and
/// closing `.12` on more than that would be a release gate removed and
/// written down as passed.
#[tokio::test]
async fn ac_task_1_12_subscription_admission_hides_another_principals_task() {
    let fixture = state().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(23, "mik-7272-task-1-12-create"),
    )
    .await;
    let task_id = task_id_of(&created);

    let (_, admitted) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(
            24,
            "subscriptions/listen",
            json!({ "taskIds": [task_id.clone()] }),
            true,
        ),
    )
    .await;
    assert!(
        admitted.get("error").is_none(),
        "the owner is admitted — without this the comparison below is vacuous: {admitted}"
    );

    let (_, foreign) = post_against(
        Arc::clone(&fixture.state),
        "key-b",
        modern(
            25,
            "subscriptions/listen",
            json!({ "taskIds": [task_id] }),
            true,
        ),
    )
    .await;
    let (_, absent) = post_against(
        Arc::clone(&fixture.state),
        "key-b",
        modern(
            26,
            "subscriptions/listen",
            json!({ "taskIds": [FABRICATED_ID] }),
            true,
        ),
    )
    .await;
    assert_eq!(
        shape(foreign),
        shape(absent),
        "listening on another principal's task is byte-identical to listening on a fabricated id"
    );
}

// =======================================================================
// MIK-7272.TASK.1.9 — a `subscriptions/listen` carrying `taskIds` emits
// `notifications/tasks` and no `notifications/progress` or `.../message`.
// =======================================================================

/// VACUOUS IN ITS NEGATIVE HALF UNTIL SUB.2 LANDS: nothing emits task
/// notifications, so an empty stream satisfies "and no progress or message"
/// trivially. What IS asserted is the half that can be: a listen naming a
/// task the caller really owns is admitted. Asserting the emission today
/// would name a notification the gateway has no producer for, which fails
/// as an absent name rather than as a defect.
#[tokio::test]
async fn ac_task_1_9_a_task_subscription_is_admitted_for_its_owner() {
    let fixture = state().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(27, "mik-7272-task-1-9-create"),
    )
    .await;
    let task_id = task_id_of(&created);

    let (_, listened) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(
            28,
            "subscriptions/listen",
            json!({ "taskIds": [task_id] }),
            true,
        ),
    )
    .await;
    assert!(
        listened.get("error").is_none(),
        "a `subscriptions/listen` carrying `taskIds` is admitted for the owner: {listened}"
    );
}

// =======================================================================
// MIK-7272.TASK.1.18 — a caller that presented no credential owns no task,
// and is told so in the same words as an id that never existed.
// =======================================================================

/// `session_owner_key` returns the empty string for a caller with no
/// credential, and `TaskStore` compares principals by plain equality — so
/// every unattributed caller answers to the same owner key and they own
/// each other's tasks. The gateway states the opposite rule in that
/// function's own doc comment ("Empty ... is not an identity, and the
/// controls that key on this refuse rather than pool every anonymous caller
/// into one bucket"), and the firewall arm honours it. Only the task arms
/// pool.
///
/// The credentialled half of this case is the vacuity guard: it proves the
/// fixture can tell a retrieved task from a not-found answer, so the
/// byte-identity assertion below is a real comparison and not two refusals
/// agreeing for an unrelated reason. That guard only works on a task that
/// exists, which is why the create here is asserted rather than fallen back
/// from — it was the fallback that let this row report agreement between
/// two answers about nothing.
#[tokio::test]
async fn ac_task_1_18_an_unattributed_caller_owns_no_task() {
    let fixture = state_public_mcp().await;

    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(30, "mik-7272-task-1-18-create"),
    )
    .await;
    let owned_id = task_id_of(&created);
    fixture.backend.wait_for_calls(1).await;
    let (_, owner_view) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(31, "tasks/get", json!({ "taskId": owned_id.clone() }), true),
    )
    .await;
    let (_, owner_absent) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        modern(32, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
    )
    .await;
    assert_ne!(
        shape(owner_view),
        shape(owner_absent),
        "a credentialled owner must see its own task differently from one \
         that never existed — without this the comparison below is vacuous"
    );

    let (_, unattributed_created) = post_unattributed(
        Arc::clone(&fixture.state),
        task_invoke(33, "mik-7272-task-1-18-unattributed"),
    )
    .await;
    assert_eq!(
        unattributed_created
            .pointer("/error/message")
            .and_then(Value::as_str),
        Some("no such task"),
        "the unattributed dispatch must be refused BY THE ROUTER, in the \
         id-free wording of `missing_task_error` — a middleware refusal \
         short of the router would answer 401 to everything below and make \
         the comparison vacuous: {unattributed_created}"
    );
    assert_eq!(
        fixture.backend.calls(),
        1,
        "the refused unattributed create must reach no backend: the only \
         dispatch is the credentialled one above"
    );
    // That refusal is the point, so there is no pooled id to name: the
    // unattributed caller was handed nothing. The comparison below is
    // therefore between an id no unattributed caller could have been given
    // and one that never existed, which is exactly what "an empty principal
    // is not an identity" means. Its vacuity guard is the credentialled
    // half above, on a task that really does resolve.
    let pooled_id = UNDISPATCHED_ID;
    let (_, second_caller) = post_unattributed(
        Arc::clone(&fixture.state),
        modern(34, "tasks/get", json!({ "taskId": pooled_id }), true),
    )
    .await;
    let (_, never_existed) = post_unattributed(
        Arc::clone(&fixture.state),
        modern(35, "tasks/get", json!({ "taskId": FABRICATED_ID }), true),
    )
    .await;

    assert_eq!(
        shape(second_caller),
        shape(never_existed),
        "a task another unattributed caller dispatched is indistinguishable \
         from an id that never existed: an empty principal is not an identity"
    );
}

// =======================================================================
// MIK-7272.TASK.1.19 — an unattributed listen never says whether an id
// resolves.
// =======================================================================

/// Amended by A5c (MIK-7570.NOTIFY.2): with authentication on, a
/// credential-less `subscriptions/listen` is refused 401 before any task id
/// is read, so "never refused" no longer holds. What survives is the point
/// of the row: the answer must not depend on the id. A listen naming a task
/// that resolves, for A, and one naming an id nobody holds get the same
/// status, code and message, so the refusal discloses nothing.
#[tokio::test]
async fn ac_task_1_19_unattributed_subscription_discloses_nothing() {
    let fixture = state_public_mcp().await;
    let (_, created) = post_against(
        Arc::clone(&fixture.state),
        "key-a",
        task_invoke(36, "mik-7272-task-1-19-create"),
    )
    .await;
    let owned_id = task_id_of(&created);

    let listen = |id: i64, task: &str| {
        modern(
            id,
            "subscriptions/listen",
            json!({ "taskIds": [task] }),
            true,
        )
    };
    let owned = post_unattributed(Arc::clone(&fixture.state), listen(37, &owned_id)).await;
    let absent = post_unattributed(Arc::clone(&fixture.state), listen(38, "no-such-task")).await;

    assert_eq!(owned.0, axum::http::StatusCode::UNAUTHORIZED, "{}", owned.1);
    assert_eq!(owned.0, absent.0, "the status must not depend on the id");
    assert_eq!(
        owned.1["error"]["code"], absent.1["error"]["code"],
        "{}",
        owned.1
    );
    assert_eq!(
        owned.1["error"]["message"], absent.1["error"]["message"],
        "an id that resolves must be indistinguishable from one that does not"
    );
}

// =======================================================================
// MIK-7272.TASK.1.20 — with authentication DISABLED the pool is the
// operator's own configuration, and the refusal deliberately does not fire.
// =======================================================================

/// `.18` refuses the credential-less caller because, where the operator
/// declared distinct principals, the empty owner key pooled callers who
/// were supposed to be kept apart. The predicate therefore reads
/// `owner.is_empty() && auth_config.enabled` — it does not ask "did this
/// request carry a credential", it asks "did the operator draw a boundary
/// here at all". With authentication off there is none to enforce:
/// `anonymous_client` makes one shared caller the operator's stated choice,
/// and an unconditional refusal would take tasks away from every
/// single-user gateway to protect a line nobody drew.
///
/// Both halves are ONE assertion and neither works alone: the same
/// unattributed dispatch, refused and then admitted under configurations
/// that differ in `enabled` AND NOTHING ELSE. Both come from
/// `public_mcp_auth()`, because the earlier spelling admitted under
/// `AuthConfig::default()`, which also drops the two API keys and the
/// public `/mcp` listing — a guard keyed on key-count or on the public
/// path would have kept the pair green while `enabled` did no work.
/// The admission half on its own passes just as well against a guard
/// someone deleted outright, and the refusal half is already `.18` — only
/// the pair can fail for the right reason. The call is the same
/// `task_invoke` in both halves for the same reason: a difference in the
/// request would be a second variable, and the pair would stop being about
/// `enabled`.
///
/// The admission is asserted POSITIVELY — answered, with a REAL handle —
/// not as "some message other than `no such task`". A method-not-found, a
/// capability miss or a tool error all satisfy the negation while the
/// caller reaches nothing, so the negation passes on a broken gateway. It
/// used to stop at "answered", which was one assertion short of the
/// criterion: "the credential-less caller reaches the dispatcher" is a
/// claim about a task being CREATED, and an answer carrying no handle, or a
/// handle behind which nothing runs, satisfies "answered" while the caller
/// still reaches nothing. So the admitted half now goes the whole way — a
/// real `taskId` (never a fabricated fallback: `task_id_of` panics), a real
/// backend run counted exactly once, the same handle for a second
/// unattributed request and for a same-key retry, and a real terminal
/// outcome polled under the suite's one bound. None of that is `.1`'s claim
/// borrowed: `.1` observes a CREDENTIALLED create, and every line here
/// fails for this row's own predicate, on the gateway `enabled` decides.
///
/// Both halves post the SAME `Value` — one `task_invoke`, cloned, down to
/// the idempotency key — which is what retires the "a difference in the
/// request would be a second variable" caveat rather than merely stating
/// it. The two gateways hold separate stores and separate admission
/// indexes, so one key across both is one request asked of two
/// configurations, never a retry.
#[tokio::test]
async fn ac_task_1_20_auth_disabled_admits_the_unattributed_caller() {
    // The one request. Everything below posts THIS value.
    let call = task_invoke(40, "mik-7272-task-1-20");

    let public_fixture = state_public_mcp().await;
    let (_, refused) = post_unattributed(Arc::clone(&public_fixture.state), call.clone()).await;
    assert_eq!(
        refused.pointer("/error/message").and_then(Value::as_str),
        Some("no such task"),
        "control: with auth ENABLED the same call must still be refused, or \
         the contrast below says nothing about the predicate: {refused}"
    );
    assert_eq!(
        refused.pointer("/error/code"),
        Some(&json!(-32602)),
        "and refused in `missing_task_error`'s own code — a different error \
         wearing that message would be a different rule: {refused}"
    );
    assert_eq!(
        refused.pointer("/error/data"),
        None,
        "id-free: a refusal carrying data about a task would hand the \
         unattributed caller exactly what the wording withholds: {refused}"
    );
    // Not a racy negative. The refusal is an early return in the router,
    // before any dispatch is spawned, so a count read straight after it
    // cannot be observing work that has merely not started yet.
    assert_eq!(
        public_fixture.backend.calls(),
        0,
        "the refused create must have no backend effect whatsoever"
    );

    let mut disabled = public_mcp_auth();
    disabled.enabled = false;
    let fixture = state_from(disabled).await;

    let (_, admitted) = post_unattributed(Arc::clone(&fixture.state), call.clone()).await;
    assert!(
        admitted.get("error").is_none(),
        "with auth DISABLED there are no principals to keep apart, so the \
         credential-less caller reaches the dispatcher like every other \
         caller on that gateway and is ANSWERED: {admitted}"
    );
    assert_eq!(
        admitted.pointer("/result/resultType"),
        Some(&json!("task")),
        "and answered with a task handle, not with a synchronous result \
         that quietly dropped the `task` member: {admitted}"
    );
    // Panics rather than falling back: an id this row invented would let
    // every comparison below agree about a task that was never created.
    let task_id = task_id_of(&admitted);
    // The handle is a promise that work is under way, so the work is
    // observed: exactly one dispatch reached the real backend.
    fixture.backend.wait_for_calls(1).await;

    // A SECOND unattributed request — another credential-less caller on
    // that gateway — resolves the very handle the first was handed. This is
    // the shared anonymous owner the operator chose by turning
    // authentication off, and it is the half `.18` refuses where the
    // operator DID draw a boundary.
    let (_, fetched) = post_unattributed(
        Arc::clone(&fixture.state),
        modern(41, "tasks/get", json!({ "taskId": task_id.clone() }), true),
    )
    .await;
    assert_eq!(
        fetched.pointer("/result/taskId"),
        Some(&json!(task_id)),
        "an unattributed caller on an auth-disabled gateway sees the task \
         the shared anonymous owner created: {fetched}"
    );

    // The same key, the same operation, the same owner: the handle it
    // already owns comes back, and the tool does not run twice. The first
    // dispatch may have settled by the time this retry arrives.
    //
    // The BYTE-IDENTICAL value, request id included: unlike the polls
    // below, which are distinct requests and carry distinct ids, this one is
    // deliberately the create resent. A retry that differed anywhere would
    // leave open which difference admission keyed on.
    let (_, retried) = post_unattributed(Arc::clone(&fixture.state), call.clone()).await;
    assert_eq!(
        retried.pointer("/result/taskId"),
        Some(&json!(task_id)),
        "a same-key retry is the same logical request and must be answered \
         with the same handle: {retried}"
    );
    assert_eq!(
        fixture.backend.calls(),
        1,
        "and must not run the tool a second time: the dedupe key is \
         (owner, idempotency key), and the anonymous owner is an owner"
    );

    // Real work, really finished. The poll is bounded by the suite's one
    // bound and ends on the store's own terminal status, so a handle behind
    // which nothing ever runs fails this row instead of passing it.
    let terminal = poll_unattributed_until_terminal(Arc::clone(&fixture.state), 42, &task_id).await;
    assert_eq!(
        terminal.pointer("/result/status"),
        Some(&json!("completed")),
        "the backend answered, so the task settles completed: {terminal}"
    );
    assert_eq!(
        terminal
            .pointer("/result/result/structuredContent/marker")
            .and_then(Value::as_str),
        Some(super::fixture::MARKER),
        "the completed task preserves the actual backend payload: {terminal}"
    );
    assert_eq!(
        fixture.backend.calls(),
        1,
        "one create, one retry, one dispatch: settling is not a second run"
    );
}

mod lifecycle;
