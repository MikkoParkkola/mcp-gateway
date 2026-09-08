// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The shared result-shape selector, observed on the wire.
//!
//! One dispatch tail serves two callers with two shapes (`meta_mcp/mod.rs`,
//! `ResultShape`): the request thread asks for `Wrapped` — the synchronous
//! meta-tool reply, whose single text item is the tool's result serialised into
//! a string — and the task worker asks for `Native`, the backend's own result
//! object, because design §4 settles a task on that result verbatim.
//!
//! Both rows here drive the real `/mcp` router and one counted mock, and both
//! read the shapes off the answers a client gets rather than off the selector's
//! own enum. A test that inspected the enum could not tell the two shapes apart
//! at all: the defect worth catching is a worker that settles on the wrapped
//! envelope (a JSON document stuffed into a text field, and no
//! `structuredContent` for the client to read), and that defect is only visible
//! in `tasks/get`.
//!
//! Neither row asserts a whole envelope. The gateway legitimately adds fields on
//! the way out — `trace_id` on every result, `recovery` beside a tool-level
//! `isError` — so each row names the fields the backend supplied and checks
//! those, which is the claim ("carried through, not rebuilt") without pinning an
//! unstable trace id.
use super::super::*;
use super::support::*;

/// The successful payload both shapes must carry. Distinctive, so "the client
/// got the backend's own result" is an observation rather than a coincidence
/// between two default-shaped objects, and deliberately unlike
/// [`Answer::ok`]'s marker so a row cannot pass on the suite's stock fixture.
const CARRIED_TEXT: &str = "result-shape-selector-carried-this-text";

/// The text a backend-authored refusal carries. Also the row's evidence that
/// the settled result is not one the gateway wrote: every gateway-authored
/// settlement payload (`interrupted_before_dispatch`, `abandoned_input_round`)
/// carries its own sentence, and neither is this one.
const REFUSED_TEXT: &str = "the backend refused this call itself";

// =====================================================================
// adapter design r3 §4 — the two shapes of one dispatch tail
// =====================================================================

/// GIVEN one backend result, WHEN the same call is made synchronously and as a
/// task, THEN the synchronous reply carries it wrapped in a text item and the
/// task settles on it natively.
///
/// The two halves share a fixture on purpose: with one mock answering both, a
/// difference between the two answers can only be the selector, never two
/// backends that were set up differently. The counter closes the row — `2` is
/// one dispatch per call, so neither half was served from a cache and neither
/// was dispatched twice.
#[tokio::test]
async fn the_selector_wraps_the_synchronous_reply_and_settles_a_task_natively() {
    let carried = json!({
        "content": [{ "type": "text", "text": CARRIED_TEXT }],
        "structuredContent": { "shape": CARRIED_TEXT, "items": [1, 2] }
    });
    let mock = MockBackend::answering(Answer::Result(carried.clone()));
    let (state, _store) = state_with(&mock).await;

    // ---- the ordinary path: `Wrapped`, exactly as it is today ----
    let sync = post(&state, "key-a", sync_invoke(20, json!({ "q": "ordinary" }))).await;

    assert!(
        sync.pointer("/result/taskId").is_none(),
        "a call with no `task` member is answered with a result, never a handle: {sync}"
    );
    assert!(
        sync.pointer("/result/structuredContent").is_none(),
        "`gateway_invoke` declares no output schema, so the synchronous reply \
         carries no native `structuredContent` — that is the existing contract \
         this row is here to hold still: {sync}"
    );
    let wrapped = sync
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("the synchronous reply carries one text item: {sync}"));
    let unwrapped: Value = serde_json::from_str(wrapped).unwrap_or_else(|e| {
        panic!("the wrapped text item is the tool result serialised ({e}): {sync}")
    });
    std::assert_eq!(
        unwrapped.get("content"),
        carried.get("content"),
        "the backend's content crosses the wrapper unchanged: {unwrapped}"
    );
    std::assert_eq!(
        unwrapped.get("structuredContent"),
        carried.get("structuredContent"),
        "and so does its structured content — inside the text item, which is \
         where the synchronous shape puts it: {unwrapped}"
    );

    // ---- the task path: `Native`, and no second wrapper ----
    let created = post(
        &state,
        "key-a",
        task_invoke(21, "shape-native", json!({ "q": "task" })),
    )
    .await;
    let id = task_id(&created);
    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "the backend answered, so the task settles completed: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/content"),
        carried.get("content"),
        "the settled result is the backend's own object: a worker that settled \
         on the synchronous wrapper would carry one text item holding a JSON \
         document instead: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/structuredContent"),
        carried.get("structuredContent"),
        "and its structured content is readable as structure rather than as a \
         string a client would have to parse: {fetched}"
    );
    std::assert_eq!(
        mock.calls(),
        2,
        "one dispatch for the synchronous call and one for the task — the two \
         shapes are two renderings of one tail, not two backend calls each. The \
         backend saw {:?}",
        mock.seen()
    );
}

/// GIVEN a backend that answers with a tool-level `isError`, WHEN it is called
/// as a task, THEN the task completes carrying that refusal.
///
/// Design §4: the worker settles `Complete(result)` on whatever the backend
/// returned, `isError` included. `failed` is reserved for a JSON-RPC error, and
/// a backend that answered "no" answered. Two defects this row separates:
/// settling `failed` on a successful response that happens to say `isError`,
/// and replacing the backend's payload with a gateway-authored one.
///
/// Nothing in the runtime decodes a wrapped text item back into a result, so a
/// worker that settled on the synchronous shape would carry `isError: false`
/// with the refusal buried in a string — which is exactly what the `isError`
/// assertion below would catch.
#[tokio::test]
async fn a_backend_authored_is_error_settles_completed_carrying_its_own_result() {
    let refusal = json!({
        "content": [{ "type": "text", "text": REFUSED_TEXT }],
        "structuredContent": { "refusal": REFUSED_TEXT },
        "isError": true
    });
    let mock = MockBackend::answering(Answer::Result(refusal.clone()));
    let (state, _store) = state_with(&mock).await;

    let created = post(
        &state,
        "key-a",
        task_invoke(22, "shape-is-error", json!({ "q": "refused" })),
    )
    .await;
    let id = task_id(&created);
    let fetched = poll_until_terminal(&state, "key-a", &id).await;

    std::assert_eq!(
        status_of(&fetched),
        "completed",
        "a backend that answered has answered: `failed` is for a JSON-RPC \
         error, not for a tool that said no: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/isError"),
        Some(&json!(true)),
        "the backend's own `isError` reaches the client rather than being \
         flattened into a success: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/content"),
        refusal.get("content"),
        "the refusal the CLIENT reads is the one the BACKEND wrote — not the \
         gateway's interrupted-before-dispatch payload, which carries its own \
         sentence and would fail here: {fetched}"
    );
    std::assert_eq!(
        fetched.pointer("/result/result/structuredContent"),
        refusal.get("structuredContent"),
        "and the structured half of that refusal survives too: {fetched}"
    );
    std::assert_eq!(
        mock.calls(),
        1,
        "an `isError` answer is one dispatch: the worker must not retry a \
         backend that refused. The backend saw {:?}",
        mock.seen()
    );
}
