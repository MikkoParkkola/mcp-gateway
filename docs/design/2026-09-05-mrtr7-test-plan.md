# MRTR.7 production bridge — test plan

Status: full HTTP + stdio release delta awaiting fresh design and test-plan
review. Companion: [design](2026-09-05-mrtr7-bridge-wiring.md). No new test code
is written or runtime pass claimed by this amendment. Canonical process and
DoR/DoD paths, scope approval and review-provenance limitation are in the design.

## Existing evidence to preserve

`tests/mik_7212_mrtr7_bridge_acs.rs` currently declares **23 tests**: 18 MRTR.7
acceptance cases, three fixture/contract checks and two MIK-7388 projection
regressions. This count was obtained from source on 2026-09-06; the prior design
reported 23 passing, but this amendment has not rerun that command. The tests
exercise the real `InputBridge::run` using trait fakes, not the production
channel or session capture. Keep them all; adapt the fake backend to typed `Ok(...)` and equality checks
to variant/field assertions if the original typed backend error removes `Eq`
from `BridgeError`. The fake channel accepts the new delivery-progress argument
and marks handoff only for a simulated delivered request. Preserve their intent,
including the already-delivered unanswered-prompt case. Root approved the
pinned-spec elicitation correction: replace obsolete content-only backend
expectations with whole accepted ElicitResult objects, keeping existing case
names and the one InputBridge implementation. Those changed tests receive their
own review before implementation.

Three additional real-process stdio tests exist in
`tests/mik_7212_mrtr7_stdio_acs.rs`. Their current `#[ignore]` markers record
missing implementation. Remove those markers with the implementation and run
all three in ordinary CI before declaring full bridge acceptance. Repair the
shared `asking_call` helper first: it currently inserts
`io.modelcontextprotocol/protocolVersion` and `clientCapabilities` in `_meta`,
which classifies the request as Modern despite its 2025 version string. Legacy
calls must omit those protocol keys and declare support only in initialize's
`params.capabilities`; assert `RequestShape::Legacy` on that fixture. Send
`notifications/initialized` after the initialize response in STDIO.1/3, and
stage it explicitly in STDIO.2. This corrects the existing fixtures, not the
production classifier, to exercise the approved legacy requirement.

| row | test |
|---|---|
| 308 | `ac_mrtr_7a_elicitation_params_reach_the_client_whole` |
| 309 | `ac_mrtr_7a_a_method_outside_the_closed_set_is_refused_unsent` |
| 310 | `ac_mrtr_7a_wire_methods_and_id_prefixes_match_the_admitted_set` |
| 311 | `ac_mrtr_7a_an_undeclared_variant_is_not_asked_under_an_empty_slice` |
| 313 | `ac_mrtr_7b_an_accepted_answer_is_filed_under_the_backend_key` |
| 314 | `ac_mrtr_7b_a_decline_fails_the_call_as_a_refusal_by_a_person` |
| 315 | `ac_mrtr_7b_an_error_reply_fails_the_call_as_a_client_refusal` |
| 316 | `ac_mrtr_7b_an_unusable_accept_fails_as_malformed` |
| 317 | `ac_mrtr_7b_content_violating_the_requested_schema_is_forwarded_unchanged` |
| 318 | `ac_mrtr_7b_the_retry_bound_cuts_off_after_three_retries` |
| 319 | `ac_mrtr_7b_the_request_budget_is_checked_before_a_batch_is_sent` |
| 320 | `ac_mrtr_7b_an_unanswered_prompt_ends_its_round_not_the_call` |
| 321 | `ac_mrtr_7b_answered_rounds_are_ended_by_the_aggregate_deadline` |
| 322 | `ac_mrtr_7b_a_batch_of_three_answers_arrives_in_one_retry` |
| 325 | `ac_mrtr_7a_a_session_declared_capability_is_asked_with_no_slice` |
| 326 | `ac_mrtr_7a_sampling_and_roots_each_complete_an_accepted_round` |
| 327 | `ac_mrtr_7b_cancel_unnamed_action_and_no_member_fail_distinguishably` |
| 328 | `ac_mrtr_7ab_a_bridged_round_is_counted_without_the_answer_body` |
| — (fixture) | `ac_mrtr_7b_the_shipped_bounds_are_the_documented_ones` |
| — (fixture) | `ac_mrtr_7b_the_asking_fixture_is_what_the_parser_reads` |
| — (fixture) | `ac_mrtr_7a_the_capability_fixture_declares_what_it_names` |
| 312 / `MIK-7387.STDIO.1` | `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` — in `mik_7212_mrtr7_stdio_acs.rs`, `#[ignore]`d today; required enabled release case |
| 323 / `MIK-7387.STDIO.2` | `ac_mrtr_7a_bridged_request_follows_the_initialize_response` — same file, `#[ignore]`d today; required enabled release case |
| 324 / `MIK-7387.STDIO.3` | `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` — same file, `#[ignore]`d today; required enabled release case |
| MIK-7388.BRIDGE.5 | `mik_7388_an_action_member_does_not_reshape_a_sampling_answer` |
| MIK-7388.BRIDGE.5 | `mik_7388_an_elicitation_reply_without_an_action_fails_as_malformed` |

The component cases cannot prove production reachability. No production suite
may substitute a fake session store, fake `ClientChannel`, or a reimplementation
of `InputBridge::run` for the owner whose behavior it asserts.

## Production acceptance matrix

Existing `WIRE.*` IDs retain their intent except `WIRE.10`: the operator's full
stdio scope replaces its former all-stdio refusal expectation with an
**unsupported-client refusal control**. A capable, ready stdio client now must
complete the affirmative STDIO.1 journey. Planned test names below are prefixes
for named cases, not evidence of tests already implemented.

| AC / planned case | Given / when / then and falsifier | V-model level | Type |
|---|---|---|---|
| `MIK-7212.WIRE.1` / `mik_7212_wire_modern_cannot_inherit_session` | Initialize elicitation, then send well-formed modern `_meta` omitting elicitation while the backend asks it. Assert MRTR.9 refusal and zero client frames. Explicit modern metadata is required; absent `_meta` would test Legacy instead. An unconditional merge fails. | Integration | Negative/security |
| `MIK-7212.WIRE.2` / `mik_7212_wire_legacy_reads_initialize` | Real initialization records a declaration; ready legacy invoke causes a client question and backend retry with that answer. Run through each transport's caller-context constructor. The unwired implementation cannot emit the question. | Integration | Positive |
| `MIK-7212.WIRE.3` / `mik_7212_wire_undeclared_refuses_before_send` | Legacy initialization omits capability, or the session is absent; backend asks. Assert bounded refusal, zero frames, zero retry. Include unsupported elicitation mode and a mixed batch containing one undeclared entry: no partially sent batch. A fail-open default fails. | Integration | Negative/security |
| `MIK-7212.WIRE.4` / `mik_7212_wire_modern_uses_only_request` | Two modern invokes under a session declaring elicitation, with request metadata declaring sampling only: sampling yields a continuation and zero old client frames; elicitation refuses. Mixing both into one backend batch would obscure the first assertion. Bridging every capable client fails. | Integration | Boundary/regression |
| `MIK-7212.WIRE.5` / `mik_7212_wire_every_attempt_accounted` | Backend asks twice then completes: assert three paid dispatches and each applicable metrics/error-budget/cost/spend sink matches actual attempts. Separate budget fixture admits first attempt, denies second: zero second backend call/spend and the same `-32003` plus block reason reaches caller. Existing pre-governance invocation statistics/rank use still count the attempted denied retry (two attempts); paid-dispatch/error-budget/cost/spend counters count only the first actual dispatch. A bare-Value error conversion, duplicate sink or bypassed budget fails. | Integration | Positive/negative/governance |
| `MIK-7212.WIRE.6` / `mik_7212_wire_retry_bounds_match_attempts` | Repeated input requests exceed round or aggregate/request budgets. Assert the bridge's existing bounds stop dispatch, accounting agrees with actual attempts and pending state drains. Include a backend retry that never completes: the existing aggregate deadline must cancel that wait and return Deadline without another retry. Test elapsed bounds with controlled time where the production clock supports it. Duplicated counters or uncancelled futures fail. | Integration | Boundary |
| `MIK-7212.WIRE.7` / `mik_7212_wire_session_lifecycle` | Successfully bridge once, then DELETE that owner session and retry under its old ID: no inherited declaration or pending entry. Also reaper eviction; owner-authorized reconnect retains declaration while a different owner cannot read/delete/answer it. Success before removal prevents a no-op store passing. | Integration | Lifecycle/security |
| `MIK-7212.WIRE.8` / `mik_7212_wire_http_roundtrip` | Real HTTP initialize + initialized notification, legacy tools/call, backend `input_required`, live SSE question, same-session reply POST, final result and cleanup. Exercise elicitation, sampling and roots; assert exact raw params including unknown fields, absent params where applicable, original bridge ID, exact backend overlay and no continuation for the finished legacy exchange. Keep this case single-stream so a delivery-selection failure cannot hide loss of raw fields. A stubbed adapter or altered params/ID fails; the separate WIRE.18 case owns stream selection. | System | End-to-end/conformance |
| `MIK-7212.WIRE.9` / `mik_7212_wire_final_result_settles_and_caches` | Backend asks then succeeds; assert idempotency completed. Follow up with a different idempotency key but identical response-cache key and assert no backend call. Reusing the first idempotency key alone would not exercise cache eligibility. A verdict derived from the first interim fails. | Integration | Regression |
| `MIK-7212.WIRE.10` / `mik_7212_wire_stdio_unsupported_refuses_promptly` | Initialized stdio without the requested capability, and an unavailable-channel control: refused inside a 2-second deadline, zero question frames/retries. Pair with STDIO.1's capable success. The former test demanding refusal for a capable stdio client is retired; an uninitialized-only fixture is not this row. | System | Negative/compatibility |
| `MIK-7212.WIRE.11` = `MIK-7388.BRIDGE.2` / `mik_7388_channel_abort_cleans_pending` | Real `ProxyManager` channel and live receiver accept the supplied ID and never answer. Await pending-ID precondition under 5 seconds, abort task, await cancelled join, assert that ID removed. Repeat cancellation during awaited receive and live exchange outer timeout; assert pre-handoff expiry fails delivery while an acknowledged still-live unanswered prompt retains row 320; cover no receiver, JSON-RPC error, bridge-owned prompt timeout and normal completion. For the acknowledged still-live timeout case, assert the answer key is omitted and it does not become a whole-call adapter TimedOut error. NoSession alone or inspection before join is invalid staging. Missing RAII fails. | Integration | Cancellation/negative |
| `MIK-7388.CANCEL.1` / `mik_7388_cancelled_exchange_cannot_steal_reply` | Cancel a real HTTP and real stdio bridged exchange after observing its prompt, verify cleanup, start another exchange, then inject old, duplicate, unknown and wrong-session replies. New waiter stays pending until its own admitted response, with no old retry. Assert owner state before and after so a resolver discarding every response cannot pass. | System | Isolation/race |
| `MIK-7387.STDIO.1` / existing `ac_mrtr_7a_stdio_client_answers_while_serve_loop_reads` | Spawn the gateway executable with fixture backend; complete valid handshake, start legacy call, receive its question, reply while call is still pending, inspect backend inputResponses and final original-ID response. Extend the fixture across elicitation, sampling and roots. A serial reader or writer cannot reach the answer assertion. | System | End-to-end |
| `MIK-7387.STDIO.2` / existing `ac_mrtr_7a_bridged_request_follows_the_initialize_response` | Pipeline initialize, initialized notification and a prompt-capable call; inspect raw output ordering, asserting initialize response precedes prompt. Add a deterministic writer-seam fixture that holds the gateway initialize flush pending while a prompt-capable call is ready; zero prompt bytes may pass it. Release flush, withhold initialized, assert no prompt yet, then send initialized and complete. The existing backend initialize delay does not delay the gateway local initialize response and cannot falsify this barrier; do not use that timing as the oracle. | System | Ordering/conformance |
| `MIK-7387.STDIO.3` / existing `ac_mrtr_7a_concurrent_bridged_requests_write_whole_frames` | Two calls are outstanding before either answer, each produces a question, then answers arrive in reverse order. Assert nonzero expected frame counts, every line parses independently, exact IDs/content, both final responses and correctly keyed backend overlays. Keep large-payload process coverage, but add a deterministic short-writing AsyncWrite seam: force a yield between fragments while two dispatches are ready, and show the same fixture tears a frame under a deliberately unserialized writer. The production one-writer path must emit two complete frames. Empty output or probabilistic interleaving is not sufficient evidence. | System | Concurrency/framing |
| `MIK-7212.WIRE.12` / `mik_7212_wire_stdio_saturation_still_reads_replies` | Fill the concrete reviewed in-flight bound with calls waiting on input; submit excess work and then valid replies/cancellation. Assert bounded admission refusal, replies still finish existing calls, and capacity is reclaimed. Reader-awaiting-a-permit deadlocks; unbounded spawn violates observed bound. | System | Capacity/negative |
| `MIK-7212.WIRE.13` / `mik_7212_wire_stdio_shutdown_drains` | EOF, closed stdout, output saturation/lag and parent task cancellation while real prompts and dispatches are pending. Await shutdown under the recorded deadline, assert no pending session entries or live dispatch/writer tasks and no post-close backend retry. One detached task or conversion of lost output into timeout retry fails. | Integration + system | Lifecycle/fault injection |
| `MIK-7212.WIRE.14` / `mik_7212_wire_stdio_dispatch_parity` | Use existing public stdio fixture for batch/mixed notification envelopes, malformed JSON, duplicate active request IDs, cancellation, discovery before initialize, and inbound telemetry before an awaited handler. Explicit `initialize_with_prompt_batch` subcase sends initialize and a prompt-capable call in one JSON-RPC batch: assert initialize result, `-32600` for that call member, zero outbound prompts, and batch completion before the client sends initialized. Then send initialized and a separate call that succeeds so blanket refusal cannot pass. Assert existing error/response shapes, no notification response, no lost cancellation and durable observation. Moving observation behind await or waiting for initialized inside the batch fails. | System | Regression/conformance |
| `MIK-7212.WIRE.15` / `mik_7212_wire_initialize_is_once_per_session` | Two concurrent initializes target one fresh session: exactly one captures its declaration. Bridge under the winner, reject reinitialize both during and after that call with `-32600`, then create a fresh owned session lacking the capability and assert refusal. Explicit empty narrowing asks nothing. Mutable or unioned declarations fail; changing support requires a fresh session/process. | Integration | Lifecycle/security |
| `MIK-7212.WIRE.16` / `mik_7212_wire_legacy_confirmation_composes` | Through the confirmation owner's fixture, capable legacy HTTP and stdio admin requests receive a valid form requestedSchema and complete after whole ElicitResult `{action:"accept",content:{}}`. A strict fixture rejects missing requestedSchema. Explicit decline/cancel, missing/nonobject content, unknown/missing action, JSON-RPC errors and all non-admin requests refuse with zero destructive dispatch; malformed/client-error replies are terminal refusals, not Unsupported warning fallback. Incapable/unavailable/timed-out legacy stdio remains refused. Legacy HTTP genuinely unavailable confirmation retains its canonical warning fallback, separately identified and never counted as confirmed. Modern request takes CONFIRM.2's input-required path, zero old-channel requests. Confirmation's own plan owns full replay/cache/audit assertions. | System | End-to-end/security dependency |
| `MIK-7212.WIRE.17` / `mik_7212_wire_observation_omits_payloads` | Capture both production observer records and the live ingress/dispatch tracing logs for success, malformed reply, refusal and timeout with unique secret sentinels in prompts/answers. Assert `phase="bridge"` and required kind/outcome/count fields, no session-ID metric labels, and absence of payload sentinels from both logs and observer records. Enable debug logging so the existing HTTP reply-body log at handlers.rs is exercised. Reuse existing component row 328; a no-op observer, missing bridge phase or logged payload fails. | Integration | Observability/privacy |
| `MIK-7212.WIRE.18` / `mik_7212_wire_http_single_recipient_and_handoff` | Attach two real SSE streams to one admitted session; one question is received exactly once total and its same-session answer completes the original call. Separate deterministic cases hold the selected body before handoff, close it and assert NoSession plus zero backend retry; repeat closure after handoff while awaiting the response. On pre-handoff deadline expiry, assert delivery failure rather than answerless retry. Run ordinary broadcast-notification regressions separately. Enqueue-only acknowledgement or replay to the other stream fails. | Integration + system | Delivery/conformance |
| `MIK-7212.WIRE.19` / `mik_7212_wire_stdio_owner_cannot_be_http` | Host both transport edges over the actual shared multiplexer; create a stdio-local session and complete a bridge. Present its exact ID through HTTP GET, reply POST and DELETE as unauthenticated and authenticated callers. None can read its prompt, answer its waiter, resume or remove it; its genuine stdio response still succeeds. DELETE assertions require the separately owned `GH452.SESSION.1` implementation; this package neither changes HTTP DELETE nor treats today's bearer DELETE as passing evidence. Reuse of anonymous owner or prefix collision fails. | System | Isolation/security |
| `MIK-7212.WIRE.20` / `mik_7212_wire_elicitation_results_and_url_adapter` | Over both real HTTP and stdio, a valid form answer reaches backend inputResponses as the whole `{action, content}` result, including unknown result fields. A URL-capable client receives the backend URL/message/unknown fields unchanged plus only a missing legacy elicitationId equal to the exact bridge ID, answers `{action:"accept"}` with no content, and the backend receives that action-only result and opaque state before returning the final result. Separate cases preserve an existing valid elicitationId, reject a present null/empty/nonstring ID before any prompt in a mixed batch, refuse undeclared URL mode, reject missing form content and content-bearing URL acceptance. No ID is inserted into form/sampling/roots params. Content-only projection, invented form content or lost unknown params fails. | Component + system | Conformance/positive/negative |
| `MIK-7212.WIRE.21` / `mik_7212_wire_interim_admission_precedes_question` | An input_required challenge is refused by configured D1 fail_closed/no tool contract: zero client frames, pending IDs and backend retries. Separate cases declare a tool contract but forbid a sentinel located only inside prompt params, exceed its challenge byte bound, trigger D2 action mode, firewall Block and context-integrity enforcement. Each refuses before that artifact is exposed; an allowed neighbour still completes. Repeat with a permitted first round and a blocked second challenge: no second prompt or subsequent retry, while first-round counts remain truthful. Final result has its separate single inspection; final-only FWR-02 is not challenge coverage. A dedicated bridged-checkpoint case must observe an admitted first prompt and valid answer, then exactly one completed side-effecting backend retry whose final response is refused by policy. Resubmit the original call with the same idempotency key and assert the recorded effect remains one, with zero extra backend dispatch or prompt. A direct call with no prompt cannot satisfy this case; omitting the checkpoint in the retry path must make it fail. | Integration + system | Security/ordering/regression |
| `MIK-7212.WIRE.22` / `mik_7212_wire_http_control_progress_at_capacity` | Use the actual HTTP handler with a small normal semaphore; fill it with calls waiting on observed prompts. Valid reply, initialized and cancellation control ingress remains usable and finishes those calls. Pure-control and mixed control/normal batches process controls first, release their control permit, then non-blocking-admit normal members; saturated members receive -32000 and never wait while holding control occupancy. Fill normal capacity with unrelated prompt-waiting calls, submit at least the configured control limit of mixed batches with `notifications/initialized` controls and normal calls, await their bounded per-member capacity responses, then answer an unrelated pending prompt successfully. Holding mixed-batch control permits across normal admission must fail this discriminator; normal members never bypass admission. An initialize-plus-prompt batch returns initialize success plus prompt-member -32600 without waiting for initialized. Separate controls exhaust the actual control lane, assert prompt HTTP503 without consuming replies, release capacity and prove recovery. Wrong-owner replies and a forged methodful result cannot use the lane to resolve pending work or dispatch tools. | System | Capacity/concurrency/security |

WIRE.20 uses legacy 2025-11-25 for URL journeys and includes separate omitted
mode (valid default form) and explicit null/nonstring/unknown mode negatives.
The invalid-mode batch must emit zero frames even when form was declared.
Invert the existing protocol unit case
`an_explicit_null_mode_resolves_the_same_way_as_an_absent_one` and rename it
to express refusal; preserve a separate omitted-mode success case. WIRE.20 also
splits missing/null/scalar/array params, missing/nonstring message,
missing/nonobject requestedSchema, non-object schema type/nonobject properties,
and missing/nonstring/invalid URL. Each invalid request appears beside a valid
request in a mixed batch and emits zero total frames; valid adjacent fixtures
preserve all unknown fields and complete. Shared result-validator cases are
consumed by both bridge and legacy confirmation, with whole accepted result
preservation asserted by the bridge.
Form-schema subcases admit every pinned primitive and single/multi-select enum
variant, including titled options and valid optional constraints/defaults.
Separate nested-object, array-of-objects, arbitrary-array, unknown property
type, unsupported reference/composition, malformed option/default/constraint
and invalid required-list cases refuse a mixed batch with zero frames/retries.
Do not fetch schema references. The existing content-violates-requested-schema
case must still forward the whole accepted object result: request-schema
validation must not become answer-content validation.
WIRE.8 and STDIO.1 also assert every actual backend retry has a fresh JSON-RPC
request ID, while the original caller ID remains stable in the final response.
WIRE.21 filters firewall events by server-owned artifact kind: one
`bridge_challenge` scan/final-action audit per internally consumed legacy
challenge, and one `final_response` inspection for the eventual externally
returned result. A modern externally returned InputRequired uses only its
external response boundary: the firewall owner's real modern-wire control
refuses question/state-changing redaction before one final Block audit and
proves allowed inputRequests/requestState remain exact. The firewall owner's FWR-20 covers the shared
helper's Block/Warn/Allow/mutation/disabled controls; WIRE.21 owns actual
client-frame and backend-retry proof through that helper.

WIRE.20 schema refusal controls include duplicate `required` names and `$ref`
or `allOf` beside an otherwise supported primitive type. The latter fixtures
must not rely on a missing-type refusal: removing the forbidden-key guard must
make them fail, even when every other shape check is intact. Each asserts
`MalformedParams`, zero client frames and zero backend retries for the batch.

Use separate named cases under each prefix so one early failure does not hide a
sibling contract. WIRE.11 splits `abort_after_register`, `abort_awaiting_reply`,
`no_receiver`, `client_error`, `pre_handoff_expiry`,
`handed_off_live_timeout`, `normal_completion` and
`cancel_during_partial_stdio_write`. The last case must complete a whole frame
or close the transport within its deadline, with no pending waiter or backend
retry. WIRE.16 splits capable affirmative HTTP/stdio, explicit decline/cancel,
`malformed_form_result`, `jsonrpc_error_reply`, non-admin HTTP/stdio, incapable/unavailable/timed-out stdio, legacy HTTP warning
fallback and modern continuation controls. Keep each case's decisive assertion.

WIRE.12 also has independent `pre_initialize_capacity` (8 waiting requests),
`response_queue_capacity` (32 frames), `request_writer_queue_capacity`
(configured positive streaming buffer) and `zero_streaming_buffer` cases.
Configure a small writer request queue, fill it while preventing handoff and
prove the next enqueue refuses without a retry or exceeding that queue bound.
A zero streaming buffer must fail configuration before serving, never silently
clamp. Fill the pre-initialize queue, admit the configured eight requests and
assert the excess request gets the non-blocking `-32000` response while the
reader can still accept initialized/cancellation. Fill the response queue and
stage another admission refusal: if its error frame cannot be enqueued, the
defined result is bounded transport shutdown, not an impossible extra frame.
Hold/release each capacity precondition explicitly and demonstrate recovery
where the design keeps the connection open. Record queued serialized bytes as
well as item counts and assert both return to zero after drain; this does not
claim an additional default output-size or process-RSS budget.

## Canonical criterion-to-case matrix

Stable canonical IDs, rather than the historic numeric row offsets, are the
release closure keys. WIRE IDs are supporting tests under these requirements.

| Canonical criterion | Bridge cases / scope disposition |
|---|---|
| `MIK-7212.MRTR.7a` | WIRE.1–4, 7–8, 10–11, 14–15, 18–23; STDIO.1–3; existing component rows 308–312, 325–326. Production HTTP and stdio affirmative delivery both required. |
| `MIK-7212.MRTR.7b` | WIRE.5–6, 8–9, 11–13, 17–18, 20–23; STDIO.1/3; CANCEL.1; component rows 313–324 and 327–328. Assert complete collected client results in real backend retries and final caller result, not just prompt emission. |
| `MIK-7212.MRTR.1a`, `MIK-7212.MRTR.1b` | WIRE.8 and STDIO.1 inspect backend retry overlays with inputResponses and opaque backend requestState. Modern client field extraction remains regression coverage in `tests/mik_7212_acs.rs`; this bridge does not replace it. |
| `MIK-7212.MRTR.2a`, `MIK-7212.MRTR.2b` | WIRE.4 modern continuation control and WIRE.8 no legacy continuation/body leak. Full modern mint/seal behavior remains in the existing MRTR/continuation suite; a held-open legacy exchange creates no client continuation. |
| `MIK-7212.MRTR.3a`, `MIK-7212.MRTR.3b` | Existing `tests/mik_7212_acs.rs` / MRTR component suite owns modern verification/tamper controls. No new redemption path in this bridge; run those regressions after invoke extraction. Backend-owned retry state must not be redeemed as a gateway handle. |
| `MIK-7212.MRTR.4a`, `MIK-7212.MRTR.4b` | Existing continuation tests own principal/request binding; WIRE.7/19 and CANCEL.1 cover newly shared legacy session/reply isolation. These are complementary, not substitutes. |
| `MIK-7212.MRTR.5a`, `MIK-7212.MRTR.5b`, `MIK-7212.MRTR.5c`, `MIK-7212.MRTR.5d` | Existing continuation suite and the separately owned lifetime/idempotency work own single-use, expiry, atomicity and replica behavior. N/A to new legacy continuation minting because the bridge mints none; regression run remains required. |
| `MIK-7212.MRTR.6` | Existing modern-client-to-legacy-backend routing/fail-explicitly suite owns the opposite direction. No second exchange or failover replay introduced by this bridge; it cannot close that separate criterion with a local prompt test. |
| `MIK-7212.MRTR.8a`, `MIK-7212.MRTR.8b` | WIRE.6–7, 11–13 and CANCEL.1 verify newly held bridge count/lifetime/cleanup; separately owned [scheduled continuation expiry](2026-09-06-continuation-scheduled-expiry.md) remains required for idle continuation residency. Pending guards alone do not replace that timer. |
| `MIK-7212.MRTR.9`, `MIK-7212.MRTR.9a` | WIRE.23 exact supported kind/mode advertisement and current-request declaration; WIRE.1–4, 10, 15, 20 and the existing declared-kind/mode/slice component cases. Zero frames on whole-batch refusal is part of the oracle. |
| `MIK-7212.MRTR.10a`, `MIK-7212.MRTR.10b` | WIRE.9 verifies final-result settlement/cache after a bridge; existing modern retry fingerprint tests remain required. The CONFIRM.2 test plan owns cache-before-redemption at its distinct meta-tool gate. |
| `MIK-7387.STDIO.1`, `MIK-7387.STDIO.2`, `MIK-7387.STDIO.3` | Named system fixtures plus WIRE.12/14 capacity and dispatch-parity cases and deterministic flush/short-write falsifiers above; required enabled in ordinary CI. |
| `MIK-7388.CANCEL.1` | CANCEL.1 real transport cases plus WIRE.11/13/18; a removed waiter must not be answerable through another exchange or transport. |

## Component criteria and truthful exclusions

- Rows 308–328 retain their named intent with the pinned-spec payload correction:
  row 308 uses a real URL-mode request and action-only accepted reply, while
  checking the fake channel receives the original params. WIRE.20 proves the
  separate production legacy envelope adaptation. Rows 313/317/322 assert the
  whole accepted form result under its backend key, rather than content alone;
  schema-invalid content is still forwarded inside that unchanged result.
  Row 316 remains a form-mode malformed-content negative, paired with a valid
  URL action-only positive; do not weaken it to allow missing form data.
  Row 320 also pins
  `MIK-7388.BRIDGE.4`: an abandoned answer has **no** `/inputResponses/k1` key;
  accepted empty content and decline are distinct outcomes. Preserve this
  assertion; do not invent approval from timeout. `MIK-7388.BRIDGE.1` was retired
  with the withdrawn defect, so it receives no replacement acceptance claim.
- The two existing kind-aware projection tests cover `MIK-7388.BRIDGE.5`;
  full-suite regression covers `MIK-7388.BRIDGE.3`. They are not reasons to
  rebuild `InputBridge::project` in the adapter. Its mode-aware result correction
  stays in the existing bridge, and sampling/roots preservation remains exact.
- `MIK-7387.STDIO.1`–`.3` have executable fixtures and remain mandatory even
  while ignored in the current tree. No unsupported-client refusal can close
  those positive cases.
- CONFIRM.2 modern replay/cache/audit cases are owned by its [test
  plan](2026-09-06-confirm-2-destructive-confirmation-test-plan.md), not
  duplicated here. WIRE.16 proves the shared session/channel composes.
- Real Open WebUI on Spark is the personal-account reference environment. Its
  installation is not evidence that it supports every bridge method; protocol
  fixture clients exercise declared methods and real-client acceptance remains
  separately required by the release plan.

## WIRE.23 — trusted per-attempt modern capability advertisement

This supporting row completes canonical MRTR.7a/7b and MRTR.9. It does not
replace any existing positive bridge, declaration or refusal row. Review the
[source-backed design delta](2026-09-05-mrtr7-bridge-wiring.md#capability-advertisement-delta--strict-modern-backend-review-pending)
before authoring dependent source. Existing component approvals do not certify
this transport contract.

| Case / type | Discriminating fixture and required evidence |
|---|---|
| `wire23_modern_backend_requires_trusted_declaration` / integration, functional | Strict modern server/discover backend refuses tools/call unless modern protocol metadata and the expected supported input kinds/modes are present. Real ready legacy client asks/answers; capture question plus final result, exact original tool/arguments, retry fields only at sibling level, full accepted result and unchanged backend state. Record two distinct backend IDs. Removing capability propagation must fail the declaration assertion before any question. |
| `wire23_exact_capability_projection` / component + integration, functional/security | Independently named exact-wire cases for NONE, sampling-only, roots-only, form-only, URL-only and both elicitation modes; assert the complete bounded capability object, with a strict backend question of each declared kind/mode. Unknown-only and invalid-only elicitation mode objects parse to no known modes and advertise no elicitation key at all, never `{}`. Mixed known/unknown mode declaration retains only its known mode. Dropping sampling or URL projection must fail its own positive case. |
| `wire23_narrowing_and_none_do_not_advertise_support` / component + integration, security | Already form-only source declaration plus sampling/roots is narrowed by the existing capability-name slice to elicitation only (and separately empty), producing exactly form-only or NONE. This does not invent mode-level slicing. Absent/unready session and independent backend request/request_with_headers paths advertise NONE. Untrusted protocol capability metadata and an argument named clientCapabilities cannot widen it. Explicit no-support backend control returns ordinary completed result and zero client frames. |
| `wire23_concurrent_callers_keep_disjoint_declarations` / integration, isolation | Barrier-controlled callers share one backend transport: form-only A and roots-only B enter concurrently, backend records disjoint per-attempt declarations, responses arrive in reverse order, and both retries retain their own declaration, opaque state and accepted result. No sleep establishes concurrency. No session identity or capability state persists on the shared transport. |
| `wire23_modern_caller_declaration_and_retry_are_local` / integration, regression | Modern caller's per-request validated declaration reaches a strict modern backend, including the sealed continuation retry through the original target. The trusted retry target is carried from the single redemption, not rediscovered by a second consume. The retry uses the new request's effective declaration and existing MRTR refusal policy; it never inherits another caller's declaration or bypasses narrowing. This is distinct from the legacy bridge's fixed declaration across its internally owned retries. |
| `wire23_metadata_extensions_and_legacy_peer_are_preserved` / component + integration, compatibility | Unrelated metadata and user arguments survive; forged capability/protocol keys are overwritten by trusted facts. Existing modern notifications/probes still advertise NONE. A genuine legacy backend receives its existing envelope without modern injection. Existing propagated identity headers and backend accounting/retry tests remain green through the shared entry. A staged transient transport failure exercises automatic backend retry: observe the same declaration on both attempts and distinct backend request IDs, with no lost identity headers. |

U9 outcome is pending execution. First measure the missing-declaration assertion
on current source, then full journey success after the reviewed change. Test
code is reviewed as tests; compilation-only failures do not close the behavioral
red. Report exact matched counts, no ignored positives, and separate refusal
controls from successful bridge journeys. The three existing real-process
stdio case names retain their legacy client and are upgraded only to the strict
modern HTTP backend fixture; no modern metadata is added to the legacy client. Controlled
writer/readiness tests still own deterministic ordering and whole-frame proof.

## Fail-fast order and evidence labels

1. Review this matrix and design. Questions are: every AC has a case or justified
   N/A, and every fixture can fail against a concrete defect. Root records fresh
   verdicts bound to full material, then owns a separate test-code review.
2. Resolve design U2's bounded-capacity/error/deadline inventory and U4's shared
   ownership interface before their dependent source edits. Review U5
   before HTTP delivery implementation: the selected private request-queue and
   handoff-progress mechanism replaces broadcast for requests only.
3. Write and run `WIRE.11` red first against the raw production adapter seam.
   A compile error demonstrates a missing interface, **not** the cancellation
   defect. The executable red must stage a real pending entry that survives
   cancellation without the guard. Record command, exact assertion and exit.
4. Declaration/shape rows 1–4 and 15 plus WIRE.20 (U6 mode, required-request
   fields, whole results and URL adaptation) before connecting production
   delivery. Then accounting/bounds/cache/lifecycle rows 5–7 and 9, with
   WIRE.21 (U7 admission and bridged completed-effect checkpoint) before the
   invoke hook. Re-run all 23 component tests after the typed-result change.
5. WIRE.23/U9 strict backend declaration red before capability propagation;
   each supported kind/mode must have its own exact-envelope positive and
   unknown-only/empty refusal control. No dependent transport implementation
   precedes this reviewed executable falsifier.
6. WIRE.22 (U8 real HTTP control capacity and mixed-batch permit release)
   before the production HTTP bridge. Then real stdio rows (existing three
   plus 10, 12–14), then complete HTTP WIRE.8
   raw params, separate WIRE.18 stream selection/handoff and WIRE.19 stdio
   owner isolation, cleanup/isolation CANCEL.1,
   confirmation WIRE.16 and observer WIRE.17.
7. Broaden to applicable release regression, clippy/fmt, coverage/mutation and
   independent functional execution. Attach exact commands and artifacts to
   acceptance and DoD records; never infer passes from a source count.

Current outcomes for **planned** tests are unknown. Static inspection predicts
positive production bridge cases fail because no caller/adapter exists, while
refusal controls can pass on an unwired implementation. Those are **I**, not
measured reds. The three ignored stdio cases and deferred executable evidence
for the decisions recorded in U2–U9 remain
visible blockers to their dependent implementation or release acceptance.

Targeted commands after reviewed tests exist (the implementation owner records
the final filenames and nonzero matched-test counts):

```sh
cargo test --test mik_7212_mrtr7_bridge_acs
cargo test --test mik_7212_mrtr7_stdio_acs -- --include-ignored
cargo test -- mik_7212_wire
cargo test -- mik_7388
```

The ordinary stdio command must subsequently pass with **zero ignored tests**.
For this documentation amendment, validation is test-name/AC inventory, relative
link resolution and `git diff --check`; it does not claim these runtime commands
were run, reviews passed, CI passed, or release blockers closed.
