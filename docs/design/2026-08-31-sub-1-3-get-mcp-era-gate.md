# GET /mcp has no protocol-era gate (MIK-7272 SUB.1, SUB.3)

## Scope

FOR: refusing `GET /mcp` when the caller declares the 2026-07-28 era, so the endpoint the revision
replaced is actually replaced and its resumability is unreachable on that path.

OUT:

- `MIK-7272.SUB.2` clause 2 — emitting `notifications/progress` / `notifications/message` on a
  request's own response stream. That is an unbuilt feature, not a missing gate.
- `MIK-7272.SUB.4`, `TASK.1` — the reissue path.
- The legacy (2025) GET behaviour, which stays exactly as it is.
- `DELETE /mcp`. No criterion covers it and the revision does not remove it.

## Problem

`mcp_sse_handler` (`src/gateway/router/handlers.rs:262`) serves an SSE notification stream to
any caller. It reads `Last-Event-ID` (`:206`) and hands it to `create_sse_response`
(`src/gateway/streaming.rs:326-339`), which stores it as `session.last_event_id` for redelivery.

Nothing in that function asks which protocol era the caller declared: searching the function for
`is_modern` or `RequestShape::Modern` returns nothing. No test exercises `GET /mcp` at all —
`tests/mik_7272_subscriptions_acs.rs` is the only test file that mentions `text/event-stream`, and
only inside the POST `subscriptions/listen` harness.

Two blocking criteria are ABSENT because of this one omission:

- **SUB.1 (GET endpoint replaced)** — `subscriptions/listen` is served, correctly, but the GET
  endpoint it replaces is still served alongside it. Supplemented, not replaced. A client that can
  still reach the old endpoint has no reason to move.
- **SUB.3** — resumability must be gone from the modern path: no `Last-Event-ID`, no event ids, no
  redelivery. Production implements the opposite, unconditionally.

`tests/mik_7272_subscriptions_acs.rs:188` carries a comment asserting "resumability is gone" as the
premise for the tests below it. That premise is false against current source.

## Constraints, measured

- A GET carries no body, so `classify_request` (which reads `_meta` **and** the header) cannot be
  used. The only era declaration a GET can make is the `MCP-Protocol-Version` header.
- `declares_modern_era(version)` (`src/protocol/meta.rs:209`) is the existing single owner of the
  "which era is this" question — `classify_request`'s own doc comment records that splitting that
  predicate in two previously let a request take the legacy path past every modern gate.
- `server.modern_protocol` (`src/config/mod.rs:1127`, default `false`) decides whether the modern
  era is served at all. A modern-declaring POST with it off is refused `-32022 unsupported protocol
  version` (`handlers.rs:708-716`), not served as legacy.
- The POST path refuses a **duplicated** `mcp-protocol-version` header with `-32020`
  (`handlers.rs:745-753`) precisely because an intermediary can split what it sees from what the body
  says. `headers.get()` silently takes the first of two.

## Options

1. **Refuse `GET /mcp` when the header declares the modern era.** One check at the top of the
   handler. SUB.1 closes because the endpoint is no longer reachable on the modern path; SUB.3
   closes as a consequence, because the entire resumable stream is unreachable rather than
   conditionally trimmed. **Chosen.**
2. Keep serving GET to modern callers but ignore `Last-Event-ID` and suppress event ids when the
   era is modern. Closes SUB.3's letter and leaves SUB.1 open — the endpoint is still supplemented.
   It also invents a third stream shape that neither revision specifies, and the finding "the GET
   endpoint is not replaced" survives the fix verbatim. Rejected.
3. Delete `GET /mcp` outright. Closes both, and breaks every conforming 2025 client. The revision
   removes the endpoint on the modern path only. Rejected.

Option 1 is the elimination: after it, "a GET that declares the modern era can resume an SSE
stream" cannot be stated, because such a GET cannot open one. The claim is deliberately about the
declaration, not the client -- a mixed-era client that omits the header is a 2025 caller on this
endpoint, which SUB.1 leaves alone.

## Design

At the top of `mcp_sse_handler`, before the streaming-enabled and Accept checks.

**One tokenisation, then one predicate.** Collect every `mcp-protocol-version` field line, split
each on `,`, trim, drop empties. The count decides:

- 0 tokens: legacy path, unchanged.
- More than 1 token: refuse `-32020 "mcp-protocol-version appears more than once"`, 400.
  This is one mechanism, not two. Two field lines and one comma-combined line are the same
  ambiguity, because RFC 9110 lets any intermediary fold the first into the second. Counting field
  lines alone -- which is what the POST path's `single_header` does (`handlers.rs:738`) -- leaves
  `2025-06-18, 2026-07-28` reading as a single legacy value. POST survives that because its header
  value is then checked against the body's (`HeaderCheck::validate`), and a combined value cannot
  equal the body's single one. A GET has no body, so the tokenisation *is* the check.
- Exactly 1 token: the era question below.

**The era question, mirroring what POST already answers.** `declares_modern_era` (`meta.rs:209`) is
deliberately broader than `MODERN_VERSIONS`: it is true for a 2026 revision this build does not
serve. That breadth is right -- such a caller is stateless, not legacy -- but it does not decide
*which* refusal. The POST path splits it (`handlers.rs:583-589`) and the GET path uses the same
split:

| token | `modern_protocol` | answer |
|---|---|---|
| in `MODERN_VERSIONS` | on | 405 + `Allow: POST`, `-32600`, `"GET /mcp was removed in MCP 2026-07-28; use subscriptions/listen"` |
| declares the era, not in `MODERN_VERSIONS` | on | 400, `-32022 unsupported protocol version '<v>'`, `data.supportedVersions = MODERN_VERSIONS` |
| declares the era | off | 400, `-32022`, `data.supportedVersions = []` |
| anything else (2025 revisions, unknown) | either | unchanged -- the stream opens as today |

Naming `subscriptions/listen` to a caller whose revision this build refuses would send it to a
method that also answers `-32022`; naming it only in the first row is what stops that.

405 is the specification's own answer, not a choice this design gets to make: "HTTP GET or DELETE
to the MCP endpoint: respond with `405 Method Not Allowed`" (2026-07-28 Streamable HTTP, Backward
Compatibility). RFC 9110 then requires a 405 to carry `Allow`, so the response names POST. An
earlier round reached for 404 with `-32601` by analogy to a removed *method* (`handlers.rs:809-817`,
`"method 'X' was removed in MCP 2026-07-28"`); the analogy is sound and the specification still
overrules it, because a status code an intermediary reads is not ours to reason about from
symmetry. `-32600` is the JSON-RPC code this handler already pairs with 405
(`handlers.rs:276-284`), and the message carries what the status cannot: where to go instead. 400 with `-32022` and a `supportedVersions`
array is the POST path's shape for the same client (`handlers.rs:172-196`). No code is invented here.

Two predicates, two jobs, and they are not interchangeable: `declares_modern_era` decides **whether**
to refuse, and `MODERN_VERSIONS` decides only **which** refusal to send. Narrowing the first to the
served list is the bypass its doc comment warns about, and widening the second would name a
replacement method this build refuses for that version.

A caller that declares nothing is served as legacy. That is the classifier's already-settled
trade-off (`meta.rs` module doc), not an open question -- "when the caller declares the modern era"
is the criterion's own term, and an absent header is not a declaration.

Refusals reuse `build_http_error_response`, as the streaming-disabled refusal in the same handler
already does. No refusal sets `Content-Type: text/event-stream`, so a refused caller cannot mistake
one for a stream.

## Unknowns

| question | check | answer | what it changed |
|---|---|---|---|
| Does anything depend on `GET /mcp` with a modern header? | searched `tests/` and `src/` for `mcp_sse_handler` and `text/event-stream` | only the route wiring at `src/gateway/router/mod.rs:233`; no test opens the endpoint | nothing to migrate, and the tests this change adds are the first coverage the endpoint has had |
| Is the era predicate already owned somewhere? | read `src/protocol/meta.rs:96-211` | `declares_modern_era`, whose doc records that a second predicate previously caused exactly this class of bypass | ruled out writing a GET-local version of the check |
| Does a modern-declaring caller reach this build when `modern_protocol` is off? | read `handlers.rs:583-589, 708-716` | POST refuses `-32022`; nothing gates GET | produced the two-branch refusal rather than one message that would misdirect the caller |

No deferred unknowns.

## Decisions this design makes beyond the gate

`NotificationMultiplexer::last_event_id(&self, session_id) -> Option<String>` is added: a read-only
accessor for a field that already exists. SUB.3.1 asserts resumption state is *not* written, and
without a reader that assertion can only be inferred from "no session was created", which is a
weaker claim than the criterion makes. One public symbol, no behaviour change, named here because
it moves the API surface and the design did not originally call for it.

`unsupported_version_error` is extracted from the POST classifier and shared with the GET gate. It
moves a private function into `handlers.rs`'s file-level surface and changes the POST path's
construction site; both paths now build one `-32022` body, which is the point -- two copies is how
the two answers drift.

`NotificationMultiplexer::last_event_id` stays `pub` but is `#[doc(hidden)]`. A reviewer asked for
crate-private; Rust has no test-only public visibility, and SUB.3.1 is an end-to-end claim that only
an integration test can observe. Hiding it from the published surface is the closest honest answer,
and it is recorded here rather than left to be re-found.

## Findings this change does not act on

Both were raised against this diff, both are about `GET /mcp` behaviour SUB.1 does not claim, and
both are recorded here rather than filed -- a ticket costs a human's attention forever and neither
finding names a decision a human has to make.

- **A malformed or unsupported non-2026 version token is served as legacy.** True today, and true
  before this change: the legacy path has never validated its version header. SUB.1 is about the
  era, and narrowing the legacy path is a separate behavioural change with its own compatibility
  question. Disposal: observation.
- **The refusals emit no metric or log.** Worth having during a rollout, and it is an operability
  addition rather than a defect in the gate. Disposal: observation.

## Acceptance criteria

- `MIK-7272.SUB.1.1` -- Given a `GET /mcp` carrying `MCP-Protocol-Version: 2026-07-28`, When the
  gateway serves the modern era, Then the response is 405 with `Allow: POST` and `-32600`, its
  message names `subscriptions/listen`, and its `Content-Type` is not `text/event-stream`.
- `MIK-7272.SUB.1.2` -- Given the same request, When `server.modern_protocol` is off, Then the
  response is 400 with `-32022 unsupported protocol version` and `data.supportedVersions` is empty.
- `MIK-7272.SUB.1.2b` -- Given a `GET /mcp` declaring a 2026 revision this build does not serve
  (`2026-11-01`), When the modern era is served, Then the answer is `-32022` with
  `data.supportedVersions` listing `MODERN_VERSIONS` -- not the `subscriptions/listen` refusal,
  which would name a method this build also refuses for that version.
- `MIK-7272.SUB.1.3` -- Given a `GET /mcp` with no `MCP-Protocol-Version`, or with `2025-06-18`, or
  with `2025-11-25`, Then the SSE stream opens exactly as it does today.
- `MIK-7272.SUB.3.1` -- Given an existing session whose `last_event_id` is set, When a `GET /mcp`
  declaring the modern era arrives carrying that session id and a different `Last-Event-ID`, Then it
  is refused, that session's `last_event_id` is unchanged, and the multiplexer's session count is
  unchanged -- a refusal that ran after `get_or_create_session_for` would mint one entry per
  refused caller.
- `MIK-7272.SUB.1.4` -- Given a `GET /mcp` whose `MCP-Protocol-Version` carries two tokens -- as two
  field lines, or as one comma-combined line -- Then it is refused `-32020` rather than served on
  the first token seen.

## Test plan

All cases are integration-level: request goes through `create_router(state)`, because
`mcp_sse_handler` is `pub(super)` and a test calling it directly would prove nothing about the
route. Home: `tests/mik_7272_subscriptions_acs.rs::http`, reusing its `state(modern)` builder.

| AC | case | level | type | fails today because |
|---|---|---|---|---|
| SUB.1.1 | `ac_sub_1_1_modern_get_is_refused_and_names_the_replacement` | integration | negative | the handler answers 200 with an SSE body |
| SUB.1.2 | `ac_sub_1_2_modern_get_is_unsupported_when_modern_is_off` | integration | negative | no era gate exists in either config |
| SUB.1.2b | `ac_sub_1_2b_unserved_2026_revision_is_not_told_to_use_listen` | integration | negative | an unserved 2026 revision streams like a legacy caller |
| SUB.1.3 | `ac_sub_1_3_legacy_get_still_opens_the_stream` | integration | regression | passes today; it is the row that goes red if the gate over-blocks |
| SUB.3.1 | `ac_sub_3_1_refused_modern_get_leaves_resumption_state_alone` | integration | negative | the handler reaches `get_or_create_session_for` and `create_sse_response` overwrites the stored event id |
| SUB.1.4 | `ac_sub_1_4_duplicate_protocol_version_is_refused` | integration | negative | `headers.get()` takes the first token and serves the stream |

### Can each case fail?

- 1.1, 1.2, 1.2b, 3.1 and 1.4 are red against current source. That failure is free and real; no
  retrofit probe is needed.
- 1.3 is green today by construction, and that is its job: it goes red if the gate refuses a caller
  that declared nothing or declared a 2025 revision. Without it, "refuse every GET" passes every
  other row.
- 1.2b asserts the message does **not** name `subscriptions/listen`. Asserting only the error code
  would let the 1.1 refusal satisfy it.
- 3.1 seeds its session through the real legacy GET path, then asserts the *stored* event id and the
  session count across the refusal. Asserting the status alone would pass for a refusal that still
  minted a session and overwrote the id, which is the defect the criterion names.
- No fixture stands in for production code: the state builder wires the real
  `NotificationMultiplexer` and the real router, and the seed uses the same handler under test.
