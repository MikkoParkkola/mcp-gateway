# SUB.2b — gateway-minted progress token, transport-independent

Design for `MIK-7272.SUB.2b`, outbound half. Reviewed before code.

## Scope

**In.** Make `tests/mik_7272_sub2b_acs.rs::s02_stdio_progress_reaches_its_own_call_before_the_result`
pass: the token the gateway sends to a backend on `tools/call` must differ from the
client's, and the notification delivered back to the client must carry the client's
token byte- and type-identically.

**Out.** `GH475.RL.5` (awaiting a requester ruling). Any change to the SSE decoder's
framing, the overflow policy (ADR-014 §5), or the stdio reaper.

## The base this builds on (verified 2026-09-11)

Two of the three pieces this design needs are **uncommitted work parked in the shared
worktree**, not code on any branch. `git log --all -S` finds
`notification_sink::scope` in `src/gateway/server/mod.rs` and `current_sender` in
`src/transport/notification_sink.rs` on **no commit**; the files were last written
between 02:45 and 02:53 UTC and have not moved since. Stating them as "at HEAD" would
be wrong, and building on them silently would make this change depend on code that may
never land.

Parked, not landed:

- **Client-facing forward path.** `src/gateway/server/mod.rs:1978-1995` installs a
  per-dispatch sink and spawns a writer that writes each notification to stdout
  *concurrently* with the call, so a notification can precede its own result. This is
  what makes the acceptance test's liveness reachable at all.
- **`notification_sink::current_sender` and `send`**
  (`src/transport/notification_sink.rs:107,113`), used by `src/transport/stdio.rs`.

Landed at HEAD:

- `notification_sink::scope` and `publish`
  (`git show HEAD:src/transport/notification_sink.rs`, `:48` and `:87`).
- Backend-facing publish for HTTP: `src/transport/http/sse_decoder.rs:262-265`
  publishes each notification to the request-scoped sink as its SSE frame is decoded,
  inside the requesting task.

Absent everywhere:

- **Any mint.** `src/transport/stdio.rs:436,603,1308` state the opposite rule outright
  ("never mints one"), and `progressToken` has zero occurrences in
  `src/transport/http/mod.rs` and `src/gateway/server/mod.rs`.

**Consequence for sequencing.** The mint (D1) and the translation store (D2) depend on
nothing parked and can land against HEAD. The client-facing half of the acceptance test
cannot pass until the parked forward path lands. This design therefore does not claim to
close `MIK-7272.SUB.2b` on its own: it closes the outbound half, and the row flips only
once both are on the branch.

## Why this is not a stdio-only concern

`ADR-014` §2's table is headed *"Correlation, per transport"* and gives HTTP
*"none needed — the connection is the key"*. That is a statement about **attribution**,
and it is right: an SSE notification on a response body belongs to that request
structurally. Minting answers a different question — **not handing a backend the
client's own token**. The acceptance test asserts the mint against an HTTP backend
(`tests/mik_7272_sub2b_acs.rs:271` configures `streamable_http`; `:509-520` reads the
token off frames that backend received), so the mint cannot live in a transport.

Consequence: `docs/release/SUB2b-implementation-brief.md` §"HTTP needs nothing" is
false as written and is corrected alongside this change.

## D1 — mint site: the backend request funnel

`Backend::request_with_headers` (`src/backend/ops.rs:184`). `Backend::request`
(`:47`) delegates to it, so it is the one function every outbound backend call
passes through, and the comment already at `:193-197` says exactly that of the
`Mcp-Param-*` mirror it already hosts: *"every tools/call — the MCP provider,
meta-MCP invoke, the router's direct backend route — funnels through this one
function, so a per-caller mirror would leave the siblings unmirrored."* The mint
is the same shape of cross-cutting outbound rewrite and takes the same seat.

**An earlier revision put the mint at `src/gateway/meta_mcp/invoke.rs:3018-3024`**
on the strength of that site's own comment, *"`_meta` is one object, so one
writer owns it"*. That comment is true about how `invoke` constructs `_meta`; it
is not true of the system. The router's direct backend route dispatches at
`src/gateway/router/backend_handlers.rs:830,833,888,891` and the file contains no
occurrence of `_meta` or `progressToken` at all — it forwards the caller's params
verbatim. A mint in `invoke` would have left that route handing backends the
client's own token. Reading a single-site ownership comment as a system-wide
invariant is the same error this document already corrected once over ADR-014 §2's
per-transport table.

Placing it at the funnel also keeps `build_outbound_meta`
(`src/gateway/meta_mcp/prompt_cache.rs:235`) a pure merge of inbound fields, with
no scope-sensitive side effect and no signature change.

Rule: if the request carries `_meta.progressToken` **and** the call is inside a
notification scope, emit `_meta.progressToken = "gw-<uuid>"` instead of the
caller's value and record the translation. Outside a scope (health probes,
warm-up handshakes, the reaper) nothing is recorded and the field passes through
unchanged.

`gw-<uuid>` is a `String` by construction, which closes ADR-014 §2's three defects
at the source rather than in the map: it cannot alias a numeric token, it cannot
collide between two in-flight calls, and it cannot be reused by a later call.

## D2 — translation store

A task-local in `notification_sink`, installed by `scope()` next to the existing sender
task-local, holding `RefCell<Vec<(minted: String, client: Value)>>`. The client value is
kept as `Value`, not `String`: the test requires `7` back as `7`, never `"7"`.

New API:
- `mint_progress_token(client: &Value) -> Option<String>` — `None` outside a scope.
- `translate_back(notification: &mut JsonRpcNotification)` — rewrites
  `params.progressToken` from the minted value to the client's.

A list, not a single slot. An earlier revision assumed one mint per scope on the
grounds that the gateway issues one `tools/call` per dispatch, and had
`mint_progress_token` debug-assert the cell was empty. A scope wraps a whole client
request, which may dispatch several backend calls — a JSON-RPC batch, or a meta-tool
that fans out — so that assertion would fire on legitimate traffic. Lookup is linear
over a list whose length is the number of progress-bearing calls in one request.

## D3 — translate-back sites

The notification carries the token at `params.progressToken`; the request carries it at
`params._meta.progressToken`. These are different pointers and both are load-bearing.

Two sites, because the two transports read the notification from different tasks:

1. **HTTP backend** — inside `notification_sink::publish`
   (`src/transport/notification_sink.rs:87`). `publish` is called from
   `sse_decoder::drain_events`, which runs in the requesting task, so the task-local is
   readable there.
2. **stdio backend** — inside the stdio reader's delivery path
   (`src/transport/stdio.rs`, the `send(entry.value(), …)` call). That reader is a
   detached task shared across every call on the backend and can never see the
   task-local. It therefore stores the client token beside the sender when the request
   registers, keyed by the **minted** token, and translates on delivery.

**Eviction (stdio).** The entry is keyed by the minted token and removed when the
owning request's response is consumed, on the same path that already drops the
registration — one insert, one remove, the request's own lifetime. Without this the map
gains a permanent entry per progress-bearing call, which is a leak in a long-lived
gateway process. The removal is an RAII guard rather than an explicit call so a `?` on
the response path cannot skip it; `PendingRequestGuard` in the same file is the in-repo
idiom to match.

**Behaviour on a miss.** `translate_back` is a single shared helper and defines exactly
one non-match policy: **pass the notification through unchanged**. A notification whose
token matches no mapping is not necessarily a leak — a backend may broadcast progress
for work the gateway never minted for — and dropping it would discard a frame the
client is entitled to see. A miss is logged at debug with the method and the unmatched
token so a future mint leak is observable in logs rather than only in client behaviour.
Both call sites inherit this from the helper; neither chooses its own.

Rejected: a single choke point in `send`. `send` is the one place a drop is decided
(ADR-014 §5) and is reached from both a task that has the task-local and one that
cannot; making it responsible for translation would mean passing the mapping in at
every call site, which is the threading the task-local exists to avoid.

## Tests that discriminate

Each must fail at HEAD and pass after.

1. The acceptance binary, `s02_stdio_progress_reaches_its_own_call_before_the_result`.
   Fails at HEAD on `assert_ne!(minted, client_token)` — there is no mint.
2. Unit, `notification_sink`: a client token of `7` (JSON number) round-trips as `7`.
   Guards the `Value`-not-`String` decision in D2.
3. Unit, `notification_sink`: outside a scope, `mint_progress_token` returns `None` and
   the outbound `_meta` is untouched. Guards the health-probe path.
4. Unit, `invoke`: a caller with no `_meta.progressToken` produces outbound params with
   no `progressToken`, so the gateway never synthesises one a client did not ask for.
5. Unit, stdio: two concurrent dispatches on one backend carrying distinct client tokens
   get distinct mints and each receives only its own translated notification. This is
   the only test that exercises the shared reader's map under concurrency.
6. Unit, stdio: a numeric client token `7` round-trips as `7` through the reader's keyed
   map. Test 2 guards the task-local path; the stdio storage path is the one that can
   string-coerce, and test 1 does not pin the token's JSON type.
7. Unit, `notification_sink`: a notification whose token matches no mapping is forwarded
   unchanged, not dropped. Pins the miss policy in D3.

## Sequencing — what lands against HEAD, and what does not

The mint has a live consumer at `HEAD`. `notification_sink::scope` is installed on the
client-facing HTTP dispatch path (`src/gateway/router/handlers.rs:608`, with `collect`
at `:614`), so a call arriving over HTTP reaches `invoke.rs:3018-3024` inside a scope and
mints. D1, D2 and D3 site 1 are therefore reachable behaviour on the branch, not code
waiting for another lane.

What does **not** land with them is the client-facing forward path for stdio —
`notification_sink::current_sender` and `send`, which D3 site 2 calls. That work is
uncommitted in the shared worktree and on no branch. Until it lands,
`s02_stdio_progress_reaches_its_own_call_before_the_result` cannot pass, because nothing
delivers a notification to a stdio client at all.

So this design closes the outbound half: the gateway stops handing a backend the
client's own token, and translates its own token back on the path that can observe it.
The ledger row `MIK-7272.SUB.2b` moves off `ABSENT` only when both halves are on the
branch and the acceptance binary is green. Landing the mint alone is progress on the
row, not closure of it.

## Review status

`grok-review` returned a verdict on this design: **SHIP-WITH-FIXES**
(`~/.claude/data/reviews/runs/grok-20260911T055118Z-19273.md`). Two HIGH findings and
two improvements; the disposition of each:

- **Direct route bypasses the mint** (HIGH). Verified at source and **fixed**: D1 moved
  from `invoke.rs` to the backend funnel. The finding was correct and the design's
  single-writer premise was not.
- **stdio registration leaks on a dropped future** (HIGH). Accepted, **not fixed here**.
  It belongs to D3 site 2 in `src/transport/stdio.rs`, which another lane holds; the
  design already specifies an RAII guard mirroring `PendingRequestGuard` and this
  change does not touch that file.
- **Keep `build_outbound_meta` pure** (improvement). **Adopted** — a consequence of the
  D1 move, at no extra cost.
- **Add an ADR-014 stdio acceptance row** (improvement). Accepted, deferred with D3
  site 2.

`gpt-review` was credit-exhausted for the period (`try again at Sep 15th, 2026`). The
delivery process asks for two independent non-Claude reviewers; one returned. The gate
is recorded as partially met rather than treated as satisfied.

## Risks

- **The mint leaks to the client.** If D3 misses a path, the client sees `gw-<uuid>` and
  cannot match it to its own call. Test 1 asserts the client side explicitly
  (`:501-506`), but only inside the window before the result. On stdio, a notification
  arriving after eviction takes the pass-through branch and would carry the minted
  token; the debug log on a miss is what makes that case visible. It is accepted, not
  prevented.
- **A backend emits progress after its result frame, on HTTP.** This is legal SSE and
  the gateway never sees it. `drain_events` returns as soon as it parses a
  `JsonRpcMessage::Response` (`src/transport/http/sse_decoder.rs:261`) and
  `decode_sse_exchange` returns with it (`:290`), abandoning the rest of the body —
  including any event later in the same chunk. Such a frame is not a translate-back
  miss; it is never decoded. Out of scope here: closing it means changing when the
  decoder stops reading, which is a separate decision about request lifetime.
- **A backend echoes the minted token in its result body** rather than a notification.
  Out of scope and untranslated; the gateway does not rewrite result payloads.
- **Two translate-back sites can drift apart.** Mitigated by both calling one shared
  helper; the helper, not the call sites, owns the pointer and the comparison.
