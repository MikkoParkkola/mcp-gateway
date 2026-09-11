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

## D1 — mint site: the single outbound `_meta` writer

`src/gateway/meta_mcp/invoke.rs:3018-3024` builds the outbound params and its comment
already claims sole ownership: *"`_meta` is one object, so one writer owns it"*. Both
backend transports converge here (`:3037` and `:3040`). The mint is computed in `invoke.rs`, which already sits inside the request scope, and
the minted value is passed into `build_outbound_meta` as an argument.
`build_outbound_meta` today merges the caller's trace context and this hop's cache key
and reads no ambient state; it keeps that property. Minting is gateway policy — *never
hand a backend the client's own token* — so the decision stays in the gateway layer and
only the mapping goes into the transport-owned sink.

Rule: if the caller's `_meta.progressToken` is present **and** the call is inside a
notification scope, emit `_meta.progressToken = "gw-<uuid>"` instead of the caller's
value and record the translation. Outside a scope (health probes, warm-up handshakes,
the reaper) nothing is recorded and the field passes through unchanged.

`gw-<uuid>` is a `String` by construction, which closes ADR-014 §2's three defects at
the source rather than in the map: it cannot alias a numeric token, it cannot collide
between two in-flight calls, and it cannot be reused by a later call.

## D2 — translation store

A task-local in `notification_sink`, installed by `scope()` next to the existing sender
task-local, holding `Option<(minted: String, client: Value)>`. The client value is kept
as `Value`, not `String`: the test requires `7` back as `7`, never `"7"`.

New API:
- `mint_progress_token(client: &Value) -> Option<String>` — `None` outside a scope.
- `translate_back(notification: &mut JsonRpcNotification)` — rewrites
  `params.progressToken` from the minted value to the client's.

One mint per request. The gateway issues one `tools/call` per dispatch, so a second
mint inside one scope cannot occur; rather than add an untestable reuse branch for it,
`mint_progress_token` debug-asserts the cell is empty. If the invariant is ever broken,
an assertion names the bug instead of a silent reuse hiding it.

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

## Risks

- **The mint leaks to the client.** If D3 misses a path, the client sees `gw-<uuid>` and
  cannot match it to its own call. Test 1 asserts the client side explicitly
  (`:501-506`), but only inside the window before the result — a notification arriving
  after eviction takes the pass-through branch and would carry the minted token. The
  debug log on a miss is what makes that case visible; it is accepted, not prevented.
- **A backend echoes the minted token in its result body** rather than a notification.
  Out of scope and untranslated; the gateway does not rewrite result payloads.
- **Two translate-back sites can drift apart.** Mitigated by both calling one shared
  helper; the helper, not the call sites, owns the pointer and the comparison.
