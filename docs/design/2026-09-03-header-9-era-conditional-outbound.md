<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: MIT
-->

# HEADER.9a/9b — era-conditional outbound headers

`MIK-7214.HEADER.9a` and `HEADER.9b`, the last pair on the release board with no design
behind it. Assigned 2026-09-03. Design only; no code in this document, and none written
against it until it is reviewed.

## Scope (§P0)

**FOR**: era-conditional outbound emission in `build_mcp_headers` — a request the gateway
sends to a peer it has classified `Modern` carries the modern shape; a request to any
other peer carries exactly what it carries today.

**OUT**:

- adding `2026-07-28` to `SUPPORTED_VERSIONS`. Permanently excluded and pinned by the test
  at `src/protocol/mod.rs:80`; the outbound handshake stays a 2025 negotiation forever.
- the probe and discovery path. `docs/design/2026-08-31-discover-outbound-era-probe.md`
  owns it, including the probe's own header suppression (§3a there).
- inbound classification. `classify_request` and the router's mirrored-header checks are
  settled and this change does not touch them. Note that they are still the *source* of the
  outbound requirement resolved below — out of scope to change, not out of scope to read.
- any change to `Era`, `EraCache`, or when the probe runs. This design consumes the era; it
  does not decide it.

## The problem, at source

`build_mcp_headers` (`src/transport/http/mod.rs:534-627`) is the single outbound header
builder, by its own doc comment. It inserts `MCP-Protocol-Version` at `:560` and
`MCP-Session-Id` at `:595`/`:598`, unconditionally, on every outbound request to every
backend. The value it writes is the legacy handshake's: `protocol_version` (`:200`) is
written at `:469` from `negotiate_protocol_version` (`:644`) and read at `:539-543`,
defaulting to `PROTOCOL_VERSION`.

Era classification landed and is per-backend — `Era::{Modern, Legacy}`
(`src/protocol/era.rs:22-26`), `classify` (`:61`, "Modern requires positive evidence",
`:57`), `EraCache` (`:115`) with `cached()` (`:130`) returning `Option<Era>`;
`Backend::cached_era` (`src/backend/era.rs:61`), resolved on the start path
(`src/backend/lifecycle.rs:232`), field at `src/backend/mod.rs:58`. The header builder
cannot see any of it. That gap is the whole of HEADER.9.

## What "the modern shape" is

Not invented here. `src/protocol/meta.rs:4-37` documents the revision this gateway already
serves inbound: `initialize` is deleted, so a request declares itself in `params._meta`
under reverse-DNS keys — `io.modelcontextprotocol/protocolVersion` and
`io.modelcontextprotocol/clientCapabilities` **required** (`:42`, `:44`),
`io.modelcontextprotocol/clientInfo` optional (`:46`). Sessions are gone with the
handshake.

The shape is four fields, not one. `HEADER.9a` says "the modern `_meta` envelope and the
standard headers" — plural and unenumerated — so what counts as standard is settled
elsewhere, not by this design's preference. `src/protocol/headers.rs` is that anchor, in
shipped source rather than in a test: `:131` "`Mcp-Method`. Required on every modern
request", `:36` "the methods that carry a name, and therefore require `Mcp-Name`", and `:47`
"which body field `Mcp-Name` mirrors". The first draft of this design emitted only the
version and `_meta`; both reviewers found the same two missing fields.

| field | modern peer | where it comes from |
|---|---|---|
| `MCP-Protocol-Version` | **emitted**, `MODERN_VERSIONS[0]` | a constant, read once per request and used for both header and body (below) |
| `Mcp-Method` | **emitted** | the JSON-RPC method. `HeaderMode::Request { method }` carries it (`src/transport/http/mod.rs:206`); `Notify` does **not**, so that arm widens to `Notify { method }`. `Close` is an HTTP DELETE and needs none |
| `Mcp-Name` | **emitted as a header, for the three methods that require it** | a header whose *value* is read from a body field (`params.name`, `params.uri`) per `headers.rs:47`. Sentinel-encoded where the value is not representable in ASCII, per `MIK-7214.HEADER.4a`
(`docs/requirements/RELEASE-4.0.0-requirements.md:121`). The encoder is the inverse of
`decode_header_value` (`headers.rs:79`) and **does not exist yet** — building it is part of
this increment, and until it does HEADER.4a is vacuously met. It is not a `_meta` key.
Where the selected field is missing or not a string, the **header is omitted and the request
goes out**: the field is the caller's content, not this gateway's assertion, and a peer that
requires it is the right place to reject it. Contrast `_meta` below, which carries an
assertion we owe the peer and therefore fails locally |
| `params._meta` | **added** | the declaration the revision put in place of `initialize` |
| `MCP-Session-Id` | **omitted on `Request` and `Notify` when the era is `Modern`; kept on `Close`** | see next paragraph. `Sse` is not in this row: `build_mcp_headers` matches `HeaderMode::Sse => {}` (`mod.rs:600`) and `establish_sse_connection` passes `None` (`mod.rs:667-670`), so no session header is emitted there on any era and there is nothing for this design to omit or keep. An earlier draft raised it as a design event; source says there is no decision to make |

**The session header is omitted per mode, not per peer.** An earlier draft deleted the
omission clause outright, on the reasoning that a modern peer never mints a session so
nothing is ever inserted. That reasoning is wrong for the only modern peer this gateway can
currently reach. The era resolves *after* the handshake (`lifecycle.rs:375` initialises,
`:232` resolves), so a dual-era backend answers the legacy `initialize` first, its
`mcp-session-id` response header lands in the map (`:873`), and every later call finds it
there (`:590`) — including calls the gateway has by then classified `Modern`. Deleting the
clause therefore sends a forbidden session header on exactly the path 9a is about.

The orphan risk that motivated the deletion is real but narrower than the deletion was: it
applies to `Close`, which must still terminate a session the backend minted, and to nothing
else. `Sse` needs no exception because it has no session header to lose — `build_mcp_headers`
matches `HeaderMode::Sse => {}` (`:600`) and `establish_sse_connection` passes `None`
(`:667-670`), on every era, before and after this change. An earlier draft argued the `Close`
case for `Sse` too and raised the result as a design event; reading the arm showed there was
nothing to decide.
So the rule splits by `HeaderMode` rather than by peer — omit on `Request` and `Notify`
when `cached() == Some(Modern)`, keep on `Close` unconditionally. Both reviewers
raised this; the GPT leg proposed a lifecycle-versus-ordinary mode and the Claude leg named
the mode boundary exactly. `HeaderMode` already is that boundary, so no new mode is added.

**A custom header can overwrite what this design emits. DESIGN EVENT (§P3): the design
decides it may.** The user-supplied `self.headers` loop runs *after* everything above
(`:607-616`) and uses `insert`, so a backend configured with an explicit
`MCP-Protocol-Version` or `MCP-Session-Id` overrides or reinstates it on the modern path.
This is a decision the design makes rather than a fact it reports, so it is named as one
here: **the modern branch does not reserve, strip, or reject either name, with one
exception.** A custom header is an operator's deliberate instruction about one specific
backend, and silently dropping it would make configuration lie. What 9a promises is that the
*gateway* stops originating the header, not that the header becomes unreachable.

The exception is `MCP-Protocol-Version`, and it is not a preference. On the modern path that
value also appears in the body, so an override does not express an operator's intent about
one header — it produces a frame whose header and `_meta` disagree, which this gateway's own
inbound check rejects (`HeaderMismatch`). A configuration that cannot produce a valid request
is not configuration worth honouring. **On the modern branch only, `MCP-Protocol-Version` is
re-asserted from the same per-request read after *every* custom-header merge on the path being
built.** The merges are not the same on both paths, and a design that named only the request
path's would have left notifications unprotected:

- **`Request`** has two. The static `self.headers` merge happens inside `build_mcp_headers`
  (`mod.rs:607-616`); the per-request `extra_headers` merge happens in
  `send_request_with_headers` at `mod.rs:846-854`, *after* the builder has returned. The
  re-assertion therefore lives after that merge, not inside the builder.
- **`Notify`** has one, and it is inside the builder. `notify_with_headers` calls
  `build_mcp_headers` and posts the result directly (`mod.rs:1051-1053`) — there is no
  `extra_headers` merge on this path at all. A re-assertion sited only in
  `send_request_with_headers` never runs for a notification, so the static merge at
  `:607-616` would win and `Modern`/`Notify` could not hold its version or method cell.
  Notify gets its own finalisation, on the headers the builder returned, before the post.

That is also why `Close` and `Sse`, which call the builder directly and pass no modern value,
keep today's shape for these headers.

`MCP-Session-Id` was exempted in an earlier revision — "an operator who pins one gets one,
because nothing in the body contradicts it". **That was wrong against the requirement.**
`MIK-7215.STATELESS.3a` is a prohibition, not a default:
`docs/requirements/RELEASE-4.0.0-requirements.md:92` — "The gateway MUST NOT emit
`Mcp-Session-Id` on the modern path." Not minting one is not enough; a statically configured
one reaching a modern peer violates it just as squarely. So on `Modern`/`Request` and
`Modern`/`Notify` the header is **removed** at the same finalisation point where the other
three are re-asserted, whatever any merge put there. `Close` keeps it, because `Close` is not
on the modern path. The rule is therefore not "a header the body constrains is re-asserted"
but "the finalisation owns four headers on the modern path: three asserted, one removed" —
and the operator-preference argument does not reach a MUST NOT.

Both reviewers raised the override; the narrowing to the headers the body constrains was this
design's, not theirs, and the session half of that narrowing is what the requirement retracted.

`Mcp-Method` and `Mcp-Name` fall on the same side of that line as the version and are
re-asserted with it: both mirror a body field the peer re-reads, so an override makes header
and body disagree exactly as a pinned version does — `HeaderMismatch`, or worse, a call routed
under the wrong name. The rule is therefore not "the version is special" but "a header the
body constrains is re-asserted"; three headers meet it, `MCP-Session-Id` does not.

The reviewer's proposed hardening — treat both names as case-insensitive reserved fields —
is half already true and half declined. Already true: the loop parses into
`reqwest::header::HeaderName`, which is case-insensitive, so a custom `mcp-session-id`
collides with `MCP-Session-Id` rather than sitting beside it; no separate mechanism is
needed for that. Declined: rejecting a conflicting configuration, for the reason above. The
residual is stated rather than closed — a backend configured with a stale session header
sends one, and that is the operator's configuration doing exactly what it says.

`HEADER.9b` — "values derived from the negotiated envelope, not the legacy handshake
version" — is satisfied by construction, but only if the header and the body cannot
disagree. **One era read and one version value per request, used for both.** The emitted
value is `MODERN_VERSIONS[0]` (`src/protocol/meta.rs:216`), a constant, *not* the string
`protocol_version` holds. There is no negotiated 2026 string to derive from and there never
will be, because `SUPPORTED_VERSIONS` excludes the revision permanently. 9b's requirement is
that the value not come from the handshake; a constant meets it. The divergence objection is
real in the general case and answered by the single-source rule, not by the constant on its
own: two independent reads on either side of an era flip could still differ.

**The mechanism, since a rule without one is a wish.** The body is assembled before
`build_mcp_headers` runs, so the era must be read where the body is: once at the top of
`request_with_headers` (`src/transport/http/mod.rs:968`) and `notify_with_headers` (`:1045`),
which are the two outbound body-assembly owners on this transport. That single read shapes
`_meta` and is passed into `build_mcp_headers` as the already-chosen value. The builder then
writes what it is given rather than reading the era a second time. This is what the rejected
alternative below was rejected *in favour of*: not an `Era` argument on every call site, one
value on the two sites that assemble a body.

**Those two sites, and no others — which is what keeps the handshake legacy.** `Request`
headers are built in `send_request_with_headers` (`:830`), and that function also serves the
bare `Transport::send_request` (`:816-817`), which is how `initialize` goes out (`:451`,
`:486`). Putting the read there instead would modern-shape the handshake on any transport
already classified `Modern` — a session recovery re-initialising, for instance — which is
precisely the traffic the 2026 revision deleted `initialize` from.

**Named constraint: `initialize()` must not route through `request_with_headers`.** Today it
does not, and the only thing recording that is an inline comment on the MIK-5982 session
recovery — "`initialize()` calls `send_request` directly (not `request`), so this cannot
recurse" (`mod.rs:996`). That comment is load-bearing for this design and was written for a
different purpose: it exists to argue the recovery cannot loop, not to protect an era
invariant that did not yet exist. Anyone re-routing `initialize()` through `request` later,
for any unrelated reason, would silently modern-shape the recovery handshake against a peer
whose era the handshake itself is supposed to establish, and no test would notice. Stated
here as a constraint of this design and pinned by a matrix row, so the invariant survives an
edit made for a reason that has nothing to do with eras.

The era probe is **not** in that set, and an earlier draft said it was. It goes out through
`transport.request(DISCOVER_METHOD, None)` (`src/backend/era.rs:33`), which is
`Transport::request` (`:957`) calling `request_with_headers` (`:958`) — one of the two sites
that *do* read the era. **An earlier revision of this document said it stays legacy because
`cached()` returns `None` at probe time. That is wrong, and the way it is wrong disables the
whole mechanism.** `EraCache::resolve_with` holds the era mutex *across* the probe await
(`src/protocol/era.rs:150-161`) — deliberately, so concurrent resolution serialises onto one
probe — and `cached()` takes that same mutex (`:131`). Tokio's `Mutex` is not re-entrant, so
the probe's own request, arriving at `request_with_headers`, would not read `None`: it would
*await a guard its own call frame holds*. `PROBE_TIMEOUT` (2s) then cancels the probe,
`classify(ProbeOutcome::NoAnswer)` answers `Legacy`, and `resolve_with` deliberately caches
nothing. Every backend start would pay two seconds and no peer would ever resolve `Modern`.
The mechanism would be inert in production while every test that primes the cache directly
stayed green.

**So the hot-path read is non-blocking: it must be unable to await the probe's guard.** The
outbound sites read the era through a `try_lock`-shaped accessor and treat contention as
`None`. That is not a workaround for the lock, it is the truthful answer: while a probe is in
flight the era is *by definition* undetermined, and the probe's own request must be
legacy-shaped. The two facts coincide, which is why this eliminates the finding rather than
guarding against it — after the change the deadlock cannot be described, because no outbound
read can block on the era mutex at all.

`invalidate` rejected exactly this shape (`era.rs:140-143`: "under contention it would
silently do nothing... a control that fails silently is worse than one that blocks briefly"),
and that rejection does not reach here. `invalidate` is a **control**: contention makes it
fail to do the thing it was called to do. `cached()` on the outbound path is an
**observation**, and its contention answer — no era resolved yet — is true, not silent
failure. The two calls need opposite shapes for the same reason.

`EraCache` therefore gains one accessor this increment: a synchronous, non-blocking read
alongside `cached()`. That is a public-surface addition (D28) on a type §P0 declares out of
scope for *behavioural* change; adding a read that cannot block is not a change to what `Era`
or `EraCache` mean, and this design does not touch `resolve_with`, `invalidate` or the
classification rules. Flagged rather than assumed, because it is the one line of this design
that reaches into a type the scope statement fences off.

So the modern value arrives as an
argument from `request_with_headers`/`notify_with_headers`; a caller that passes none gets
today's shape. `Close` (`:1108`) and `Sse` (`:670`) call `build_mcp_headers` directly, pass no
modern value for the same reason, and so emit today's headers: `Close` keeps the session
header it carries, `Sse` continues to carry none. The Claude leg
raised this against the repair and was right that the site matters; it named `Close` and `Sse`
as callers of `send_request_with_headers`, which the source does not bear out — they have
their own call sites — but the conclusion is unchanged.

## Questions, and how they were settled

| question | how it was settled | what came back | what it changed |
|---|---|---|---|
| for a Modern peer, is `MCP-Protocol-Version` emitted or omitted? | *raised as askable; turned out checkable* — read `src/protocol/meta.rs:99-104` and `src/gateway/router/handlers.rs:552-568` | the revision uses **mirrored headers**: the gateway's own inbound path "refuses a modern request that omits `MCP-Protocol-Version`, so every modern request that survives carries it" (`handlers.rs:556`), and classifies on header **and** body precisely so the two cannot disagree (`meta.rs:99-104`) | removed the omit option. Omitting it outbound would have the gateway send modern requests it would itself reject inbound — an asymmetry with a citation, not a preference. Confirmed by the team lead 2026-09-03, who re-read both anchors at source; the routing chose the question's FORM, not the answer, and finding the rule moved it from askable to checkable |
| is the era known when the handshake runs? | read the construction path: `lifecycle.rs:360` constructs, `:375` calls `initialize()`, `resolve_era` runs later at `:232` via `reconcile_after_start` | no — and permanently not, because the probe is issued through the transport after it is up | forced the era read to be **per request**, not at construction. `build_mcp_headers` is already `async` and `cached()` is `async`, so the read costs nothing structural |
| is an era always available? | `cached()` returns `Option<Era>` (`src/protocol/era.rs:130`) | no — `None` before the probe resolves, and on any backend that never probes | made `None` an explicit case rather than an assumed one: **`None` maps to the legacy shape**, which is `classify`'s own positive-evidence rule (`era.rs:57`) rather than a second policy invented here |
| does the era cache reach the transport today? | read `HttpTransport::new`/`new_with_oauth` (`src/transport/http/mod.rs:266`, `:280`) and the call site (`src/backend/lifecycle.rs:360`) | it does not, but `self.era` is in scope at the call site — the `Arc` exists exactly where the transport is built | made the plumbing a three-line change rather than a mechanism, and named the API-surface cost below |

## What to build

Share the backend's `Arc<EraCache>` into `HttpTransport`. The era is read at the two
body-assembly sites named above, never inside `build_mcp_headers`, which writes the value it
is handed:

- `Some(Era::Modern)` → emit `MCP-Protocol-Version: MODERN_VERSIONS[0]`, `Mcp-Method`, and
  `Mcp-Name` **as headers**, add `_meta` to the body from the same read, and **omit
  `MCP-Session-Id` on `Request` and `Notify`**.
- `Some(Era::Legacy)` or `None` → today's behaviour, byte for byte.

Three details of the modern branch live outside `build_mcp_headers` and are easy to lose by
reading only the bullet above. The finalisation is **per path, at the last writer on that
path**: on `Request` that is after the per-request `extra_headers` merge (`mod.rs:846-854`),
past the builder's return; on `Notify` there is no per-request merge at all, so it is after
the builder returns and before the post (`mod.rs:1051-1053`). An implementation that writes
the values inside the builder is overridable by per-request configuration on `Request`; one
that finalises only in `send_request_with_headers` leaves `Notify` unshaped entirely. Second,
a **malformed body fails the call locally on this branch, before any send** — three shapes,
one rule: a non-object `params`, an object `params` whose `_meta` is not an object, and a
named method whose name source (`params.name`, `params.uri`) is missing or not a string.
Third, that third shape reverses an earlier decision to omit `Mcp-Name` and send anyway. The
reversal is deliberate and its reason is consistency, not diagnostics: two adjacent
malformed-body shapes with opposite dispositions is the split rule that produces the next
defect, and a gateway that forwards a call it can already see is malformed spends a network
round trip to learn what it knew. The cost is a new local failure on a path that previously
had none, which is why it is named here rather than left to the implementation.

An earlier revision of this section said the opposite of all three — that the builder reads
`cached()` itself, that `Mcp-Name` travels in the body, and that nothing is removed because a
modern peer mints no session. The repairs above retracted each one and this section was left
behind; the confirmation pass caught it. Recorded rather than silently corrected, because a
repair that updates one section and not the one an implementer reads first is the failure
mode, not an editing slip.

**API surface (D28).** `new` and `new_with_oauth` are public and called from tests; widening
both signatures is an API-surface change for a value only one caller can supply. Prefer a
setter — the same shape as `mark_single_tenant` (`src/backend/lifecycle.rs:373`), which
already exists for exactly this situation: a fact only the pool key knows, told to the
transport after construction. A setter is *itself* a public-surface addition, as the
reviewer noted — the choice is not between an API change and none, it is between adding one
symbol and changing two existing signatures every caller must follow. D27: no new
dependency, no new module edge; the transport already depends on `protocol`, which is where
`EraCache` lives. Rejected alternative: an `Option<Arc<EraCache>>` parameter on both
constructors, which changes two public signatures and leaves every test passing `None`.

**Alternatives rejected.** Threading an `Era` argument through every `build_mcp_headers`
call site — mechanical, and it puts the era on the call path of code that has no business
knowing about it. Moving header construction up to `Backend` — a much larger change that
would move the "single source of truth for all outgoing request headers" out of the
transport that sends them.

**The body half: `_meta`, and the body field `Mcp-Name` reads.** `build_mcp_headers` cannot
reach `params`, so this lands where the outbound request body is assembled — named, not left
to the implementer: `request_with_headers` (`src/transport/http/mod.rs:968`) and
`notify_with_headers` (`:1045`). Those two are the HTTP transport's owners and this design's
whole scope; **stdio and websocket outbound `_meta` is OUT** (§P0 already scopes this design
to `build_mcp_headers`' transport), deferred to whichever increment gives those transports an
era at all — today they have none to read. The test plan must cover both halves or 9a is only
half met. What goes in, exactly:

| field | value | source |
|---|---|---|
| `io.modelcontextprotocol/protocolVersion` | the same `MODERN_VERSIONS[0]` read the header used | required (`meta.rs:42`) |
| `io.modelcontextprotocol/clientCapabilities` | `{}` — an empty object | required (`meta.rs:44`), and `{}` is what this gateway already declares outbound today: the legacy `initialize` body it sends carries `"capabilities": {}` (`src/transport/http/mod.rs:443`, `:478`). So the modern envelope declares neither more nor less than the handshake it replaces — no regression to name. `meta.rs:63` warns against copying an attacker-sized value, so a minimum is the safe value as well as the honest one |
| `io.modelcontextprotocol/clientInfo` | omitted | optional (`meta.rs:46`). The Claude leg asked for it, on the symmetry with `clientCapabilities`; declined, because the two are not symmetric — `clientCapabilities` is *required* (`STATELESS.9b`, `-32602` if absent) while `clientInfo` is self-asserted and may not influence any decision (`IDENT.1b`). Emitting an optional untrusted field buys nothing 9a asks for |

Merge behaviour, for each shape `params` can take — the reviewer was right that leaving this
implicit invites three different implementations:

- **absent** → create `params` as an object carrying only `_meta`.
- **an object** → merge `_meta` in. An existing `_meta` object keeps its other keys; the
  **two** reverse-DNS keys this design writes — `protocolVersion` and `clientCapabilities` —
  overwrite whatever held them. `clientInfo` is neither inserted nor stripped: a caller that
  set one keeps it, and this design adds none.
- **an object whose `_meta` is not an object** (null, scalar, array) → **fail the call
  locally, before anything is sent**, on the same rule and for the same reason as a non-object
  `params`. The reviewer was right that the shape was left undefined: three implementations
  were available — overwrite the caller's value, nest under it, or send it unchanged — and
  each is wrong differently. Overwriting destroys data the gateway does not own; sending it
  unchanged emits a frame carrying no `clientCapabilities`, which a modern peer is required
  to reject (`-32602`), turning a local diagnosable error into a remote one. Failing locally
  is the only response that neither lies nor loses anything.
- **not an object** (array, scalar) → **fail the call locally, before anything is sent.**
  There is nowhere to put `_meta` without destroying the caller's params, and an undeclared
  modern request is not the harmless fallback the first draft assumed: `_meta` is where
  `clientCapabilities` is asserted, and a modern peer is required to reject a request that
  omits it with `-32602` (`docs/requirements/RELEASE-4.0.0-requirements.md:104`, STATELESS.9b).
  Sending anyway buys a round trip and the same failure, minus the explanation. Failing locally
  is not a behaviour change for any input that works today, because the modern shaping path is
  new — every call today takes the legacy branch, which this rule does not touch.

  **DESIGN EVENT (§P3).** No review decided this. The first draft's leave-untouched rule was
  written on the belief that no such caller existed, and the enumeration below shows one does.
  It is named rather than absorbed silently because it introduces a local failure the design
  did not previously have. It moves nothing in §P0's FOR or OUT, changes no acceptance
  criterion, and adds no wire behaviour — the failure is strictly before the send.

## Composition with the era probe

Stated so the next reviewer does not have to find it. The probe issues its `server/discover`
through `Transport::request` (`src/backend/era.rs:33`), so it goes through the same builder
as everything else and reads the era through the non-blocking accessor above, which answers
`None` under the probe's own contention — no era resolved yet, by definition, since
the probe is what resolves it. It therefore takes the legacy shape and carries the legacy
protocol header. That is the exact defect §3a of the 08-31 design eliminates. This design
neither creates it nor fixes it: the two increments compose in that order, and the ordering
is not a dependency, because `None` → legacy is correct behaviour for this design regardless
of what the probe carries.

The GPT reviewer raised this as a SCOPE-CHALLENGE, reading it as a claim that the
composition already works in current code. It is not that claim — it is the same observation
this paragraph makes, at the same source line. Disposition: no change; the reviewer's
BEFORE-DEPLOY gate is agreed and already recorded as the 08-31 increment's, not this one's.

## Unknowns — resolved, none deferred

**Is there a call path where the outbound `params` is a non-object?** — enumerated the callers
of the outbound body assembly (`.request(`, `.request_with_headers(`, `.notify(` and
`.notify_with_headers(` across `src/`) — **yes**. Most callers pass `None` or a literal
object, but the gateway's own pass-through forwards the connected client's params unchanged
(`src/gateway/router/backend_handlers.rs:814`, `src/gateway/meta_mcp/invoke.rs:2510`), typed
`Option<Value>` and never narrowed to an object; JSON-RPC permits array params, so a client
can produce one. — **changed the rule**: the leave-untouched disposition above was written for
a case believed unreachable and would have sent an undeclared modern request on a reachable
one. It is now a local failure, and the test plan's non-object `_meta` case is a real case
rather than a defensive one.

The question this design was expected to defer — emit or omit the protocol version — turned
out checkable, is recorded above, and was confirmed by the team lead on 2026-09-03. Recorded
in checkable form in `docs/requirements/RELEASE-4.0.0-residue-triage.md`, which no longer
carries it as a deferral.

## Next step

Test plan (§P2), reviewed as a plan before any test is written. One row per clause: the
emitted version value, `Mcp-Method` on a modern request **and on a modern notification**,
`Mcp-Name` on each of the three methods that require it and its absence on one that does not,
the `_meta` body declaration with its five merge shapes, the session header's three
`HeaderMode` arms (absent on a modern `Request` and `Notify` whose backend minted a session
during its legacy handshake, present on that backend's `Close`), the re-assertion of all three
constrained headers over custom values at the last writer on **each** path, the outbound
encoder over every row of the repository's own `SPEC_ENCODING_TABLE`, and the
`None`-means-legacy default — the last of which must be
written so it can fail, since "unchanged behaviour" is the assertion most easily satisfied by
a fixture that never reached the code.

Two rows carry the plan's weight and neither is about a value being wrong. **Production era
wiring**: every other case primes the era cache as a fixture input, so all of them pass
against a lifecycle that never attaches the cache to the transport — a green suite over a
feature that never runs. **A read while the probe is in flight**: it asserts elapsed time as
well as shape, because the blocking read this design rejects also answers legacy, two seconds
later, and would satisfy a shape-only assertion.

**Assert on the captured wire request, not on the builder's return value.** The reviewer's
point, and it is the difference between a plan that can fail and one that cannot:
`build_mcp_headers` is private and its output is merged with static headers inside itself
(`:607-616`) and, on the `Request` path only, with per-request `extra_headers` afterwards
(`:846-854`). An earlier draft cited `:618-624` for the second merge; that block is the
ambient trace-id insert, and an implementer sent there would finalise before the merge that
overrides. A test reading the builder result sees neither a custom
header override nor a body/header divergence nor anything the body half does — the three
failure modes this review actually found.

## Canonical criteria — DoR and DoD, applicable only

This increment is DOCS: a design and a test plan, no source change. Both canonical files
cited by full path, per §P4.

`rules-source/workflows/quality-gates-dor.md` — DOCS applicability is `G0`, `G4-G5`, `L1`,
`O1-O3`:

| gate | verdict |
|---|---|
| G0 biggest ROI | the design gates every later HEADER.9 commit; nothing in this milestone can be built ahead of it |
| G4 requirements clear | `MIK-7214.HEADER.9a`, `9b` and `4a` quoted at source in `docs/requirements/RELEASE-4.0.0-requirements.md` |
| G5 critic — real problem, minimum scope | the problem is at `src/transport/http/mod.rs:534`, unconditional today; §P0 names four carried exclusions |
| L1 IP | no new dependency, no third-party text |
| O1-O3 structure, clutter, naming | two files under `docs/design/`, named for their date and criterion, matching the directory's convention |

`rules-source/workflows/quality-gates-dod.md` — DOCS applicability is `H1-H11`, `D7`, `D9`,
`D14`, `D15`, `D24`:

| gate | verdict |
|---|---|
| H1-H5 search, update, consolidate, location, naming | searched before creating; the requirement text is cited, never restated; the residue-triage entry is updated in place rather than duplicated |
| H6-H11 orphans, redundancy, temp files, tracking | both files are referenced from the readiness board and from each other; no temp files; both tracked |
| D7 wired | the design is consumed by the test plan, which is consumed by the implementation increment that follows |
| D9 static | N/A — no source, no linter or type checker applies to Markdown here |
| D14 documented | these files *are* the documentation; §P4a's question is whether they make any other document untrue, answered below |
| D15 clean | the residue-triage deferral this design closed is removed there, not left contradicting |
| D24 enforcement | N/A — a design document has nothing to enforce; the rules it decides are enforced by the test plan's cases, which is the next increment |

**§P4a documentation delta.** `docs/requirements/RELEASE-4.0.0-residue-triage.md` carried the
protocol-version question as an open deferral with a leading option; this design settled it,
so that entry is updated in the same change. No other document is made untrue: the requirement
text is unchanged, and the readiness board's row for HEADER.9 already points here.
