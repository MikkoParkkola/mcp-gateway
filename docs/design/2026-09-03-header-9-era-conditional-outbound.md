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
this increment, and until it does HEADER.4a is vacuously met. It is not a `_meta` key |
| `params._meta` | **added** | the declaration the revision put in place of `initialize` |
| `MCP-Session-Id` | **omitted on `Request` and `Notify` when the era is `Modern`; kept on `Close` and `Sse`** | see next paragraph. The `Sse` half is a **DESIGN EVENT (§P3)** — neither review decided it |

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
else — and to `Sse`, for the same reason: neither carries a JSON-RPC method, and the
stream a dual-era backend serves is identified by the session it minted, so dropping the
header there breaks continuity for exactly the backends the `Close` exception protects.
So the rule splits by `HeaderMode` rather than by peer — omit on `Request` and `Notify`
when `cached() == Some(Modern)`, keep on `Close` and `Sse` unconditionally. Both reviewers
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
re-asserted from the same per-request read after the custom-header merge.** `MCP-Session-Id`
is not: an operator who pins one gets one, because nothing in the body contradicts it. Both
reviewers raised the override; the narrowing to the headers the body constrains is this
design's, not theirs.

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
bare `Transport::send_request` (`:816-817`), which is how `initialize` and the era probe go
out. Putting the read there instead would modern-shape the handshake on any transport already
classified `Modern` — a session recovery re-initialising, for instance — which is precisely
the traffic the 2026 revision deleted `initialize` from. So the modern value arrives as an
argument from `request_with_headers`/`notify_with_headers`; a caller that passes none gets
today's shape. `Close` (`:1108`) and `Sse` (`:670`) call `build_mcp_headers` directly, pass no
modern value for the same reason, and keep the session header they carry today. The Claude leg
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
- **not an object** (array, scalar) → leave the request untouched and do not declare. There
  is nowhere to put `_meta` without destroying the caller's params, and destroying them is
  worse than an undeclared request. No such call exists on this path today; the rule is here
  so the case is decided rather than discovered.

## Composition with the era probe

Stated so the next reviewer does not have to find it. The probe issues its `server/discover`
through `Transport::request` (`src/backend/era.rs:33`), so it goes through the same builder
as everything else and sees `cached() == None` — no era resolved yet, by definition, since
the probe is what resolves it. It therefore takes the legacy shape and carries the legacy
protocol header. That is the exact defect §3a of the 08-31 design eliminates. This design
neither creates it nor fixes it: the two increments compose in that order, and the ordering
is not a dependency, because `None` → legacy is correct behaviour for this design regardless
of what the probe carries.

The GPT reviewer raised this as a SCOPE-CHALLENGE, reading it as a claim that the
composition already works in current code. It is not that claim — it is the same observation
this paragraph makes, at the same source line. Disposition: no change; the reviewer's
BEFORE-DEPLOY gate is agreed and already recorded as the 08-31 increment's, not this one's.

## Still open

One, opened by review. It does not block this design's own build.

| field | |
|---|---|
| question | when the outbound modern body is assembled, is there a call path where `params` is a non-object? |
| owner | this ticket, at §P2 test-plan time |
| what resolves it | enumerate the callers of the outbound body assembly and read what each passes as `params` |
| when | before the first test is written, since the answer decides whether the "not an object" row is a real case or a defensive one |
| if it resolves badly | if such a path exists, the leave-untouched rule stands and the row becomes a real test rather than a documented impossibility. Either way the rule is already decided above, so nothing waits on the answer |

The question this design was expected to defer — emit or omit the protocol version — turned
out checkable, is recorded above, and was confirmed by the team lead on 2026-09-03. Recorded
in checkable form in `docs/requirements/RELEASE-4.0.0-residue-triage.md`, which no longer
carries it as a deferral.

## Next step

Test plan (§P2), reviewed as a plan before any test is written. One row per clause: the
emitted version value, `Mcp-Method` on a modern request **and on a modern notification**,
`Mcp-Name` on each of the three methods that require it and its absence on one that does not,
the `_meta` body declaration with its three merge shapes, the session header's three
`HeaderMode` arms (absent on a modern `Request` and `Notify` whose backend minted a session
during its legacy handshake, present on that backend's `Close`), the re-assertion of
`MCP-Protocol-Version` over a custom header that tries to pin it, and the
`None`-means-legacy default — the last of which must be
written so it can fail, since "unchanged behaviour" is the assertion most easily satisfied by
a fixture that never reached the code.

**Assert on the captured wire request, not on the builder's return value.** The reviewer's
point, and it is the difference between a plan that can fail and one that cannot:
`build_mcp_headers` is private and its output is merged with static and per-request headers
afterwards (`:607-616`, `:618-624`). A test reading the builder result sees neither a custom
header override nor a body/header divergence nor anything the body half does — the three
failure modes this review actually found.
