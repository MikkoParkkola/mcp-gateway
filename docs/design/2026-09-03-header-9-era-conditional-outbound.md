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

The shape is four fields, not one, and the same inbound rules the gateway already enforces
say what each of them is. `tests/mik_7214_acs.rs:109` is the normative anchor for the two
this design first missed: "`Mcp-Name` is required for three methods, and for no others",
alongside `Mcp-Method` on every modern frame (`tests/nfr_sec1_controls.rs:150-158`).

| field | modern peer | where it comes from |
|---|---|---|
| `MCP-Protocol-Version` | **emitted**, `MODERN_VERSIONS[0]` | a constant, read once per request and used for both header and body (below) |
| `Mcp-Method` | **emitted** | the JSON-RPC method. `HeaderMode::Request { method }` already carries it (`src/transport/http/mod.rs:206`), so this one is free |
| `Mcp-Name` | **emitted for the three methods that require it** | a body field, not a header input — see the body-side note below |
| `params._meta` | **added** | the declaration the revision put in place of `initialize` |
| `MCP-Session-Id` | **nothing to do** | see next paragraph — the omission this requirement asks for already holds by construction |

**The session header needs no era branch, and adding one would be a defect.** The whole
block is guarded by `if let Some(session_id) = session` (`:590`), and the map is only ever
populated from a backend's own `mcp-session-id` response header (`:873`). A modern peer
never mints one, so nothing is inserted and there is nothing to omit. Branching on era
instead would be actively wrong: the era resolves *after* the handshake
(`lifecycle.rs:375` initialises, `:232` resolves), so a backend that gave us a session and
was then classified `Modern` would have its `Close` sent without the id it minted — an
orphaned session, caused by the omission rule rather than prevented by it. The requirement
is met by deleting the clause, not by writing it. Raised by the GPT reviewer as a
lifecycle-mode finding; eliminated rather than patched, per the repair protocol's step 0.

**A custom header can overwrite what this design emits. DESIGN EVENT (§P3): the design
decides it may.** The user-supplied `self.headers` loop runs *after* everything above
(`:607-616`) and uses `insert`, so a backend configured with an explicit
`MCP-Protocol-Version` or `MCP-Session-Id` overrides or reinstates it on the modern path.
This is a decision the design makes rather than a fact it reports, so it is named as one
here: **the modern branch does not reserve, strip, or reject either name.** A custom header
is an operator's deliberate instruction about one specific backend, and silently dropping it
would make configuration lie. What 9a promises is that the *gateway* stops originating the
header, not that the header becomes unreachable.

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
that the value not come from the handshake; a constant meets it. The GPT reviewer's
divergence objection is real in the general case and answered here by the single-source
rule, not by the constant on its own: two independent reads of the same constant on either
side of an era flip could still differ.

## Questions, and how they were settled

| question | how it was settled | what came back | what it changed |
|---|---|---|---|
| for a Modern peer, is `MCP-Protocol-Version` emitted or omitted? | *raised as askable; turned out checkable* — read `src/protocol/meta.rs:99-104` and `src/gateway/router/handlers.rs:552-568` | the revision uses **mirrored headers**: the gateway's own inbound path "refuses a modern request that omits `MCP-Protocol-Version`, so every modern request that survives carries it" (`handlers.rs:556`), and classifies on header **and** body precisely so the two cannot disagree (`meta.rs:99-104`) | removed the omit option. Omitting it outbound would have the gateway send modern requests it would itself reject inbound — an asymmetry with a citation, not a preference. Confirmed by the team lead 2026-09-03, who re-read both anchors at source; the routing chose the question's FORM, not the answer, and finding the rule moved it from askable to checkable |
| is the era known when the handshake runs? | read the construction path: `lifecycle.rs:360` constructs, `:375` calls `initialize()`, `resolve_era` runs later at `:232` via `reconcile_after_start` | no — and permanently not, because the probe is issued through the transport after it is up | forced the era read to be **per request**, not at construction. `build_mcp_headers` is already `async` and `cached()` is `async`, so the read costs nothing structural |
| is an era always available? | `cached()` returns `Option<Era>` (`src/protocol/era.rs:130`) | no — `None` before the probe resolves, and on any backend that never probes | made `None` an explicit case rather than an assumed one: **`None` maps to the legacy shape**, which is `classify`'s own positive-evidence rule (`era.rs:57`) rather than a second policy invented here |
| does the era cache reach the transport today? | read `HttpTransport::new`/`new_with_oauth` (`src/transport/http/mod.rs:266`, `:280`) and the call site (`src/backend/lifecycle.rs:360`) | it does not, but `self.era` is in scope at the call site — the `Arc` exists exactly where the transport is built | made the plumbing a three-line change rather than a mechanism, and named the API-surface cost below |

## What to build

Share the backend's `Arc<EraCache>` into `HttpTransport`, and have `build_mcp_headers` read
`cached().await`:

- `Some(Era::Modern)` → read the era once, then emit `MCP-Protocol-Version:
  MODERN_VERSIONS[0]` and `Mcp-Method`, and on the body side carry `_meta` and `Mcp-Name`
  from that same read. Nothing is removed: the session header is already absent whenever the
  peer is genuinely modern.
- `Some(Era::Legacy)` or `None` → today's behaviour, byte for byte.

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

**The body half: `_meta` and `Mcp-Name`.** `build_mcp_headers` cannot reach `params`, so
two of the four fields land wherever the outbound request body is assembled. The design's
test plan must cover both halves or 9a is only half met. Named here rather than discovered
in review. What goes in, exactly:

| field | value | source |
|---|---|---|
| `io.modelcontextprotocol/protocolVersion` | the same `MODERN_VERSIONS[0]` read the header used | required (`meta.rs:42`) |
| `io.modelcontextprotocol/clientCapabilities` | `{}` — an empty object | required (`meta.rs:44`); empty is the documented minimal shape (`meta.rs:12`), and the gateway declares nothing on a routed call. `meta.rs:63` warns specifically against copying an attacker-sized value, so a minimum is the safe value as well as the honest one |
| `io.modelcontextprotocol/clientInfo` | omitted | optional (`meta.rs:46`); nothing to say |
| `Mcp-Name` | the method-selected body field, for the three methods that require it | `tests/mik_7214_acs.rs:109` |

Merge behaviour, for each shape `params` can take — the reviewer was right that leaving this
implicit invites three different implementations:

- **absent** → create `params` as an object carrying only `_meta`.
- **an object** → merge `_meta` in. An existing `_meta` object keeps its other keys; the
  three reverse-DNS keys above are set by this design and overwrite whatever held them.
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
emitted version value, `Mcp-Method` on a modern request, `Mcp-Name` on each of the three
methods that require it and its absence on one that does not, the `_meta` body declaration
with its three merge shapes, and the `None`-means-legacy default — the last of which must be
written so it can fail, since "unchanged behaviour" is the assertion most easily satisfied by
a fixture that never reached the code.

**Assert on the captured wire request, not on the builder's return value.** The reviewer's
point, and it is the difference between a plan that can fail and one that cannot:
`build_mcp_headers` is private and its output is merged with static and per-request headers
afterwards (`:607-616`, `:618-624`). A test reading the builder result sees neither a custom
header override nor a body/header divergence nor anything the body half does — the three
failure modes this review actually found.
