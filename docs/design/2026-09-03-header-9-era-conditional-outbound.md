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
  settled and this change does not touch them.
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

So the modern outbound shape is two decisions, not one, and they go opposite ways:

| header | modern peer | why |
|---|---|---|
| `MCP-Protocol-Version` | **emitted**, with `MODERN_VERSIONS[0]` | the revision mirrors the version in header and body; see the resolved question below |
| `MCP-Session-Id` | **omitted entirely** | the revision deleted sessions. A session id sent to a peer that has none is at best ignored and at worst re-attached by an intermediary |

Plus the `_meta` declaration in `params`, which is what `HEADER.9a`'s "outbound modern
`_meta`" clause names. `HEADER.9b` — "values derived from the negotiated envelope, not the
legacy handshake version" — is then satisfied by construction: the emitted value is
`MODERN_VERSIONS[0]` (`src/protocol/meta.rs:216`), a constant, *not* the string
`protocol_version` holds. There is no negotiated 2026 string to derive from and there never
will be, because `SUPPORTED_VERSIONS` excludes the revision permanently. 9b's requirement is
that the value not come from the handshake; a constant meets it.

## Questions, and how they were settled

| question | how it was settled | what came back | what it changed |
|---|---|---|---|
| for a Modern peer, is `MCP-Protocol-Version` emitted or omitted? | *raised as askable; turned out checkable* — read `src/protocol/meta.rs:99-104` and `src/gateway/router/handlers.rs:552-568` | the revision uses **mirrored headers**: the gateway's own inbound path "refuses a modern request that omits `MCP-Protocol-Version`, so every modern request that survives carries it" (`handlers.rs:556`), and classifies on header **and** body precisely so the two cannot disagree (`meta.rs:99-104`) | removed the omit option. Omitting it outbound would have the gateway send modern requests it would itself reject inbound — an asymmetry with a citation, not a preference. Pending the lead's confirmation, since it was routed as an operator question before the mirroring rule was found |
| is the era known when the handshake runs? | read the construction path: `lifecycle.rs:360` constructs, `:375` calls `initialize()`, `resolve_era` runs later at `:232` via `reconcile_after_start` | no — and permanently not, because the probe is issued through the transport after it is up | forced the era read to be **per request**, not at construction. `build_mcp_headers` is already `async` and `cached()` is `async`, so the read costs nothing structural |
| is an era always available? | `cached()` returns `Option<Era>` (`src/protocol/era.rs:130`) | no — `None` before the probe resolves, and on any backend that never probes | made `None` an explicit case rather than an assumed one: **`None` maps to the legacy shape**, which is `classify`'s own positive-evidence rule (`era.rs:57`) rather than a second policy invented here |
| does the era cache reach the transport today? | read `HttpTransport::new`/`new_with_oauth` (`src/transport/http/mod.rs:266`, `:280`) and the call site (`src/backend/lifecycle.rs:360`) | it does not, but `self.era` is in scope at the call site — the `Arc` exists exactly where the transport is built | made the plumbing a three-line change rather than a mechanism, and named the API-surface cost below |

## What to build

Share the backend's `Arc<EraCache>` into `HttpTransport`, and have `build_mcp_headers` read
`cached().await`:

- `Some(Era::Modern)` → emit `MCP-Protocol-Version: MODERN_VERSIONS[0]`, omit
  `MCP-Session-Id` for every `HeaderMode`, and carry the `_meta` declaration in `params`.
- `Some(Era::Legacy)` or `None` → today's behaviour, byte for byte.

**API surface (D28).** `new` and `new_with_oauth` are public and called from tests; widening
both signatures is an API-surface change for a value only one caller can supply. Prefer a
setter — the same shape as `mark_single_tenant` (`src/backend/lifecycle.rs:373`), which
already exists for exactly this situation: a fact only the pool key knows, told to the
transport after construction. Rejected alternative: an `Option<Arc<EraCache>>` parameter on
both constructors, which changes two public signatures and leaves every test passing `None`.

**Alternatives rejected.** Threading an `Era` argument through every `build_mcp_headers`
call site — mechanical, and it puts the era on the call path of code that has no business
knowing about it. Moving header construction up to `Backend` — a much larger change that
would move the "single source of truth for all outgoing request headers" out of the
transport that sends them.

**`_meta` placement is a body change, not a header change.** `build_mcp_headers` cannot
reach `params`. The `_meta` half of 9a therefore lands wherever the outbound request body is
assembled, and this design's test plan must cover both halves or 9a is only half met. Named
here rather than discovered in review.

## Composition with the era probe

Stated so the next reviewer does not have to find it. Until the 08-31 increment lands its
§3a header suppression, the probe request itself sees `cached() == None` — no era resolved
yet, by definition, since the probe is what resolves it — and therefore takes the legacy
shape and carries both headers. That is the exact defect §3a there eliminates. This design
neither creates it nor fixes it: the two increments compose in that order, and the ordering
is not a dependency, because `None → legacy` is correct behaviour for this design regardless
of what the probe carries.

## Still open

Nothing deferred. The one question this design was expected to defer turned out checkable
and is recorded above, pending the lead's confirmation that a finding may close a question
that was routed as an operator decision.

## Next step

Test plan (§P2), reviewed as a plan before any test is written. One row per clause: the
emitted version value, the omitted session header across all four `HeaderMode` variants, the
`_meta` body declaration, and the `None`-means-legacy default — the last of which must be
written so it can fail, since "unchanged behaviour" is the assertion most easily satisfied by
a fixture that never reached the code.
