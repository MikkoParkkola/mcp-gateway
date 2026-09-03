# HEADER.9a/9b — test plan

Reviewed as a plan per §P2, before any test is written. No case predates it.

**Criteria.** `MIK-7214.HEADER.9a` — outbound requests carry the modern `_meta`
envelope and the standard headers only where the peer negotiated a modern era.
`MIK-7214.HEADER.9b` — the emitted values are not derived from the legacy
handshake version. Design:
`docs/design/2026-09-03-header-9-era-conditional-outbound.md`.

## The coverage matrix

Rows are the outbound call shape: the peer's cached era crossed with the
`HeaderMode` arm that shapes the call. Columns are the five fields the design
decides. `=` the legacy value the builder already emits, `M` the modern
constant, `·` absent, `S` the minted session id, `+` added.

An empty cell is a finding. Every cell below is filled, and three of them are
decisions the design had to make rather than behaviour it inherited. One more
was examined and turned out to be inherited; it is recorded below the table so
it reads as settled rather than missing.

| era \ field | `MCP-Protocol-Version` | `Mcp-Method` | `Mcp-Name` | `MCP-Session-Id` | `params._meta` |
|---|---|---|---|---|---|
| `None`, `Request`/`Notify`/`Close` | = | · | · | S | · |
| `None`, `Sse` | = | · | · | · | · |
| `Legacy`, `Request`/`Notify`/`Close` | = | · | · | S | · |
| `Legacy`, `Sse` | = | · | · | · | · |
| `Modern`, `Request` (named method) | M | + | + | · | + |
| `Modern`, `Request` (unnamed method) | M | + | · | · | + |
| `Modern`, `Notify` | M | + | · | · | + |
| `Modern`, `Close` | = | · | · | S | · |
| `Modern`, `Sse` | = | · | · | · | · |

**The collapsed rows are run per `HeaderMode` arm, not once.** Three arms read
as one row because they expect the same five values, but the session cell is
where the new code puts a conditional that did not exist before: an
implementation with the era test inverted loses the session header on
`Legacy`/`Request` and passes every other cell in this matrix. That cell is the
regression cell, and a row collapsed in the table but run once in code would be
the only thing that misses it. `Sse` is not collapsed with them because it
carries no session header on any era.

Two cells carry a decision, not an inheritance. A third was considered and
produced none: **`Sse`'s session cell is `·` on every era**, because
`build_mcp_headers` matches `HeaderMode::Sse => {}` (`mod.rs:600`) and
`establish_sse_connection` passes `None` (`mod.rs:667-670`) — the header is not
emitted today and this design does not add it. Recorded so the question is not
re-opened as if it were open.

- **`Modern`/`Request`+`Notify` session cell is `·`, and `Close` is `S`.** The
  omission is per mode, not per peer, because a dual-era backend mints a session
  during the legacy handshake that runs *before* the era resolves. Both are real
  and both must be tested against the same backend state — a fixture where the
  session map is empty proves neither.
- **`Close` and `Sse` inherit the protocol-version cell (`=`, not `M`).** Both
  arms call `build_mcp_headers` directly and never reach the per-request merge
  at `src/transport/http/mod.rs:848`, which is the only site where this design
  re-asserts the modern constant. Their cells are what the builder already
  emits, on every era.
- **`Modern`/`Notify` method cell is `+`.** `HeaderMode::Notify` carries no
  method today (`src/transport/http/mod.rs:206-210`), so this cell cannot be
  filled without widening the arm. The cell is the reason the widening exists.

## Cases

Table-driven over the matrix: one component test per row, asserting each of the
five fields on the **captured wire request** — after the static and per-request
header merges (`:607-616`, `:618-624`), not on `build_mcp_headers`' return
value, which is private and sees none of them.

Beyond the matrix, six cases for the rules the matrix cannot express:

| case | asserts | can fail because |
|---|---|---|
| named-method coverage | `Mcp-Name` present for each of `tools/call`, `resources/read`, `prompts/get`, and absent for one method that is not | a per-method table, run against the production selector, not a hand-listed pair |
| `Mcp-Name` mirrors the body | the header's **value** equals the body field the method selects — `params.name` for `tools/call` and `prompts/get`, `params.uri` for `resources/read` (`headers.rs:47`) — asserted per method against a body whose field is set to a value the builder could not invent | a presence assertion passes against a header carrying any string, including one read from the wrong field; each method's fixture uses a distinct sentinel value, so a builder that reads `params.name` for `resources/read` sends the other method's value and the case fails on the comparison rather than on absence |
| `_meta`, absent `params` | the body carries a `params` object holding only `_meta`, and `_meta` holds exactly the two reverse-DNS keys | a builder that skips declaration when there is nothing to merge into sends no `params` at all, and the case fails on the object's absence |
| `_meta`, object `params` without `_meta` | the caller's own keys survive unchanged beside a newly inserted `_meta` | the fixture's keys are values the builder could not invent, so a builder that replaces `params` rather than merging loses them |
| `_meta`, object `params` with an object `_meta` | foreign `_meta` keys survive — `clientInfo` among them, neither inserted nor stripped — and only the two reverse-DNS keys this design writes are overwritten | the fixture pre-sets both a foreign key and one of the two design keys to a wrong value; a wholesale replace loses the first, a merge that skips existing keys keeps the second |
| `_meta`, non-object `params` | the call fails locally with the error the design names, and **nothing is sent** | asserted on the captured-request recorder being empty, not only on the `Err` — a builder that sends first and errors after passes an `Err`-only assertion |
| pinning, one case per re-asserted header | a backend configured with a custom `MCP-Protocol-Version`, a custom `Mcp-Method` and a custom `Mcp-Name` — set once as a static header and once as a per-request `extra_headers` entry — still sends this design's values on the modern path | each custom value is one the builder would never produce; the re-assertion happens after the per-request merge (`mod.rs:848`), so a re-assertion placed inside `build_mcp_headers` passes the static half and fails the per-request half. Three headers × two merge sites = six assertions, and an implementation at the wrong site fails exactly three of them |
| non-ASCII `Mcp-Name` (HEADER.4a) | a tool whose name is not representable in ASCII is emitted Base64-sentinel-wrapped, and `decode_header_value` round-trips it back to the original | the encoder does not exist yet, so this case fails on today's tree in one of two ways — illegal header bytes, or a silent mangle — and the round-trip assertion distinguishes them from a value that merely looks wrapped |
| session pinning, the declined half | a backend configured with a custom `MCP-Session-Id` **does** send it on a modern `Request` | the design declines to strip it; a test asserting absence would pin the opposite of what was decided |

## What must be written so it can fail

The `None`-means-legacy row is the case most easily satisfied by a fixture that
never reached the code: "unchanged behaviour" passes when nothing runs. It
asserts positively — the legacy protocol header carries the handshake value and
`_meta` is absent — against a backend whose era cache was explicitly primed to
`None`. A test that asserts only "no modern header" would pass against a
transport that never built headers at all. The plan does **not** assert how many
times the cache was read: the count is not observable from a captured request,
and a case asserting it would be pinning the implementation rather than the
criterion.

The `Modern` rows have the opposite risk: the era cache is a fixture input, so a
case can assert modern shaping against a backend the production path would never
classify `Modern`. Every `Modern` row primes the cache through
`EraCache::resolve_with` — the same entry point the production path resolves
through (`src/backend/era.rs`) — never by constructing the enum inline.

## Level and type

| criterion | cases | level | type |
|---|---|---|---|
| HEADER.9a, header half | matrix rows 1-9; named-method coverage; `Mcp-Name` mirrors the body; pinning | component (transport, captured request) | functional, table-driven |
| HEADER.9a, body half | matrix `params._meta` column; the four `_meta` cases | component (body assembly at `:968`, `:1045`) | functional, table-driven |
| HEADER.9b | pinning (all three headers, both merge sites) | component | regression — pins the value's source, not its spelling |
| HEADER.4a | non-ASCII `Mcp-Name` | component | functional — encoder round-trip against `decode_header_value` |

Every criterion has at least one case and no case belongs to none. The
`MCP-Session-Id` column belongs to no criterion of its own: it is behaviour this
design decides but neither criterion asserts, covered by the matrix and by the
declined-half pinning case so a regression there cannot pass silently.

No integration or E2E case: the criterion is about what leaves the transport, and
a captured wire request is where that is observable without a live backend.

## The two questions a plan review must answer (§P2)

**Q1 — does every acceptance criterion have a case, or a stated reason it has none?** Yes,
and the criterion-to-case table above is the answer in artifact form rather than in prose, so
an empty cell is visible to a reader who did not write it. Four criteria, four rows, none
empty. `HEADER.4a` is included even though it is not this increment's headline criterion,
because the encoder it needs does not exist yet and a plan that omitted it would let the
implementation ship with the criterion vacuously met. One behaviour — the `MCP-Session-Id`
column — belongs to no criterion and is stated as such rather than dropped.

**Q2 — can each named case actually fail?** Every row carries its own "can fail because"
column, which is where that is argued case by case. Three of them are worth naming here
because they are the ones a careless fixture would defeat:

- The `None`-means-legacy row asserts positively, because "unchanged behaviour" is satisfied
  by a transport that never ran. It fails if the legacy protocol header is missing its
  handshake value, not merely if a modern header is absent.
- `Mcp-Name` mirrors the body compares the header's **value** against a per-method sentinel,
  so a builder reading the wrong body field fails on the comparison. A presence assertion
  would pass against any string.
- The pinning cases set each custom value to something the builder cannot produce, at both
  merge sites. An implementation that re-asserts inside `build_mcp_headers` passes the static
  half and fails the per-request half — three assertions, not zero, which is what makes the
  wrong site visible rather than merely unproven.

No case in this plan is staged so that its fixture makes its own assertion true; the closest
risk is the `Modern` rows, whose era cache is a fixture input, and they are constrained to
prime through `EraCache::resolve_with` for that reason.
