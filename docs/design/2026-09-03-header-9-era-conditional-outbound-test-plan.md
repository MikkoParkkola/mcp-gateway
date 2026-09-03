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

- **`Modern`/`Request`+`Notify` session cell is `·`, and `Close` is `S`.** `MIK-7215.STATELESS.3a`
  is a prohibition — the gateway MUST NOT emit `Mcp-Session-Id` on the modern path
  (`docs/requirements/RELEASE-4.0.0-requirements.md:92`) — so the header is *removed* at
  finalisation, not merely left unminted. The omission is per mode, not per peer, because a
  dual-era backend mints a session during the legacy handshake that runs *before* the era
  resolves. Both are real and both must be tested against the same backend state — a fixture
  where the session map is empty proves neither.
- **`Close` and `Sse` inherit the protocol-version cell (`=`, not `M`).** Both arms call
  `build_mcp_headers` directly and pass no modern value, so they never reach either
  finalisation site. Their cells are what the builder already emits, on every era.
- **`Modern`/`Notify` method cell is `+`.** `HeaderMode::Notify` carries no
  method today (`src/transport/http/mod.rs:206-210`), so this cell cannot be
  filled without widening the arm. The cell is the reason the widening exists.
- **`Modern`/`Notify`'s version and method cells depend on a *second* finalisation site.**
  `notify_with_headers` calls `build_mcp_headers` and posts the result directly
  (`mod.rs:1051-1053`); there is no `extra_headers` merge on that path, and the static
  `self.headers` merge inside the builder (`:607-616`) is the last writer. An implementation
  that finalises only in `send_request_with_headers` passes every `Modern`/`Request` cell and
  fails these two — which is exactly what the Notify half of the pinning case exists to catch.

## Cases

Table-driven over the matrix: one component test per row, asserting each of the
five fields on the **captured wire request** — after every merge that path runs
(`Request`: the static merge at `:607-616` then the per-request `extra_headers`
merge at `:846-854`; `Notify`: the static merge only), not on
`build_mcp_headers`' return value, which is private and sees neither.

Beyond the matrix, cases for the rules the matrix cannot express:

| case | asserts | can fail because |
|---|---|---|
| named-method coverage | `Mcp-Name` present for each of `tools/call`, `resources/read`, `prompts/get`, and absent for one method that is not | a per-method table, run against the production selector, not a hand-listed pair |
| `Mcp-Name` mirrors the body | the header's **value** equals the body field the method selects — `params.name` for `tools/call` and `prompts/get`, `params.uri` for `resources/read` (`headers.rs:47`) — asserted per method against a body whose field is set to a value the builder could not invent | a presence assertion passes against a header carrying any string, including one read from the wrong field; each method's fixture uses a distinct sentinel value, so a builder that reads `params.name` for `resources/read` sends the other method's value and the case fails on the comparison rather than on absence |
| `_meta`, absent `params` | the body carries a `params` object holding only `_meta`, and `_meta` holds exactly the two reverse-DNS keys | a builder that skips declaration when there is nothing to merge into sends no `params` at all, and the case fails on the object's absence |
| `_meta`, object `params` without `_meta` | the caller's own keys survive unchanged beside a newly inserted `_meta` | the fixture's keys are values the builder could not invent, so a builder that replaces `params` rather than merging loses them |
| `_meta`, object `params` with an object `_meta` | foreign `_meta` keys survive — `clientInfo` among them, neither inserted nor stripped — and only the two reverse-DNS keys this design writes are overwritten | the fixture pre-sets both a foreign key and one of the two design keys to a wrong value; a wholesale replace loses the first, a merge that skips existing keys keeps the second |
| `_meta`, non-object `params` | the call fails locally with the error the design names, and **nothing is sent** | asserted on the captured-request recorder being empty, not only on the `Err` — a builder that sends first and errors after passes an `Err`-only assertion |
| `_meta`, object `params` whose `_meta` is not an object | driven over `null`, a string, a number and an array: each fails locally with the error the design names, and **nothing is sent** | the same recorder-empty assertion. An implementation that overwrites destroys caller data and passes an `Err`-free happy path; one that sends unchanged emits no `clientCapabilities` and is rejected `-32602` by a real modern peer, which no local assertion would catch |
| pinning, per re-asserted header, per path | a backend configured with a custom `MCP-Protocol-Version`, a custom `Mcp-Method` and a custom `Mcp-Name` — set once as a static header and once as a per-request `extra_headers` entry — still sends this design's values, on a modern `Request` **and** on a modern `Notify` | each custom value is one the builder would never produce. On `Request` the finalisation must run after the `extra_headers` merge (`mod.rs:846-854`), so a re-assertion placed inside `build_mcp_headers` passes the static half and fails the per-request half. On `Notify` there is no per-request merge at all (`mod.rs:1051-1053`), so an implementation that finalises only in `send_request_with_headers` sends the operator's values and fails every Notify assertion. Three headers × two paths, with the `Request` path asserted at both merge sites: an implementation at the wrong site fails a named subset rather than all of them, which is what makes the site visible |
| session removal, both modern paths | a backend that **has** a minted session and is additionally configured with a custom `MCP-Session-Id` sends neither on a modern `Request` or `Notify`, and still sends the minted one on `Close` and on every legacy row | `MIK-7215.STATELESS.3a` prohibits emission, not minting; a fixture with an empty session map passes an absence assertion without the removal existing. The custom static value is the second half: an implementation that only skips the mint still forwards the operator's header |
| outbound encoding (HEADER.4a) | driven over **every row** of `SPEC_ENCODING_TABLE` (`tests/mik_7214_acs.rs:25-38`): the plain ASCII row passes through untouched, and the non-ASCII, leading/trailing-whitespace, embedded-newline and literal-sentinel rows are emitted exactly as the table's expected column says, each round-tripping through `decode_header_value` back to the original | the encoder does not exist yet, so this fails on today's tree in one of three ways — illegal header bytes, a silent mangle, or a wrapped value that decodes to something else — and the round-trip assertion separates them. Sharing the repository's own table is what stops the case from being an encoder written twice and agreeing with itself; the literal-sentinel row is the one an encoder that only tests `is_ascii()` gets wrong |
| every `_meta` shape, on both outbound paths | the five `_meta` cases above are driven through `Request` **and** through `Notify` assembly, not through `Request` alone | the two paths assemble their bodies at different sites (`:968`, `:1045`); a merge implemented on one leaves the other sending an unenveloped body, and a plan that exercises only `Request` cannot see it. Satisfied either by running each shape twice, or by one shared production helper plus a captured-wire case per caller — the second is cheaper and the shared helper is what makes it honest |
| production era wiring | an HTTP `Backend` started through its **real** lifecycle, whose peer answers the discovery probe as modern, shapes the next ordinary request modernly | every other case primes the era cache as a fixture input, so all of them pass against a lifecycle that never attaches the cache to the transport at all. This is the only case whose failure means "the feature is unreachable in production" rather than "a value is wrong", and on today's tree it fails for exactly that reason |
| era read while the probe is in flight | a request issued concurrently with an unresolved probe is shaped legacy and **does not stall**: the case asserts both the legacy shape and that the call returns well inside `PROBE_TIMEOUT` (`src/backend/era.rs`, 2s) | the design's hot-path read is non-blocking by construction; a blocking read deadlocks against the probe's own request, which holds the era lock across its await (`src/protocol/era.rs:157-161`). A blocking implementation fails this case on the elapsed-time assertion after 2s, and passes every cache-primed row in this plan — which is what makes the assertion, not the shape, the load-bearing half |
| `initialize()` stays off the shaped path | a re-handshake against a backend already cached `Modern` still sends a legacy-shaped `initialize` | `initialize()` calls `send_request` directly rather than `request` (`mod.rs:996`), and that is what keeps it off this design's path; the comment there was written for MIK-5982 recursion, not as an era invariant, so nothing today would notice a refactor routing it through `request_with_headers`. A modern-shaped `initialize` is a handshake the legacy peer cannot answer |

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
| HEADER.9a, header half | matrix rows 1-9; named-method coverage; `Mcp-Name` mirrors the body; pinning per path; `initialize()` stays off the shaped path | component (transport, captured request) | functional, table-driven |
| HEADER.9a, body half | matrix `params._meta` column; the five `_meta` cases, each on both paths | component (body assembly at `:968`, `:1045`) | functional, table-driven |
| HEADER.9a, reachability | production era wiring; era read while the probe is in flight | component (real `Backend` lifecycle; concurrent probe) | integration-shaped — the only cases whose failure means the feature never runs |
| HEADER.9b | pinning (three headers, both paths, both merge sites on `Request`) | component | regression — pins the value's source, not its spelling |
| HEADER.4a | outbound encoding over `SPEC_ENCODING_TABLE` | component | functional — encoder round-trip against `decode_header_value` |

Every criterion has at least one case and no case belongs to none. The
`MCP-Session-Id` column belongs to no criterion of *this* ticket: its
prohibition is `MIK-7215.STATELESS.3a`
(`docs/requirements/RELEASE-4.0.0-requirements.md:92`), which this design must
not violate while meeting its own criteria. The session-removal case is what
holds that line, and it is listed here rather than dropped precisely because a
criterion owned by a neighbouring ticket is the kind that goes untested by
both.

No integration or E2E case: the criterion is about what leaves the transport, and
a captured wire request is where that is observable without a live backend.

## The two questions a plan review must answer (§P2)

**Q1 — does every acceptance criterion have a case, or a stated reason it has none?** Yes,
and the criterion-to-case table above is the answer in artifact form rather than in prose, so
an empty cell is visible to a reader who did not write it. Three criteria across five rows —
`HEADER.9a` is split into its header half, its body half and its reachability, because a
single row for it would let two of the three pass while the third had no case at all — and
none empty. `HEADER.4a` is included even though it is not this increment's headline criterion,
because the encoder it needs does not exist yet and a plan that omitted it would let the
implementation ship with the criterion vacuously met. One behaviour — the `MCP-Session-Id`
column — is owned by a criterion of a neighbouring ticket rather than by either of this
one's, and is carried here for that reason rather than dropped.

**Q2 — can each named case actually fail?** Every row carries its own "can fail because"
column, which is where that is argued case by case. Four of them are worth naming here
because they are the ones a careless fixture would defeat:

- The `None`-means-legacy row asserts positively, because "unchanged behaviour" is satisfied
  by a transport that never ran. It fails if the legacy protocol header is missing its
  handshake value, not merely if a modern header is absent.
- `Mcp-Name` mirrors the body compares the header's **value** against a per-method sentinel,
  so a builder reading the wrong body field fails on the comparison. A presence assertion
  would pass against any string.
- The pinning cases set each custom value to something the builder cannot produce, at every
  merge site each path runs. An implementation that re-asserts inside `build_mcp_headers`
  passes the static half of `Request` and fails its per-request half; one that finalises only
  in `send_request_with_headers` passes all of `Request` and fails all of `Notify`. Each wrong
  site fails a *named subset*, not zero and not everything, which is what makes the site
  visible rather than merely unproven.
- The probe-in-flight case asserts elapsed time as well as shape. Shape alone is satisfied by
  the deadlocked implementation this design exists to avoid — it also answers legacy, two
  seconds later — so the timing assertion is the one that can fail.

No case in this plan is staged so that its fixture makes its own assertion true; the closest
risk is the `Modern` rows, whose era cache is a fixture input, and they are constrained to
prime through `EraCache::resolve_with` for that reason.
