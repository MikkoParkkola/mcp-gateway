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
decisions the design had to make rather than behaviour it inherited.

| era \ field | `MCP-Protocol-Version` | `Mcp-Method` | `Mcp-Name` | `MCP-Session-Id` | `params._meta` |
|---|---|---|---|---|---|
| `None`, any arm | = | · | · | S | · |
| `Legacy`, any arm | = | · | · | S | · |
| `Modern`, `Request` (named method) | M | + | + | · | + |
| `Modern`, `Request` (unnamed method) | M | + | · | · | + |
| `Modern`, `Notify` | M | + | · | · | + |
| `Modern`, `Close` | M | · | · | S | · |
| `Modern`, `Sse` | M | · | · | S | · |

**The two collapsed rows are run per `HeaderMode` arm, not once.** They read as
one row because all four arms expect the same five values, but the session cell
is where the new code puts a conditional that did not exist before: an
implementation with the era test inverted loses the session header on
`Legacy`/`Request` and passes every other cell in this matrix. That cell is the
regression cell, and a row collapsed in the table but run once in code would be
the only thing that misses it.

Three cells carry a decision, not an inheritance:

- **`Modern`/`Request`+`Notify` session cell is `·`, and `Close` is `S`.** The
  omission is per mode, not per peer, because a dual-era backend mints a session
  during the legacy handshake that runs *before* the era resolves. Both are real
  and both must be tested against the same backend state — a fixture where the
  session map is empty proves neither.
- **`Modern`/`Sse` session cell is `S`.** Named here because the design's prose
  argues `Close`, and `Sse` decides the same way for the same reason: neither
  carries a JSON-RPC method, and the stream a dual-era backend serves is
  identified by the session it minted. Dropping the header there would break
  stream continuity for exactly the backends the `Close` exception protects.
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
| `_meta` merge shapes | absent `params` → object holding only `_meta`; object `params` → merged, foreign `_meta` keys kept (`clientInfo` among them, neither inserted nor stripped), the two reverse-DNS keys this design writes overwritten; non-object `params` → untouched, no declaration | three distinct inputs with three distinct expected bodies; the third asserts the body is byte-identical to what went in |
| version pinning | a backend configured with a custom `MCP-Protocol-Version` still sends `MODERN_VERSIONS[0]` on the modern path, and its body agrees | the custom header is set to a value the builder would never produce, so an implementation that skips the re-assertion emits it |
| non-ASCII `Mcp-Name` (HEADER.4a) | a tool whose name is not representable in ASCII is emitted Base64-sentinel-wrapped, and `decode_header_value` round-trips it back to the original | the encoder does not exist yet, so this case fails on today's tree in one of two ways — illegal header bytes, or a silent mangle — and the round-trip assertion distinguishes them from a value that merely looks wrapped |
| session pinning, the declined half | a backend configured with a custom `MCP-Session-Id` **does** send it on a modern `Request` | the design declines to strip it; a test asserting absence would pin the opposite of what was decided |

## What must be written so it can fail

The `None`-means-legacy row is the case most easily satisfied by a fixture that
never reached the code: "unchanged behaviour" passes when nothing runs. It
asserts positively — the legacy protocol header carries the handshake value and
`_meta` is absent — against a backend whose era cache was explicitly primed to
`None` and read once during the call. A test that asserts only "no modern header"
would pass against a transport that never built headers at all.

The `Modern` rows have the opposite risk: the era cache is a fixture input, so a
case can assert modern shaping against a backend the production path would never
classify `Modern`. Every `Modern` row primes the cache through the same
`mark_*`/probe path the production code writes it with, never by constructing the
enum inline.

## Level and type

| criterion | level | type |
|---|---|---|
| HEADER.9a, header half | component (transport, captured request) | functional, table-driven |
| HEADER.9a, body half | component (body assembly at `:968`, `:1045`) | functional, table-driven |
| HEADER.9b | component | regression — pins the value's source, not its spelling |

No integration or E2E case: the criterion is about what leaves the transport, and
a captured wire request is where that is observable without a live backend.
