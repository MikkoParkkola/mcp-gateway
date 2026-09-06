<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Test plan — NFR.SEC.1 row 5, NFR.COMPAT.1 revision matrix

Design: `docs/design/2026-09-07-nfr-sec1-row5-and-compat1-matrix.md`.
One row per control (SEC.1) and one per revision (COMPAT.1), as the criteria
are worded. An empty evidence cell is the finding, not an omission.

## Rows

| id | criterion | case | level | type | production entry | passes only if |
|---|---|---|---|---|---|---|
| S5.a | SEC.1 row 5 | an authenticated client whose circuit is open is refused | system | negative | `POST /mcp` after N erroring calls | HTTP 503 **and** code `-32003` |
| S5.b | SEC.1 row 5 | falsifier — the same frame from a client whose circuit is closed | system | positive | `POST /mcp`, fresh client name | 200, no error member |
| C1.a | COMPAT.1 | 2026-07-28 is served | system | positive | `POST /mcp` + `MCP-Protocol-Version: 2026-07-28` | served statelessly; response carries 2026-07-28 |
| C1.b | COMPAT.1 | falsifier — same frame with `modern_protocol` off | system | negative | as C1.a, flag flipped | `-32022` unsupported protocol version |
| C2 | COMPAT.1 | 2025-11-25 served | system | positive | `server/discover` | `supportedVersions` **contains** 2025-11-25 |
| C3 | COMPAT.1 | 2025-06-18 served | system | positive | `initialize` | negotiated version **equals** 2025-06-18 |
| C4 | COMPAT.1 | 2025-03-26 not dropped | system | positive | `initialize` | negotiated version **equals** 2025-03-26 |
| C5 | COMPAT.1 | 2024-11-05 not dropped | system | positive | `initialize` | negotiated version **equals** 2024-11-05 |
| C6 | COMPAT.1 | falsifier for C3-C5 — a revision absent from `SUPPORTED_VERSIONS` | system | negative | `initialize` with `1999-01-01` | downgraded to `PROTOCOL_VERSION` (2025-11-25), **not** echoed |
| S15.a | SEC.1 row 15 | a `tools/call` the firewall blocks as an anomaly is refused | system | negative | `POST /mcp`, `tools/call`, firewall configured to block | HTTP 400 **and** code `-32002` |
| S15.b | SEC.1 row 15 | falsifier — every non-anomaly firewall block | system | negative | as S15.a, non-anomaly rule | HTTP 400 **and** code `-32600`, distinguishing it from S15.a |

## Can each case actually fail?

The question a plan review must answer, per case:

- **S5.a** fails today if the breaker never opens, if it opens but the handler
  does not consult it, or if an earlier gate refuses first. The last is the
  live risk and is why the assertion pins `-32003`, not merely "an error":
  row 4's rate limiter answers 429/`-32000` from the *same function*
  (`client_preflight`), so a status-only assertion would pass on the wrong gate.
- **S5.b** fails if the fixture leaves the breaker open across cases — which
  is the specific way S5.a could pass while proving nothing. The two cases
  must use **distinct client names**, or S5.b inherits S5.a's tripped circuit.
- **C1.a** fails if `modern_protocol` defaults off, if the header path stops
  being reachable, or if the response echoes `PROTOCOL_VERSION` instead.
- **C1.b** is what distinguishes "served because the flag is on" from "served
  because nothing checks". Without it C1.a passes on a build that ignores the
  header entirely.
- **C3-C5** fail if the revision is removed from `SUPPORTED_VERSIONS`. Each
  asserts **equality** with the requested revision, not merely absence of an
  error: `negotiate_version` (`src/protocol/mod.rs:54`) answers
  `PROTOCOL_VERSION` for anything it does not know, so an error-free response
  is compatible with the revision having been dropped. Equality discriminates
  here because `PROTOCOL_VERSION` is `2025-11-25` — different from all three.
- **C2 cannot be observed through `initialize` at all**, and this is why the
  case moved. `PROTOCOL_VERSION` **is** 2025-11-25. Delete 2025-11-25 from
  `SUPPORTED_VERSIONS` and `negotiate_version` still answers 2025-11-25, from
  the fallback. Every assertion available on the handshake — echo, equality,
  absence of error — is then satisfied by the downgrade path's own output.
  A second assertion beside it would not help: the whole observable is
  degenerate. So C2 observes a **different surface**, `server/discover`'s
  `supportedVersions` (`src/gateway/meta_mcp/mod.rs:1155`), which is built
  from the constant itself and stops listing the revision the moment it goes.
  The state "passes while 2025-11-25 has been dropped" is not constructible
  there, rather than merely detectable.
- **C6** proves C3-C5's assertion is discriminating rather than tautological.
  It does not cover C2, whose falsifier is structural: `1999-01-01` and a
  dropped 2025-11-25 produce the identical handshake answer, which is the
  finding.

## Retrofit — the falsifier probe

These controls already work, so no case here earns the free failure that comes
from writing the test before the code. Each row therefore carries an in-file
falsifier (S5.b, C1.b, C6) rather than relying on a staged regression.

Where a probe is run instead, it must restore **pre-fix content**, not a
working-tree state: `git stash` around a committed change removes only later
edits, and `git checkout --` discards the uncommitted work being verified.
Neither is permitted in this shared checkout regardless.

## Out of plan

The legacy-client bridge (`src/protocol/continuation.rs`) — peer-held. Named
here so the plan is visibly short rather than silently so.

The firewall (inventory row 15) was listed here and is not any more. The
design's scope move records why: the refusal S15 names is emitted by
`src/gateway/router/handlers.rs` (the `-32002`/`-32600` pair at `:1244`), not
by the firewall crate, so the case is a fixture change rather than an edit to
a peer-held file. A scope move that reaches the design and not the plan
leaves the row with no executable evidence, which is the defect this repairs.
