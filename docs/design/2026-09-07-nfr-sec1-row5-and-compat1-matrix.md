<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Closing NFR.SEC.1 row 5 and the NFR.COMPAT.1 revision matrix

Two BLOCKING release criteria for 4.0.0. Both are ABSENT for the same
underlying reason: a claim was graded against tests that never drove the
production path the claim is about.

## Problem

### NFR.SEC.1 — row 5's refusal test does not prove the production path records

**This section's original claim was wrong and is corrected in place.** It said
row 5 had no refusal test. It has one —
`control_5_a_modern_caller_whose_circuit_is_open_is_refused`
(`tests/nfr_sec1_controls.rs:495`), landed before this document was written —
which drives `POST /mcp` and asserts 503 with `-32003`. The claim came from
the inventory's *refusal test* column rather than the test file that column
describes; the inventory now carries the correction as its fourth miscitation.

The residue is narrower and still worth the change. That test **stages** the
open circuit by calling `record_client_failure` directly. Nothing in it
touches the site where production records a failure
(`record_client_failure` in `handle_jsonrpc_request`, `handlers.rs:1511`), so deleting that call leaves the test
green and the breaker inert for every real caller. The work here is to trip
the breaker the way a caller trips it — repeated erroring `POST /mcp` — and
keep every assertion the existing test already makes.

The inventory's old N/A argument ("a circuit breaker has no absent input to
remove") is moot rather than rejected: the row is tested, so nothing turns on
whether the criterion could have excused it.

### NFR.COMPAT.1 — one row, two assertions, two different mechanisms

The row reads: 2026-07-28, 2025-11-25 and 2025-06-18 are served; 2025-03-26
and 2024-11-05 are not dropped. A single test shape cannot answer both, and
the reason is structural, not stylistic:

| revision | how it is reached | constant |
|---|---|---|
| 2026-07-28 | `MCP-Protocol-Version` header on `POST /mcp`, stateless path, gated on `server.modern_protocol` | `MODERN_VERSIONS` (`src/protocol/meta.rs:216`) |
| 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 | `initialize` negotiation | `SUPPORTED_VERSIONS` (`src/protocol/mod.rs:48`) |

The two sets are deliberately disjoint (`meta.rs:210-215`): 2026-07-28 deleted
the handshake it would have to be negotiated through. **A test that drives
2026-07-28 through `initialize` is testing the wrong path** and will fail for
a non-defect; a test that drives the 2025 revisions through the header is
testing the other wrong path.

## The enumerated work

| # | claim | production entry | expected | falsifier in the same file |
|---|---|---|---|---|
| S5 | circuit breaker refuses an open-circuit caller | `POST /mcp`, authenticated client, N consecutive JSON-RPC errors | HTTP 503 + code `-32003` (`circuit_open_response`, `src/gateway/middleware/errors.rs:29`) | same frame, untripped client name → served |
| C1 | 2026-07-28 served | `POST /mcp` + `MCP-Protocol-Version: 2026-07-28`, `modern_protocol` on | served statelessly, revision echoed | `modern_protocol` off → `-32022` |
| C2 | 2025-11-25 served | `server/discover` | `supportedVersions` lists it | drop it from `SUPPORTED_VERSIONS` → discovery stops listing it |
| C3 | 2025-06-18 served | `initialize` | negotiated version equals 2025-06-18 | a revision absent from `SUPPORTED_VERSIONS` → downgraded to `PROTOCOL_VERSION` |
| C4 | 2025-03-26 not dropped | `initialize` | negotiated version equals 2025-03-26 | as C3 |
| C5 | 2024-11-05 not dropped | `initialize` | negotiated version equals 2024-11-05 | as C3 |
| S15 | the firewall gate refuses a blocked `tools/call` | `POST /mcp`, `tools/call`, a configured firewall that blocks | HTTP 400 + `-32002` for an anomaly block, `-32600` for every other (`handlers.rs:1244-1266`) | the same frame with `firewall: None` — the seven router fixtures' own state → served |

C1's second clause — the wired legacy-client bridge, `MIK-7212.MRTR.7a`/`7b`
in `src/protocol/continuation.rs` — is **not in this change**. That file is
peer-held. C1 as written asserts the revision is served; it does not assert
the bridge exists, and the criterion stays blocking until the bridge lands
regardless of what this change proves.

## 2025-11-25 is the fallback, so the handshake cannot observe it

`PROTOCOL_VERSION` is `2025-11-25` (`src/protocol/mod.rs:27`) and
`negotiate_version` returns it for every revision it does not recognise
(`:54`). The consequence is narrow and decisive: for C2 alone, the answer to
`initialize` is the same whether 2025-11-25 is served or has been deleted from
`SUPPORTED_VERSIONS`. "Echoed back, not downgraded" is a distinction the wire
does not carry there — the echo and the downgrade are the same string.

C2 therefore claims its revision on the surface that is built from the
constant: `server/discover`'s `supportedVersions`
(`src/gateway/meta_mcp/mod.rs:1155`). C3-C5 keep the handshake, where equality
with 2025-06-18 / 2025-03-26 / 2024-11-05 is genuinely discriminating against a
2025-11-25 fallback.

This was found by checking `PROTOCOL_VERSION`'s value against the review
finding rather than accepting the finding's aim. Both vendors flagged C4/C5 as
unfalsifiable; at source C4/C5 are sound once they assert equality, and the
degenerate case is the one neither named.

## Gate order is part of the S5 claim

Carried forward from the inventory, because it already cost one test: removing
a gate's input can land the request on an *earlier* gate, which refuses, and
the test goes green while the control it names never ran. S5's signature is
what makes it falsifiable — 503 / `-32003` is distinct from row 4's rate limit
(429 / `-32000`, `errors.rs:20`) and from every JSON-RPC error the handler
emits. **Asserting the status alone is insufficient; the test asserts the code
too.**

## Options considered

1. **Mark row 5 N/A with reason.** Rejected: the standing operator ruling says
   build the mechanism, and narrowing a criterion is not available. It is also
   unnecessary — the trip is drivable.
2. **Trip the breaker by calling `record_client_failure` directly.** This is
   what the existing test does, and the rejection is narrower than it first
   read: the test is *not* a helper unit test — it stages with the helper and
   asserts through `POST /mcp`, which is a production path. What it does not
   cover is the recording site, so a build that stops recording failures still
   passes. Rejected as the *whole* of S5's evidence, kept as its assertions.
3. **Trip it through `POST /mcp` with repeated calls to a method that does not
   exist.** Chosen, as a strengthening of the existing test rather than a
   second one. Uses the same recording site production uses
   (`handlers.rs:1511`), so a change that stops recording failures breaks the
   test. The trip is named rather than left conditional: the recorder sits
   below the dispatch match, so `-32601` from the `_` arm reaches it while an
   error refused *before* dispatch — auth, parse, the rate limiter — does not.
   Each staging call asserts its own `-32601`, so a build where the trip
   silently stops erroring fails at the staging step instead of at the claim.
4. **One combined COMPAT test parameterised over five revisions.** Rejected:
   the 2026 revision and the 2025 ones enter by different paths, so one
   parameterised body would need a branch on the parameter — which is two
   tests wearing one name, and the branch is where the wrong-path bug hides.

## The documentation the same finding falsifies

`docs/ARCHITECTURE.md:65` described the protocol module as negotiating
"2024-11-05 through 2025-11-25". Two defects in one clause: it reads as a
continuous range where the constant holds four discrete revisions, and it omits
2026-07-28 entirely — the revision the header path does serve. This document's
own table is the correction, so the line is repaired here rather than recorded
against someone else; the team lead assigned it in this change (`§P4a`: a
document the change makes untrue is updated inside the change).

## Scope move — the firewall row is not blocked by file ownership

This document first listed the firewall gate (the inventory's blocked 15th
control) as out of scope, on the ground that it "needs
`src/security/firewall/**`, owned by another session". That ground is false and
the surface moves accordingly (§P0: a move costs a paragraph saying why).

The refusal is not emitted from the firewall crate. It is emitted from the
`tools/call` arm of `src/gateway/router/handlers.rs` (the block ending at the
`build_error_response` call, ~`:1244-1266`): an anomaly block answers `-32002`,
every other firewall block answers `-32600`, both with HTTP 400. A test that
drives `POST /mcp` and asserts that pair reads the same production path row 15
names while touching no file another session owns. Ownership of the firewall
*source* never blocked a test of the gateway's *refusal*; the two were
conflated.

The fixture question that remained — whether a test can stand up a gateway
whose firewall blocks — is answered in the unknowns table below, and answered
yes: the router's own tests already set that field, they just set it to `None`.

## Out of scope
- The legacy-client bridge (`src/protocol/continuation.rs`) — peer-held.
- Any edit to `docs/requirements/RELEASE-4.0.0-criteria-status.md`. Evidence is
  reported; the team lead regrades.

## Unknowns

| unknown | check | result | what it changed |
|---|---|---|---|
| Is the client circuit breaker trippable from outside the `/mcp` route? | read every caller of `record_client_failure` (`rg` over `src/`) | Yes, and narrower than first recorded. The call sits **below the method-dispatch match** in `handle_jsonrpc_request` (`src/gateway/router/handlers.rs:1511`; cited as `:1330` before a peer's edits shifted it), so it sees every response that match produces — including the `_` arm's `-32601` — and no error returned before dispatch. `backend_handlers.rs` records on the backend path. | Killed the N/A, and named the trip: repeated authenticated calls to a method that does not exist. |
| Which path serves 2026-07-28? | read `MODERN_VERSIONS` and its consumers | The stateless POST path via the version header, gated on `server.modern_protocol`; never `initialize`. | Split C1 from C2-C5. Without this the C1 test would have driven `initialize` and failed for a non-defect. |
| Does `modern_protocol` default on? | `src/config/mod.rs:1236` | true, since `83c98902` (2026-09-04) | C1 needs no config mutation for its positive arm; its falsifier flips the flag off. |
| Does the breaker's refusal have a signature distinct from the gates around it? | read `errors.rs:20,:29` | 503/`-32003` vs the rate limiter's 429/`-32000` | Made the S5 falsifier decidable. |
| Is the firewall row testable without editing the peer-held firewall source? | read the refusal site and the state the router tests build | Yes twice over. The refusal is emitted by `handlers.rs` (~`:1244-1266`), not by the firewall crate; and `firewall` is a settable field on the router's state, `None` in seven existing fixtures (`src/gateway/router/tests.rs:82` and after). The `firewall` feature is on by default (`Cargo.toml` `[features] default`). | Killed the out-of-scope bullet. Row 15 is a fixture change, not a peer-file edit. |

No deferred unknowns.

## Not a design decision this document may take

Reclassifying an inventory row is the operator's call. This document does not
reclassify row 5 — it removes the reason anyone wanted to, by building the
test the row asks for.
