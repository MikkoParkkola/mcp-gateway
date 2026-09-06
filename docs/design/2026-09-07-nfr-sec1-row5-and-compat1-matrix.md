<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Closing NFR.SEC.1 row 5 and the NFR.COMPAT.1 revision matrix

Two BLOCKING release criteria for 4.0.0. Both are ABSENT for the same
underlying reason: a claim was graded against tests that never drove the
production path the claim is about.

## Problem

### NFR.SEC.1 — one control has no refusal test

`docs/requirements/nfr-sec1-control-inventory.md` closes the set at 14 gates
plus a blocked 15th. Thirteen carry a refusal test. Row 5 — the per-client
circuit breaker, `client_preflight` at `src/gateway/auth.rs:963` — does not.

The committed inventory argues row 5 is N/A: "refuses on a *trip count*, not
an absent input... a circuit breaker has no absent input to remove." **That
argument is rejected here.** It reads the criterion off its own sub-clause
rather than its subject. The row says *no 3.5.0 control becomes inoperative
for a modern caller; each has a refusal test*. What a breaker refuses is a
caller whose circuit is open. That is an input, it is removable, and removing
it is drivable — see the resolved unknown below. Narrowing a criterion is not
available this release, so N/A is not this document's to take.

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
| C2 | 2025-11-25 served | `initialize` | echoed back, not downgraded | a revision absent from `SUPPORTED_VERSIONS` → downgraded to `PROTOCOL_VERSION` |
| C3 | 2025-06-18 served | `initialize` | echoed back | as C2 |
| C4 | 2025-03-26 not dropped | `initialize` | negotiates without error | as C2 |
| C5 | 2024-11-05 not dropped | `initialize` | negotiates without error | as C2 |

C1's second clause — the wired legacy-client bridge, `MIK-7212.MRTR.7a`/`7b`
in `src/protocol/continuation.rs` — is **not in this change**. That file is
peer-held. C1 as written asserts the revision is served; it does not assert
the bridge exists, and the criterion stays blocking until the bridge lands
regardless of what this change proves.

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
2. **Trip the breaker by calling `record_client_failure` directly.** Rejected:
   a unit test of a helper. MET is defined as a test driving the behaviour
   through a production path.
3. **Trip it through `POST /mcp` with repeated erroring calls.** Chosen. Uses
   the same recording site production uses (`handlers.rs:1330`), so a change
   that stops recording failures breaks the test.
4. **One combined COMPAT test parameterised over five revisions.** Rejected:
   the 2026 revision and the 2025 ones enter by different paths, so one
   parameterised body would need a branch on the parameter — which is two
   tests wearing one name, and the branch is where the wrong-path bug hides.

## Out of scope

- The firewall gate (inventory's blocked 15th) — needs `src/security/firewall/**`,
  owned by another session.
- The legacy-client bridge (`src/protocol/continuation.rs`) — peer-held.
- `docs/ARCHITECTURE.md:65`, which advertises a revision `SUPPORTED_VERSIONS`
  does not serve. Real defect, different owner, recorded not repaired.
- Any edit to `docs/requirements/RELEASE-4.0.0-criteria-status.md`. Evidence is
  reported; the team lead regrades.

## Unknowns

| unknown | check | result | what it changed |
|---|---|---|---|
| Is the client circuit breaker trippable from outside the `/mcp` route? | read every caller of `record_client_failure` (`rg` over `src/`) | Yes. `src/gateway/router/handlers.rs:1330` records a failure for the authenticated client on **any** JSON-RPC error response, excluding confirmation refusals. `backend_handlers.rs:559,:814,:868` record on the backend path. | Killed the N/A. Row 5 is buildable, and option 3 became available. |
| Which path serves 2026-07-28? | read `MODERN_VERSIONS` and its consumers | The stateless POST path via the version header, gated on `server.modern_protocol`; never `initialize`. | Split C1 from C2-C5. Without this the C1 test would have driven `initialize` and failed for a non-defect. |
| Does `modern_protocol` default on? | `src/config/mod.rs:1236` | true, since `83c98902` (2026-09-04) | C1 needs no config mutation for its positive arm; its falsifier flips the flag off. |
| Does the breaker's refusal have a signature distinct from the gates around it? | read `errors.rs:20,:29` | 503/`-32003` vs the rate limiter's 429/`-32000` | Made the S5 falsifier decidable. |

No deferred unknowns.

## Not a design decision this document may take

Reclassifying an inventory row is the operator's call. This document does not
reclassify row 5 — it removes the reason anyone wanted to, by building the
test the row asks for.
