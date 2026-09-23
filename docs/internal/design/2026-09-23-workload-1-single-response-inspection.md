<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.WORKLOAD.1: one response inspection per meta `tools/call`

Status: reviewed (grok SHIP-WITH-FIXES, kimi SHIP-WITH-FIXES); fixes folded in. No code yet.

## Problem

NFR.WORKLOAD.1 has no graded result at the release tip: every re-run on spark
has voided on host load. Latency cannot be measured on that host, but executed
instructions can, and they are insensitive to load.

Gateway-only user-space instructions per `tools/call`, measured on spark with
the harness's own config (`RUST_LOG=error`, the pinned `gateway_invoke` →
`workload_probe` request, paced at 200 req/s, 3000 calls, zero errors):

| build | instructions / call | repeat |
|---|---|---|
| v3.5.0 (`32f135a6`) | 532,650 | 547,018 |
| 4.0.0 tip (`fe2ed154`) | 752,478 | 754,677 |

+39%, about 210K per call. The standing latency FAIL is +8.4% on `tools/call`
only (measured at `14933f9a`); latency moves at roughly a fifth of the
instruction delta because most of a call's wall time is the backend round trip.

Turning `security.firewall.scan_responses` off in the same config isolates the
share spent inspecting responses:

| build | scan on | scan off | inspection cost |
|---|---|---|---|
| v3.5.0 | 517,317 | 495,616 | 22K |
| 4.0.0 tip | 717,744 | 647,456 | 70K |

The tip spends about 48K more per call on response inspection than 3.5.0 —
roughly a quarter of the regression. This design addresses that quarter only;
the remaining ~151K is a separate investigation (see "Out of scope").

## Cause

A successful meta `tools/call` is inspected twice, by two `Firewall`
instances built from the same `security.firewall` config:

1. `meta_mcp_dispatch`, `tools/call` arm (`src/gateway/router/handlers.rs:1783-1834`):
   `state.firewall.check_response_artifact(result, &response_targets, …,
   FinalResponse, Redact)`. Blocks on the verdict; the comment at `:1828` says
   the shared finalization below still runs.
2. The same function then calls `MetaMcp::finalize_response_for_delivery`
   (`handlers.rs:1993`), which for `tools/call` runs
   `self.firewall.check_response_artifact(result, context.targets, …,
   FinalResponse, PreserveInputRequired)` (`src/gateway/meta_mcp/response_security.rs:59-81`).
   `PreserveInputRequired` is not `Redact`, so it also clones the whole result
   (`src/security/firewall/response.rs:38`) to detect a rewritten protected value.

The two firewalls: `AppState.firewall` is built in `run()`
(`src/gateway/server/mod.rs:1976`); `MetaMcp.firewall` separately at
`src/gateway/server/mod.rs:1273-1287`, "each keeps its own `TransitionTracker`".

## Why the second inspection cannot change the outcome on this path

- Scan 2 inspects the artifact scan 1 already redacted under the same config
  and the same `response_targets`. Credential findings scan 1 redacted are no
  longer present; non-redacting findings (e.g. prompt injection) are the same
  findings scan 1 already resolved into an action, over the same targets.
- If scan 1 refused, `call_response` is already a delivery-refusal error, and
  scan 2's guard (`response.error.is_none()`) skips it.
- Scan 2's protected-value check compares against a clone taken AFTER scan 1,
  so it cannot observe a change scan 1 made.

## Proposal

Skip the delivery-time inspection when, and only when, the `tools/call` arm has
already inspected this exact artifact.

- `ResponseDeliveryContext` gains `inspection: DeliveryInspection`, an enum
  (repo rule: behaviour-selecting parameters are enums, not booleans; named to
  avoid the existing `ResponseInspectionConfig`):
  `DeliveryInspection::Required` | `DeliveryInspection::AlreadyInspected`.
- `meta_mcp_dispatch` declares a local `let mut inspection =
  DeliveryInspection::Required;` BEFORE the method `match`, and sets
  `AlreadyInspected` ONLY inside the `tools/call` arm, immediately after scan 1
  has run on `call_response.result`. It is never derived from `Some`-ness at the
  shared context builder: `ResponseDeliveryContext` is built once for every
  method, and HTTP `tools/list` has no pre-pass — its finalization scan is its
  ONLY blocking inspection (grok design review, CRITICAL).
- `finalize_response_for_delivery` inspects when `Required`, exactly as today.
- Every other caller (`src/gateway/server/mod.rs:3041`, the stdio path, where
  finalization is the ONLY inspection) passes `Required`. Unchanged.

Default is fail-closed: anything not provably inspected is inspected.

Audit consequence, stated: with `security.firewall.audit_log` set, a successful
HTTP `tools/call` emits one `response` audit line (from `AppState.firewall`)
instead of two identical ones.

Alternative considered and not taken: delete the arm pre-pass and let
finalization be the single inspection, passing `Redact` for `tools/call`. It is
simpler, but the pre-pass exists deliberately (`handlers.rs:1775`: a response
continuing past it "would launder it past the delivery chokepoint") and moves a
refusal decision earlier than the owned-execution finalization; keeping it
changes nothing about when a refusal is decided.

## Review questions, answered at source

1. **Does the meta instance observe anything the handler instance does not?**
   No. Each instance opens its own `AuditLogger` on the SAME
   `security.firewall.audit_log` path (`src/security/firewall/mod.rs:331`;
   unset by default), and both write a `FinalResponse` record with the same
   correlation — so today every response produces two identical records in one
   file, and the skip removes a duplicate. `src/security/firewall/response.rs`
   has zero references to the `TransitionTracker`; the tracker feeds only the
   anomaly detector (`mod.rs:318-326`). The handler instance additionally
   carries session-lifecycle wiring (`src/gateway/server/mod.rs:1822-1824`);
   the meta instance carries nothing the handler instance lacks.
2. **Can the instances diverge?** No. Both are built once at startup from
   `self.config.security.firewall.clone()` (`src/gateway/server/mod.rs:1274`,
   `:1807`). `src/config_reload/` never references the firewall;
   `AppState.firewall` is a plain `Option<Arc<Firewall>>`
   (`src/gateway/router/mod.rs:125`); `set_firewall` has one caller, at
   construction behind `Arc::get_mut` (`server/mod.rs:1285-1287`). The handler
   instance is always `Some` (`server/mod.rs:1804-1818`), even when disabled.
3. **Does anything mutate the result between the scans?** Only
   `shape_modern_response` (`handlers.rs:2103-2147`, modern era only). It adds
   gateway-authored constants: `resultType` when absent, `ttlMs`/`cacheScope`
   for `CACHEABLE_METHODS` (list methods; `tools/call` is not among them,
   `handlers.rs:2077`), and `_meta` server info (`"mcp-gateway"` and the crate
   version). Nothing backend-derived reaches the result after scan 1.

## Tests (written first, must fail against today's code)

- T1: one successful meta `tools/call` with response scanning on produces
  exactly ONE inspection on the handler (`AppState`) instance and ZERO on the
  `MetaMcp` instance (today: one on each). Per-instance, not a sum: a
  regression that dropped scan 1 and kept scan 2 would also sum to one. The
  test-only `ResponseObserver` (`src/security/firewall/response_observer.rs`)
  counts per instance.
- T2: a response carrying a credential is still redacted in the delivered body.
- T3: a response carrying a blocking finding is still refused.
- T4: the stdio path (`server/mod.rs:3041`) still inspects (one inspection).
- T5 (mutation): forcing `AlreadyInspected` everywhere must fail T4.
- T7: HTTP `tools/list` is still inspected exactly once, by the `MetaMcp`
  instance (the flag must not leak to methods without a pre-pass).
- T6: a modern-era `tools/call` (which runs `shape_modern_response` between the
  scans) is still inspected exactly once, on the handler instance — pinning the
  Q3 conclusion so a later shaping change cannot silently invalidate the skip.

## Out of scope

- The remaining ~151K instructions per call with scanning off. Profiling
  attributes much of it to allocation volume (`malloc`/`free`, glibc arena
  lock traffic) across the 4.0.0 dispatch layers; the per-function inclusive
  comparison is in progress and will be its own design.
- Whether scan 1 should redact inside input-required content that scan 2's
  policy would preserve — a pre-existing semantic question, not changed here.
