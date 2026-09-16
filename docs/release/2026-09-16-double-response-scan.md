<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# The `tools/call` response is firewall-scanned twice, on the release line

A peer session isolated the 4.0.0 response-firewall p50 regression on
`feat/v4-workload-harness` and measured it: **~7–13 µs fixed per scan plus
~13–15 µs per kB**, with the fixed term dominating on a 271-byte `tools/call`
payload. Its conclusion was that the meta path scans that response twice.

This note records the independent confirmation **at the release line**, because
a defect proven on a harness branch is not a defect proven where 4.0.0 ships.
Line numbers below are this branch's, not the harness branch's.

## Both scans, verified

`src/gateway/router/handlers.rs` scans the response inside one function, twice:

| | site | artifact kind | targets | mutation policy |
|---|---|---|---|---|
| first | `handlers.rs:1723` | `FinalResponse` | `response_targets` | `Redact`, hardcoded |
| second | `response_security.rs:67`, entered from `handlers.rs:1915` | `FinalResponse` | `&response_targets` — the same variable | `context.mutation` |

Same scanner, same artifact kind, same target set, same correlation (session,
caller, `external_server: "gateway"`), same payload. The second is gated to
`"tools/call" | "tools/list"` and to a successful response.

## Why the second scan is defensible and the first may not be

`shape_modern_response(&mut response, &method)` runs at `handlers.rs:1913` —
**between** the two scans. So the second scan is not naive duplication: it
inspects a payload that was mutated after the first scan looked at it. Re-checking
after a mutation is the correct instinct.

That inverts the obvious fix. The cheap win is dropping the **earlier** scan, not
the later one, and the question for the owner is narrow:

> Does anything between `handlers.rs:1723` and `:1915` depend on the redaction
> or the block decision the first scan performs — or is the only reason it runs
> first that it was written first?

If nothing depends on it, one scan after the mutation is both cheaper and
strictly safer than one before plus one after. If something does — an early
block that must not reach `shape_modern_response` — then both scans are load
bearing and the cost is the price of the guard, which is a legitimate answer
worth writing down rather than re-deriving next quarter.

## What is not established

The peer session is explicit that only 18.0–21.2 µs of the 34.1 µs graded gap on
`tools/call` ablates away; the ~13 µs residual is unattributed 4.0.0 response
work. Which component carries the fixed per-scan cost — target vector handling,
`audit.log_response_artifact`, scanner setup — was not investigated by either
session. `firewall/response.rs:38` deep-clones the whole result to feed an O(1)
two-key comparison, which is a candidate and not a measurement.

No fix is proposed here and none should be applied before the question above is
answered. This is `NFR.PERF.1` evidence, not an `NFR.PERF.1` closure.
