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

## Why neither scan is simply redundant

`shape_modern_response(&mut response, &method)` runs at `handlers.rs:1913` —
between the two scans — so where it mutates the payload, the second scan is a
recheck rather than duplication. Three findings from the peer session bound that
reading (`0601f024` on `feat/v4-workload-harness`; the line numbers in this
section are that branch's, not this one's, and do not transfer):

1. **The shaping is era-gated, and the graded cell is not in that era.** It runs
   only when the caller is `Era::Modern` (`handlers.rs:1822`, `:808`). The
   workload runner gives arms A/B/C the legacy protocol and only D/E the modern
   one (`benchmarks/workload/run_workload.sh:76`), and every measured number
   comes from **C**. On the graded arm nothing mutates between the scans: the
   second inspects byte-identical bytes. The recheck justification is sound, and
   it applies to D/E, which were never measured.
2. **The two scans carry different policies, so neither is a deletion
   candidate.** The first runs `ResponseMutationPolicy::Redact` and takes no
   clone — `firewall/response.rs:38` clones only when the policy is not
   `Redact`. The second runs `PreserveInputRequired`, clones, and cannot redact:
   it can only detect and refuse (`response.rs:118-123`). Dropping the first
   removes the only redacting pass. Their scopes differ too — the first sits
   inside the meta `tools/call` arm while the finalizer is unconditional for
   every method, which is why `tools/list` goes from zero scans to one and pays
   ~213 µs.
3. **A block at the first scan is not an early return.** The code says so at
   `handlers.rs:1666-1669`: a block substitutes a `delivery_refusal_error` that
   still traverses shaping and the second scan.

Half of the question this note opened with is therefore answered: no early-block
dependency exists. A single post-shaping pass would have to run `Redact`, not
`PreserveInputRequired` — a policy change, not a deletion, and one that would
have to keep the redacting behaviour the first pass is the only source of.

> Still open: does anything between `handlers.rs:1723` and `:1915` consume the
> first scan's **redaction** before the finalizer runs?

## What is not established

The peer session is explicit that only 18.0–21.2 µs of the 34.1 µs graded gap on
`tools/call` ablates away; the ~13 µs residual is unattributed 4.0.0 response
work. Which component carries the fixed per-scan cost — target vector handling,
`audit.log_response_artifact`, scanner setup — was not investigated by either
session. `firewall/response.rs:38` deep-clones the whole result to feed an O(1)
two-key comparison, which is a candidate and not a measurement.

No fix is proposed here and none should be applied before the question above is
answered. This is `NFR.PERF.1` evidence, not an `NFR.PERF.1` closure.

Measurement of record: `72865b2c` on `feat/v4-workload-harness` carries the
corrected fit. Only ~6.9 µs of the 21.2 µs ablated on `tools/call` is per-byte,
so the fixed per-scan term is the larger half of what a scan costs there. The
probe run itself is diagnostic, not graded: its closing quiet gate failed
(`load 9.09 >= 8.00`, exit 3) and was not retried, which the peer's own note now
discloses in its opening paragraph.
