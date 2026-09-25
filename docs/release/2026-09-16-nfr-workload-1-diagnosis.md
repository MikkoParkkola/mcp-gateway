<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.WORKLOAD.1 — diagnosis before grading

The release owner ruled that `NFR.WORKLOAD.1` is to be diagnosed before it is
graded, and declined both "lower the threshold to what was measured" and "hold
it as NOT MET" until a cause is established. This document establishes the
cause.

Evidence is labelled **verified** (read or computed here, with a citation),
**inferred** (follows from one source), or **assumption** (neither). Every
harness citation is read out of `origin/feat/v4-workload-harness` with
`git show`; the branch is not checked out anywhere by this document.

## Where the row actually lives

**Verified.** The row is not in `docs/requirements/RELEASE-4.0.0-criteria-status.md`:
`rg -i -c workload` over that file exits 1 with no match. The graded entry is
`criteria[26]` of `docs/requirements/RELEASE-4.0.0-scope-status.json`
(`id: NFR.WORKLOAD.1`, `status: pending`). Its requirement text is at
`docs/requirements/RELEASE-4.0.0-scope-update.md:55` and its test obligation at
`docs/requirements/RELEASE-4.0.0-scope-tests.md:69`. Anyone re-grading this row
should edit the JSON entry, not the criteria-status document.

## 1. Where the threshold is written, and what the score measures

**Verified.** The threshold is written in three places, all agreeing on 100%:

- `benchmarks/workload/eval_workload.py:107-109` — the only enforcing copy:

  ```python
  # Void 2: semantic assertions must be perfect, not merely mostly right.
  if rate(summary, "semantic_assertion_rate") < 1.0:
      raise Void(f"{rep}: semantic assertion rate below 100%")
  ```

- `docs/requirements/RELEASE-4.0.0-workload-contract.md:136-139` — "Semantic
  assertion: every measured `tools/call` must return the exact pinned payload
  string. A response that is merely HTTP 200, or JSON-RPC well-formed, or an
  error, fails the assertion. A cell whose semantic assertion rate is below 100%
  voids."
- The same contract's §8 void-condition list, item 2, at line 286.

The score itself is a k6 `Rate` over one boolean per iteration
(`benchmarks/workload/k6_workload.js:51`, `:236-247`):

```javascript
const callRes = invokePinnedTool(mcpToolsCallLatency);

const payload = callRes && callRes.result ? JSON.stringify(callRes.result) : "";
const ok = callRes !== null && callRes.error === undefined && payload.includes(EXPECT_TEXT);

semanticOk.add(ok);
if (!ok) semanticFailures.add(1);

check(callRes, {
  "tools/call: no error": (r) => r !== null && r.error === undefined,
  "tools/call: semantic payload matches the pin": () => ok,
});
```

So `semantic_assertion_rate` is the fraction of `gateway_invoke` calls whose
JSON-RPC `result`, serialised, contains the exact string
`WORKLOAD_OK case=042 bundle=deterministic`. That string is pinned twice, in the
fixture (`benchmarks/workload/mcp_backend.py:28`) and in the runner
(`benchmarks/workload/run_workload.sh:39`). The backend is a frozen stdio script
with one tool, one argument and no per-call I/O, so the payload it returns cannot
vary.

## 2. Was the threshold wrong, or is the behaviour wrong? Neither

**Verified, and this is the decisive evidence.** The same 4.0.0 binary that
scored 0.6685–0.6692 scored 1.0000 once the harness changed — with no source
change at all.

`benchmarks/results/rehearsal-2026-09-14/07-header-fix-and-rerun.md:13-33`
records run `2026-09-14-hdrfix-v2` on the same pinned arm binaries as rehearsal 2
(`C/D/E = 69ba9e03`, 4.0.0), and states that the fix is harness-only:
`git diff --stat 69ba9e03..bfeec660 -- src/` is empty. On that run:

| cell | reps | semantic |
|---|---|---|
| A (3.5.0) | 1–3 | 1.0000 |
| B (3.5.1) | 1–3 | 1.0000 |
| C (4.0.0) | 1–3 | 1.0000 |

"C took **zero** rate-limit rejections across 3 reps at the harness's offered
rate … Semantic assertion is 100% on all three gating cells, for the first time
this harness has run."

That settles both halves of the question:

- **The threshold was not wrong at authoring time.** A rate over a single
  per-iteration boolean has no impossible member, and 1.0 has now been observed
  on the gating cell at 4.0.0. 1.0 is reachable by construction and reachable in
  fact.
- **The measured behaviour is not a product defect either.** The failing runs did
  not catch the gateway returning a wrong answer to a well-formed request; they
  caught the gateway shedding load it was never configured to accept.

The actual cause is a **harness configuration defect with two layers**:

1. **Layer one, fixed.** The k6 client sent a request shape that carried no
   `MCP-Protocol-Version` header and bound no session revision. On 3.5.x that
   shape is cached unconditionally; on 4.0.0 `cache_protocol_revision`
   (`src/protocol/meta.rs`) fails closed and returns `None`, so every call
   reached the backend. Recorded at
   `benchmarks/results/rehearsal-2026-09-14/06-finding-response-cache.md:16`
   (3.5.x: 319 of 320 from cache, 1 backend invocation; 4.0.0: 0 cache hits,
   320 invocations). Commits `13f12709` and `bfeec660` send the header on the
   legacy cells; C then reached 1.0000.
2. **Layer two, still open.** Once calls reach the backend, they meet the shipped
   default rate limit that the pinned config never overrides —
   `DEFAULT_RATE_LIMIT_RPS = 100`, `DEFAULT_RATE_LIMIT_BURST = 50` at
   `src/config/features/failsafe.rs:20-21` (**verified in this worktree**) —
   against a closed-loop offer of roughly 137 iterations/s (ramping-vus, 50 VUs,
   `k6_workload.js:56-64`). Cells D and E are still in that state and still
   score ~0.663.

So the 0.6685–0.6692 band is not a measurement of 4.0.0's semantic correctness.
It is a measurement of admission control under an offered rate the workload
config never asked the gateway to accept.

## 3. Which assertion fails, and what the gateway returns

**Exactly one assertion fails.** Of the four k6 checks per iteration —
`initialize: no error` (`k6_workload.js:223`), `tools/list: no error` (`:230`),
`tools/call: no error` (`:245`) and `tools/call: semantic payload matches the pin`
(`:246`) — only the last one fails.

**Verified by arithmetic on the committed figures.**
`benchmarks/results/rehearsal-2026-09-14/02-results.md:19` records rep C2 as
`sem 0.6685`, `sem pass 5444`, `sem fail 2700`, `check rate 0.9171`. With four
checks per iteration and 8144 iterations, a single failing check per
semantically-failing iteration predicts `1 − 2700/(4 × 8144) = 0.91713`. The
recorded check rate is 0.9171. Two failing checks would predict 0.8343. So on a
failing iteration `tools/call: no error` **passes**: the response is a well-formed
JSON-RPC `result`, not a JSON-RPC `error`, and not a non-200 (the `http error
rate` column is 0 for every rep in that table).

**What is in that result.** `06-finding-response-cache.md:125-126` records it
directly: "every semantic failure was `Circuit breaker open`". The mechanism is
verified in this worktree:

- `src/backend/ops.rs:305-313` gates every backend request on
  `entry.failsafe.can_proceed()` and returns `Error::CircuitOpen(self.name)` when
  it is false.
- `src/failsafe/mod.rs:48-50` defines that gate as
  `self.circuit_breaker.can_proceed() && self.rate_limiter.try_acquire()`.
- `src/error.rs:92-93` gives that variant the message
  `Circuit breaker open for backend '{0}'`.

One gate, two causes, one message. A rate-limiter denial is indistinguishable
from a breaker trip in the error text, which is why an earlier revision of
`03-finding-breaker.md` diagnosed a breaker trip and later withdrew it (commit
`9a4f4d5c`). The gateway therefore answers roughly one call in three with
`Circuit breaker open for backend 'workload'` in place of the pinned payload, and
the semantic assertion correctly rejects it.

**The concrete failing cells and reps:**

- Run `2026-09-14-rehearsal2` (`02-results.md:12-26`): C1 0.6692, C2 0.6685,
  C3 0.6685, D1 0.6685, D2 0.6687, D3 0.6682, E1 0.6685, E2 0.6683, E3 0.6683 —
  9 of 15 reps. A1–A3 and B1–B3 are 1.0000.
- Run `2026-09-14-hdrfix-v2` (`07-header-fix-and-rerun.md:22-30`): A, B and C all
  1.0000; D1–D3 and E1–E3 at 0.6630–0.6636 — 6 of 15 reps. The evaluator reports
  `VERDICT: VOID (exit 3) / D1: semantic assertion rate below 100%`.

**One failure that is not a semantic-assertion failure**, and should not be
counted as one: under the first version of the header fix (`13f12709`, which sent
the header unconditionally) D1 aborted in `setup()` with
`initialize failed: {"error":{"code":-32602,"message":"missing required request
metadata: io.modelcontextprotocol/protocolVersion,
io.modelcontextprotocol/clientCapabilities"}}`
(`07-header-fix-and-rerun.md:62-67`). The header alone flips `classify_request`
to `Modern`, which then demands a `_meta` block the script's bodies never carried.
`bfeec660` scoped the header to the legacy cells to restore D/E.

## 4. Why "C4" is not evaluable

**First, a labelling correction.** "C4" is not an evaluation cell. The cells are
A–E and the measured reps are 1–3 — `MEASURED_REPS = (1, 2, 3)` at
`benchmarks/workload/eval_workload.py:33` — so no rep named `C4` exists or can
exist. `C4` is **conjunct 4** of the criterion in the conjunct-by-conjunct
grading at `benchmarks/results/rehearsal-2026-09-14/05-grading.md:12`: "Preserves
the P50 ≤5% and P99 ≤10% budgets — **NOT EVALUABLE**".

**Second, it is a human grading judgement, not an evaluator output.**
`eval_workload.py:145` builds every rep's result inside a list comprehension over
`check_rep`, which raises `Void` on the first failing rep. Both scored runs voided
on a semantic assertion before the budget comparison at `:164-165`
(`limit_p50 = P50_BUDGET * base_p50`, `limit_p99 = P99_BUDGET * base_p99`) was
ever reached, and before a `verdict.json` was written
(`07-header-fix-and-rerun.md:43-50`). There is no machine verdict of "not
evaluable"; the evaluator has no such status.

**Third, the mechanism — one reason per side of the comparison**, both recorded
in `05-grading.md:12` and traceable to source:

- **Candidate side (C/D/E).** `rpc()` adds every response's duration to the
  latency Trend unconditionally, before any semantic check:
  `if (trend) trend.add(res.timings.duration);` at `k6_workload.js:144`. A
  short-circuited `Circuit breaker open` refusal never reaches the backend and is
  therefore much faster than a served call, yet it lands in the same
  `mcp_tools_call_latency` sample. About a third of that distribution is
  refusals. The p50 and p99 the evaluator would read are a blend of two different
  operations.
- **Baseline side (A/B).** The 3.5.0 and 3.5.1 figures are predominantly
  cache-hit service time: 1 backend invocation over a 60.00 s probe at the rep's
  own offered rate (`06-finding-response-cache.md:16`, `05-grading.md:12`).

So the ratio gate would compare a baseline that did essentially no backend work
against a candidate that did backend work for two thirds of its sample and
refused the rest. That is not a pass and not a fail; there is no comparison to
grade.

**A caution that follows from the fix, inferred from one source.** The header fix
puts A, B and C on the same path, which removes the "different experiments"
objection — but the path they now share is the cached one. `07-header-fix-and-rerun.md:86-89`
makes the point for D/E and it applies to C as well: caching a cell "removes the
real-backend property, not just the throttling". A budget comparison across
A/B/C on `hdrfix-v2` would therefore be a valid comparison of cache-service
latency, and the criterion's "deterministic real-backend workload" conjunct would
still be unmet. C4 has not been re-graded on that run in any case: it voided on
D1 before the budget check ran.

## 5. Is 0.6685 versus 0.6692 a meaningful spread?

**Noise. Verified by arithmetic on the committed counts.**

The whole band across nine reps in `2026-09-14-rehearsal2` is 0.6682–0.6692
(`02-results.md:12-26`) — a relative spread of 0.15%. The widest pair inside it,
C1 at 0.6692 and C2 at 0.6685, differs by nine iterations: C1 recorded 5444 passes
and 2691 failures (8135 iterations), C2 recorded 5444 passes and 2700 failures
(8144 iterations). The *served* count is identical to the digit; only the number
of iterations the closed loop managed to offer moved.

That is exactly what the mechanism predicts. A token bucket of 100 rps plus a
burst of 50 pins the served count for a fixed-length rep, while the offered count
in a closed loop drifts with VU scheduling — and a refused call returns faster
than a served one, so the offered rate is itself a function of how many were
refused. The ratio is therefore a quotient of one near-constant over one slightly
variable quantity.

Two further observations point the same way:

- Cells C, D and E agree to within 0.001 across three different protocol-era
  configurations in the same run. A semantic defect sensitive to protocol
  handling would not be that indifferent to which era the client speaks;
  `02-results.md:32-34` draws the same conclusion.
- The model is fitted independently at a second offered rate in
  `06-finding-response-cache.md:93-98`: 320 calls offered at ~160/s over 2.00 s
  predicts `50 + 100 × 2.00 = 250` served and 70 rejected; 249 and 71 were
  observed.

The larger step — from ~0.6685 in `rehearsal2` to 0.6630–0.6636 for D/E in
`hdrfix-v2` — is about 0.8% and is **also** not signal about semantics: it is a
different run on a different day with a changed client, and both numbers sit on
the same shed-load plateau. **Do not read any digit past the second in these
figures as information.** The band means "roughly two calls in three were served";
it does not distinguish one rep, cell or run from another.

## What this means for the row

**Recommendation: keep the 100% threshold, and hold `NFR.WORKLOAD.1` as blocked
on the harness, not on the product — then take neither option in the decision
docket as written.**

The threshold is sound and has been met at 4.0.0 on the gating cell. The product
behaviour behind 0.6685–0.6692 is admission control refusing an offered rate the
workload never configured the gateway to accept. Lowering the threshold would
bless a number that measures the harness; holding the row as NOT MET would record
a product failure the evidence does not support. Both declined options were
declined correctly.

`docs/release/v4.0.0-decision-docket.md:17` frames the owner's choice as "raise
`requests_per_second`, or scope the §8 void condition to the gating cells", and
gives as the cost of raising that it "breaks the byte-identical-config pin". That
cost is overstated. **Verified:** `benchmarks/workload/run_workload.sh:50-55`
renders one config file shared by cells A, B, C and D, and §8 condition 8 requires
that A, B and C run a *byte-identical config as each other* — not that the
template never changes. Editing the shared template raises the limit on every
gating cell at once and leaves that pin intact. The real cost of raising is a full
re-run, nothing more.

The second option is the one to avoid. Scoping the void condition to the gating
cells would let `hdrfix-v2` grade, and on that run A, B and C are all answering
from the response cache — `07-header-fix-and-rerun.md:86-89` says of the same
change that caching a cell "removes the real-backend property, not just the
throttling". A passing verdict would then rest on cache-service latency, which is
the flattering non-measurement the rehearsal existed to catch.

The change that closes the row is two keys in the one shared template. **Verified:**
`benchmarks/workload/gateway.workload.yaml` is 16 lines and contains no `cache:`
and no `failsafe:` key, so both the response cache and the 100 rps / burst 50
limit are shipped defaults the workload silently inherits. Disable the response
cache for every cell, and set `requests_per_second` above the harness's offered
rate (~137/s at 50 VUs; ~160/s was observed on the probe, so a limit of 500 has
margin). Every cell then takes the deterministic real-backend path the criterion
asks for, at 100% semantic assertion, with a latency comparison that compares
like with like — and C4 becomes evaluable for the first time. Re-pin, re-run,
then grade.

This diagnosis stops at the edge of measurement. Confirming the fix requires
executing the harness, which contract §4 admits only post-merge and which runs on
bench-host, not here. No harness run was performed for this document.

**The one thing that would falsify this recommendation:** a re-run with the
response cache disabled and `requests_per_second` above the offered rate on all
five cells, in which cell C still scores below 1.0 while taking zero rate-limit
rejections. That would mean the gateway returns something other than the pinned
payload on an uncontended real-backend path, the semantic assertion is rejecting
it correctly, and the row becomes a product defect rather than a harness one.
