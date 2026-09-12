# NFR.PERF.1 — benchmark contract

**Written before the run, on purpose.** A benchmark whose pass rule is chosen after the
numbers arrive is not a measurement, it is a defence. Nothing below may be edited once the
first measured rep starts; if something here turns out to be wrong, the run is void and a
new contract is written.

Status when written: **contract only, nothing measured yet.**

## What is being settled

`NFR.PERF.1` (`docs/requirements/RELEASE-4.0.0-requirements.md:230`) — verbatim:

> Tool-call latency through the gateway MUST NOT regress by more than 5% at P50 or 10% at
> P99 against 3.5.0 on the same workload.

This is an **end-to-end** requirement: "tool-call latency through the gateway", with P50 and
P99, which are properties of a distribution and cannot be produced by a microbenchmark. The
existing artifact `RELEASE-4.0.0-performance.md` measured the *added work* with criterion and
said so honestly in its own closing section. This contract replaces the argument with the
measurement it names.

## Arms

| arm | ref | commit |
|---|---|---|
| baseline | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` |
| candidate | `fix/mrtr2-continuation-handle` | `6218b8577e79b6cc07f34dd4c64326d1117558c6` |

Both built from source on the same machine, in the same session, with the same toolchain:

```
cargo build --release --locked --features a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics
```

The feature list is stated explicitly as a **pin**, not as a divergence from `default`: at both
refs `default` names exactly these nine features, and no `--no-default-features` is passed, so
both arms build the same set either way (A6.1). Writing it out means the build line does not move
if `default` moves under one arm — which matters because a feature absent in one arm compiles
some benchmarked paths away entirely. Verified before writing this:
the `[features]` tables at the two refs are identical, so the same explicit list is achievable
at both (`git show v3.5.0:Cargo.toml` vs `Cargo.toml`). Each arm uses **its own** `Cargo.lock`
(`--locked`), because the dependency set is part of what the release is.

## Workload — the same one, and it is the repo's own

`tests/load/k6_gateway.js`, scenario `load` (50 VUs: 10 s ramp, 40 s hold, 10 s ramp down).

The script is present at **both** refs and is **byte-identical** between them:

| file | sha256 (first 16) at v3.5.0 | at HEAD |
|---|---|---|
| `tests/load/k6_gateway.js` | `6a8873a0a908566d` | `6a8873a0a908566d` |
| `tests/load/wrk_basic.lua` | `707fe47e32fb7d69` | `707fe47e32fb7d69` |
| `tests/load/README.md` | `4e5cd75900d45a5e` | `4e5cd75900d45a5e` |

That identity is what makes "the same workload" a fact rather than a claim. One copy of the
script is used to drive both arms.

Each VU iteration performs `initialize` -> `tools/list` -> `tools/call` against `POST /mcp`,
plus `/health`, `/dashboard`, `/ui/api/status`. The gateway is started with no backends
registered, so the surface under test is the Meta-MCP surface itself — which is the part of
the request path this release changed.

### The one workload hazard, named in advance

`k6_gateway.js:277-285` picks the tool to call as `listRes.result.tools[0].name`, falling back
to `gateway_status`. If the two arms order their tool list differently, the two arms call
**different tools**, and the comparison is between two workloads rather than two builds.

Pre-run check, mandatory: `tools/list` is issued once against each arm and `tools[0].name` is
recorded. If the names differ, this run is **void** and is repeated with the tool name pinned
identically for both arms.

## Primary metric and pass rule

Primary: **`mcp_tools_call_latency`**, the script's own Trend metric around the `tools/call`
request — the literal subject of the requirement.

```
PASS  iff  HEAD p50 <= 1.05 x v3.5.0 p50   AND   HEAD p99 <= 1.10 x v3.5.0 p99
```

Both computed on the **pooled** samples across that arm's measured reps, and additionally
reported **per rep**, so that variance is visible rather than hidden behind a median. A pass
whose per-rep spread is wider than the margin it passed by is reported as inconclusive, not
as a pass.

Secondary, reported but not the gate: `http_req_duration` p50/p95/p99,
`mcp_tools_list_latency`, `mcp_initialize_latency`, `health_latency`.

k6 runs with `--summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max"`, because p(99)
is not in k6's default summary for custom Trend metrics, and with `--summary-export`, so the
numbers come from JSON rather than from parsed console text.

## Rep schedule — interleaved, because the machine is shared

```
warm-up:  A0  B0        (discarded, never reported)
measured: A1  B1  A2  B2  A3  B3
```

A = v3.5.0, B = HEAD. **Interleaved, not blocked.** Spark is a shared machine with other
sessions' jobs landing on it; running all of one arm and then all of the other lets drift in
machine load masquerade as a difference between versions. Interleaving makes that drift appear
as within-arm variance, where it is visible.

Warm-up reps are discarded because a cold first arm is the standard way to manufacture a
regression that is not there.

Only one gateway process runs at a time. The arms bind **different ports** (v3.5.0 -> 39400,
HEAD -> 39401) so a stale listener from the previous rep cannot silently serve the next one.
Before every rep, `GET /health` is read and its reported version must match the arm being
measured — a positive identity check, not an assumption.

## Void conditions — declared now, so they cannot be negotiated later

The run is void, and is reported as void rather than quietly repaired, if any of:

1. `tools[0].name` differs between arms (see hazard above).
2. `http_error_rate` > 0 on any measured rep. Error responses have their own latency
   distribution; a fast 500 is not a fast tool call.
3. `checks` pass rate < 99% on any measured rep.
4. `/health` version does not match the arm under test at any rep.
5. Either build fails, or the two builds do not use the same feature list and toolchain.
6. Any measured rep runs while a second gateway process is listening.

Machine load is **recorded** (`uptime` before and after every rep) rather than used as a void
condition — interleaving is what handles load, and a load threshold chosen after seeing the
numbers would be exactly the kind of post-hoc rule this contract exists to prevent.

## Environment — pinned

| | |
|---|---|
| host | `spark` (all benchmarking; a Mac number would be rejected, correctly) |
| cores | 20 |
| rustc | `1.98.1 (48a229cea 2026-09-01)`, aarch64-unknown-linux-gnu, LLVM 22.1.8 — corrected from the pre-run pin of 1.98.0 per A4.3; both arms build with it, and it is above the `rust-version = "1.95"` both arms require |
| k6 | `grafana/k6` container image, one image for both arms; exact digest recorded with results |
| shared? | yes — other sessions' jobs run concurrently. Load recorded per rep; arms interleaved. |
| transport | both arms delivered to Spark as one git bundle, built in an isolated directory, not in the shared checkout |

## What this measurement will not establish

Stated in advance, because a benchmark that oversells itself is worse than none:

- It measures a gateway with **no backends registered**. Real tool calls cross a second
  process boundary, which adds latency this run does not contain. That makes the test
  *harsher* than production — gateway overhead is a larger share of a smaller total — so it
  does not flatter the candidate.
- 50 VUs on a shared 20-core box is a load level, not *the* load level. Nothing here licenses
  a public throughput or latency claim.
- It settles `NFR.PERF.1` only. `NFR.PERF.2` is a separate question about header-first
  routing, answered separately.

---

## Amendment 1 — 2026-09-08, before any measured rep

The contract above forbids edits **once the first measured rep starts**. No rep has
started: `fd -HI 'k6|perf.*json|summary.*json'` across the repo returns only the load
script itself, and `~/.claude/data/spark-jobs/jobs.log` carries no run for this contract.
So this amendment is legal, and it is recorded as an amendment rather than folded into the
text above, because silently rewriting a pre-run contract is exactly the move the contract
exists to prevent. Each item below states what changed and why, and every one of them was
settled *before* seeing a number.

### A1 — the candidate SHA was stale, and is now pinned as a SHA

`6218b8577e79b6cc07f34dd4c64326d1117558c6` was the branch tip when the contract was
written on 2026-09-02. It is not the tip now, and measuring it would have produced a
number for a commit nobody is shipping.

| arm | ref | commit |
|---|---|---|
| baseline | `v3.5.0` | `32f135a61fb50c20a044fb4c2347bc1cf8015d89` |
| candidate | `fix/mrtr2-continuation-handle` @ 2026-09-08 | `79352d150ebec7ce010403676eeb30d32899a975` |

**The candidate is the SHA, not the branch.** Several sessions commit to this branch: the
tip moved twice during the writing of this amendment (`6218b857` -> `77f10201` ->
`79352d15`). A run pinned to "the branch" would measure whatever landed while it was
running. The results section and the `NFR.PERF.1` row therefore state the SHA measured and
say plainly that it was branch tip at the time, not that it is branch tip now.

### A2 — toolchain drift: 1.98.0 -> 1.98.1

The environment table pins `rustc 1.98.0 (88d9e12ae 2026-08-18)`. Spark now carries
`rustc 1.98.1 (48a229cea 2026-09-01)`, and downgrading a shared machine's toolchain for a
benchmark is not this session's call. Both arms build with **1.98.1**.

The real requirement was never a specific version — it is that **both arms use the same
toolchain**, which is what makes a difference attributable to the code. That is what this
amendment pins, and 1.98.1 satisfies it as 1.98.0 would have. Both refs declare
`rust-version = "1.95"`, so neither arm is being built below its own floor.

### A3 — the pass rule could not be executed as written

The rule says percentiles are computed on the **pooled** samples across an arm's measured
reps. `--summary-export` emits *per-rep percentiles*, and percentiles cannot be pooled by
averaging them — averaging three p99 values is not the p99 of the three reps. As written,
the rule named a computation the run does not produce, and discovering that while holding
three summary files is how a pass rule gets chosen after the numbers.

The first draft of this amendment replaced pooling with the **median of the three per-rep
values**. Review killed it, correctly, with a counterexample: baseline per-rep p99
`[99, 100, 100]` and candidate `[108, 108, 109]` gives medians 100 and 108, which passes the
10% gate with room to spare and survives the spread guard — while the pooled p99 goes from
99 to 109, a **10.1% regression**. A statistic that admits a distribution the requirement
forbids is not a cheaper way to answer the question, it is a different and weaker question.
"Pooled" therefore **stands**, and the run is changed to produce it.

```
k6 emits raw samples:  --out json=<rep>.json   (in addition to --summary-export)
reduction on Spark:    all mcp_tools_call_latency point values for an arm's three measured
                       reps are concatenated and p50/p99 computed once over that pooled set
returned to the Mac:   the computed percentiles only, never the sample files
PASS  iff  HEAD p50 <= 1.05 x v3.5.0 p50   AND   HEAD p99 <= 1.10 x v3.5.0 p99
```

Raw sample files are large and stay on Spark; the reduction runs there. Per-rep p50/p99 are
still reported beside the pooled figures, because that is what makes variance visible, and
the inconclusive rule now has a definition it can be checked against: if an arm's per-rep
spread (`max - min`, reported) is wider than the margin the pooled comparison passed by, the
result is reported **inconclusive**, not as a pass.

### A4 — the workload's fallback tool name does not exist

`k6_gateway.js:277` sets `let toolName = "gateway_status"` with the comment "always
available when meta-mcp enabled". It is not available: `gateway_status` appears **zero**
times under `src/` at either ref (`git grep -c gateway_status v3.5.0 -- src`, and the same
at the candidate — no hits at either). The name is stale in the script, identically at both
refs, so it does not bias the comparison — but it means the fallback path calls a tool that
does not exist.

That path is only taken when `tools/list` returns an empty list, which for a gateway with
the Meta-MCP surface up it will not.

The first draft said such a call would already be void under condition 3, the 99% checks
threshold. Review showed that reasoning is wrong: a JSON-RPC error arrives as **HTTP 200**
and fails exactly one of the iteration's checks, so calls to a nonexistent tool can be a
tenth of the run while the aggregate checks rate still reads about 99.5%. An aggregate
cannot police a condition that must be zero.

**New void condition 7, zero tolerance:** any `tools/call` in a measured rep whose response
is not a successful result — a JSON-RPC error, an `isError` result, or a call made through
the fallback name — voids the run. One is enough. Error responses have their own latency
distribution, which is the same reason condition 2 exists for HTTP errors.

### A5 — remediation for the `tools[0].name` hazard, decided in advance

Void condition 1 stands **for an unpinned run**: if `tools[0].name` differs between arms,
this run is void. It cannot also bind the pinned repeat — review caught that the remediation
below can never clear the condition it exists to remedy, leaving the operator to void every
repeat or override a frozen contract. So: **a pinned repeat is checked against the pin
instead** — the pinned tool must exist at both refs and must return a successful result
against both running arms, verified before the warm-up reps. The
contract said the repeat pins the tool name identically without saying how, which leaves the
method to be invented at the worst moment. The method: the **single driving copy** of the
script (one copy already drives both arms) gets `toolName` read from `__ENV.MCP_TOOL_NAME`,
defaulting to the existing `tools[0].name` behaviour, and the repeat run sets it to a name
verified present at both refs. The chosen name, and the `git grep` output proving it exists
at both, are recorded with the results. The same patched copy drives both arms, so the
workload stays identical between them — which is the property that matters, not that the
file matches the tag byte-for-byte.

### A6 — k6 image is pinned by digest, not by tag

The environment table promises "exact digest recorded with results". `grafana/k6:latest` is
already pulled on Spark (image id `388d60cf73b6`). `latest` is a moving tag; the digest is
resolved **once**, before the warm-up reps, and that one digest drives every rep of both
arms. If the resolved digest changes mid-run, the run is void.

### A7 — the binary is the arm, and `/health` cannot prove it

The contract's per-rep identity check reads `/health` and requires the reported version to
match the arm. Review pointed out the hole: `/health` reports the **package version**, and
two different 4.0.0 commits report the same string. The check catches a stale listener from
the *other* arm, which is what it was for, but it cannot establish which commit a binary was
built from.

Recorded with the results, per arm: the SHA of the detached checkout the build ran in
(`git rev-parse HEAD` in the isolated build directory, not the shared worktree), the
**sha256 of the release binary**, and the exact argument vector the gateway was launched
with. The binary hash is what ties a number to a commit; `/health` stays as the cheap
per-rep guard it always was.

### A8 — the evaluator is frozen before the run, not written after it

A pass rule stated in prose is still applied by a human who has seen the numbers. The rule
in A3 is implemented as a small script on Spark and frozen **before the warm-up reps**: it
takes the six measured reps' sample files, emits pooled and per-rep p50/p99, the two ratios,
the spread, and one of `PASS` / `FAIL` / `INCONCLUSIVE` / `VOID`. It refuses — `VOID`, never
a verdict — on a missing rep, a non-finite value, or an empty metric. Identical inputs give
an identical verdict, which is the only version of "the rule was not chosen afterwards" that
can be checked by someone who was not there.

### A9 — a defect in the workload script, recorded and not fixed here

`k6_gateway.js:345` calls `Array.every` on k6's threshold object in its custom summary
callback, which throws before the report prints. It is identical at both refs, so it cannot
bias the comparison, and A3 now takes its numbers from the raw JSON output rather than the
console summary, so it does not block this run either. Recorded as an observation against
the load script, not repaired inside a benchmark contract — fixing the workload mid-contract
is how a workload stops being the same workload.

### What this amendment does not change

Arms' feature list, the workload and its scenario, the primary metric, the 5%/10%
thresholds, the interleaved rep schedule, the warm-up discard, the port separation, the
per-rep `/health` identity check, and void conditions 1 to 6 are untouched — condition 7 is
**added**, and adding a way for the run to fail is the only direction an amendment may move
a gate in. No threshold moved, and none of them may move once the first measured rep starts.

### Review record

Reviewed adversarially before any rep, on the amendment plus the contract as context.

| reviewer | verdict | disposition |
|---|---|---|
| `gpt-review` (codex, `~/.codex/config.toml` model) | `SHIP-WITH-FIXES` | 3 findings confirmed at source and repaired above (A3 statistic, A4 void mechanism, A5 unreachable remediation); 1 LOW finding recorded as A9; 3 improvements adopted as A7, A8 and the launch-argv record |
| `kimi-review` | `SHIP-WITH-FIXES` (process exit 0) | 4 findings, 4 improvements; dispositions in Amendment 2 below |

The A3 counterexample was checked by hand before the repair, not taken on the reviewer's
word: median-of-three passes a distribution whose pooled p99 regresses 10.1%. That is the
finding that mattered, and it was the reviewer's, not the author's.

## Amendment 2 — 2026-09-08, still before any measured rep

Legality is the same as Amendment 1's and is checkable after the fact: Amendment 1 landed as
`c3a042e3`, both arms finished building at 16:17 and 16:20 local time, and the first measured
rep's start time is recorded with the results. A build is not a rep. If the results package
shows a rep starting before this amendment's commit, the amendment is illegal and the run is
void — that ordering is the whole authority for editing a contract, so it is stated as a
checkable fact rather than an assurance.

This amendment exists to record the second reviewer's verdict and dispose of its findings.

### The second reviewer read the pre-repair draft — and that is why two of its findings are already closed

`kimi-review` was launched against the draft in which A3 still substituted **median of three
per-rep p99s**. `gpt-review` returned first, killed that statistic with a counterexample, and
A3 was rewritten to pool the raw samples before the second reviewer's verdict landed. Stated
plainly so nobody reads a stale finding as an open one:

| finding | disposition |
|---|---|
| F1 — median-of-three is not the run's p99 and discards the worst rep | **Died at source.** The committed A3 computes p50/p99 once over the concatenated samples of an arm's measured reps. The reviewer's prescribed fix — compute true pooled percentiles from the raw JSON samples, reduced on Spark itself — is verbatim what A3 now does, arrived at independently. Two vendors converging on the same repair is the strongest signal either produced. |
| F4 — the inconclusive rule's "margin the comparison passed by" has no units | **Died with F1.** That sentence guarded the median statistic. The rule now reads on the pooled figures, where the spread guard compares per-rep p99 spread in milliseconds against the pooled margin in milliseconds. Units are the same on both sides. |
| F2 — void condition 3 tolerates a 1% check-failure rate | **Materially closed by void condition 7**, added in Amendment 1 for exactly this reason: any `tools/call` in a measured rep whose response is not a success voids the run, zero tolerance. Residual, named rather than waved away: condition 3 still admits up to 1% of *other* check failures. It is not raised to 100% here, because a single connection reset on a shared box would then void a run whose latency samples are all good. Instead: **any measured rep whose checks rate is below 100% has the names and counts of its failing checks recorded with the results.** A reviewer sees what failed instead of inferring it from an aggregate. |
| F3 — nothing ties the measured SHA to the commit 4.0.0 actually ships | **Adopted as R1 below.** The one finding neither the author nor the first reviewer raised, and the only one that survives the run. |

### R1 — the measurement expires if the release moves off the measured commit

The candidate arm is pinned to `79352d15`. The branch moved twice while Amendment 1 was being
written, so this is not hypothetical.

**The NFR.PERF.1 evidence stands only if the shipped 4.0.0 release commit is `79352d15`, or a
recorded diff of `src/`, `Cargo.toml` and `Cargo.lock` between `79352d15` and the release
commit is empty.** Neither holds, and the row reverts to unmeasured with an amendment-legal
re-run required before release. This is a release-gate rule, not a run rule: it cannot be
satisfied today, and the criteria-status row will say so in as many words.

### Improvements — dispositions

| improvement | disposition |
|---|---|
| record per-rep sample counts, with a floor | **Adopted in part.** The frozen evaluator already reports pooled `n` per arm with the per-rep figures beside it. The numeric floor is **declined**: it was proposed because median-of-three mixes reps of unlike quality, and pooling already weights each rep by its own sample count. A floor invented now would be a threshold with no measured basis — the exact thing this contract exists to prevent. |
| record the checkout SHA per build directory and each binary's SHA-256 | **Already implemented** as A7, before the review. |
| per-rep gateway CPU and memory snapshot | **Declined, recorded as an observation.** It buys diagnostic attribution, not verdict correctness, and it would require re-freezing the runner whose SHA-256 is the guarantee that the evaluator was written before the numbers. The cost falls on the wrong thing. |
| archive the amendment-legality evidence | **Adopted**, in the cheapest durable form: the commit SHAs of both amendments and the first rep's start time in the results package. Two timestamps a reviewer can order, rather than a copied log nobody can re-derive. |

### What Amendment 2 does not change

No threshold, no arm, no workload, no metric, no rep schedule. It adds one recording
obligation (failing-check names), one release-gate rule (R1), and the second reviewer's
verdict. Both reviewers now stand at `SHIP-WITH-FIXES`, with every confirmed finding either
repaired or recorded with its reason.

## Amendment 3 — 2026-09-08, before any measured rep: the run would have measured a stranger's gateway

A pre-flight check of the two ports the runner uses, made minutes before launch, returned:

```
LISTEN 127.0.0.1:39401  users:(("mcp-gateway",pid=3481483))
LISTEN 127.0.0.1:39400  users:(("hebb-serve",pid=704930))
```

Both ports the contract pinned were **already occupied on the shared box** — 39401 by another
session's `mcp-gateway` of unknown provenance, 39400 by an unrelated service. The runner
starts a gateway, waits for `/health` to answer, and proceeds. Nothing in it checked *which*
process answered.

Had the run launched: arm A would have driven `hebb-serve`, failed every check and voided
loudly. Arm B would have driven **a stranger's mcp-gateway** — a live process, answering
`/health`, serving `tools/list`, returning plausible latencies for a binary nobody pinned. It
would have produced a full set of numbers, passed every void condition, and measured the
wrong thing. That is the precise failure this contract exists to prevent, and no void
condition written before today would have caught it.

### A3.1 — ports moved

`PORT_A` 39400 -> **39410**, `PORT_B` 39401 -> **39411**, both verified free at patch time.
Moving a port changes no threshold, arm, workload or metric.

### A3.2 — the runner now proves it is talking to the process it launched

A free port is a fact with a shelf life; the next check is what makes it durable. After each
gateway start the runner reads back the listening socket's owning PID and compares it with the
PID it launched:

```
pid=$(cat "$R/gw-$tag.pid"); own=$(ss -ltnp | grep ":$p " | grep -c "pid=$pid,")
[ "$own" = "1" ] || { echo "VOID: port $p is not owned by the process we launched"; exit 4; }
```

`VOID`, never a number. The ownership line for every start is written to
`results/port-ownership.txt`, so the claim "each arm was driven against its own binary" is
checkable by someone who was not there, rather than assumed from a port number.

This fires in the pre-flight `tools/list` step, before any measured rep, so a false positive
(a gateway that re-execs into a different PID) costs about forty seconds and is visible
immediately — it cannot silently consume the run.

### Re-freeze

`run-reps.sh` sha256 is now `b65e2331085e86d26bbf0ba4425708e8d9512e6aa315644d9ae334f8a4fb56db`,
superseding the pre-patch value. `eval-nfr1.sh` is **untouched** and still
`7b3d6225a34d0aab8229b417edb686ead80ffbd109f2f7a1d460831fe4c49d09`, verified by re-hashing it
on Spark after the patch: the script that decides `PASS`/`FAIL` has not been edited since it
was frozen, which is the only freeze that guards against choosing a rule after seeing numbers.

### What Amendment 3 does not change

No threshold, arm, workload, metric or rep schedule. Two port numbers moved and one way for
the run to fail was added — the only direction an amendment may move a gate in.

## Amendment 4 — 2026-09-08, on release-owner rulings R18-R20

Three rulings landed while the run was in flight (`21bf7566`,
`docs/release/2026-09-08-team-lead-rulings.md`). Two of them change what this contract
measures and one changes what a result *means*. All three are recorded before any number
exists, which is the only time a reclassification rule is worth anything.

### A4.1 — the run now in flight is the REHEARSAL, and its numbers are not evidence

R19 splits the measurement in two: one rehearsal now, one scored run when `MRTR.7a`/`MRTR.7b`
are MET with strict CI green. Strict CI is red on a compilation failure another lane owns, so
the scored trigger has not fired and this run is the rehearsal.

**Its numbers are discarded and may not be cited — including if they look good.** That
sentence is written here, before the reducer has run, precisely so it cannot be revisited
afterwards by anyone who liked what came back. The rehearsal's whole job is to trip void
conditions while tripping them is free, and it has already earned its cost by tripping one
that was not among the six: both pinned ports were held by other processes, and the scored
run would have measured a stranger's gateway (Amendment 3).

What carries forward from the rehearsal is not a latency but a list of facts: that the arms
build, that `tools[0].name` matches, that the port-ownership check passes, that the reducer
consumes what the runner emits, and the wall-clock cost of a full eight-rep cycle.

### A4.2 — the candidate is a RULE, not a string

A1 pinned `79352d15`. R19 retires fixed pins for this branch: six lanes commit here every few
minutes, so any SHA typed in advance is stale before the build starts.

**The scored candidate is the HEAD of `fix/mrtr2-continuation-handle` at the moment the first
scored rep starts, recorded then** — checkout SHA, binary sha256 and launch argv, per A7. A
pin whose only property is that someone typed it earlier buys nothing.

`79352d15` remains recorded as the *rehearsal's* candidate, which is what it always was.

**R1 moves with it.** Amendment 2's expiry rule read against `79352d15`; it now reads against
the SHA recorded at the first scored rep. The rule is unchanged in substance — the evidence
stands only if the shipped release commit equals the measured one or diffs empty against it
over `src/`, `Cargo.toml` and `Cargo.lock` — but a contract that names two different
candidates in two amendments is a contract that will be read wrongly by whoever gets here
next.

### A4.3 — 1.98.1 against a pinned 1.98.0 is not a void (R20)

Recorded as drift in A2; the ruling settles the severity. Void condition 5 is **arm-to-arm** —
"the two builds do not use the same feature list and toolchain" — and says nothing about
matching the environment table. The table's own gloss explains why 1.98.0 sits there: above
the `rust-version = "1.95"` both arms require. 1.98.1 is also above it. Both arms on 1.98.1
satisfies condition 5 exactly.

Environment row corrected to the toolchain actually used, recorded from the candidate
checkout on Spark:

```
rustc 1.98.1 (48a229cea 2026-09-01)  host: aarch64-unknown-linux-gnu  LLVM 22.1.8
```

The general form, because it will recur: **a pinned environment value serves a stated purpose;
judge drift against the purpose, not the string.** And only the declared void conditions may
void a run — an author who invents a seventh at reduction time is choosing a rule after seeing
numbers, whichever direction it points.

### A4.4 — a void run and a failing run are different outcomes and may not be collapsed (R18)

The row at `RELEASE-4.0.0-criteria-status.md` already carries a release-owner ruling dated
2026-09-05: **4.0.0 ships on the headroom argument**, blocking flag lifted the same day, grade
left at PARTIAL deliberately. This measurement does not gate the release and the release does
not wait on it. What it can do is let the row close **at its own wording** rather than by
exception, and lift the residual attached to that ruling — that no P50 or P99 may be quoted
publicly until an end-to-end run produces one.

Dispositions, fixed now rather than at reduction time:

| outcome | what it means | what happens |
|---|---|---|
| `VOID` | neutral. The run measured nothing; no claim moves in either direction | re-run, cost is machine time |
| `PASS` | the row closes at its own wording, and the public-quotation residual lifts **across the three surfaces its check covers** — `README.md`, `benchmarks/public_claims.json`, `docs/BENCHMARKS.md`. Release notes and published issue text are not checked by it and stay open, named as such at closure (A6.2) | results section + row rewrite |
| `FAIL` — P99 past the bound | **evidence against a decision already made on headroom** | §11 stop-the-line, reported as exactly that: not buried, not softened, and not re-framed as `INCONCLUSIVE` |

`INCONCLUSIVE` remains what A3 defined it as — a spread the pooled margin cannot survive — and
is not a landing place for a result somebody dislikes.

## Amendment 5 — 2026-09-08, the rehearsal record: VOID by harness defect, four defects named

Legality, in the same checkable form as Amendments 1-3: the rehearsal's eight reps ran and
finished before this amendment was written, and **no scored rep has started**. A4.1 already
discarded the rehearsal's numbers as evidence, so nothing this amendment touches has been
measured by anything that counts. That ordering is the entire authority for editing a contract
after a machine has produced output, and it is stated as a fact a reader can order from the
commit times rather than as an assurance.

### A5.1 — the rehearsal's outcome is `VOID`, and the cause is the harness

Under R18 a void is neutral: the run measured nothing, no claim moves in either direction, and
the remedy is machine time. That is what happened. The evaluator could not read the runner's
output, and the workload asked a question the product answers correctly with a "no". Neither
fact is a latency, so both are reportable; the numbers on the disk are not, and are not
repeated here, above, or anywhere else.

The rehearsal has now paid for itself twice. Amendment 3 recorded the first: two pinned ports
held by strangers' processes, which would have measured someone else's gateway. This amendment
records the second, third, fourth and fifth.

### A5.2 — the four defects

| # | defect | where | consequence had the scored run gone first |
|---|---|---|---|
| D1 | k6's JSON-lines stream shared stdout with its own end-of-test text summary, and `--summary-export=/dev/stderr` shared stderr with the progress log | `run-reps.sh` rep() | `.raw.json` and `.summary.json` both unparseable; the frozen evaluator reports a missing rep and the run voids on plumbing |
| D2 | `handleSummary` called `.every` on `m.thresholds`, which k6 hands over as an object keyed by threshold expression | `tests/load/k6_gateway.js` | TypeError kills handleSummary; the run's summary is lost |
| D3 | the check `dashboard: 200 or 404` never allowed 403 | `tests/load/k6_gateway.js` | 0 of ~5,428 passes per rep, **in both arms**; aggregate checks rate far below 99%, so **void condition 3 fires on every measured rep** |
| D4 | A7's launch argv and per-arm checkout SHA were specified but never actually written by the runner | `run-reps.sh` | the results package cannot show which commit each arm was built from — the exact thing A4.2 now depends on |

D3 is the one that mattered, and it is worth being precise about what it is not. `/dashboard`
is **admin-only by design**: `dashboard_handler` gates on `is_admin` and returns 403 with an
HTML explainer, deliberately, so the page cannot serve as a way around the redaction
`/ui/api/status` applies to a non-admin caller. The gateway under test runs with authentication
disabled, so every caller is anonymous, so 403 is the correct answer — in both arms, identically.
The sibling check one group down already accepts 403 for `/ui/api/status`, which is gated by the
same rule. The dashboard check simply never had it. **This is a wrong question, not a wrong
answer, and it is not a candidate regression.**

Correcting a check expectation after watching it fail is the move A4.3 forbids — choosing a rule
after seeing numbers, whichever direction it points. It is legal here for two reasons, both
stated so a reader can refuse them: the rehearsal is explicitly non-evidence under A4.1, and this
correction lands before the first scored rep. What settles it beyond the timing is that the
correction is **checkable against the product's source rather than against the run's output**:
the handler's own documentation says it is admin-only, and the adjacent check for the endpoint
under the same gate already reads the way this one now does.

### A5.3 — both fixes, and the runner's re-freeze

Repo fix, committed as `7a6d752b`: D2 and D3 in `tests/load/k6_gateway.js`.

Runner fix, on Spark: D1 and D4. k6 now writes the JSON-lines stream and the JSON summary to
separate files on a mounted results directory, and its human console output to
`<tag>.console.txt`; nothing shares a stream with anything. The runner also writes
`launch-argv.txt` and `checkout-sha.txt` (per-arm `HEAD` plus a dirty-file count, so a modified
tree is visible rather than implied), and — closing the A2 residual, which had likewise been
specified and not implemented — `<tag>.failing-checks.txt`, naming and counting every check that
failed in a rep whose checks rate is below 100%.

```
run-reps.sh   sha256 003571d72e8af744260fa57641bc4ec47735764b519e7729994cdce839f97c1c
              (supersedes b65e2331…, the Amendment 3 freeze, and the intermediate
               817e23fd… corrected by A5.5 below)
eval-nfr1.sh  sha256 7b3d6225a34d0aab8229b417edb686ead80ffbd109f2f7a1d460831fe4c49d09
              UNCHANGED, re-hashed after the patch
```

The evaluator is the script that decides `PASS`/`FAIL`, and it has not been edited since it was
frozen. Every defect above was repaired in the thing that **produces** the evidence, never in the
thing that **judges** it. Filtering the rehearsal's unparseable files into something the
evaluator would accept was available and was refused: it would have fed the evaluator something
the runner never emitted, which hides D1 instead of fixing it.

A 10-second smoke rep against the patched harness returns 0 non-JSON lines in the raw stream,
2,090 parseable records, a summary that parses, no failing checks, and a completed
`handleSummary`. Reported as plumbing verification, not as a measurement: the smoke scenario is
1 VU and appears in no arm.

### A5.4 — an observation the rehearsal produced, recorded rather than acted on

The candidate emits three INFO log lines per iteration from `mcp_gateway::observed` — protocol
revision on `initialize`, `tools/list` and `tools/call`, plus a surface-inputs line — which the
baseline does not. Over one rep that is roughly 16,000 lines and a gateway log about 2.7x the
baseline's — log-volume facts about what the two arms *emit*, not latency measurements, and
so within what A4.1 lets a void rehearsal carry forward. No rehearsal timing is quoted here,
or anywhere else. This is the product's own behaviour on the measured path, not a harness defect, so it
is **part of what the scored run measures** and is not touched. It is recorded here because a
reader comparing the two arms' logs will notice the asymmetry and should not have to re-derive
its cause.

### A5.5 — the first re-freeze put a hole in the thing it was freezing

The patched runner briefly read the workload from the environment (`SCENARIO=${SCENARIO:-load}`)
instead of the hardcoded `load` the frozen runner had. That is worse than it looks: `SCENARIO=smoke`
would then produce a full results package at a 1-VU, ten-second workload while `run-reps.sh` hashed
**identically** — and the hash is the entire reason a frozen runner is worth anything. A freeze that
a caller can walk around is not a freeze.

Re-pinned to `load` in the container invocation, and the sha256 in A5.3 is the post-correction value.
The intermediate `817e23fd…` is recorded here rather than deleted, because a hash that appeared in a
committed amendment and then changed is exactly the kind of thing a later reader must be able to
account for. The smoke rep in A5.3 was run before this correction, via that variable; it produced no
measurement, only the plumbing verification it is cited for.

### A5.6 — the downgrade warning on arm A is not drift, and the shared data directory does not move

Every arm-A gateway log opens with `Downgrade detected: running an older binary against a newer data
directory installed=4.0.0 binary=3.5.0`. Both arms share one data directory and the reps alternate,
so the question is real: if the 4.0.0 arm mutated that directory, arm A would stop measuring 3.5.0
as shipped and `A0` would stop being comparable to `A1..A3`.

It does not. Checked three ways, against the product source and the artifacts already on disk:

- `check_upgrade` at `src/commands/upgrade.rs:501-508` takes the `Ordering::Greater` branch — a
  single `tracing::warn!` and nothing else. No stamp write, no migration. The equal case (candidate
  4.0.0 against a 4.0.0 stamp) is an empty arm.
- the warning appears in **all four** arm-A logs, not only the first. A migration that ran once and
  silenced itself would show as that asymmetry; there is none.
- the four `health-A*.json` are byte-identical to each other, as are the four `health-B*.json`.

Recorded as an observation, not a defect, and not a fifth harness fix. Had any of the three come
back the other way, the runner would have needed a per-arm data directory before the scored run.

### What Amendment 5 does not change

No threshold, arm, workload shape, metric or rep schedule. One tension with Amendment 3 is named
rather than left for a reader to raise: A3 closed by saying one way for the run to fail was added,
“the only direction an amendment may move a gate in”, and A5.2's D3 repair moves a gate the other
way — a check that was failing now passes. What makes that legal is not the direction but the
CHECKABLE SOURCE: the widened expectation is verified against `dashboard_handler`'s own admin-only
rule and the sibling `/ui/api/status` check that already admits 403, never against this run's output.
An amendment that loosened a gate to fit a number would have no such source, and that is the
distinction A3's sentence was reaching for. One check expectation was widened to
match documented product behaviour, four recording obligations that were already specified are
now actually implemented, and one broken stream split into three. **No number from the rehearsal
is carried forward into this contract, the criteria-status row, or any release document.** The
NFR.PERF.1 row stays exactly as it reads today, because a void run moves no claim — rewriting it
now would be the first citation of numbers this amendment exists to discard.

## Amendment 6 — 2026-09-08, after the void and before the scored run: two sentences of this contract were wrong about their own reasons

Neither correction moves a threshold, an arm, a workload, a metric or a void condition. Both fix
a sentence that a later reader would have believed.

### A6.1 — `firewall` is a DEFAULT feature, and the explicit list is identical to `default` at both refs

The release owner flagged that `firewall` is a default feature and warned the comparison might
have been modelled against a lighter binary than the one actually built. Checked at source
rather than reasoned about: at **both** refs the `default` line names the same nine features as
this contract's build line, in the same order.

```
default = ["a2a", "webui", "config-export", "cost-governance", "firewall", "discovery", "semantic-search", "tool-profiles", "metrics"]
```

(`git show v3.5.0:Cargo.toml` vs `Cargo.toml`, second line of each `[features]` table.) No
`--no-default-features` is passed, so each arm builds `default ∪ explicit list` — the same nine,
identically, on both sides. The warning does not land in the direction it was given: nothing was
modelled lighter, because the two spellings name one set.

It does land one line over. The rationale at the build line says the list "is stated explicitly
rather than left to `default`", which reads as a deliberate **divergence** from `default`. There
is none, and a reader chasing that difference would find nothing and mistrust the rest. What the
explicit list actually buys: the sets coincide **today, at these two refs**, and the list is a
**pin** — if `default` moves under either arm before the scored run, the build line does not move
with it. Worth keeping, and not what the sentence claimed.

Void condition 5 — "the two builds do not use the same feature list and toolchain" — is now
satisfied by verification on both halves rather than by assumption: same nine features both arms
(here), same toolchain both arms (A4.3).

### A6.2 — A4.4's `PASS` row promised more than the residual's own check covers

The residual attached to the 2026-09-05 ruling is about how widely the latency claim is
**quoted**, and the check in the criteria row's evidence cell covers three surfaces: `README.md`,
`benchmarks/public_claims.json`, `docs/BENCHMARKS.md`. Release notes and published issue text are
outside it (release owner, 2026-09-08).

A4.4's `PASS` row said the residual "lifts", unqualified — an overclaim living in the row a
reader will actually read at reduction time. Corrected **in the row itself**, the way A5.5
corrected A5.3 rather than annexing a note further down: a `PASS` lifts the residual across the
three surfaces its check covers, and the unchecked half is named at closure instead of closing
silently with it. A row that reads as fully closed while two public surfaces were never inspected
is the same collapse A4.4 exists to forbid, one category over.

### What Amendment 6 does not change

No threshold, arm, workload, metric, rep schedule, void condition, or disposition. The scored
run's trigger is unmoved and still unfired.
