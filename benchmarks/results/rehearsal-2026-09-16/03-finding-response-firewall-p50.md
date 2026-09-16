# Finding — the 4.0.0 `tools/call` p50 regression is the new response-firewall pass on the final response

Scope: diagnosis of the `NFR.WORKLOAD.1` A/B/C p50 FAIL recorded in
`01-compile-quiet-rerun.md` (commit `4f2b498d`). **No fix is proposed or
implemented here.** The run-level verdict is still VOID exit 3 on D1 admission,
an owner decision that this file does not touch.

## Verdict

The regression is a **4.0.0-only, per-response cost that scales with response
payload size, confined to exactly `tools/call` and `tools/list`**. It is the
second, unconditional response-firewall scan that `finalize_response_for_delivery`
runs on the delivered JSON-RPC result, together with the full deep clone and
deep comparison that its `PreserveInputRequired` mutation policy forces.

Two independent lines carry it, one free and one measured:

1. A four-metric ablation ladder **already present in the graded run's own
   summaries** isolates the regression to `tools/call` and `tools/list` and
   clears `/health` and `initialize`.
2. A confirmatory probe on the same host with `security.firewall.scan_responses:
   false` removes most of the C-versus-B gap on both affected metrics and
   nothing on the unaffected ones.

## The number that has to be explained

Two different numbers are in play and they are not interchangeable.

| Quantity | Value | What it is |
|---|---|---|
| **Regression** | **+34.1 µs** | C pooled p50 0.4097 ms − min(A,B) 0.3756 ms |
| Overshoot | +18 µs | C 0.410 ms − the +5% limit 0.392 ms |

The mechanism has to account for **34 µs**, not 18. A candidate that explains
18 µs explains a little over half the regression and leaves the rest unaccounted
for. Both numbers are stated here so the smaller one cannot be quoted as the
target by accident.

## 1. The free ablation ladder — the harness already measured four surfaces

`k6_workload.js` records four independent latency trends per rep, not one. The
graded run's own `{A,B,C}{1,2,3}.summary.json` therefore contain a three-rung
ablation that cost nothing extra to read. Mean of the three reps' `p(50)`, in ms,
per-rep values in brackets:

| trend | A (3.5.0) | B (3.5.1) | C (4.0.0) | C − min(A,B) | within-cell spread |
|---|---|---|---|---|---|
| `health_latency` | 0.4079 [0.405/0.395/0.424] | 0.3903 [0.385/0.405/0.381] | 0.3944 [0.401/0.400/0.382] | **+4.1 µs** | 19–29 µs |
| `mcp_initialize_latency` | 2.5611 [2.542/2.510/2.630] | 2.4987 [2.459/2.588/2.450] | 2.5301 [2.533/2.572/2.485] | **+31.4 µs** | ~120 µs |
| `mcp_tools_list_latency` | 0.9025 [0.900/0.906/0.901] | 0.9021 [0.899/0.910/0.898] | 1.1545 [1.164/1.151/1.148] | **+252.4 µs** | ≤ 6 µs |
| `mcp_tools_call_latency` | 0.3756 [0.374/0.380/0.373] | 0.3760 [0.374/0.373/0.382] | 0.4097 [0.410/0.406/0.412] | **+34.1 µs** | ≤ 7 µs |

Read rung by rung:

- **`/health` — no signal.** C sits *between* A and B, and the +4.1 µs is a
  fifth of the within-cell spread. Whatever changed does not live in the HTTP
  server, the connection path, the shared tower middleware stack, or anything
  else every request pays. **This kills every common-mode candidate.**
- **`initialize` — no signal, and specifically not evidence of a fixed
  `POST /mcp` cost.** C (2.5301) again sits *between* A (2.5611) and B (2.4987),
  and the within-cell spread (~120 µs) is four times the +31.4 µs difference.
  `initialize` is a `POST /mcp` JSON-RPC request that traverses the same router,
  the same session handling and the same dispatch as `tools/call`. It did not
  regress. A per-`POST /mcp` or per-JSON-RPC-request cost is therefore ruled out
  as well.
- **`tools/list` — unambiguous and large.** A and B agree to **0.4 µs** with a
  within-cell spread of ≤ 6 µs; C is **+252 µs** and every C rep
  (1.164/1.151/1.148) is more than forty spreads clear of both baselines.
- **`tools/call` — unambiguous.** A and B agree to **0.4 µs** with a spread of
  ≤ 7 µs; C is **+34 µs**, and the three C reps (0.410/0.406/0.412) do not
  overlap the six A/B reps at all.

The A≈B agreement on both regressed metrics is the load-bearing part: it shows
the two metrics are quiet enough to resolve tens of microseconds, so the C
excursion is not instrument noise. It also localises the change to the
3.5.1→4.0.0 step, not to 3.5.0→3.5.1.

**Conclusion of the ladder: the regression is confined to exactly `tools/call`
and `tools/list`, and it scales with response size.** The `tools/list` result is
the whole meta-tool surface — many kilobytes of tool schemas; the `tools/call`
result is one small pinned payload (`WORKLOAD_OK case=042 bundle=deterministic`).
The costs differ by ~7×, in the direction of, and roughly in proportion to, the
bytes in the response.

That shape — *these two methods, in proportion to response bytes* — is a
fingerprint. There is exactly one gate in 4.0.0 that matches it.

## 2. The mechanism — one gate in 4.0.0 matches that fingerprint exactly

Pins for this section: C = `69ba9e03cc6df0a6a92fdaa813444a61e97cc29e` (4.0.0),
B = `e138680a542b41fa156a94a1ffc9decd9692be77` (3.5.1). Both arm checkouts were
read on the measurement host.

### 2.1 What 4.0.0 added

`src/gateway/meta_mcp/response_security.rs` is **new at 4.0.0** — the file does
not exist at B. So is `src/security/firewall/response.rs`, and with it
`check_response_artifact`. `grep` for either symbol at B returns nothing.

`meta_mcp_handler` calls the new finalizer **unconditionally, for every method**,
after the big `match method` that produced the response
(`src/gateway/router/handlers.rs:1824-1840`):

```rust
response = state.meta_mcp.finalize_response_for_delivery(
    response,
    &ResponseDeliveryContext {
        method: &method,
        targets: &response_targets,
        correlation: ResponseCorrelation { ... },
        mutation: ResponseMutationPolicy::PreserveInputRequired,
        signing: signing_context.as_ref(),
    },
);
```

The method filter is *inside* the finalizer
(`src/gateway/meta_mcp/response_security.rs:58-61`):

```rust
#[cfg(feature = "firewall")]
if matches!(context.method, "tools/call" | "tools/list")
    && response.error.is_none()
    && let Some(result) = response.result.as_mut()
    && let Some(firewall) = &self.firewall
{ ... firewall.check_response_artifact(result, context.targets, &context.correlation,
        ResponseArtifactKind::FinalResponse, context.mutation); ... }
```

**`matches!(context.method, "tools/call" | "tools/list")` is the fingerprint.**
It is a literal enumeration of the two metrics that regressed, and of nothing
else. `initialize` reaches this same line and falls through the `matches!`, which
is why the `initialize` rung is flat — that rung is not merely an absence of
evidence, it is the control that the filter itself produces.

### 2.2 What each method pays, before and after

At B (3.5.1) the only response scan on this path is in the `tools/call` arm
(`src/gateway/router/handlers.rs:712-735`), calling the older
`Firewall::check_response` (`src/security/firewall/mod.rs:402`) once per backend
target. The meta `tools/list` response is **never scanned at B** — no caller of
`check_response` handles it on the meta surface.

| method | B (3.5.1) | C (4.0.0) | delta in passes |
|---|---|---|---|
| `initialize` | 0 scans | 0 scans | **0** — matches the flat rung |
| `tools/list` | **0 scans** | **1 scan + 1 deep clone** of a multi-kB tool surface | 0 → 1 |
| `tools/call` | 1 scan, no clone | **2 scans + 1 deep clone** of a small payload | 1 → 2 |

C's `tools/call` pays twice because the arm-local scan survived the refactor and
the new finalizer was added on top of it, not in place of it:

- `handlers.rs:1633` — inside the `tools/call` arm, `check_response_artifact(...,
  FinalResponse, ResponseMutationPolicy::Redact)`
- `handlers.rs:1824` — the unconditional finalizer,
  `ResponseMutationPolicy::PreserveInputRequired`

Both target `ResponseArtifactKind::FinalResponse`. The same bytes are inspected
twice per `tools/call`.

### 2.3 Why the cost scales with response bytes

`check_response_artifact` (`src/security/firewall/response.rs:19-61`) does, per
call, in order:

```rust
if !self.config.enabled || !self.config.scan_responses { return Ok(allow()); }   // :27
let mut targets = targets.to_vec(); targets.sort_unstable(); targets.dedup();    // :34-36
let original = (mutation != ResponseMutationPolicy::Redact).then(|| response.clone());  // :38
let findings = self.inspect_response_content(response, correlation);            // :39
```

Two of those are O(response size):

1. **Line 38 — a full deep clone of the result `Value`**, taken whenever the
   policy is *not* `Redact`. The finalizer passes `PreserveInputRequired`, so
   every `tools/list` and the second `tools/call` pass clone the entire result.
2. **Line 39 — `inspect_response_content`** (`:64-100`): the prompt-injection
   `response_scanner` pass plus the `redactor.scan_and_redact` walk, both over
   the whole result tree.

The clone is the sharper observation. Its only consumer is
`protected_value_changed` (`:112-125`), and under `PreserveInputRequired` that
function compares exactly two top-level keys:

```rust
ResponseMutationPolicy::PreserveInputRequired => {
    original.get("inputRequests") != inspected.get("inputRequests")
        || original.get("requestState") != inspected.get("requestState")
}
```

So 4.0.0 deep-clones a multi-kilobyte tool-surface response in order to compare
two top-level keys that a `tools/list` result does not carry. The comparison is
O(1); the clone that feeds it is O(payload).

That is the payload scaling the ladder measured: `tools/list` (whole meta-tool
surface) pays ~252 µs, `tools/call` (one short pinned payload) pays ~34 µs, and
`initialize` and `/health`, which never enter the gate, pay nothing.

## 3. Confirmatory ablation — turn the scan off and the gap mostly goes away

### Method

`~/perf-workload/fw_probe.sh` on the measurement host. **This is a diagnostic
probe, not a graded run**: the `ablate` arms deliberately do not use the pinned
config artefact, so no row here is gradeable against `NFR.WORKLOAD.1`.

- Cells **B** (3.5.1) and **C** (4.0.0), same arm binaries and same k6 image
  digest (`sha256:1f40432b1cbe...e9e755`) as the graded run.
- Two configs: `pinned.yaml` (the graded artefact with the fixture path
  substituted) and `ablate.yaml` (byte-identical plus
  `security.firewall.scan_responses: false`). Both hashed to
  `runs/2026-09-16-fwprobe/config.sha256`.
- Order `C-pinned, C-ablate, B-pinned, B-ablate`, repeated twice — interleaved so
  host drift cannot be charged to one arm, and so each pinned/ablate pair is
  adjacent in time.
- Fresh gateway process and fresh `HOME` per rep; ports checked free; same k6
  `load` scenario as the graded run (~32.9K requests/rep).
- `http_error_rate` 0 and `checks` 1.0000 in all eight reps; no gateway stderr in
  any rep.

`scan_responses: false` short-circuits `check_response_artifact` at its first
line (`response.rs:27`), **before** the deep clone and before the detector pass.
At C it therefore removes both response scans and the clone; at B it removes
B's single `check_response`. It is an ablation of the whole response-scanning
path in each arm, not of the added pass alone.

### Raw p50 (ms)

| rep | cell | config | health | initialize | tools/list | tools/call |
|---|---|---|---|---|---|---|
| 1 | C | pinned | 0.3302 | 0.4055 | **1.1548** | **0.4131** |
| 1 | C | ablate | 0.3218 | 0.4036 | **0.9410** | **0.3889** |
| 1 | B | pinned | 0.3157 | 0.3757 | 0.8977 | 0.3768 |
| 1 | B | ablate | 0.3060 | 0.3850 | 0.9936 | 0.3762 |
| 2 | C | pinned | 0.3386 | 0.4380 | **1.2966** | **0.4448** |
| 2 | C | ablate | 0.3363 | 0.4347 | **1.0838** | **0.4268** |
| 2 | B | pinned | 0.3291 | 0.4005 | 1.0029 | 0.4011 |
| 2 | B | ablate | 0.3252 | 0.4082 | 0.9969 | 0.3733 |

### Paired ablation effect (ablate − pinned, same cell, adjacent reps)

| rep | cell | health | initialize | tools/list | tools/call |
|---|---|---|---|---|---|
| 1 | **C** | −8.4 µs | −1.9 µs | **−213.8 µs** | **−24.3 µs** |
| 2 | **C** | −2.3 µs | −3.3 µs | **−212.8 µs** | **−18.0 µs** |
| 1 | B | −9.7 µs | +9.3 µs | +95.9 µs | −0.6 µs |
| 2 | B | −4.0 µs | +7.7 µs | −6.0 µs | −27.8 µs |

### The probe reproduces the graded run

The probe's `pinned.yaml` hashes to
`8b638a9e7e20d55eaead735dd8761bb78a41c547d21513e52ca7d5ea392fa65e`, **byte-identical
to the graded run's own substituted config**
(`runs/2026-09-16-quiet-v1/config/gateway.workload.yaml`). The graded run's
`C1.meta.json` records the same binary, the same config path and the same port
(39422) that the probe's C arm used.

The pinned arms land on the graded run's numbers for both regressed metrics:

| metric | graded pooled B | probe B-pinned-1 | graded pooled C | probe C-pinned-1 |
|---|---|---|---|---|
| `tools/call` | 0.3760 | 0.3768 (+0.8 µs) | 0.4097 | 0.4131 (+3.4 µs) |
| `tools/list` | 0.9021 | 0.8977 (−4.4 µs) | 1.1545 | 1.1548 (+0.3 µs) |

`tools/list` at C reproduces to **0.3 µs**. This is the graded experiment, not a
neighbouring one.

One metric does **not** reproduce: `initialize` runs ~0.38–0.44 ms here against
~2.50–2.56 ms in the graded run. The probe gives each rep a fresh `HOME`; the
graded run used the ambient one, whose gateway state directory is populated. That
gap is unexplained beyond that and is **not** investigated here. It does not
reach the paired comparison — both halves of every pair used a fresh `HOME` — and
`initialize` is not a regressed metric in either measurement.

### Reading

**`tools/list` — decisive.** Disabling the scan at C removes **−213.8 µs** and
**−212.8 µs**: the two reps agree to **1.0 µs** even though their absolute p50s
differ by 142 µs. A paired difference that reproduces to 1 µs across a box that
moved that much is not noise. It accounts for **213.3 of the 252.4 µs**
(**85%**) that the graded run measured on this metric.

**`tools/call` — same direction, same order, weaker.** −24.3 µs and −18.0 µs,
mean **−21.2 µs**, i.e. **62%** of the 34.1 µs graded regression. In rep 1, where
the B control is trustworthy, the C−B `tools/call` gap falls from **+36.3 µs
pinned to +12.6 µs ablated** — the same 65% reduction seen from the C side alone.

**`health` and `initialize` — flat, as they must be.** |effect| ≤ 8.4 µs with no
consistent sign, at C and B alike. Neither method enters the `matches!` gate, so
this is the probe's own noise floor: **roughly ±10 µs**. That sets the bar the
other two rows have to clear — `tools/list` clears it by 20×, `tools/call` by
about 2×.

### Where this evidence is weak — stated, not buried

1. **The B control is noisy, and one B rep is contaminated.** `B-pinned-2`
   `tools/call` p50 is 0.4011 ms against 0.3768 / 0.3762 / 0.3733 in the other
   three B reps. It is the outlier, and it is why rep 2's C−B columns are not
   usable. Rep 1's B control behaves (`tools/call` ablation effect −0.6 µs: at B
   the single older scan costs essentially nothing on this payload), but rep 1's
   B `tools/list` moves **+95.9 µs in the wrong direction**. B is a control, not
   a treatment, so a wrong-direction swing there does not reverse the C result —
   but it does mean **this box can produce ±96 µs excursions on `tools/list` and
   ~28 µs on `tools/call`, which is the same size as the `tools/call` effect I am
   attributing.** Taken alone, the `tools/call` ablation arm is suggestive, not
   decisive.
2. **The post-run quiet gate failed.** `gate after` recorded `load 9.09, cargo=1`
   and the script exited 3. Per-rep load: rep 1 ran on a falling box
   (6.88 → 4.74 → 3.28 → 2.72); rep 2 ran dirty (7.58 → 9.53 → 8.09 → 7.80).
   All eight reps completed and their artefacts are intact, but **rep 2's
   absolute levels are contaminated**. Its paired C deltas are not: they
   reproduce rep 1's to 1 µs on `tools/list` and 6 µs on `tools/call`, which is
   the point of pairing adjacent runs of the same binary.
3. **The ablation is not surgical.** `scan_responses: false` removes *all*
   response scanning in the arm, so it cannot separate "the second, added pass"
   from "the first pass plus the clone" within C. It bounds the whole
   response-scanning path; §2 is what assigns the delta to the newly added work.

## 4. What is established, and how firmly

| Claim | Status |
|---|---|
| The regression is confined to `tools/call` and `tools/list` | **Proven** — graded run, four-metric ladder, A≈B to 0.4 µs on both regressed metrics |
| It is not transport, middleware, session, router or per-`POST /mcp` cost | **Proven** — `/health` and `initialize` both flat, C between A and B on each |
| It appeared at 3.5.1 → 4.0.0, not 3.5.0 → 3.5.1 | **Proven** — A and B agree to 0.4 µs on both regressed metrics |
| The responsible code is the 4.0.0 response-firewall pass reached via `finalize_response_for_delivery` | **Proven on `tools/list`** (85% of the effect ablated, reproducing to 1 µs); **strongly supported on `tools/call`** (62% ablated, right direction both reps, but only ~2× this box's noise floor) |
| `tools/call` is scanned **twice** per request at 4.0.0 | **Proven by construction** — two `check_response_artifact` call sites, `handlers.rs:1633` (`Redact`) and `handlers.rs:1824` (`PreserveInputRequired`), both on `ResponseArtifactKind::FinalResponse` |
| `tools/list` was never scanned on the meta path at 3.5.1 | **Proven** — no `check_response` caller covers it at B; `response_security.rs` and `firewall/response.rs` do not exist at B |
| A full deep clone of the result is taken to support an O(1) two-key comparison | **Proven by construction** — `response.rs:38` vs `response.rs:112-125` |
| The residual — ~13 µs on `tools/call`, ~39 µs on `tools/list` — is also 4.0.0 response work | **Not established.** Unattributed. |

## 5. Not claimed

- **No fix.** The clone at `response.rs:38`, the duplicate `tools/call` pass, and
  the unconditional finalizer are each obvious places to look, and none of them
  is evaluated here for correctness, security consequence or release risk.
  Whether the second pass is redundant or deliberately defence-in-depth is a
  question for the owner of that code, not an inference from a latency number.
- **No verdict change.** `01-compile-quiet-rerun.md` stands: scoped A/B/C p50
  FAIL, run-level VOID exit 3 on D1 admission. This file explains the FAIL; it
  does not regrade it.
- **Nothing about D/E.** The modern-era cells are still blocked on the D1
  admission decision and were not probed.
- **Nothing about p99.** The p99 reading was already the weaker one (A/B p99 rose
  ~80% between boxes on identical pins); no attempt was made to extend this
  mechanism to it.
- **The `initialize` +31.4 µs is noise, not a small version of this effect.** It
  is a quarter of that metric's own within-cell spread, and `initialize` does not
  enter the gate.

## 6. If one more measurement is wanted

The `tools/call` arm is the one that carries the graded metric and it is the one
resting on ~2× the noise floor. A quiet-box rerun of exactly this probe — same
script, gate held for the whole sequence, 3 reps instead of 2 — would move
"strongly supported" to "proven" on `tools/call` without any new code. That is a
measurement decision, not a blocker on this diagnosis.

## Artefacts

Host: measurement box, `~/perf-workload/runs/2026-09-16-fwprobe/`.
Eight `*.summary.json`, eight `*.k6.txt`, per-rep gateway stdout/stderr (all
empty), `config.sha256`, `quiet-gate.log`. Probe script
`~/perf-workload/fw_probe.sh`. Source read at the pinned arm checkouts
`~/perf-workload/arms/{B,C}`.
