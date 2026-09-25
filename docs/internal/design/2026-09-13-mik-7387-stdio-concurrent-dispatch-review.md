# Design review — MIK-7387 stdio concurrent dispatch

Reviewed: `docs/design/2026-09-13-mik-7387-stdio-concurrent-dispatch.md`, as a
design, before the implementation on `stdio-keystone-rebase` is graded. Two
independent non-Claude reviewers, run on the same payload with the same three
criteria stated as scope.

| Reviewer | Verdict | Record |
|---|---|---|
| gpt (`gpt-daybreak-blue-latest`, effort high) | **SHIP-WITH-FIXES** — the package omits the production bridge wiring required to close all three stated criteria | `<review-archive>/runs/gpt-20260914T212858Z-6204.md` |
| kimi (`synthetic-review`) | **SHIP** — mechanism is sound for a pre-implementation design; the one material gap is that the three criterion rows stay ignored | `<review-archive>/runs/synthetic-20260914T212937Z-9855.md` |

`grok-review` and `glm-review` were both unavailable: the grok CLI is missing at
`<review-tools>/grok`, and the GLM route returns `404 model "hf:zai-org/GLM-5.3-Flash"
not found`. Recorded rather than silently substituted — two reviewers ran, not the
usual pair.

## The finding both reviewers reached independently

**The transport half closes none of MIK-7387.STDIO.1, .2 or .3.** Each row needs
an outbound `elicitation/create` frame on the pipe, which needs a production
caller of `InputBridge`, and there is none: the design's own §acceptance records
`rg -n 'InputBridge' src/` returning the definition
(`src/gateway/input_bridge.rs:348`, `:359`) and two doc comments, zero
constructions. The interim arm of `src/gateway/meta_mcp/invoke.rs` computes
`InputRequired::from_result` at `:1779` and mints a continuation envelope at
`:1852` instead. So the three acceptance rows in
`tests/mik_7212_mrtr7_stdio_acs.rs` stay `#[ignore]`d (`:356`, `:421`, `:471`),
and a transport package that lands alone moves the release count by zero.

gpt rates it HIGH / CERTAIN / gate NOW; kimi rates it MEDIUM / CERTAIN /
BEFORE-PRODUCTION. Both propose the same fix, and it is the one that changes the
shape of the work: **fold the minimal production `InputBridge::ask` call site
into this package and un-ignore the three rows.** The same caller also unblocks
`MIK-7388.CANCEL.1` (`docs/requirements/RELEASE-4.0.0-scope-update.md:36`), which
cannot cancel a bridged exchange that never happens — so the wiring is worth four
rows, not three, and the transport alone is worth none.

The design already says this about itself, under "Corrected during
implementation". What the review adds is that the deferral is not a neutral
sequencing choice: it is the difference between a package that closes criteria
and one that does not.

## Remaining findings, merged and deduplicated

| # | Finding | Where | crit / prob / gate | Fix |
|---|---|---|---|---|
| 2 | The unbounded writer queue and unbounded task spawning let one fast or non-reading client exhaust process memory | design §1, line 45 | HIGH / POSSIBLE / BEFORE-PRODUCTION | Bound active dispatches and queued output; reject or terminate on saturation without blocking reply classification |
| 3 | The bounded EOF dispatch drain can abort an already-accepted request that would have completed, contradicting the preservation guarantee the design states | design line 166 | MEDIUM / POSSIBLE / NOW | Let a normal EOF drain accepted dispatches to completion; reserve abort for external cancellation |
| 4 | Awaiting the writer task without a timeout hangs shutdown forever when the client closes stdin but stops reading stdout | design line 167 | MEDIUM / POSSIBLE / BEFORE-PRODUCTION | Bound the writer flush separately and abort it when stdout cannot drain |
| 5 | The inline-`initialize` / spawn-everything-else split depends on `initialize` never resolving to a bridging question — the request-vs-response property §2 says cannot be assumed | design §2 | MEDIUM / UNLIKELY / BEFORE-DEPLOY | Give inline `initialize` dispatches a `NoClientChannel` context, so a future bridging initialize fails loudly instead of stalling for the bridge timeout |
| 6 | No behaviour is specified for the stdout-writer task exiting early (panic, EPIPE on a half-dead client); producers keep sending into a dead queue and responses are silently dropped while the serve loop looks healthy | design §1/§6 | MEDIUM / UNLIKELY / BEFORE-DEPLOY | Hold the writer's `JoinHandle` and select it against the read loop, so a dead writer stops the loop instead of absorbing frames |
| 7 | Classifying every object with an `id` and no `method` as a reply silently drops malformed JSON-RPC requests carrying neither `result` nor `error` | design line 91 | LOW / POSSIBLE / BEFORE-PRODUCTION | Treat a frame as a reply only when it also carries exactly one of `result` or `error` |

Findings 3 and 4 are the same shutdown window read from opposite ends: one says
the drain gives up too early on the dispatch side, the other that it waits
forever on the writer side. A repair that moves only one of them will look
correct against the test that motivated it.

## Improvements worth taking

- Extract the reply-id normalisation rule (`as_str()` else number `to_string()`)
  into one shared `pending_key(&Value) -> String` used by both the routing loop
  and `send_request`. Its drift is the exact silent-unrouted-reply failure §4
  names, and two call sites staying in sync is the only thing preventing it.
- Add an injectable short-writing sink and dispatch barriers, so the framing and
  initialize-order tests fail reliably against a naive implementation instead of
  depending on timing or pipe capacity.
- Add a mixed race — an ordinary response against an outbound bridged request,
  with concurrent client replies returned in reverse order — to prove every
  producer uses the sole writer and that pending replies route by identifier.
- Pin the terminal-close branch: a dispatch reaching its question during the
  drain window must get `DeliveryError::NoSession`, distinct from the `TimedOut`
  given to prompts already outstanding. It is the most novel control flow in the
  design and currently has no test.
- Emit a counter alongside the `debug!` for unmatched pending replies, so late
  answers (expected) are distinguishable from key-normalisation routing bugs
  (defects) without reading debug logs.

## Observed in CI: the untested `NoSession` branch is reached

The last recommendation above was not acted on, and the branch it names is now
the cause of two red rows. Recorded here rather than in a new document because
this review is where the gap was first called.

`ac_mrtr_7a_the_reader_keeps_reading_past_the_admission_cap` and
`ac_mrtr_7b_the_excess_past_the_inflight_cap_is_refused_not_queued` both assert
64 outstanding questions and both observe 58 (CI run 35248322170; an earlier run
gave 57/58). The census the tests print themselves:

| | 7a (65 calls) | 7b (1026 calls) |
| --- | --- | --- |
| `elicitation/create` | 58 | 58 |
| plain results | 7 | 966 |
| `-32003` | 58 | 11 |
| `-32000` busy | 0 | 2 |

The prompt count is pinned at 58 across a 16x load change while plain results
scale with load. That was first read here as ruling out the 64-slot dispatch cap;
it is the opposite, and the correction is at the end of this document.

Ruled out at source: admission permits are moved into the spawned task and
dropped on every exit path (`src/gateway/server/mod.rs:2645`), so there is no
permit leak; `read_only_tools` defaults to empty and the test config declares no
idempotency section (`src/config/features/idempotency.rs:7`), so that cache never
engages; and the fixture backend is stateless, answering every call without
`inputResponses` with `input_required` plus an elicitation
(`tests/mik_7212_mrtr7_stdio_acs.rs:147-172`), so every plain result frame is
manufactured by the gateway rather than returned by the backend.

The only candidate manufacturing site is the empty match arm at
`src/gateway/meta_mcp/invoke.rs:2271-2274`. Falling through leaves `interim` set,
so the ask goes out as a minted continuation (`invoke.rs:2358`) instead of a
bridged elicitation, and it is the only arm that can reach the mint:
`ChallengeRefused` returns `ResponseFirewallRefused` and the catch-all
`Err(error)` arm at `:2306` returns -32003. That makes it the candidate rather
than the established cause — see "Not reproduced locally" below. The comment
above that arm (`invoke.rs:2247`) states the invariant
that made it safe — stdio declares `Declared::NONE`, so `plan` refuses before
`ask` and the failure lands as `Refused`, never `NoSession` — then names this
work package as "the only thing that lifts it", names `MIK-7212.WIRE.10` as the
missing row, and warns that until it lands "an edit to either half breaks this
silently". That is what happened.

Consequence beyond the two rows, if the candidate is the cause: a caller that
asked for a bridged elicitation is silently answered with a continuation envelope
instead. That consequence is what makes the include/exclude call load-bearing, and
it is the claim the next section qualifies.

The census closes exactly against the call counts, and that is what carries the
finding. 7a sends 65 calls (`FIRST_CALL_ID..=FIRST_CALL_ID + ADMISSION_CAP`,
`tests/mik_7212_mrtr7_stdio_acs.rs:743-795`) and 58 + 7 = 65. 7b sends 1,026
(`INFLIGHT_CAP` is 1024 at `:865`, and the burst runs `2..=1027` at `:895-899`)
and 58 + 966 + 2 = 1026. Every call that does not win an elicitation is answered
with a plain result. No error path can produce that shape: the fixture returns
`input_required` for any call without `inputResponses`, so a refused, rate-limited
or failed call surfaces as an error frame, never as a success.

An independent review read the same CI log and attributed the plain results to
backend rate limiting, on the grounds that the log records
`Delivery { error: TimedOut }` and never `NoSession`. It was right about the call
count and the review is what corrected it here. The absence is not evidence,
though: the `NoSession` arm is `=> {}` and emits no `warn!`, unlike the
`ChallengeRefused` arm below it, so a hit on it is invisible in any log by
construction. The 74 `TimedOut` warnings are the other half of the census — the
58 elicitations that did go out and then expired against the bridge timeout,
which is what the -32003 frames report.

## Not reproduced locally: both rows are green off CI

The mechanism above is inference from the CI census. It was then tested directly
and the test did not confirm it, because the failure does not occur here at all.

Two probes were added temporarily — a `warn!` inside the empty `NoSession` arm
and a second at the continuation mint — and the file was run on macOS
(`cargo test --all-features --test mik_7212_mrtr7_stdio_acs`), six consecutive
times. Every run: **6 passed, 0 failed**, in about 10s, with **zero hits on
either probe**. The probes were removed afterwards; nothing here is committed.

So on a healthy run neither the silent arm nor the mint is reached, all 64
dispatches park as the rows expect, and both rows pass. The 58-versus-64
shortfall, the 966 plain results and the silent downgrade are all specific to
CI. That is a real finding rather than an absence of one, and it changes the
shape of the work in two ways:

- The mechanism cannot be confirmed or refuted from a machine where the failure
  never happens. Confirming it needs the probes run in the environment that
  fails, not another local run.
- A count that is green six times locally and pinned at 58 in CI is at least
  partly a property of the environment. A count *pinned* under a 16x load change
  is the signature of a cap, and `MAX_CONCURRENT_STDIO_DISPATCHES` is 64 with its
  permit held across the bridge await — so the earlier claim in this document
  that the 64-slot cap "is not what bounds it" was argued backwards and should
  not be relied on.

Consequently a fix written against the `NoSession` arm today would be written
against an unconfirmed cause, and could not be shown to turn either row green: a
row asserting 64 outstanding questions and observing 58 is not made green by
changing what the other calls are told.
