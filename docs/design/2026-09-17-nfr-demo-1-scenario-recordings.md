# Design: five NFR.DEMO.1 recordings a broken build would fail

Status: reviewed design, 2026-09-17; the four open questions are decided by the
release owner and recorded under [Rulings](#rulings-decided). Tracked as NFR.DEMO.1
(`docs/requirements/RELEASE-4.0.0-scope-update.md:58`,
`docs/requirements/RELEASE-4.0.0-scope-tests.md:72`).

## SCOPE

FOR: what each of the five required recordings contains, what on screen makes it
evidence, how versions/expected/actual are carried, and what keeps the set from
rotting. Five drivers, one manifest, five thin tapes.

OUT: recording anything. No tape is run, no gateway is started and no fixture is
written by this document. Also out: the Open WebUI → Google Workspace journey
(MIK-6745.JOURNEY.1), which is a different criterion with its own live-run
blocker; NFR.DEMO.1 asks for "two personal accounts", not that journey.

## Problem

The criterion asks for recorded demonstrations of five scenarios — mixed-era
interaction, a reconnectable task, isolated personal accounts, useful
large-catalogue discovery, and error-budget diagnosis/recovery — each carrying
the versions used with expected and actual observations. The grading note in
`docs/requirements/RELEASE-4.0.0-scope-status.json` records all five as ABSENT
and the versions/expected/actual conjunct as moot, because nothing exists to
carry it.

One thing in that note is now stale and it matters. The note (2026-09-13) warns
that the mixed-era scenario depends on the legacy stdio bridge being mid-flight
and would have to be re-recorded. MIK-7387.STDIO.1, .2 and .3 are all `met` as of
2026-09-16 (`f93a805b` + `756bd6cd`, same status file), so that particular
re-record risk is gone. The size-8 estimate holds; its composition moved. The
live re-record risk today sits on scenario 4 instead — see that section.

## The fail-fast, run before designing

The question that decides the shape: is `demo.tape` a pipeline to extend, or a
marketing asset that happens to use VHS?

Measured against this tree on 2026-09-17:

| Check | Result |
|---|---|
| What the tape displays | `cat /tmp/gw-demo/client-config.json`, `meta-tools.txt`, `backends.txt` (`demo.tape:45,55,72`) |
| Are those fixtures in the repo? | No. `rg -uu --hidden --no-ignore -l 'gw-demo' .` returns `demo.tape` alone |
| Is the tape worktree-portable? | No. It hardcodes `~/github/mcp-gateway/...` (`demo.tape:24,93,103,107`) |
| Does it exercise the gateway? | No. Every frame is `cat`, `ls`, `wc` or `python3 benchmarks/token_savings.py` |
| Any recording job in CI? | No. `rg -uu -n -i 'vhs\|demo\|\.tape\|recording' .github/workflows/` returns no lines |
| Any asciicast in tree? | No. `fd -uu -e tape -e cast .` returns `demo.tape` only |

So VHS is reusable and the tape is not. `demo.tape` shows hand-typed prose about
files; a reader cannot fail it, because nothing in it can be wrong. Reuse is
therefore: keep VHS as the recorder, and do not copy its "type a claim, `cat` a
file" grammar.

The house already has the grammar to copy instead. `scripts/release/nfr_upgrade_1_rehearsal.sh`
drives real binaries in an isolated `HOME`, records one PASS/FAIL row per
conjunct through a `record id status detail` helper (`:42-48`), writes
`results.json`, and is graded in one markdown file,
`docs/release/nfr-upgrade-1-rehearsal-results.md`, which opens with a verdict and
a "Revision under test" block. NFR.UPGRADE.1 was flipped from ABSENT to `met` on
that evidence. NFR.DEMO.1 differs from it in exactly one way: a camera.

## The shape

Per scenario, three artifacts and one committed file:

1. **Driver** — `scripts/release/demo/<n>-<slug>.sh`, same skeleton as the
   upgrade rehearsal: isolated `RUN_DIR`/`HOME`, free-port selection, explicit
   `record` rows, `results.json` on exit. The expectations live here as
   executable assertions, so there is no second copy of "expected" to drift.
2. **Tape** — `scripts/release/demo/<n>-<slug>.tape`, thin: set the terminal,
   `Type` the one driver invocation, `Sleep`, done. A tape that types prose is a
   tape that can lie; a tape that types one command cannot say more than the
   driver proved.
3. **Transcript** — the driver tees its own stdout to `$RUN_DIR/transcript.txt`.
   The GIF is for a human; the transcript is what a grader greps.
4. **Manifest** — `docs/release/nfr-demo-1-recordings.md`, one file for all five.

## Why one manifest, not five sidecars and not a header frame

The criterion wants versions, expected and actual per scenario. Three candidates:

- **Header frame in each tape.** Rejected: a frame typed into a GIF cannot be
  diffed, grepped or gate-checked, and it is written by hand next to the run it
  describes — the classic drift source this repo already tracks for README
  numbers (`benchmarks/public_claims.json`).
- **Sidecar markdown per scenario.** Rejected: the release gate and every future
  grader then have five files to reconcile, and a missing fifth looks like a
  passing fourth.
- **One manifest.** Chosen. It mirrors `docs/release/nfr-upgrade-1-rehearsal-results.md`,
  which a grader has already accepted once for this release: verdict line,
  "Revision under test" block (gateway `--version`, build SHA, `Cargo.lock`
  commit, VHS version, fixture interpreter versions), then one section per
  scenario with an expected/actual table quoting the driver's own row ids. The
  version block is written once and covers all five because all five run against
  one build; that is a property of the design, not an accident, and the drift
  check below enforces it. The recorder is pinned to an exact VHS version in the
  driver, not floated: a re-record on a newer recorder that renders differently
  is indistinguishable from a product change in the artifact it produces.

## Scenario 1 — mixed-era interaction

**Verdict: designable-as-tape.**

Environment: one gateway build; two clients against it in the same run. The
modern client speaks `2026-07-28` (`src/protocol/meta.rs:291`,
`MODERN_VERSIONS`); the legacy client speaks `2025-06-18`, one of the four in
`SUPPORTED_VERSIONS` (`src/protocol/mod.rs:48`). The legacy peer is a stdio
fixture on the bridge (`src/gateway/input_bridge.rs`); the existing era test
already scripts exactly such a peer as a shell `printf` of a JSON-RPC
`initialize` result (`tests/nfr_obs_3_era_observability.rs:144`), so the fixture
is a lift, not an invention. Config: a demo YAML in `scripts/release/demo/fixtures/`
mounting the legacy stdio peer and a modern HTTP peer; nothing external.

Observable: the gateway's own era fields, which are structured and already
asserted in-tree — `era`, `era_source`, `era_evidence`, `era_probe_trigger`,
`era_probed_at` (`tests/nfr_obs_3_era_observability.rs:425-429`). The recording
shows the two backends side by side: `era=modern, era_source=probed,
era_evidence=discover_modern` (`:506-509`) next to `era=legacy, era_source=probed,
era_evidence=discover_not_modern` (`:524-527`), and the same tool call succeeding
through both.

Broken build shows: `era_source=assumed` / `era_evidence=never_probed`
(`:490-492`) where a probe did run — the unprobed default leaking into a probed
backend; or `2026-07-28` echoed to the legacy client, which would be the
negotiation defect `negotiate_version` exists to prevent (`src/protocol/mod.rs:53`).

## Scenario 2 — a reconnectable task

**Verdict: designable-as-tape on any Unix host under ruling 2; the pinned-SDK
variant stays needs-live-environment and is cited, not re-recorded.**

Environment: `tests/task_upstream_recovery.rs` already runs this journey over
real gateway processes, a real durable store and the real route, with a loopback
peer and no container (`:1-13`, `#![cfg(unix)]`); `rg -uu -c -i 'redis|docker'`
over it returns nothing, while the SDK sibling
(`tests/task_upstream_recovery_sdk.rs`) does hit Docker/Redis and its driver
refuses to run off Linux (`scripts/test-task-sdk-recovery.sh:8`). So the
recordable scenario is the synthetic-peer one; the pinned-SDK proof stays where
it already lives, in `.github/workflows/task-sdk-recovery.yml`.

Cost to make it recordable: the peer in that test is Rust and in-process
(`tests/task_upstream_recovery/helper.rs:229`, `serve_peer`). A shell driver
needs a standalone peer — a stdlib-only stdio/HTTP fixture in the shape of
`scripts/release/fixtures/nfr_upgrade_1_mount_stub.py`, roughly 150 lines. It
does not invent a vocabulary: the helper already encodes the whole exchange the
fixture must speak — submission accounting (`helper.rs:77`, `submissions`),
durable record and status shape (`:370`, `:385`) and the peer's serve loop
(`:229`). Port those four, and nothing else. That is the single largest new
artifact in this design.

Observable: a task id issued, the gateway killed mid-flight
(`tests/task_upstream_recovery/helper.rs:522`, `kill`), the gateway restarted,
and `tasks/get` answering for the same id — either the resumed result or an
explicit interrupted/indeterminate outcome, which is what MIK-7311.LIFECYCLE.4
requires instead of silence. The durable record is readable from disk on camera
(`helper.rs:370`, `durable_record`; `:385`, `record_status`).

Broken build shows: the peer's submission counter at two (`helper.rs:77`,
`submissions`) — a silently replayed side effect, the one outcome
LIFECYCLE.4 forbids; or `tasks/get` answering the restarted gateway with a
no-such-id error, which is the durable store not surviving at all.

## Scenario 3 — isolated personal accounts

**Verdict: designable-as-tape, against a scripted provider (ruling 3).**

**Constraint, not a footnote: this recording cannot be cited as
MIK-6745.JOURNEY.1 evidence.** That criterion stays NEEDS-LIVE-RUN with its
connect and cancelled-consent conjuncts ABSENT, and a scripted provider proves
nothing about either. Any grader reaching for this row to close JOURNEY.1 is
closing it on the wrong artifact.

Environment: one gateway with `multi_user` on and a backend bound to a
gateway-held personal credential; two principals, one connected, one verified but
unconnected. No live Google Workspace: the isolation guard is provider-agnostic
and fires on config state, not on any real IdP.

Observable: the refusal text. The guard enumerates the three ways a backend is
personally bound and carries a per-arm reason and remediation
(`src/gateway/meta_mcp/mod.rs:1103-1139`), then refuses with JSON-RPC `-32001`
and a message that names the backend, the reason and a `Fix:` line
(`:1147-1155`). On camera: user A's call through the backend succeeds; user B's
identical call returns that message; the aggregation routes omit the backend for
B rather than listing what B cannot use (`:1162`, `meta_route_isolation_refused`).

Broken build shows: B receiving A's data — the INV-2 leak itself — or a bare
`-32603` with no backend name and no `Fix:`, which is a refusal an operator
cannot act on. That second control is the one worth recording, because
MIK-6745.JOURNEY.2's C3 conjunct is graded ABSENT *in tests*: no test drives a
verified-but-unconnected caller through an entry point. The product path exists
(cited above); the recording is the first artifact to exercise it end to end.

## Scenario 4 — useful large-catalogue discovery

**Verdict: designable-as-tape, but sequenced behind MIK-3274.RANKING.1.**

Environment: the in-tree catalogue. `fd -uu -e yaml . capabilities` counts 125
capability definitions, which is a real large catalogue with no external
dependency — unlike `examples/config-fulcrum.yaml`, which points at a separate
repository (`:1-6`). Client: the meta surface itself.

Observable, three claims in one frame: the served meta-tool count stays in the
compact band while the reachable catalogue is in the hundreds; a search by
abbreviation or word boundary returns the right tool; and a restricted caller's
search omits a forbidden tool even when it is the most-used match — authorization
before disclosure, ranking before truncation (MIK-3274.RANKING.2's contract).

Broken build shows: the forbidden-but-popular tool ranked above the allowed
relevant one, or present at all for the restricted caller; or a result set
truncated before ranking, visible as the exact identifier match missing from a
short list that contains weaker matches.

Sequencing, and it is the longest pole here: MIK-3274.RANKING.1 is `pending`,
its design sits unmerged on `feat/v4-ranking-fuzzy`, and that branch is itself
blocked on MIK-7469 — rebased clean onto main, but two authorization control
tests owned by main go red because the branch's exact-match sort key overrides
score globally. Result ordering is therefore unsettled, and ordering is the whole
point of this scenario. Ruling 4 puts scenario 4 behind MIK-7469, not merely
behind RANKING.1. This is the same trap the 2026-09-13 note flagged for the stdio
bridge, now moved one row down and one ticket deeper.

## Scenario 5 — error-budget diagnosis and recovery

**Verdict: designable-as-tape, with one open question about the diagnosis surface.**

Environment: a flaky peer — the upgrade rehearsal's mount stub extended with a
fail-N-then-succeed mode — plus a demo config whose `error_budget:` section is
tuned down from the shipped example (`examples/gateway-full.yaml:107-118`:
`threshold`, `window_size`, `min_samples`, and a `capability.cooldown` that ships
at `5m`). The cooldown must be seconds in the demo config or the recording is
five minutes of nothing; the operator section is applied at
`src/gateway/server/mod.rs:1074-1096`, so this is configuration, not a code path
built for the demo.

Observable, in order on one screen: calls failing; `Kill switch engaged: server
disabled` (`src/kill_switch/mod.rs:120`); a dispatch to that backend now refused
rather than attempted; then, after the
cooldown, `Kill switch released: server re-enabled` (`:130`) or `Capability
auto-recovered after cooldown` (`:470`), and the same call succeeding.

Broken build shows: dispatch continuing to the dead backend after the engage line
— a budget that reports but does not protect; or the release line never arriving,
leaving a healthy backend permanently disabled, which is the worse failure of the
two and the reason the recovery half is in the criterion at all.

Diagnosis surface, verified and narrower than it should be: `/health` renders
`state.backends.statuses()` (`src/backend/registry.rs:264`), and `BackendStatus`
carries name, running, lifecycle, transport, cached-tool count, circuit state,
request count and liveness (`:52-70`) — no kill-switch field, and nothing couples
the two (`rg -n -i 'circuit' src/kill_switch/mod.rs` and `rg -n -i 'kill_switch'
src/backend/registry.rs` both return nothing). So the engaged kill switch is
observable only as a log line and a refused dispatch; the scenario is recorded on
those two and must not claim any HTTP surface reports it. An operator with no way
to see an engaged kill switch except in logs is a small product gap worth filing
separately, not a reason to narrow the scenario.

## Anti-rot: a drift check, not a record-in-CI job

Recording in CI is the wrong answer here. A GIF is a binary that changes on every
run; committing one per push is churn, and a CI job that renders video on hosted
runners buys a slow, flaky dependency on a terminal recorder for no grading gain.

What rots is not the GIF — it is the claim. So check the claim:

- A CI job runs the five drivers **headless** (no VHS, no tape) and fails if any
  `record` row is FAIL. Same pattern as `scripts/release/check_scope_acceptance.py`
  and the `benchmarks/public_claims.json` drift check: the machine guards the
  numbers, a human re-renders the pictures.
- Re-recording stays manual and is required only when a driver's rows change,
  which is exactly when the recording became wrong.
- The manifest names the build SHA it was recorded against. A grader comparing
  that SHA to the release tag can see staleness without watching anything.

Cost of the job: one workflow step per scenario against an already-built binary.
Scenario 2 is Unix-only and scenario 5 depends on wall-clock cooldown, so both
need generous timeouts rather than special infrastructure.

## Sizing

The criterion is sized large (8) and this design does not shrink it. Where the 8
goes, now that the stdio bridge has landed:

| Piece | New? | Rough size |
|---|---|---|
| Driver skeleton shared by five scenarios | lift from `nfr_upgrade_1_rehearsal.sh` | small |
| Legacy/modern era fixture + demo config (S1) | lift from `tests/nfr_obs_3_era_observability.rs:144` | small |
| Standalone task peer fixture (S2) | **new**, no shell-drivable equivalent exists | medium, the largest item |
| Two-principal config + scripted provider (S3) | new config, existing guard | small |
| Catalogue + restricted-caller config (S4) | existing 125 capability YAMLs | small |
| Flaky peer mode + tuned `error_budget:` (S5) | extend the existing mount stub | small |
| Five tapes | new, thin | small |
| Manifest + headless drift job | new | small |

## Rulings, decided

The release owner decided all four on 2026-09-17. Reasons are recorded because a
decision without its reason gets re-litigated by the next reader.

1. **"Recorded" does not require a playable video.** The transcript plus the
   manifest is the graded evidence; the rendered video is a companion artifact.
   Reason: the criterion demands versions, expected observations and actual
   outcomes per scenario, and a transcript carries all three in a form CI can
   diff. A gate that cannot read its own artifact is decoration.
2. **Scenario 2 records on any Unix host, with the synthetic peer**, citing the
   existing pinned-SDK workflow beside it (`.github/workflows/task-sdk-recovery.yml`).
   Reason: standing up Linux CI or Spark capacity for one row costs more than the
   row is worth, and the pinned-SDK driver refusing to run off Linux
   (`scripts/test-task-sdk-recovery.sh:8`) is a property of that driver, not of
   the requirement.
3. **A scripted provider is acceptable for scenario 3.** Reason: the isolation
   guard fires on config state, not on a real identity provider, so a live
   provider proves nothing extra. The non-reuse constraint in scenario 3 is part
   of this decision: the row cannot be cited as MIK-6745.JOURNEY.1 evidence.
4. **Scenario 4 records after MIK-7469 settles**, not merely after
   MIK-3274.RANKING.1. Reason: the ranking branch is blocked on that ticket, so
   large-catalogue result ordering is still unsettled, and ordering is exactly
   what this scenario claims to prove.

Scenarios 1, 2, 3 and 5 are unblocked and can be recorded as soon as their
drivers exist. Scenario 4 waits. What remains is fixtures, drivers and a
manifest — work, not further decisions.

## Review

Two independent non-Claude seats were asked to review this draft before commit.
One delivered. Both non-delivering seats are recorded rather than dropped: a
reviewer that exits successfully without a verdict is the same failure mode the
drift check above exists to catch, and it should not be invisible here.

- **Seat 1 (GPT).** No verdict. Run log `gpt-20260917T132209Z-76853` holds one
  line — "ERROR: You've hit your usage limit. Visit
  https://chatgpt.com/codex/settings/usage to purchase more credits or try again
  at Sep 19th, 2026 10:14 AM." — and the wrapper still exited 0.
- **Seat 2 (Grok).** No verdict, on two attempts. Both logs
  (`grok-20260917T132210Z-77177`, `grok-20260917T132641Z-3129`) stop in the
  preamble; the second ends "The on-disk design differs slightly from the stdin
  copy; I'll check those citations and the product surfaces next." with no
  verdict line. The first exited 0, the second was terminated.
- **Substitute seat (GLM; its wrapper self-reports as kimi).** Delivered. Run log
  `kimi-20260917T132242Z-81780`, verbatim: "VERDICT: SHIP-WITH-FIXES — the S5
  observable may not exist in the product and must be verified or re-anchored
  before the drivers are written."

Each of that seat's findings was checked at source rather than accepted:

| Finding | Adjudication | Action taken |
|---|---|---|
| Scenario 5's `/health` observable may not exist | **Right** | `BackendStatus` carries no kill-switch field (`src/backend/registry.rs:52-70`) and the two modules do not reference each other. Scenario 5 now rests on the log lines and the refused dispatch, and the missing operator view is named as a product gap. |
| The capability count has drifted | Wrong | Re-counted in this tree: 125 YAML capability definitions, no `.yml` variants. |
| The era anchor `:490-492` is the wrong citation | Wrong | The anchor is correct; the sentence around it was loose and now says "unprobed default". |
| Scenario 2's verdict claims more than ruling 2 leaves open | Fair | The verdict line now defers to ruling 2 explicitly. |

Three of its improvements were taken: pin the recorder version, point the
scenario-2 fixture at the vocabulary the existing helper already encodes, and
give every open question a default disposition — which the rulings above then
adopted for the first three and overrode for the fourth. One was declined — per-driver row-id
hashes in the manifest — because the manifest already names the commit that
produced every row, and a second integrity layer over one's own output buys
nothing a grader would use.

This draft therefore carries one delivered independent verdict, not two. A
second seat should re-review before any driver is written.
