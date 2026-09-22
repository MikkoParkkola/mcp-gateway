<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.DEMO.1 — recorded demonstrations

VERDICT: NFR.DEMO.1: 5 of 5 scenarios RECORDED, 0 BLOCKED (41 rows, all PASS; scenario 4's former blocker MIK-7469 refuted by measurement)

The machine-readable evidence is [`nfr-demo-1-recordings.json`](nfr-demo-1-recordings.json).
This page is the human-readable half: what each rule in the gate is answering, and
what the recordings do and do not prove.

Gate: `python3 scripts/release/check_nfr_demo_1_recordings.py` (exit 0 = evidence holds).
Its own negative controls: `python3 scripts/release/test_check_nfr_demo_1_recordings.py`.

## What the criterion asks, and which rule answers it

The criterion (`docs/requirements/RELEASE-4.0.0-scope-update.md`): "Recorded
demonstrations prove mixed-era interaction, reconnectable tasks, isolated personal
accounts, useful large-catalogue discovery and error-budget diagnosis/recovery."
The test plan (`docs/requirements/RELEASE-4.0.0-scope-tests.md`) adds: "include
versions, expected observations and actual outcomes."

| Word in the criterion | Rule in `check_nfr_demo_1_recordings.py` |
|---|---|
| the five named scenarios | `REQUIRED_PHRASES` — each phrase must appear exactly once; a dropped, renamed or sixth scenario fails |
| "recorded" | a `recorded` scenario must cite a driver, a transcript and a results.json, all present and non-empty |
| "prove" | `check_rows` cross-checks each manifest row against the row **the driver itself wrote**; a hand-edited manifest fails |
| "expected observations and actual outcomes" | every row carries `expected` and `actual`; `expected != actual` is a failure, and the driver derives `status` by comparing them rather than labelling it |
| "versions" | every scenario carries a `versions` block |
| the revision under test | `revision_under_test` must carry `gateway_version`, `binary_sha256` and `build_sha_confidence` |
| a recording that cannot fail proves nothing | every scenario carries a `negative_control`: what a broken build would show instead |
| honest reporting | a `blocked` scenario must name a `blocked_on`, must not cite a transcript, and the verdict must say BLOCKED |
| ruling 3 (non-reuse) | the "two personal accounts" scenario must carry a machine-readable `not_evidence_for` entry for `MIK-6745.JOURNEY.1` with a reason |

## Scenario 1 — mixed-era interaction (RECORDED, 9/9 rows PASS)

Driver `scripts/release/demo/1-mixed-era.sh`, transcript
`docs/release/demo/1-mixed-era-transcript.txt`, rows
`docs/release/demo/1-mixed-era-results.json`.

Two offline stdio peers are mounted side by side on one gateway: a modern peer
(`protocolVersion` 2026-07-28, `server/discover` naming a modern revision) and a
legacy peer (2025-06-18, naming none). The fixture is a recorder, not a
participant — it holds no era logic, so the classification stays under test.

Proven: the same call succeeds through both eras from one client; the gateway
classifies each peer from its own probe (`era`, `era_source=probed`,
`era_evidence=discover_modern` / `discover_not_modern`); and a legacy client is
answered in the legacy revision, not the modern one.

**Design gap found while recording.** The era probe runs on the backend *start*
path (`src/backend/lifecycle.rs:322`, `resolve_era_after_start`), and backends
start lazily. Reading `gateway_list_servers` before any call therefore reports
`era_source=assumed` / `era_evidence=never_probed` — the unprobed default, not a
classification. The driver warms each backend with a tool call first. The design
did not mention this; anyone writing a further scenario against the era fields
needs the same warm-up.

## Scenario 3 — two personal accounts (RECORDED, 8/8 rows PASS)

Driver `scripts/release/demo/3-personal-accounts.sh`, transcript
`docs/release/demo/3-personal-accounts-transcript.txt`, rows
`docs/release/demo/3-personal-accounts-results.json`.

Alice and Bob share one gateway. Two API keys and no `single_user` override put
the gateway in the multi-user posture (`AuthConfig::implies_multi_user`), which
is the posture the isolation guard defends. Each has a personal backend; a third
backend carries `oauth.enabled: true` with `shared_account` unset, so the
gateway holds one person's login for it.

Proven: each account reaches its own backend; **neither reaches the other's**
(both rows assert the *absence* of the other peer's answer, so a leak flips
them); and the personally-bound backend is **refused** with `-32001` — "one
user's token is never served to another" (ADR-008 INV-2) — rather than answered
with a credential that belongs to somebody else.

### Two findings this recording surfaced

**The catalogue is not account-scoped.** `gateway_list_servers` returns the same
list to both keys: each account sees the other's backend, and the
personally-bound backend that neither may invoke. Credential isolation holds —
what crosses the boundary is metadata, backend names and descriptions.
`meta_route_isolation_refused` (`src/gateway/meta_mcp/mod.rs:1119`) exists to
omit isolation-refused backends from list paths, and this list path does not
consult it. The recording carries this as
`S3.CATALOGUE_IS_NOT_ACCOUNT_SCOPED`, written as a **characterisation** row: it
asserts the behaviour as observed, so a build that starts scoping the catalogue
makes the row FAIL and forces the finding to be revisited rather than quietly
closed. Whether this is a defect or accepted behaviour is an owner decision.

**The ADR-008 INV-2 refusal is spelled twice.**
`src/gateway/meta_mcp/invoke.rs:1430-1440` builds its own `-32001` saying "one
user's **token**"; `enforce_oauth_isolation_for` at
`src/gateway/meta_mcp/mod.rs:1105-1111` says "one user's **credential**".
`gateway_invoke` takes the first. Both are correct refusals — the duplication is
the risk, because a fix to one arm does not reach the other.

## Scenario 5 — error-budget diagnosis/recovery (RECORDED, 8/8 rows PASS)

Driver `scripts/release/demo/5-error-budget.sh`, transcript
`docs/release/demo/5-error-budget-transcript.txt`, rows
`docs/release/demo/5-error-budget-results.json`.

One stdio peer that fails every tool call while a marker file exists, and an
error budget tuned short for the camera (`threshold: 0.5`, `min_samples: 3`).
The peer answers; the operator injects the fault and does nothing; the budget
kills the backend on the second failure.

**Diagnosis** is the gateway's own numbers through `gateway_get_stats`:
`server_safety` reports `killed: true`, `error_rate: "66.7%"`,
`window: {successes: 1, failures: 2}`. Those numbers are arithmetic from the
config, not copied from a run: the window holds the one healthy call plus the
failures, the budget is first evaluated once it holds `min_samples` = 3 calls,
and 2/3 is already over the 0.5 threshold. A build that kills early or late
moves them. While killed the gateway **refuses** (`-32000 … currently disabled
by operator kill switch`) rather than forwarding to a peer it knows is sick.

**Recovery** is `gateway_revive_server`, which reports `was_killed: true`, and
the next call succeeds. A **server**-level kill has no auto-cooldown — the
cooldown in `examples/gateway-full.yaml` applies to per-*capability* disables —
so recovery is an operator action, not a timer the recording waits out.

**Trap found while recording.** The scenario config switches the response cache
off on purpose. With it on, a cached reply answers every retry, the sick peer is
never reached, and the budget never sees a failure: the first run of this driver
recorded a "healthy" peer through four injected faults. Any future fault
scenario needs the same key.

## Scenario 2 — reconnectable task (RECORDED, 8/8 rows PASS)

Driver `scripts/release/demo/2-reconnectable-task.sh`, transcript
`docs/release/demo/2-reconnectable-task-transcript.txt`, rows
`docs/release/demo/2-reconnectable-task-results.json`.

One client starts a task on a peer whose every tool call takes 20 seconds, then
drops the session. The task is read back on a **new session**, the gateway is
**SIGKILLed while the work is still in flight**, and the same task id is read
again from a **restarted process**.

Proven: the record survives a session change; it survives the process; the
restarted gateway answers with an explicit outcome — `executionOutcome:
"unknown"`, `reason: "gateway_restart_after_dispatch"` — which is what
MIK-7311.LIFECYCLE.4 requires instead of silence; recovery does **not** replay
the side effect (the peer's submission counter stays at 1); and the task reaches
a terminal state.

**Why the restart, and not just a session swap.** A session-header swap against
a live process cannot distinguish a durable record from a process-local map: it
passes on a build with no persistence at all. The store is left at its shipped
default (`tasks.store_dir`, `src/config/features/tasks.rs:23-32` — "a process
that cannot open it does not start; there is no volatile fallback"), and
`_common.sh` points `HOME` at the run directory, so nothing here configures
durability into existence.

**SIGTERM drains, and that hid the claim.** `_common.sh`'s `stop_gateway` sends
SIGTERM, and this gateway finishes in-flight work on it. The first run of this
driver used it, the 20-second job completed during shutdown, and the restarted
process read an **already-terminal** record — proving only that a completed
record survives, which is the weaker claim. The driver now uses its own SIGKILL.

**Scope limitation, verified at source.** The driver runs with auth **disabled**,
so it proves cross-session and cross-restart reconnect and **nothing** about
cross-account isolation (that is MIK-7311.LIFECYCLE.2's Rust ACs). With auth on,
task creation refuses with `-32600 task creation requires a verified caller
identity` unless the request carries a `VerifiedIdentity`
(`src/gateway/router/handlers/tasks.rs:145`), and the static API-key branch of
the auth middleware inserts `AuthenticatedClient` and `ApiKey` but never an
identity (`src/gateway/auth.rs:991-1002`); only `key_server_credential` does
(`:1006-1014`).

An unreviewed draft of this driver blamed OIDC's HTTPS issuer requirement
instead. That is **wrong** and was corrected rather than carried: a non-HTTPS
issuer only logs a warning (`src/key_server/oidc.rs:377`), and an explicit
`provider.jwks_uri` bypasses discovery and its HTTPS check entirely (`:399`), so
a local issuer is configurable. Minting a local JWKS and a signed JWT was simply
not built in this pass. The limitation stands; the stated reason did not.

**Negative control, exercised.** Deleting the durable store between the SIGKILL
and the restart, changing nothing else, turns three rows RED with `actual:
<absent>` — `S2.TASK_SURVIVES_A_GATEWAY_RESTART`,
`S2.STATUS_AFTER_RESTART_IS_EXPLICIT_NOT_SILENCE` and
`S2.CANCEL_LEAVES_A_TERMINAL_STATE` — while the four pre-restart rows stay green,
which is correct: they measure the live process. The restart therefore reloads
from disk, not from anything the driver seeded.

## Scenario 4 — large-catalogue discovery (RECORDED, 8/8 rows PASS)

Driver `scripts/release/demo/4-large-catalogue.sh`, transcript
`docs/release/demo/4-large-catalogue-transcript.txt`, rows
`docs/release/demo/4-large-catalogue-results.json`.

The gateway is pointed at the repository's own production catalogue
(`capabilities/`, `examples/` excluded — the directory
`tests/mik_3274_ranking_3_baseline.rs` loads for ranking regression). No live
backend, no credentials.

Proven, the three claims
[design §Scenario 4](../design/2026-09-17-nfr-demo-1-scenario-recordings.md#scenario-4--useful-large-catalogue-discovery)
asks for, in one frame:

- **Compact surface, large catalogue.** A client's `tools/list` is served 14
  tools, inside the shipped 9–17 band (`README.md:21`; lower bound from
  `benchmarks/public_claims.json`), while `gateway_list_tools` reaches 119 —
  matching the 119 capability files counted on disk in the same run.
- **Discovery works.** "send an email through gmail" returns `gws_gmail_send` at
  rank 1 out of that pool.
- **Authorization precedes disclosure, ranking precedes truncation.** A caller on
  a restricted routing profile runs the *identical* query and does **not**
  receive `gws_gmail_send`, while the unrestricted caller has it at rank 1. A
  greedy `limit: 9999` over 119 candidates returns exactly 25, the
  `MAX_SEARCH_LIMIT` ceiling (`src/gateway/meta_mcp_helpers.rs:626`).

**Why a routing profile and not an API-key denylist.** An API key's
`denied_tools` is an invocation-time control, reached only from
`authorize_tool_call` (`src/gateway/router/authorization.rs:179`, the single
caller of `check_tool_scope`). Discovery filters on `profile.tool_allowed`
instead (`src/gateway/meta_mcp/search.rs:663`, `:726`, `:755`). Measured while
writing this driver: a key carrying `denied_tools: [gws_gmail_send]` still
received that tool at rank 1, `total_available` unchanged. Two mechanisms, two
questions — but a recording built on the key denylist would have asserted a
control the discovery path never consults.

**The former blocker, MIK-7469, is refuted by measurement.** It held that
`feat/v4-ranking-fuzzy` could not land because two tests owned by `main` went red
on its rebased tip. Both **pass** on this release line: `cargo test --lib
search_ranking_authz` at `88e160d2` → ok, 20 passed, 0 failed — including
`heavy_usage_outranks_the_exact_match_when_nothing_is_denied` and its Code Mode
sibling. The ticket's last update (2026-09-17) predates PR #607, the RANKING.1
implementation merged 2026-09-20; `MIK-3274.RANKING.1` and `.2` are both graded
met. Design ruling 4 sequenced this scenario behind that ticket because result
ordering was unsettled; it is settled. The disposition is recorded in the
manifest as `previously_blocked_on` rather than deleted, so the blocker is not
re-raised from the stale ticket.

**Two traps found while recording.** The catalogue scan is not finished when
`/health` first answers: an unreviewed draft polled for the first *nonzero* tool
count and read **18 of 119**, a partially filled scan that would have been
recorded as the catalogue size. The driver now polls until the count is stable —
the same class as scenario 1's era warm-up. And the draft's clamp row queried
`"file"`, which matched 16 tools against a ceiling of 25: a row that **could not
fail**. It is now a 119-candidate query returning exactly 25, with
`S4.SEARCH_CANDIDATES_EXCEED_THE_CEILING` asserting the pool is larger than the
ceiling so a clamp is distinguishable from a small result set.

**Negative control, exercised.** Removing `deny_tools` from the restricted
profile, changing nothing else, turns exactly one row RED —
`S4.RESTRICTED_CALLER_DOES_NOT_SEE_THE_FORBIDDEN_TOOL`, actual `"gws_gmail_send"
present` — and leaves every other row green. The denial row cannot pass
vacuously either: the restricted caller still receives five other Gmail matches,
and `S4.OPEN_CALLER_SEES_THE_SAME_TOOL_AT_RANK_1` pins that the unrestricted
caller has the forbidden tool at rank 1 on the same query.

## Ruling 3 — what scenario 3 will not be evidence for

When scenario 3 is recorded it will use a scripted provider fixture and will prove
only the gateway's isolation enforcement. It is **not** a journey recording against
a real identity provider and must not be reused as evidence for
`MIK-6745.JOURNEY.1`. The constraint is carried in the manifest as a
`not_evidence_for` entry and enforced by the gate whatever the scenario's status.

## The binary these rows were produced against

There are **two** binaries behind this manifest, and the blocks say which is
which. `revision_under_test` describes scenarios 1, 3 and 5 only; scenarios 2
and 4 carry their own revision fields in their `versions` blocks.

### Scenarios 2 and 4 — measured

Built on the Spark box from a tree rsynced out of the recording worktree.
`binary_sha256` `8752a4a9…`, debug profile, Linux aarch64. The crate still
embeds no commit SHA, so the source revision is established by comparing build
**inputs** rather than trusting a label: the 606 files under `src/`, plus
`Cargo.toml` and `Cargo.lock`, hash to the same content digest `3104b06e9d33c536`
on both sides — blob ids from `git ls-tree -r 88e160d2` locally, `git
hash-object` on the Spark tree. That is what earns
`build_sha_confidence: measured` for these two, and it is the check the earlier
pass could not make.

### Scenarios 1, 3 and 5 — assumption, corroborated separately

`revision_under_test.binary_sha256` pins the exact bytes. The source revision
behind them is an **assumption**, not a measurement: this machine had too little
free disk to build, so the binary was copied from a peer worktree's `target/debug`
tree, and the crate embeds no commit SHA (no `build.rs`). `build_sha_confidence`
carries that, and the gate requires the field.

Those bytes are now **gone** — the `target/debug` tree they were copied from no
longer exists. Without a source revision and without the binary, the rows above
were, on their own, unreproducible.

### Corroboration run — the same rows from a measured revision

`docs/release/demo/corroboration-2026-09-21.json` closes that gap without
disturbing the rows above. All three recorded drivers were re-run against a
binary built from a **named commit**, and every row was compared field by field
against the committed driver output:

| | Original recording | Corroboration run |
|---|---|---|
| Source revision | assumption | `8ef7751c` — **measured** |
| Binary | `6e38ee5f…` (no longer exists) | `a2deb96b…` |
| Profile | debug | release |
| Host | darwin | Linux aarch64 |
| Rows | 25 PASS | **25 PASS, all identical** |

The tree was exported with `git archive <sha>`, so the peer working-tree edits
present in the shared checkout are excluded by construction rather than by
promise. Reproduce it by building that commit and running the three drivers with
`BIN=` set; matching rows are the check.

Beyond provenance: the corroboration run changed build profile
(debug→release), operating system and architecture (darwin→Linux aarch64) and
toolchain **all at once**, and every row still matched. That rules out any
*combination* of those flipping a row. It does not attribute per factor — they
moved together, and the original binary's toolchain version is unknown. The
error-budget arithmetic (`66.7%`, `successes: 1`, `failures: 2`) reproduced
exactly, which is the strongest single signal that it is arithmetic from the
config rather than a number copied out of one lucky run.

It does **not** upgrade `revision_under_test` in the manifest. That block
describes the bytes the committed transcripts came from, and rewriting it to
describe a different binary would misdescribe them.
