<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.DEMO.1 — recorded demonstrations

VERDICT: NFR.DEMO.1: 1 of 5 scenarios RECORDED, 4 BLOCKED (scenario 4 on MIK-7469; scenarios 2, 3 and 5 on build budget, not on product behaviour)

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

## Scenarios 2, 3 and 5 — BLOCKED on build budget

Not recorded in this pass, and blocked on the cost of building the fixtures, not
on any gateway behaviour. Nothing found during the research suggests the
recordings would fail. The manifest carries the located mechanism for each so the
next pass starts from code, not from a search:

- **Scenario 2 (reconnectable task)** — needs a standalone stdio task peer (~150 lines, design §Scenario 2).
- **Scenario 3 (two personal accounts)** — enforcement at `src/gateway/meta_mcp/mod.rs:1040` (`enforce_oauth_isolation_for`), refusal `-32001` at `mod.rs:1105-1111`, `meta_route_isolation_refused` at `mod.rs:1119`.
- **Scenario 5 (error-budget diagnosis/recovery)** — budget config at `examples/gateway-full.yaml:107-118`; kill-switch lines at `src/kill_switch/mod.rs:120` / `:130` / `:470`. A **server**-level kill has no auto-cooldown, so recovery is the `gateway_revive_server` meta-tool (`src/gateway/meta_mcp/invoke.rs:3327`), not a timer the recording waits out.

## Scenario 4 — BLOCKED on MIK-7469

Out of scope for this pass by the task brief.

## Ruling 3 — what scenario 3 will not be evidence for

When scenario 3 is recorded it will use a scripted provider fixture and will prove
only the gateway's isolation enforcement. It is **not** a journey recording against
a real identity provider and must not be reused as evidence for
`MIK-6745.JOURNEY.1`. The constraint is carried in the manifest as a
`not_evidence_for` entry and enforced by the gate whatever the scenario's status.

## The binary these rows were produced against

`revision_under_test.binary_sha256` pins the exact bytes. The source revision
behind them is an **assumption**, not a measurement: this machine had too little
free disk to build, so the binary was copied from a peer worktree's `target/debug`
tree, and the crate embeds no commit SHA (no `build.rs`). `build_sha_confidence`
carries that, and the gate requires the field.
