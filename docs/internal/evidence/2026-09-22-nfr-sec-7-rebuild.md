<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->

# NFR.SEC.7 rebuild at the release-line tip, 2026-09-22

The staged `4.0.0-e82d7ee4` was built from a commit on `origin/main`. The release
line `docs/ranking-1-release-line` is **191 commits** ahead of it — the earlier
figure of 188 was taken before `#697`, `#698` and `#701` landed. Two of those 191
are security commits absent from the staged build. This record rebuilds at the
release-line tip and stages the result beside it. The symlink flip is not taken
here.

## Why the existing artefact could not be graded into compliance

`fdc3f1c0` adds a 34th manifest control, `agent-identity-proof-rank`, with
`probe = "none"` (`security-controls.toml:106-112`). The drift checker therefore
never looks for it, and `4.0.0-e82d7ee4` grades green while lacking it. The
checker's green is not evidence about this control either way; the binary string
comparison below is what carries the claim.

## Artefact

| Field | Value |
|---|---|
| Source commit | `3ec438380abc9c404f32f9d40d31aee11f3b72b9` (`3ec43838`), tip of `origin/docs/ranking-1-release-line` |
| Recipe | `cargo build --release --target aarch64-apple-darwin` |
| Recipe authority | `.github/workflows/release.yml:230` with `matrix.target` = `aarch64-apple-darwin` (`:200`); same command the 2026-09-21 prep recorded |
| Feature set | default — no `--features` / `--no-default-features` on the release-workflow line, so `Cargo.toml:179` applies: `a2a, webui, config-export, cost-governance, firewall, discovery, semantic-search, tool-profiles, metrics` |
| Profile | `release` — `Cargo.toml:220-224`: `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = true` |
| Binary | Mach-O 64-bit executable arm64, `mcp-gateway 4.0.0` |
| sha256 | `09f4d4231dacf8c1410991a40396600fdca51b918b1aba61077a2436797635e2` |
| Installed at | `~/.local/libexec/mcp-gateway/4.0.0-3ec43838/` |
| Build wall time | 3m 19s (cargo), 09:09:45Z to 09:13:05Z, exit 0 |

Provenance remains unavailable by construction: `v4.0.0` is not a tag, there is no
`build.rs`, and `3ec43838` appears nowhere inside the binary. As in the 2026-09-21
record, the only thing tying this artefact to that tree is the directory name.

## Ancestry — both security commits are in the build

```
git merge-base --is-ancestor fdc3f1c0 HEAD   -> exit 0
git merge-base --is-ancestor 55b8bf89 HEAD   -> exit 0
git merge-base --is-ancestor fdc3f1c0 e82d7ee4 -> exit 1
git merge-base --is-ancestor 55b8bf89 e82d7ee4 -> exit 1
```

`fdc3f1c0` "rank a proven principal above a declared label"; `55b8bf89` "gate the
incomparable-namespace acceptance on an opt-in". Both are ancestors of the tip and
neither is an ancestor of the commit the old artefact was built from.

## The new binary carries controls the old one lacked

Two string markers, each tied to its commit at source level before being looked
for in either binary, so that an absence means "not yet written" rather than
"added somewhere in 191 commits":

| Marker | Commit | `git show <sha>^:` | `git show <sha>:` |
|---|---|---|---|
| `Request rejected: the declared agent label` | `fdc3f1c0` | 0 | 1 |
| `incomparable_proof_sources` | `55b8bf89` | 0 | 5 |

Then `rg -a` against both stripped release binaries:

| Marker | `4.0.0-3ec43838` | `4.0.0-e82d7ee4` |
|---|---|---|
| `Request rejected: the declared agent label` | present (1) | **absent** |
| `incomparable_proof_sources` | present (1) | **absent** |
| `known_agents` (predates both) | present (3) | present (2) |
| `Request blocked: Host does not name this gateway` | present (1) | present (1) |

The last two rows are the controls that make the first two readable. Without them
an absence would be ambiguous between "the commit is missing" and "the module is
not in this build at all" — `known_agents` proves `AgentIdentityConfig` compiles
into both binaries, and the host-guard string proves `rg -a` can see rodata in a
`strip = true` artefact. `strip` removes symbols, not string literals; the
runbook's own step 1c depends on the same property.

What this does **not** prove is behaviour. `agent-identity-proof-rank` is
structural — `ProvenAgentId` has a private field and no public constructor — so
there is no request that behaves differently and nothing for a probe to observe.
The string is evidence the code is compiled in, not that the guarantee holds; the
guarantee is held by the type system in the tree and by the tests, not by this
binary comparison.

## Staging

`~/.local/libexec/mcp-gateway/4.0.0-3ec43838/`, created beside the existing
directories and writing into none of them. Modes match the existing convention
exactly — directory 755, `mcp-gateway` 755, `servers.yaml` 400, launcher 700.
`cp` does not preserve 400, so it is set explicitly.

`servers.yaml` is copied from the running `3.4.0-f30539af` install, per runbook
step 2, and is byte-identical to it
(`fcd123d1194ac0afc496be7a51e45641393ee863408aa70bd1b98ff2044d44a6`) and to the
one staged in `4.0.0-e82d7ee4`. The launcher is derived from the previous staged
4.0.0 launcher by version substitution; it differs from it only in the two
`typeset -r` path lines, and carries no residual reference to `4.0.0-e82d7ee4`.

`~/.local/bin/start-mcp-gateway` was **not** touched. It still reads
`3.4.0-f30539af/start-mcp-gateway`, verified by `readlink` after staging.

## Closure-runbook step 4 — one half is stale

`mcp-gateway upgrade --dry-run` exits 0, `Already at version 4.0.0 — nothing to
do.`, and `~/.mcp-gateway/version.stamp` is unchanged at `4.0.0`. The dry-run is
non-writing by construction (`src/commands/upgrade.rs:555`, with
`upgrade_command_dry_run_does_not_write_stamp` at `:775`).

The other half does not work as written. `2026-09-17-nfr-sec-7-closure-runbook.md:58`
gives `<new-binary> --config <staged servers.yaml> validate` as a check on the
staged config. `validate` is a **capability-YAML linter** ("Lint capability YAMLs
against agent-UX best practices"), takes positional `<PATHS>...`, and exits 2 with
a missing-argument error when invoked that way. It never validated `servers.yaml`.
What actually proves the config parses is the step-3 smoke below, which is how the
2026-09-21 record established it too.

## Drift check without a cutover

Both modes available pre-cutover were run, from the **worktree's own** copy of the
script: `REPO_ROOT` is derived from the script's location
(`check-control-drift.py:35`), so a copy in a checkout at `origin/main` would read
a 33-control manifest and grade against the wrong set.

**Coverage-only** — grades the tree, not the artefact:

```
18 authority rows, 18 security modules, 34 manifest controls, 0 coverage gaps
```
exit 0. Against the 2026-09-21 record's 17 modules / 33 controls, this is the new
module and the new control arriving with no coverage gap.

**Spare-port smoke** (runbook step 3) — the staged build started through its own
launcher on `127.0.0.1:39412` with a throwaway `MCP_GATEWAY_CONFIG_DIR`, listening
after ~2s:

```
18 authority rows, 18 security modules, 34 manifest controls, 0 coverage gaps
origin-guard: refused 403; legitimate request 200
host-guard: refused 403; legitimate request 200
json-well-formedness: refused 400; legitimate request 200
jsonrpc-envelope-shape: refused 400; legitimate request 200
input-sanitization: refused 400; legitimate request 200
5 probed, 29 uncovered, 0 failing
```

exit 0. That block is an excerpt; the full transcript is 36 lines, the 29 omitted
being `uncovered` controls with their recorded reasons. Each probed line also
carries `[provenance unavailable: v4.0.0 is not a tag in this repository]`.

Graded on the runbook's four conditions: (1) exit 0, (2) tally ends `0 failing`,
(3) both guards read `refused 403; legitimate request 200`, (4) the same five
controls probed as the 2026-09-21 record — none regressed to `uncovered`, and the
uncovered count moved 28 to 29 solely because `agent-identity-proof-rank` was
added as `probe = "none"`. Condition 4 is still graded against prose in the prior
evidence file rather than against a committed transcript: the baseline file the
runbook asks for (`nfr-sec-7-control-drift-baseline.txt`) does not exist, and
creating it was outside this task's scope.

`/health` answered
`{"backends":{"all_healthy":true,"count":32},"capability_backend":null,"status":"healthy","version":"4.0.0"}`
and `tools/list` returned exactly `gateway_search` and `gateway_execute` — the
runbook's recorded tool-surface baseline, unchanged. `all_healthy` remains an
aggregate of request outcomes rather than a per-backend liveness probe, and this
ran against a throwaway data directory, so backend health under the real
`~/.mcp-gateway/` is still unobserved.

The smoke was torn down: port 39412 released, and `127.0.0.1:39401` confirmed
still held by PID 1908 afterwards. The live install was never contacted, signalled
or reconfigured.

## Disk

19.7 GiB free before, 18.7 GiB after — 1.0 GiB consumed, of which the `target/`
tree is 935 MiB and the staged directory 18 MiB.

This contradicts the cutover runbook's Option C cost line, which describes a build
that cannot fit and would be "cut off part-way" by the 5 GiB floor, reasoning from
two **debug** trees at 5.4 GB and 8.2 GB. A release build with `strip = true` and
no debug info is roughly an order of magnitude smaller. Option C was never the
disk risk that section makes it out to be, and a runbook that overstates a cost
gets skipped when it matters.

## What remains

The criterion stays PARTIAL. Nothing above is a deployment. What is staged is a
binary that has never been executed by `launchd`, never read the real
`~/.mcp-gateway/`, and never served a client.

Only the cutover itself can settle:

- that `launchd` execs this build cleanly and does not enter the
  `KeepAlive`/`ThrottleInterval` restart loop,
- that the 32 backends come up healthy under the **real** data directory and real
  secrets, rather than the throwaway one used here,
- that the live `127.0.0.1:39401` stops answering a foreign `Origin` with the tool
  list — the symptom the criterion actually names, which no spare-port run
  observes,
- that the rollback `kickstart` works; only the symlink flip has been rehearsed,
  never a `launchd` exec of either build.

Remaining steps are runbook steps 4-7 against `~/.local/bin/start-mcp-gateway`,
which this record deliberately leaves pointing at `3.4.0-f30539af`.
