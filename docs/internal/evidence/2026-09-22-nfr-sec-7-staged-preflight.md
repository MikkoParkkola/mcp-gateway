<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.SEC.7 — staged artifact and pre-flight, 2026-09-22

Steps 1–3 of `docs/runbooks/nfr-sec-7-cutover.md` are done. Steps 4–7 are the operator's
and nothing here has taken them: the live symlink still names the old build, and the
process on `:39401` is the same PID it was before this work started.

## The artifact

| | |
|---|---|
| Directory | `~/.local/libexec/mcp-gateway/4.0.0-017c9338/` |
| `sha256` | `93ed6b5a862066f919774231685c031e11ad54414bb2ca50c55054de829b79d8` |
| Format | Mach-O 64-bit executable arm64 |
| `--version` | `mcp-gateway 4.0.0` |
| Built from | `017c9338` — the `docs/ranking-1-release-line` tip at build time |
| Recipe | `cargo build --release` on this Mac |

**Why this supersedes `4.0.0-3ec43838`.** That directory was staged from the tip as it
stood at 10:45 the same day, and `fbc1567b` (#707) merged afterwards. `git show
3ec43838:src/backend/pool.rs | rg -c evict_identity_slots` returns `0`; the same grep on
`017c9338` returns `1`. The older staged artifact is a build from before that control
existed, and the drift checker cannot see the difference — see the runbook.

**Provenance is the directory name, and that is a known limit.** The binary embeds no
build commit, so nothing inside it attests which tree produced it. The chain here is:
the tree at `017c9338` contains `evict_identity_slots` (verified by grep on that tree),
and this binary was built from that tree in `~/github/mcp-gateway-sec7-build` with the
worktree detached at that sha. Note that `strings` on the binary does **not** find
`evict_identity_slots` — a release build strips private symbol names, so that absence is
not evidence either way and must not be read as one.

## Step 1c — the guard is compiled in

```
$ rg -a -q 'Request blocked: Host does not name this gateway' target/release/mcp-gateway
  HOST GUARD compiled in
  ORIGIN guard string present
```

## Step 3 — smoke through the real launcher, spare port, throwaway data directory

Started as `MCP_GATEWAY_CONFIG_DIR=$(mktemp -d) MCP_GATEWAY_PORT=39412` through
`4.0.0-017c9338/start-mcp-gateway`, so the real `servers.yaml` and the real secrets were
exercised while the live data directory was not touched. Up in 3 seconds.

```json
{"backends":{"all_healthy":true,"count":32},"capability_backend":null,
 "status":"healthy","version":"4.0.0"}
```

**All 32 backends healthy under the real configuration and secrets.** This is the first
time a 4.0.0 build has done so in this environment.

### The acceptance check

```
$ python3 scripts/dev/check-control-drift.py http://127.0.0.1:39412/mcp
5 probed, 29 uncovered, 0 failing
EXIT STATUS: 0
```

Graded against the runbook's four conditions rather than the transcript:

| # | Condition | Result |
|---|---|---|
| 1 | exit status 0 | **yes** |
| 2 | tally ends `0 failing` | **yes** |
| 3 | `origin-guard` and `host-guard` read `refused 403; legitimate request 200` | **both** |
| 4 | no baseline-covered control became `uncovered` | 5 probed, up from 2 in the 2026-09-13 run; none regressed |

Each probed line carries `[provenance unavailable: v4.0.0 is not a tag in this
repository]`, which is expected and not a failure — 4.0.0 is unreleased.

### The client-visible contract is unchanged

```
tools/list -> gateway_search, gateway_execute      (count 2)
```

Byte-for-byte the 2026-09-19 baseline the runbook records. A 4.0 build exposing a
different meta-tool surface would show up here and nowhere in the drift check; it does
not.

## What is still the operator's

Steps 4–7: rehearse the rollback by flipping the symlink both ways, flip it to the new
build, `launchctl kickstart`, watch ~30s for a restart loop, then re-run step 7 against
`:39401`. The symlink is deliberately left naming the old build:

```
$ readlink ~/.local/bin/start-mcp-gateway
/Users/mikko/.local/libexec/mcp-gateway/3.4.0-f30539af/start-mcp-gateway
```

Nothing above proves the row. What a spare-port smoke cannot establish is that `launchd`
execs the new launcher without a restart loop, and that the live data directory migrates
cleanly — the criterion is about the **listening** build, and this one is not listening.
