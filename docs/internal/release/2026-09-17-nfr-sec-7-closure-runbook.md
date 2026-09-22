<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.SEC.7: what is left, and the exact steps that close it

`NFR.SEC.7` is the last blocking row on the v4.0.0 line. Its second half — automatic
detection of merged-versus-listening drift — has been MET since 2026-09-11. Its first
half is not a code gap. Every build that has been probed carries the guard:

| Probed | Build | Result |
| --- | --- | --- |
| 2026-09-11 | built from the release tree, `127.0.0.1:39466` | both probes refused 403, legitimate 200, exit 0 |
| 2026-09-13 | release build of `bd1adbb4` (`origin/main`), spark loopback | `2 probed, 1 uncovered, 0 failing`, exit 0 |
| 2026-09-17 | **the listening install**, `127.0.0.1:39401` | `2 probed, 1 uncovered, 2 failing` |

The listening install still answers a foreign `Origin` and a foreign `Host` with the
full tool list, twenty-two days after `5d25f104` merged. `git merge-base
--is-ancestor 5d25f104 origin/main` confirms the guard is on `origin/main`, so no
code change and no merge of #561 is required to close this row. What is required is
that the listening process runs a build that has it.

## What is actually deployed

`launchctl` label `com.claude.mcp-gateway`, PID 1908, plist at
`~/Library/LaunchAgents/com.claude.mcp-gateway.plist`. The plist pins no version; it
execs a wrapper, and the wrapper pins the version in two lines:

```zsh
# /Users/mikko/.local/bin/start-mcp-gateway
typeset -r gateway_binary="/Users/mikko/.local/libexec/mcp-gateway/3.4.0-f30539af/mcp-gateway"
typeset -r gateway_config="/Users/mikko/.local/libexec/mcp-gateway/3.4.0-f30539af/servers.yaml"
```

Those two lines are the whole deployment control point. Note that `~/.local/bin/mcp-gateway`
symlinks to a *different* build (`3.4.0-851cc03f`) and is not what runs; repointing the
symlink would change nothing.

## Why this is not an agent action

The process on `:39401` serves the `mcp__gateway__*` tools — 494 tools across 33
backends — to every live Claude session. Restarting it drops those connections
session-wide. It is also the operator's daily driver. The restart is deliberately left
to the operator and should be run with no sessions open.

## The staged artifact is stale, and the acceptance check below cannot tell you

**Re-stage before cutting over. Do not flip the symlink to `4.0.0-3ec43838`.**

That artifact was staged from the release-line tip as it stood at 10:45 on 2026-09-22.
Seven commits later the tip is `fbc1567b`, and one of the seven is code: `#707`, which
evicts a caller's pooled backend slot when their identity grant is revoked. Without it a
revoked caller keeps serving traffic through the connection they already hold, so
revocation does not take effect. That is a security control, and the staged binary does
not contain it:

```
$ git show 3ec43838:src/backend/pool.rs | rg -c evict_identity_slots
0
```

`NFR.SEC.7` reads *"the listening build carries every merged security control"*. Flipping
to `3ec43838` would make that sentence false at the moment the row is graded MET.

**The acceptance check is structurally blind to this gap**, which is why it needs saying
here rather than being left to the gate. `security-controls.toml` derives its population
from two authorities — `docs/requirements/nfr-sec1-control-inventory.md` and the module
inventory under `src/security/` — and states its own residual: *"a control merged into a
file that is neither under `src/security/` nor named by the inventory is still invisible
to both authorities."* `#707` touched sixteen files and **none is under `src/security/`**,
so neither authority names the control. `check-control-drift.py` will report `0 failing`
and exit 0 against a build that lacks it. A green acceptance here is not evidence the
criterion holds; it is evidence about the two controls the manifest does probe.

So step 1 below is amended: build from the **release line**, at its tip, checked at build
time. `origin/main` is 198 commits behind the release line, so a binary built from main
would be missing the release, not merely this control.

## Steps

Steps 1-4 touch nothing live: they create a new versioned directory beside the existing
ones. Steps 5-6 are the operator's.

1. Build a release binary from `origin/docs/ranking-1-release-line` at its **current**
   tip, and record that tip's sha. The guard `5d25f104` is on the release line
   (`git merge-base --is-ancestor 5d25f104 origin/docs/ranking-1-release-line` exits 0),
   so provenance stays clean without depending on PR #561. Before copying the binary
   anywhere, confirm the tip has not moved again:
   `git fetch origin docs/ranking-1-release-line && git rev-parse origin/docs/ranking-1-release-line`.
2. `mkdir -p ~/.local/libexec/mcp-gateway/4.0.0-<sha>` and copy the binary in.
3. Copy the live `servers.yaml` from `3.4.0-f30539af/` beside it. This config predates
   v4 and carries all 33 backends.
4. **Validate before trusting it.** The binary has both checks:
   - `<new-binary> --config <staged servers.yaml> validate` (`src/main.rs:74`)
   - `<new-binary> upgrade --dry-run` (`src/commands/upgrade.rs:522`) to list migrations
     without applying them.
   A naive copy without this step risks breaking 33 backends on restart.
5. Repoint the two `typeset -r` lines in `~/.local/bin/start-mcp-gateway`.
6. `launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway`

## Acceptance

Two conditions, because the first one alone is the blind spot described above.

**1. The probed controls still fire.**

```
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
```

must report `0 failing` and exit 0. Check the exit status directly — piping into `tail`
reports the pipe's status, not the checker's.

**2. The listening build is the one you staged, and it carries what the tip carries.**

The checker probes two controls; it does not enumerate the merged set. So confirm
separately that the running process is executing the binary built from the recorded tip
— compare the wrapper's `gateway_binary` path against the directory you created in step
2 — and that the tip you built from is still the tip. If the release line moved while you
were staging, step 1 starts again. A build that is one merge behind is exactly the
condition this runbook was amended for, and nothing downstream will catch it.

On both, flip `NFR.SEC.7` to MET in
`docs/requirements/RELEASE-4.0.0-criteria-status.md` and its blocking cell to `no`.

This step previously promised that "the release blocking count goes to zero" on that
flip. It does not, and the claim is dropped rather than left to be discovered at the tag:
`NFR.PKG.1` is the second baseline blocking row, and `check_scope_acceptance.py
--release` reports both. Closing `NFR.SEC.7` takes the count from two to one.

Rollback is the reverse of step 5 plus another kickstart. The previous versioned
directories are left in place precisely so that stays available.
