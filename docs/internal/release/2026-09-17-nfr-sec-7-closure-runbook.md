<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.SEC.7: what is left, and the exact steps that close it

> **SUPERSEDED 2026-09-22. Do not follow the steps below. Use
> [`docs/runbooks/nfr-sec-7-cutover.md`](../../runbooks/nfr-sec-7-cutover.md).**
>
> This document is kept for its evidence table, which is still accurate, and because it
> is cited elsewhere. Its *procedure* is not, in three ways that each cost something:
>
> 1. **Step 5 destroys the rollback target.** `~/.local/bin/start-mcp-gateway` is a
>    symlink into `3.4.0-f30539af/`. Editing "the two `typeset -r` lines" through it
>    rewrites the *old* version's launcher, so the versioned directory this document
>    promises is "left in place precisely so rollback stays available" is no longer
>    pristine when you need it. The superseding runbook stages a separate launcher and
>    moves the symlink — and says so at its own step 4: *"NOT `$EDITOR` on the symlink:
>    that rewrites `$OLD` and destroys the rollback target."*
> 2. **Step 1 builds from the wrong line.** `origin/main` is ~198 commits behind
>    `origin/docs/ranking-1-release-line`, which is where the release work lives.
> 3. **The acceptance condition is not sufficient on its own**, for the reason recorded
>    in the superseding runbook's step 7 and expanded there: the drift checker probes an
>    enumerated control set and cannot see a control merged outside `src/security/`.
>
> The claim in the last paragraph that closing this row takes "the release blocking
> count to zero" is also false: `NFR.PKG.1` is a second baseline blocking row, so
> closing this one takes the count from two to one.

`NFR.SEC.7` is the last blocking row on the v4.0.0 line. Its second half — automatic
detection of merged-versus-listening drift — has been MET since 2026-09-11. Its first
half is not a code gap. Every build that has been probed carries the guard:

| Probed | Build | Result |
| --- | --- | --- |
| 2026-09-11 | built from the release tree, `127.0.0.1:39466` | both probes refused 403, legitimate 200, exit 0 |
| 2026-09-13 | release build of `bd1adbb4` (`origin/main`), bench-host loopback | `2 probed, 1 uncovered, 0 failing`, exit 0 |
| 2026-09-17 | **the listening install**, `127.0.0.1:39401` | `2 probed, 1 uncovered, 2 failing` |

The listening install still answers a foreign `Origin` and a foreign `Host` with the
full tool list, twenty-two days after `5d25f104` merged. `git merge-base
--is-ancestor 5d25f104 origin/main` confirms the guard is on `origin/main`, so no
code change and no merge of #561 is required to close this row. What is required is
that the listening process runs a build that has it.

## What is actually deployed

`launchctl` label `com.example.mcp-gateway`, PID 1908, plist at
`~/Library/LaunchAgents/com.example.mcp-gateway.plist`. The plist pins no version; it
execs a wrapper, and the wrapper pins the version in two lines:

```zsh
# /Users/<redacted>/.local/bin/start-mcp-gateway
typeset -r gateway_binary="/Users/<redacted>/.local/libexec/mcp-gateway/3.4.0-f30539af/mcp-gateway"
typeset -r gateway_config="/Users/<redacted>/.local/libexec/mcp-gateway/3.4.0-f30539af/servers.yaml"
```

Those two lines are the whole deployment control point. Note that `~/.local/bin/mcp-gateway`
symlinks to a *different* build (`3.4.0-851cc03f`) and is not what runs; repointing the
symlink would change nothing.

## Why this is not an agent action

The process on `:39401` serves the `mcp__gateway__*` tools — 494 tools across 33
backends — to every live Claude session. Restarting it drops those connections
session-wide. It is also the operator's daily driver. The restart is deliberately left
to the operator and should be run with no sessions open.

## Steps

Steps 1-4 touch nothing live: they create a new versioned directory beside the existing
ones. Steps 5-6 are the operator's.

1. Build a release binary from `origin/main` (carries `5d25f104`; keeps provenance clean
   and independent of PR #561).
2. `mkdir -p ~/.local/libexec/mcp-gateway/4.0.0-<sha>` and copy the binary in.
3. Copy the live `servers.yaml` from `3.4.0-f30539af/` beside it. This config predates
   v4 and carries all 33 backends.
4. **Validate before trusting it.** The binary has both checks:
   - `<new-binary> --config <staged servers.yaml> validate` (`src/main.rs:74`)
   - `<new-binary> upgrade --dry-run` (`src/commands/upgrade.rs:522`) to list migrations
     without applying them.
   A naive copy without this step risks breaking 33 backends on restart.
5. Repoint the two `typeset -r` lines in `~/.local/bin/start-mcp-gateway`.
6. `launchctl kickstart -k gui/$(id -u)/com.example.mcp-gateway`

## Acceptance

```
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
```

must report `0 failing` and exit 0. Check the exit status directly — piping into `tail`
reports the pipe's status, not the checker's. On that result, flip `NFR.SEC.7` to MET in
`docs/requirements/RELEASE-4.0.0-criteria-status.md` and its blocking cell to `no`; the
release blocking count goes to zero.

Rollback is the reverse of step 5 plus another kickstart. The previous versioned
directories are left in place precisely so that stays available.
