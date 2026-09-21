<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->
<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->

# NFR.SEC.7 cutover preparation, 2026-09-21

Steps 1c-4 of `docs/runbooks/nfr-sec-7-cutover.md` are complete. Steps 5-7 restart
`com.claude.mcp-gateway` under `launchd` and interrupt every connected MCP client;
the runbook reserves them for the operator and this record does not take them.

## Artefact

| Field | Value |
|---|---|
| Source commit | `e82d7ee4` (`origin/main`) |
| Recipe | `cargo build --release --target aarch64-apple-darwin` (option C) |
| Binary | Mach-O 64-bit executable arm64, `mcp-gateway 4.0.0` |
| sha256 | `07e5bb068d0568a4c1c769b8647255e9439c963c37a309ffdd3ee8d33521b54c` |
| Installed at | `~/.local/libexec/mcp-gateway/4.0.0-e82d7ee4/` |

There is no published digest to compare against: `v4.0.0` is not a tag in this
repository, so provenance is unavailable by construction rather than missing.

## Step 1c - guard compiled in

The refusal string from `src/gateway/router/origin_guard.rs:398` is present in the
binary.

## Step 3 - smoke through the launcher, spare port 39412, throwaway data directory

`scripts/dev/check-control-drift.py` exits 0:

```
18 authority rows, 17 security modules, 33 manifest controls, 0 coverage gaps
origin-guard: refused 403; legitimate request 200
host-guard:   refused 403; legitimate request 200
json-well-formedness: refused 400; legitimate request 200
jsonrpc-envelope-shape: refused 400; legitimate request 200
input-sanitization: refused 400; legitimate request 200
5 probed, 28 uncovered, 0 failing
```

That block is an **excerpt**: the checker prints one line per manifest control, so the
full transcript is 35 lines. The 28 omitted lines are the `uncovered` controls, each
carrying its recorded reason.

`/health` answered `{"status":"healthy","version":"4.0.0","backends":{"all_healthy":true,"count":32}}`,
so the 3.4.0 `servers.yaml` parses unchanged under 4.0.0 and the gateway registered all
32 backends. That is the limit of the claim: `all_healthy` is an aggregate of request
outcomes, not a liveness probe of each backend, so it cannot distinguish a backend that
is serving from one that has simply not been asked yet. Backend health under the **real**
data directory is unobserved either way — this smoke ran against a throwaway one.

The guard fires on the wire. This is the symptom the criterion names: the live
3.4.0 install answers a `POST /mcp` carrying `Origin: http://drift-check.invalid`
with 200 and the full tool list, and the 4.0.0 build refuses it 403 while still
answering the legitimate request 200.

## Step 4 - rollback rehearsed, then left at the old build

The launcher symlink was flipped to `4.0.0-e82d7ee4` and back to `3.4.0-f30539af`,
proving the flip command works before it is needed. That is the limit of the rehearsal:
no `launchd` exec of either build was performed, so the restart half of rollback is
first exercised at step 5. The exposure is small because 3.4.0 is the build currently
running, but it is not zero and it is not rehearsed. It is deliberately left
pointing at `3.4.0-f30539af`: `launchd` reads the symlink at exec time, so leaving
it at the new build would make any unattended restart an unwatched cutover.

## What remains

The criterion stays PARTIAL. Closing it needs steps 5-7 against the live install on
`127.0.0.1:39401`, graded on exit 0, a `0 failing` tally, both guards reading
`refused 403; legitimate request 200`, and no control regressing from probed to
uncovered. The smoke proves the binary runs on this machine, that the config parses, and
that the guard refuses on the wire; it does not prove backend health under the real data
directory, which only step 7 observes.
