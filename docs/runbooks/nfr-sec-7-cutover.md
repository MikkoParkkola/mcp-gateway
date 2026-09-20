<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.SEC.7 cutover — replace the listening install

The criterion's first half is a deployment, not a code change. The install answering on
`127.0.0.1:39401` is `3.4.0`, predates `5d25f104`, and still answers a foreign `Origin`
and a foreign `Host` with the full tool list. This is the operator's step; an agent
prepares it and does not take it. The row stays PARTIAL until the step-7 run exits 0 —
this runbook existing closes nothing.

## What is listening (verified 2026-09-19)

| Fact | Value |
|---|---|
| Endpoint | `127.0.0.1:39401`, PID 1908, up since 2026-09-16 |
| Binary | `~/.local/libexec/mcp-gateway/3.4.0-f30539af/mcp-gateway`, Mach-O arm64 |
| Reported version | `/health` → `{"status":"healthy","version":"3.4.0","backends":{"all_healthy":true,"count":32}}` |
| Symptom | `POST /mcp` with `Origin: http://drift-check.invalid` → **200** with the tool list |
| Supervised by | `launchd`, `~/Library/LaunchAgents/com.claude.mcp-gateway.plist` |
| Launcher | `~/.local/bin/start-mcp-gateway` → **symlink** into the version directory; the script hardcodes binary and config on lines 4–5 |
| Data directory | `~/.mcp-gateway/`, `version.stamp` already `4.0.0` |

Not a migration. Both entries in `MIGRATIONS` (`src/commands/upgrade.rs:102`) are
`notice: true`, config unchanged, and the stamp is already at the 4.0.0 ceiling. This is
a binary swap plus a symlink flip.

## The artifact

No macOS build carrying `5d25f104` exists on disk. Swept 2026-09-19 across every
mcp-gateway checkout and worktree: three `target/` trees exist, two of them debug builds
in other agents' worktrees and one with no binary at all, and **no `release/` binary
anywhere**. Spark cannot produce one either — spark is `Linux … aarch64`, the install is
Mach-O arm64.

| Option | Artifact | Cost |
|---|---|---|
| **A — published asset** | `mcp-gateway-darwin-arm64` from the **v3.5.1** release, `sha256 78fc2fdb5a56539a35b9204e704374303f140ed91f933492f92f49acdece77b1`. `git tag --contains 5d25f104` → `v3.5.0`, `v3.5.1`. | download only |
| **B — the 4.0.0 release itself** | the same asset name from a **v4.0.0** release. Not a build step — see below. | is the release, and currently unreachable |
| **C — local build** | `cargo build --release --target aarch64-apple-darwin` on this Mac, matching the recipe in `release.yml`. | cold build of 431 crates; **5.9 GB free 2026-09-19 and falling**, against a 5 GB floor a hook enforces on every build command |

No candidate is staged waiting to be selected: the three versioned directories report
`3.3.2`, `3.4.0`, `3.4.0` to `--version`, and none of the three binaries contains the
host-guard refusal string. Every route starts with fetching or building something.

**Option C has a precondition that is not met today.** No `target/` directory exists in
any mcp-gateway checkout or worktree on this Mac, so the build is cold: 431 crates from
`Cargo.lock`, and the only two build trees on the machine — both debug, both belonging to
other agents' worktrees — are 5.4 GB and 8.2 GB. Free space was 6.6 GB at 14:0x and
5.9 GB minutes later while those builds ran. A hook refuses every build command below
5 GB, so the build would be cut off part-way and leave a partial tree behind. Route C
becomes cheap the moment those two debug trees (13.6 GB between them) are released by
their owners; it is not a disk question the runbook can settle by itself.

Option B has a loop in it, and the loop is closed at both ends. `release.yml` has no
build-only entry point: `workflow_dispatch` takes a **required `tag`**, and `release`,
`publish`, `npm-publish` and `homebrew-update` all hang off `needs: [release, verify]`
with no `if:` restricting them to a tag push. Dispatching it is not a way to obtain a
binary; it is the 4.0.0 release to GitHub, crates.io, npm and Homebrew.

The artifact would not arrive even so. `build` needs `verify`, `verify` needs
`release-criteria`, and that job's last step is
`check_scope_acceptance.py --publish-check`, which in a publishing context with a 4.0.0
tag exits 1 while any criterion is pending or blocking. Reproduced 2026-09-19:

```
$ GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main INPUT_TAG=v4.0.0 \
    python3 scripts/release/check_scope_acceptance.py --publish-check ; echo $?
Release acceptance incomplete:
  MIK-7334.CATALOGUE.1
  ...
1
```

So the open criterion gates the job that would build the artifact that would close the
criterion. **No other workflow can substitute.** `ci.yml`, `docker.yml`,
`task-sdk-recovery.yml` and `dependabot-auto-merge.yml` run only `ubuntu-*` and
`windows-2025` runners, and `actions/upload-artifact` appears exactly once in the
repository — in `release.yml`'s `build` job. There is no non-publishing macOS artifact
job to borrow.

Option A breaks the loop and lands the install on exactly the version the 3.5.1 → 4.0.0
upgrade was rehearsed from (17/17 PASS, `docs/release/nfr-upgrade-1-rehearsal-results.md`).

**What option A does not close.** The manifest's three controls all come from
`5d25f104`, so a v3.5.1 install makes the checker exit 0 — but
`git log v3.5.1..origin/main -- src/security/ src/gateway/router/` is **113 commits**,
among them `782e5ac8` (refuse an unserved protocol-version header) and `992b87c3`
(request-scoped notification and outbound refusal gaps). Those are refusal behaviours the
manifest does not probe. Option A therefore satisfies the instrument, not the criterion's
wording — "every merged security control" is only true of a build from `main`. Treat A as
a stopgap that shrinks the gap from "predates the guard entirely" to "behind on the
security path", and B as the close. Which to deploy is the operator's call; the procedure
below is identical either way.

## No guarded build has ever run in this environment

The row says a build carrying the guard "has been probed twice". Both probes are real and
both exit 0 — and neither touched this machine's install. Checked at source, because a
status row is not evidence about what ran:

| Probe | What it actually was | Evidence |
|---|---|---|
| 2026-09-13, port 39411 | a release binary of `bd1adbb4` **on spark** — a Linux aarch64 host — left over from the performance benchmark run, started on a free loopback port in the spark worktree | `docs/internal/release/verify/sec7-drift-probe-2026-09-13.md`; `docs/internal/release/v4.0.0-burndown-tracker.md:190-202` |
| 2026-09-11, port 39466 | "a gateway built from the release tree", machine unstated | **no preserved transcript.** `docs/release/verify/` holds no 2026-09-11 file, the commit that landed the checker (`9a3d9cbe`) records no run, and the design doc records none. Ledger prose only |

So: no artifact has ever been installed into `~/.local/libexec/mcp-gateway/<version>/`,
started by `start-mcp-gateway`, given the real `servers.yaml` and secrets, pointed at the
real `~/.mcp-gateway/`, or supervised by `launchd`. **The cutover is simultaneously the
first deployment test of the new build in the operator's environment.** That is true of
option A as well — the install directories are `3.3.2`, `3.4.0`, `3.4.0`, so v3.5.1 has
never run here either.

Two consequences, both built into the procedure below: the smoke in step 3 runs through
the real launcher so that credentials, config parsing and the guard are exercised before
any interruption, and the rollback is rehearsed in step 4 rather than assumed.

## Procedure

```sh
cd ~/github/mcp-gateway                       # any checkout carrying scripts/dev/
OLD=3.4.0-f30539af
NEW=3.5.1                                     # or 4.0.0-<sha> for a self-built binary

# 1a. Option A — fetch the published asset
gh release download v3.5.1 -R MikkoParkkola/mcp-gateway \
  -p mcp-gateway-darwin-arm64 -D /tmp/gw
shasum -a 256 /tmp/gw/mcp-gateway-darwin-arm64
# expect 78fc2fdb5a56539a35b9204e704374303f140ed91f933492f92f49acdece77b1
GW=/tmp/gw/mcp-gateway-darwin-arm64

# 1b. Option C — build from origin/main instead, in a checkout at that commit.
#     Same recipe release.yml uses for the darwin-arm64 asset. Needs headroom:
#     cold, 431 crates, and a hook refuses to build under 5 GB free.
# cargo build --release --target aarch64-apple-darwin
# GW=target/aarch64-apple-darwin/release/mcp-gateway
# shasum -a 256 "$GW"    # record the digest here; there is no published one to compare against

# 1c. Either way, prove the guard is compiled in before installing anything
rg -a -q 'Request blocked: Host does not name this gateway' "$GW" \
  && echo "guard compiled in"   # the refusal string from src/gateway/router/origin_guard.rs:398

# 2. Install ALONGSIDE the running build; never write into $OLD
mkdir -p ~/.local/libexec/mcp-gateway/$NEW
cp "$GW" ~/.local/libexec/mcp-gateway/$NEW/mcp-gateway
chmod +x ~/.local/libexec/mcp-gateway/$NEW/mcp-gateway
cp ~/.local/libexec/mcp-gateway/$OLD/servers.yaml ~/.local/libexec/mcp-gateway/$NEW/
sed "s|$OLD|$NEW|g" ~/.local/libexec/mcp-gateway/$OLD/start-mcp-gateway \
  > ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway
chmod 700 ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway

# 3. Smoke it on a spare port, through the launcher, with its own data dir
MCP_GATEWAY_CONFIG_DIR=$(mktemp -d) MCP_GATEWAY_PORT=39412 \
  ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway & SMOKE=$!
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39412/mcp   # must exit 0
kill $SMOKE

# 4. Rehearse the rollback, then flip. launchd reads the symlink only at exec time,
#    so flipping it while the service runs changes nothing until step 5 — rehearse freely.
#    NOT $EDITOR on the symlink: that rewrites $OLD and destroys the rollback target.
ln -sfn ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway ~/.local/bin/start-mcp-gateway
ln -sfn ~/.local/libexec/mcp-gateway/$OLD/start-mcp-gateway ~/.local/bin/start-mcp-gateway
readlink ~/.local/bin/start-mcp-gateway   # must name $OLD: the rollback command works
ln -sfn ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway ~/.local/bin/start-mcp-gateway

# 5. Restart under launchd — this interrupts every connected MCP client
launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway

# 6. Watch for a restart loop for ~30s (KeepAlive Crashed + ThrottleInterval 10)
tail -f ~/.claude/logs/mcp-gateway.error.log    # repeating startup banner => roll back

# 7. Grading evidence, then the three things the drift check cannot see
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
xh -b --ignore-stdin :39401/health              # version = $NEW, all_healthy true, count 32
xh -b --ignore-stdin POST :39401/mcp Accept:'application/json, text/event-stream' \
  jsonrpc=2.0 id:=1 method=tools/list params:='{}'   # baseline 2026-09-19: 2 tools,
                                                     # gateway_search and gateway_execute
```

Baselines to compare against, taken from the live install 2026-09-19: `/health` →
`{"status":"healthy","version":"3.4.0","backends":{"all_healthy":true,"count":32}}`, and
`tools/list` → exactly `gateway_search`, `gateway_execute`. The tool surface is the
client-visible contract every connected session depends on; a 4.0 build may expose a
different meta-tool surface than 3.4.0, and that shows up here and nowhere in the drift
check.

Optionally repoint the stale sibling symlink `~/.local/bin/mcp-gateway` (still
`3.4.0-851cc03f`) so a bare CLI `--version` stops disagreeing with what is serving.

Step 3 goes through the launcher because the launcher is what `launchd` runs: it sources
`~/.secrets.env` and `~/.claude/secrets.env` first, so a bare binary invocation starts
every backend credential-less and its failures mean nothing. What the smoke proves is
that the binary runs on this machine, that the 3.4.0 config still parses, and that the
guard fires on the wire. What it does not prove is backend health under the real data
directory — step 7 covers that.

## Pass output

Step 7 must print exactly four lines, in manifest order, and exit 0:

```
origin-guard: refused 403; legitimate request 200 [<provenance>]
host-guard: refused 403; legitimate request 200 [<provenance>]
unsafe-code-denied: uncovered -- a compile-time lint leaves no signal on the wire; drift is caught by the build, not by a request
2 probed, 1 uncovered, 0 failing
```

- `<provenance>` is `provenance: 5d25f104 is in v3.5.1` for option A, and
  `provenance unavailable: v4.0.0 is not a tag in this repository` for a pre-tag 4.0.0
  build. It is corroboration; it does not change the exit code.
- Any 4xx satisfies the negative half; a `2xx`/`3xx` or a `5xx` fails it. No `--header`
  is needed — `tools/list` answers unauthenticated on this install.
- `/health` is the check the drift checker cannot make: its positive half answers 200
  even if only a handful of the 32 backends came up.

## Rollback

```sh
ln -sfn ~/.local/libexec/mcp-gateway/3.4.0-f30539af/start-mcp-gateway ~/.local/bin/start-mcp-gateway
launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway
```

Valid only because step 2 never writes into the `3.4.0-f30539af` directory, and the first
line is the exact command already rehearsed in step 4 — the untested part of a rollback is
the kickstart, not the flip. A macOS signing rejection shows up in step 3 as `Killed: 9`;
`codesign -s - <binary>` clears it, and catching it there costs nobody an interruption.
