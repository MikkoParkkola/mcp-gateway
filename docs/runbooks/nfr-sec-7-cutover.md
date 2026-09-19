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

No macOS build carrying `5d25f104` exists on disk: no `target/` in the main checkout, and
**spark cannot produce one** — spark is `Linux … aarch64`, the install is Mach-O arm64.

| Option | Artifact | Cost |
|---|---|---|
| **A — published asset** | `mcp-gateway-darwin-arm64` from the **v3.5.1** release, `sha256 78fc2fdb5a56539a35b9204e704374303f140ed91f933492f92f49acdece77b1`. `git tag --contains 5d25f104` → `v3.5.0`, `v3.5.1`. | download only |
| **B — release-aligned** | the same asset name from the **v4.0.0** release; `.github/workflows/release.yml` builds it on `macos-latest` for `aarch64-apple-darwin` on tag push or `workflow_dispatch`. | requires the tag |
| **C — local build** | `cargo build --release` on this Mac. | cold build, no `target/`, 8.8 GB free on a 98.1%-full disk |

Option B has a loop in it: NFR.SEC.7 blocks the 4.0.0 release, and the release is what
produces the 4.0.0 darwin artifact. Option A breaks that loop and lands the install on
exactly the version the 3.5.1 → 4.0.0 upgrade was rehearsed from (17/17 PASS,
`docs/release/nfr-upgrade-1-rehearsal-results.md`).

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

## Procedure

```sh
cd ~/github/mcp-gateway                       # any checkout carrying scripts/dev/
OLD=3.4.0-f30539af
NEW=3.5.1                                     # or 4.0.0-<sha> for a self-built binary

# 1. Fetch and verify the artifact (option A; skip for B/C, keep the checksum step)
gh release download v3.5.1 -R MikkoParkkola/mcp-gateway \
  -p mcp-gateway-darwin-arm64 -D /tmp/gw
shasum -a 256 /tmp/gw/mcp-gateway-darwin-arm64
# expect 78fc2fdb5a56539a35b9204e704374303f140ed91f933492f92f49acdece77b1

# 2. Install ALONGSIDE the running build; never write into $OLD
mkdir -p ~/.local/libexec/mcp-gateway/$NEW
cp /tmp/gw/mcp-gateway-darwin-arm64 ~/.local/libexec/mcp-gateway/$NEW/mcp-gateway
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

# 4. Flip the pointer (NOT $EDITOR on the symlink — that rewrites $OLD and destroys rollback)
ln -sfn ~/.local/libexec/mcp-gateway/$NEW/start-mcp-gateway ~/.local/bin/start-mcp-gateway

# 5. Restart under launchd — this interrupts every connected MCP client
launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway

# 6. Watch for a restart loop for ~30s (KeepAlive Crashed + ThrottleInterval 10)
tail -f ~/.claude/logs/mcp-gateway.error.log    # repeating startup banner => roll back

# 7. Grading evidence
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
curl -s http://127.0.0.1:39401/health           # version = $NEW, all_healthy true, count 32
```

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

Valid only because step 2 never writes into the `3.4.0-f30539af` directory. A macOS
signing rejection shows up in step 3 as `Killed: 9`; `codesign -s - <binary>` clears it,
and catching it there costs nobody an interruption.
