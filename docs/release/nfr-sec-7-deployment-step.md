# NFR.SEC.7 — the one step left, and why an agent does not take it

`NFR.SEC.7` is the sole blocking row in the core ledger. Its second half — automatic
detection of merged-versus-listening drift — is MET: `scripts/dev/check-control-drift.py`
probes a listening endpoint two ways per control (the request the control exists to refuse
must be refused, *and* a legitimate request on the same path must succeed), and CI runs the
probe rows against stub servers so a probe that has stopped discriminating fails loudly.

The first half is a deployment, not a code change. The listening install still answers a
foreign `Origin` and a foreign `Host` with the full tool list because it predates the guard.

## What is actually listening

| Fact | Value |
|---|---|
| Endpoint | `127.0.0.1:39401` |
| Binary | `~/.local/libexec/mcp-gateway/3.4.0-f30539af/mcp-gateway` |
| Running since | 2026-08-29 |
| Supervised by | `launchd`, `~/Library/LaunchAgents/com.claude.mcp-gateway.plist` |
| Launcher | `~/.local/bin/start-mcp-gateway`, which hardcodes the `3.4.0-f30539af` binary and config paths on lines 4 and 5 |

`5d25f104`, the commit carrying the guard, is not in `v3.4.0`. The drift checker already
reports this install as FAIL with that provenance note, which is the check working, not the
check being wrong.

## Why this is the operator's step

This process is the daily-driver gateway: it serves the live tool surface that connected MCP
clients route through. Replacing its binary and restarting it under `launchd` interrupts every
client bound to it. That is an outward-facing change to shared state, so it needs the
operator's decision on *when*, not a release agent's judgement that the criterion would look
better closed.

## The recipe

Nothing here is discovery work — each step is mechanical and reversible, and the old
versioned directory stays in place as the rollback.

```sh
# 1. Build the shipping line
cd ~/github/.worktrees/v4-chore-tip
cargo build --release

# 2. Install alongside, never over, the running build
V=4.0.0-$(git rev-parse --short HEAD)
mkdir -p ~/.local/libexec/mcp-gateway/$V
cp target/release/mcp-gateway ~/.local/libexec/mcp-gateway/$V/
cp ~/.local/libexec/mcp-gateway/3.4.0-f30539af/servers.yaml ~/.local/libexec/mcp-gateway/$V/

# 3. Point the launcher at it (lines 4 and 5 of the script)
$EDITOR ~/.local/bin/start-mcp-gateway

# 4. Restart under launchd
launchctl kickstart -k gui/$(id -u)/com.claude.mcp-gateway

# 5. The criterion closes only if this exits 0
python3 scripts/dev/check-control-drift.py http://127.0.0.1:39401/mcp
```

Step 5 is the grading evidence. A passing run is what moves the row from PARTIAL to MET;
until then the row stays blocking and honest. Rollback is step 3 in reverse plus step 4.

Upgrading from a 3.x data directory is separately rehearsed — see
`docs/release/nfr-upgrade-1-rehearsal-results.md`, which drives config, credentials,
permissions, mounts and an active caller through upgrade, modern-off and rollback at 17/17
PASS. That rehearsal is what makes step 4 a restart rather than a migration.
