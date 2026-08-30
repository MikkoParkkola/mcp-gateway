# MCP 2026-07-28 protocol revision, behind a default-off switch

## What this is for

Bring the gateway onto the MCP `2026-07-28` revision without moving any existing
deployment onto it. `server.modern_protocol` defaults **off**, and with it off no
client can reach the new revision.

"Unchanged" is narrower than the switch, and the difference is stated rather than
implied. Off, the 2025 request path behaves as it did. The release still changes
behaviour a default-off switch does not gate: the env-file overlay now reaches
credential and attestation readers, the OAuth and firewall changes apply on both
paths, and `server`/`discover` gained surface. Those are described in
`CHANGELOG.md` under their own entries.

## What is explicitly out

- The `io.modelcontextprotocol/tasks` extension. It is not advertised and not
  implemented to specification; MIK-7311 owns it.
- Multi-replica operation on the modern path. The consumed-continuation ledger and
  the mint counter are process-local; MIK-7312 owns the shared store.

Both are stated in `CHANGELOG.md` and `docs/DEPLOYMENT.md` rather than left for a
deployer to discover.

## Tickets

Closed by this branch when it merges: MIK-7272, MIK-7217, MIK-7215, MIK-7214,
MIK-7213, MIK-7212, MIK-7116, MIK-7256, MIK-7320.
Already closed against `v3.5.0`: MIK-7258, MIK-7257, MIK-7243, MIK-7244, MIK-7245.
Filed as fast-follows: MIK-7311, MIK-7312.
Closed by deploying this release, not by merging it: MIK-7265. The guard exists in
source and the installed build predates it; a probe of the running instance on
2026-08-30 returned version `3.4.0` and answered a foreign `Origin` with HTTP 200.

## Evidence

- Requirements, test plan, execution plan and the DoD check live under
  `docs/requirements/RELEASE-4.0.0-*.md`.
- The DoD check records what is honestly not finished, with each item owned by a
  filed ticket.
- Every control the review found failing open has been closed and re-verified at
  head; the two are named in the DoD check with their file and line.

## Review

Two non-Claude vendors returned a verdict on the release material on 2026-08-30:
GPT and Kimi, both `SHIP-WITH-FIXES`, both recorded in their ledgers. Grok exited
with an error on both attempts and produced no verdict, so it is recorded as
unavailable rather than as agreement.

Their findings are addressed in the commits that follow that review, which means
the reviewed head is not the head being merged. The gate is re-run at the final
head before the tag; the DoD check records which verdicts are current.
