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
- Retry forwarding for multi-round-trip tool requests. A well-formed retry envelope is
  accepted and then refused with `-32602`; MIK-7325 owns the forwarding path.
- Coverage and mutation measurement. Neither was run for this branch, so §4 of the DoD
  check stands BLOCKED rather than passing; MIK-7324 owns both figures.

The first three are stated in `CHANGELOG.md` rather than left for a deployer to
discover, and the multi-replica limit again in `docs/DEPLOYMENT.md`, which is where a
deployer looks for it. The fourth is a gap in this release's own record rather than
anything a deployer acts on, so it is stated here and in the DoD check, not in the
changelog.

## Tickets

Closed by this branch when it merges: MIK-7272, MIK-7217, MIK-7215, MIK-7214,
MIK-7213, MIK-7212, MIK-7116, MIK-7256, MIK-7320.
Already closed against `v3.5.0`: MIK-7258, MIK-7257, MIK-7243, MIK-7244, MIK-7245.
Filed as fast-follows: MIK-7311, MIK-7312, MIK-7324, MIK-7325.
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

The review record is kept in one place, `§12` of the DoD check, and this section
summarises it rather than restating it. Rounds 1 to 8 ran against a single vendor
(`codex`/GPT) as a recorded deviation. Rounds 9 to 17 added Grok. The release
material was then reviewed twice on 2026-08-30 by two vendors each time:

| round | head | GPT | Kimi | Grok |
|---|---|---|---|---|
| release material | `e6e2ddd9` | SHIP-WITH-FIXES | SHIP-WITH-FIXES | error, no verdict |
| repair commit | `edfd020a` | SHIP-WITH-FIXES | SHIP-WITH-FIXES | unavailable, monthly quota |

Grok is recorded as unavailable rather than as agreement. Both rounds returned
`SHIP-WITH-FIXES`, and `SHIP-WITH-FIXES` is not an authorisation: the fixes from
the second round are applied in the commit above this line, which means the head
being merged is again one commit past the last reviewed head. That is stated here
rather than rounded up.
