# MCP 2026-07-28 protocol revision, behind a default-off switch

## What this is for

Bring the gateway onto the MCP `2026-07-28` revision without moving any existing
deployment onto it. `server.modern_protocol` defaults **off**; with it off the 2025
path is unchanged, fully tested and byte-identical in behaviour. With it on, the
gateway speaks the new revision.

## What is explicitly out

- The `io.modelcontextprotocol/tasks` extension. It is not advertised and not
  implemented to specification; MIK-7311 owns it.
- Multi-replica operation on the modern path. The consumed-continuation ledger and
  the mint counter are process-local; MIK-7312 owns the shared store.

Both are stated in `CHANGELOG.md` and `docs/DEPLOYMENT.md` rather than left for a
deployer to discover.

## Tickets

Closed by this branch when it merges: MIK-7272, MIK-7217, MIK-7215, MIK-7214,
MIK-7213, MIK-7212, MIK-7116, MIK-7256.
Already closed against `v3.5.0`: MIK-7258, MIK-7257, MIK-7243, MIK-7244, MIK-7245.
Filed as fast-follows: MIK-7311, MIK-7312.
Blocked on an observation nobody can make from source: MIK-7265.

## Evidence

- Requirements, test plan, execution plan and the DoD check live under
  `docs/requirements/RELEASE-4.0.0-*.md`.
- The DoD check records what is honestly not finished, with each item owned by a
  filed ticket.
- Every control the review found failing open has been closed and re-verified at
  head; the two are named in the DoD check with their file and line.

## Review

Dual-vendor per the second-opinion gate, at final head, recorded in the ledger.
