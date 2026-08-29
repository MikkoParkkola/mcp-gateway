# 4.0.0 — execution plan to a passing DoD check

Durable checkpoint. Authority for scope: `RFC-0061-protocol-2026-07-28-release-scope.md`
(manifest) and `RELEASE-4.0.0-requirements.md`. Authority for what is already done:
`RELEASE-4.0.0-dod-check.md`. This file records only what REMAINS and in what order,
so the work survives a session boundary.

## State at the time of writing

Branch `feat/mcp-2026-protocol`, 175 commits ahead of `main`, no open PR. The DoD check
records §3, §4, §5 PASS and §8 PASS on tooling. Implementation for the protocol core and
the ride-along items is in the branch. What is left is listed below and nothing else.

## Blocking gaps to a passing DoD check

| # | Gap | Gate | Disposal |
|---|---|---|---|
| 1 | Consumed-continuation ledger is process-local; a second replica spends one continuation twice | §11 stop-the-line, gated BEFORE-PRODUCTION | needs a shared insert-if-absent store, or a recorded single-replica constraint |
| 2 | Mint counter is process-local, so a restart resets the NIST envelope bound | same | same shape as #1 |
| 3 | Task model unverified — the specification page 404s at the indexed path | §12 finding, unverified | re-fetch from another path; if still 404, record as residual with an owner |
| 4 | Failed-task payload shape unverified, same cause | same | same |
| 5 | §12 ran ONE vendor over eight rounds; the gate requires two | §12 BLOCKING | second vendor pass when quota returns (grok and kimi are both rate-limited as of 2026-08-29) |
| 6 | MIK-7256 has a reviewed design and test plan, no tests and no implementation | §P2 onward | next in the pipeline |

## Ticket hygiene the goal requires

- Six tickets are recorded in RFC-0061 as shipped in 3.5.0 and closable without work:
  MIK-7258, MIK-7257, MIK-7243, MIK-7245, MIK-7244, MIK-7265. Each needs the claim
  VERIFIED against 3.5.0 code before it is closed, then closed with the evidence comment.
- Three are re-scoped and must not be implemented: MIK-7251, MIK-7250, MIK-7042.
- In Review in Linear: MIK-7217, MIK-7214, MIK-7213, MIK-7215, MIK-7212, MIK-7116.
  Their Linear state must match the branch: implemented but unmerged, no PR.
- Backlog: MIK-7218, MIK-7219, MIK-7216. MIK-6729 sits Blocked with no recorded blocker.
- No GitHub milestone or open PR exists for 4.0.0.

## Order

1. MIK-7256 through the process: failing tests, implementation, self-QA, review, docs.
2. Verify and close the six no-work tickets.
3. Resolve or record gaps 1–4, each with an owner and a fallback.
4. Second-vendor review pass when quota returns; then the DoD comment on each ticket.
5. Open the PR, land it, then §P5 housekeeping.
