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
| 1 | Consumed-continuation ledger is process-local; a second replica spends one continuation twice | §11 stop-the-line, gated BEFORE-PRODUCTION | DEFERRED to 4.1.0 under the single-replica constraint below |
| 2 | Mint counter is process-local, so a restart resets the NIST envelope bound | same | same shape as #1 |
| 3 | Task model unverified — the specification page 404s at the indexed path | §12 finding, unverified | re-fetch from another path; if still 404, record as residual with an owner |
| 4 | Failed-task payload shape unverified, same cause | same | same |
| 5 | §12 ran ONE vendor over eight rounds; the gate requires two | §12 BLOCKING | second vendor pass when quota returns (grok and kimi are both rate-limited as of 2026-08-29) |
| 6 | MIK-7256 has a reviewed design and test plan, no tests and no implementation | §P2 onward | next in the pipeline |

### Gaps 1 and 2 — deferred, and on whose assumption

The DoD check hands the operator two options: ship 4.0.0 as legacy-safe groundwork with the
modern path documented as preview, or hold the tag until these close. This plan proceeds on
the first. **That assumption has not been put to the operator**, and one line overturns it.

It is the cheaper branch and it is reversible: both gaps bind only on multi-replica
deployment, `server.modern_protocol` defaults off, and no client can reach either. Holding
the tag buys nothing that a default-off switch and a written constraint do not already buy.

Deferred, carrying the four fields §P1 requires:

| field | value |
|---|---|
| owner | **MIK-7312**, filed before the tag, not "we" |
| what would resolve it | a shared atomic insert-if-absent store behind both the ledger and the mint counter |
| when | before the first multi-replica deployment of the modern path, whichever release that lands in |
| what if it resolves badly | the modern path stays single-replica; the release notes carry the constraint, and the deployment documentation refuses multi-replica while `modern_protocol` is on |

Nothing in 4.0.0 may depend on either gap being closed. The release notes and the
deployment documentation carry the constraint as shipped text, not as a plan to write it.

## Gates must be re-run at the head that is tagged

The §3, §4 and §5 verdicts in the DoD check are recorded at head `c4f4781a`. Every commit
since then, and MIK-7256's implementation, invalidates them. Clippy, fmt, the secret scan
and the full test suite are re-run at the final head before any of those gates is claimed.
Local `cargo` is halted by the disk guard, so that run goes to Spark via `spark-run`.

## §12 cannot pass today, and the clock is running

The dual-vendor bar is unmet: grok is at its Copilot free-tier limit and kimi returns 429.
The finder-unavailable clock under the repair protocol started at the round-18 launch,
**2026-08-29 19:15 UTC**. Everything except §12 can reach green without them.

## Ticket hygiene the goal requires

- Six tickets are recorded in RFC-0061 as shipped in 3.5.0 and closable without work:
  MIK-7258, MIK-7257, MIK-7243, MIK-7245, MIK-7244, MIK-7265. Each needs the claim
  VERIFIED against 3.5.0 code before it is closed, then closed with the evidence comment.
- Three are re-scoped and must not be implemented: MIK-7251, MIK-7250, MIK-7042.
- In Review in Linear: MIK-7217, MIK-7214, MIK-7213, MIK-7215, MIK-7212, MIK-7116.
  Their Linear state must match the branch: implemented but unmerged, no PR.
- Backlog: MIK-7218, MIK-7219, MIK-7216.
- MIK-6729 is no longer Blocked. Its blocker was recorded all along, in the description
  rather than as a Linear relation: the identity-propagation trait. That trait exists on
  this branch (`src/identity_propagation/mod.rs:160`) and the ticket's own strategy is
  implemented against it, so the block was satisfied and stale. Now In Review.
- No GitHub milestone or open PR exists for 4.0.0.

## Order

1. Verify and close the six no-work tickets; fix the three known-wrong Linear states.
2. MIK-7256 through the process: failing tests, implementation, self-QA, review, docs.
3. Gaps 3 and 4 are resolved as checks and turned into defects: the tasks specification
   was found at `/extensions/tasks/overview`, and the branch is short of it by two
   statuses, two required fields, an error payload shape and a capability check. The
   extension ships not implemented — the capability key is not advertised, so no client
   negotiates it (DoD check, disposition of 3 and 4). Verify in code that nothing offers
   the key, and say so in the release notes. Tasks conformance is owned by MIK-7311 and the
   two multi-replica gaps by MIK-7312, both filed. Put the single-replica constraint into
   shipped text.
4. Re-run §3, §4 and §5 on Spark at the final head.
5. Second-vendor review pass when quota returns; then the DoD comment on each ticket.
6. Open the PR, land it, then §P5 housekeeping.
