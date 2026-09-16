# PR #561 review findings — blocks the merge to main

Reviewed 2026-09-16 against `3fa31ccd` (branch `work/v4-audit-adjudication`
after merging `origin/main`). Scope declared to the reviewers: the production
code and tests in the PR, excluding its documentation.

Reviewers: gpt (`~/.claude/data/reviews/runs/gpt-20260916T122058Z-21802.md`,
VERDICT SHIP-WITH-FIXES) and kimi
(`~/.claude/data/reviews/runs/synthetic-20260916T122133Z-25999.md`,
VERDICT SHIP-WITH-FIXES). grok and glm were unavailable: grok 1.0.30 refuses to
start because its sandbox cannot resolve the symlinked `/var/run/docker.sock`,
and the glm endpoint answers 404 for its configured model.

## Confirmed at source

**1. The bridge delivers backend-authored prompts without the firewall gate.**
`enforce_firewall_challenge` is defined at
`src/gateway/meta_mcp/response_security.rs:176` and has **no production caller**:
every other occurrence in `src/` is in `response_challenge_tests.rs` or
`response_security_tests.rs`. The bridge construction site at
`src/gateway/meta_mcp/invoke.rs:2126` forwards the backend's elicitation,
sampling and roots requests to the client untouched. A backend can therefore put
text in front of a person that the configured firewall exists to refuse.
Severity HIGH, and it gates the merge rather than the deploy, because the
gateway's purpose is to stand between a client and untrusted backends.

**2. The stdio carve-out recorded in the criteria ledger is stale.**
`MIK-7212.MRTR.7a` and `.7b` in `docs/requirements/RELEASE-4.0.0-criteria-status.md`
both state that stdio is descoped to MIK-7387 and that
`tests/mik_7212_mrtr7_stdio_acs.rs` carries three `#[ignore]` attributes.
`rg -n 'ignore' tests/mik_7212_mrtr7_stdio_acs.rs` returns nothing, and the
concurrent-dispatch machinery is present in `src/gateway/server/mod.rs` and
`src/gateway/server/stdio_channel.rs`. Both reviewers raised this independently.
The code is not the defect; the ledger text is. The rows must either claim
MIK-7387 or the package must leave this PR.

## Reported, not yet verified

- Closing stdout ends the writer while the read loop keeps admitting calls, so
  backend side effects run with no receipt for the client
  (`src/gateway/server/mod.rs:2395`, HIGH/POSSIBLE).
- Waiting on the 65th dispatch permit blocks the only stdin reader, so replies
  to the first 64 bridged calls cannot be routed (MEDIUM).
- Any object carrying an `id` and no `method` is taken as a reply even with
  neither `result` nor `error` (LOW).

## State of the change itself

`cargo test --test mik_7212_mrtr7_bridge_acs` = 28 passed, 0 failed (2026-09-16).
CI on the PR head: 44 passed, 4 skipped, 1 pending, 0 failed. The merge of
`origin/main` into the branch was clean. Nothing here is a regression the merge
introduced; findings 1 and 3-5 describe the bridge as it has always been on this
branch.
