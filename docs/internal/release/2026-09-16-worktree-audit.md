<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Worktree audit — 2026-09-16

Read-only audit of every git worktree under `/Users/mikko/github/` except
`.worktrees/v4-codeql-record` (in active use by this session, excluded per
instruction) and the audit itself. All 46 worktrees below share one remote —
`https://github.com/MikkoParkkola/mcp-gateway.git` — none belong to
`claude-elite`.

Method: `git status --porcelain` line count (Dirty), `git log --oneline
origin/main..<ref>` count after `git fetch origin main` (Unpushed), and
`gh pr list --repo MikkoParkkola/mcp-gateway --state all --json
number,state,mergedAt,headRefName --limit 500` matched by `headRefName`
(394 PRs fetched, one call, no rate-limit or errors). Detached-HEAD
worktrees have no branch name, so no PR lookup is possible for them even
when the SHA is otherwise fully merged.

**Item 6 (open files / liveness):** no per-worktree liveness check was run
(the task's own suggested `ls -lLT` proxy doesn't prove it either, and a
repo-wide `lsof` was explicitly out of scope). Recency of dir mtime and last
commit is reported per row as the only available proxy; several worktrees
show very recent mtimes (within the last hour of this audit) and should be
treated as likely-live regardless of git classification. Idleness is never
inferred from age alone per the hard rules.

**Headline finding: 0 of 46 worktrees classify as SAFE TO REMOVE.** Every
one has either uncommitted/untracked files, branch-local commits with no
merged PR, or (one case) a detached HEAD with no branch to check evidence
against. Several also have a merged PR on file but still show local diffs
or extra unpushed commits (squash-merge ancestry, per the hard rule, so
those are held rather than assumed safe).

## Findings

| Path | Branch | Dirty | Unpushed | PR / evidence | Last commit | Dir mtime | Class |
|---|---|---|---|---|---|---|---|
| `mcp-gateway` | `fix/registry-metadata` | 8 | 41 | 8 dirty/untracked path(s) | 2026-09-09T14:46:19 | 2026-09-16T16:09:13 | HOLD — unmerged work |
| `.worktrees/mcp-2026-protocol` | `fix/mrtr2-continuation-handle` | 4 | 157 | 4 dirty/untracked path(s) | 2026-09-10T11:40:37 | 2026-09-10T16:46:42 | HOLD — unmerged work |
| `.worktrees/mcp-gh517` | `fix/gh517-protocol-negotiation` | 20 | 90 | 20 dirty/untracked path(s) | 2026-09-11T12:05:29 | 2026-09-11T14:00:53 | HOLD — unmerged work |
| `.worktrees/mcp-gh517-headcheck` | detached `b5e0914b02f2` | 2 | 80 | 2 dirty/untracked path(s) | 2026-09-11T07:02:03 | 2026-09-11T14:00:54 | HOLD — unmerged work |
| `.worktrees/mcp-merge-int` | detached `f53db1143f24` | 14 | 206 | 14 dirty/untracked path(s) | 2026-09-10T18:48:46 | 2026-09-10T19:33:21 | HOLD — unmerged work |
| `.worktrees/mcp-sub2b-mint` | detached `42f1f7de42d0` | 2 | 84 | 2 dirty/untracked path(s) | 2026-09-11T07:17:37 | 2026-09-11T14:00:55 | HOLD — unmerged work |
| `.worktrees/mcp-v4-account-descriptor-config` | `codex/v4-account-descriptor-config` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-08T06:27:04 | HOLD — unmerged work |
| `.worktrees/mcp-v4-account-foundation-qualification` | `codex/v4-account-foundation-qualification` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-08T03:23:05 | HOLD — unmerged work |
| `.worktrees/mcp-v4-account-gateway-bootstrap` | `codex/v4-account-gateway-bootstrap` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-08T05:43:20 | HOLD — unmerged work |
| `.worktrees/mcp-v4-account-oauth-provider` | `codex/v4-account-oauth-provider` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:43 | 2026-09-09T03:03:29 | HOLD — unmerged work |
| `.worktrees/mcp-v4-account-production-delivery` | `codex/v4-account-production-delivery` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:43 | 2026-09-08T03:46:28 | HOLD — unmerged work |
| `.worktrees/mcp-v4-browser-identity` | `codex/v4-browser-identity` | 1 | 2 | 1 dirty/untracked path(s) | 2026-09-08T20:38:39 | 2026-09-09T03:03:31 | HOLD — unmerged work |
| `.worktrees/mcp-v4-delivery` | `codex/v4-release-delivery` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-09T03:03:33 | HOLD — unmerged work |
| `.worktrees/mcp-v4-openwebui-runtime` | `codex/v4-openwebui-runtime` | 1 | 7 | 1 dirty/untracked path(s) | 2026-09-08T19:44:50 | 2026-09-09T03:03:34 | HOLD — unmerged work |
| `.worktrees/mcp-v4-reap-count` | `codex/v4-reap-count` | 1 | 1 | 1 dirty/untracked path(s) | 2026-09-08T20:28:09 | 2026-09-09T03:03:37 | HOLD — unmerged work |
| `.worktrees/mcp-v4-rest-task-combined` | `codex/v4-rest-task-combined` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-09T03:03:38 | HOLD — unmerged work |
| `.worktrees/mcp-v4-scope-contract` | `codex/v4-scope-contract` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-06T03:00:03 | HOLD — unmerged work |
| `.worktrees/mcp-v4-signing-integration` | `codex/v4-signing-integration` | 0 | 2 | 2 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-09T03:03:38 | HOLD — unmerged work |
| `.worktrees/mcp-v4-stability-integration` | `codex/v4-stability-integration` | 0 | 2 | 2 commits ahead of origin/main; no PR found | 2026-09-09T01:49:42 | 2026-09-07T01:22:21 | HOLD — unmerged work |
| `.worktrees/mcp-v4-stdio-account-wiring` | `codex/v4-stdio-account-wiring` | 1 | 3 | 1 dirty/untracked path(s) | 2026-09-08T17:50:16 | 2026-09-09T03:03:39 | HOLD — unmerged work |
| `.worktrees/mcp-v4-task-clippy-increment` | `codex/v4-task-clippy-increment` | 0 | 3 | 3 commits ahead; PR(s) #508:CLOSED not merged | 2026-09-09T01:49:42 | 2026-09-09T03:03:39 | HOLD — unmerged work |
| `.worktrees/mcp-v4-task-execution-adapter` | `codex/v4-task-execution-adapter` | 1 | 2 | 1 dirty/untracked path(s) | 2026-09-08T09:16:32 | 2026-09-09T03:03:40 | HOLD — unmerged work |
| `.worktrees/mcp-v4-task-service-integration` | `codex/v4-task-service-integration` | 0 | 1 | 1 commits ahead; PR(s) #495:CLOSED not merged | 2026-09-09T01:49:42 | 2026-09-09T03:03:40 | HOLD — unmerged work |
| `.worktrees/mcp-v4-task-signing-composition` | `codex/v4-task-signing-composition` | 0 | 5 | 5 commits ahead; PR(s) #499:OPEN not merged | 2026-09-09T01:49:42 | 2026-09-09T03:03:40 | HOLD — unmerged work |
| `.worktrees/mrtr-bridge-reconcile` | `work/mrtr-bridge-reconcile` | 0 | 64 | 64 commits ahead of origin/main; no PR found | 2026-09-15T07:37:39 | 2026-09-15T08:34:38 | HOLD — unmerged work |
| `.worktrees/sub2b-outbound` | `feat/sub2b-outbound-mint` | 1 | 289 | 1 dirty/untracked path(s) | 2026-09-12T17:03:32 | 2026-09-12T15:39:10 | HOLD — unmerged work |
| `.worktrees/v4-audit-bounded` | `feat/v4-bounded-audit-reads` | 4 | 0 | 4 dirty/untracked path(s) | 2026-09-12T19:56:38 | 2026-09-14T03:24:34 | HOLD — unmerged work |
| `.worktrees/v4-ci-green` | `fix/v4-integration-ci-green` | 3 | 0 | 3 dirty/untracked path(s) | 2026-09-13T14:19:08 | 2026-09-13T14:15:19 | HOLD — unmerged work |
| `.worktrees/v4-conformance` | `feat/v4-conformance-matrix` | 1 | 2 | 1 dirty/untracked path(s) | 2026-09-12T16:41:08 | 2026-09-12T18:25:01 | HOLD — unmerged work |
| `.worktrees/v4-discovery` | `feat/v4-discovery` | 0 | 5 | 5 commits ahead of origin/main; no PR found | 2026-09-12T15:50:36 | 2026-09-16T17:21:31 | HOLD — unmerged work |
| `.worktrees/v4-merge` | `merge/v4-integration-main` | 222 | 0 | 222 dirty/untracked path(s) | 2026-09-12T15:26:41 | 2026-09-12T16:05:29 | HOLD — unmerged work |
| `.worktrees/v4-ranking-fuzzy` | `feat/v4-ranking-fuzzy` | 0 | 3 | 3 commits ahead of origin/main; no PR found | 2026-09-12T16:45:32 | 2026-09-12T16:06:24 | HOLD — unmerged work |
| `.worktrees/v4-reconcile-main` | `chore/v4-reconcile-main` | 1 | 52 | 1 dirty/untracked path(s) | 2026-09-15T06:51:30 | 2026-09-15T13:00:38 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a0266aa2b70162072` | `worktree-agent-a0266aa2b70162072` | 0 | 1 | 1 commits ahead of origin/main; no PR found | 2026-09-14T11:47:53 | 2026-09-14T14:41:51 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a04ce0c0a7a322de4` | `feat/v4-stdio-production-caller` | 0 | 24 | 24 commits ahead of origin/main; no PR found | 2026-09-15T02:19:31 | 2026-09-15T08:09:53 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a35c004d2490365f5` | `control4-lifecycle-local` | 0 | 5 | 5 commits ahead of origin/main; no PR found | 2026-09-12T21:16:12 | 2026-09-12T20:55:35 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a3dd3d0587d226ef7` | `task1-caller` | 1 | 125 | 1 dirty/untracked path(s) | 2026-09-09T15:14:22 | 2026-09-09T17:22:37 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a40d82882bcded359` | `lane/error-budgets` | 0 | 120 | 120 commits ahead of origin/main; no PR found | 2026-09-09T14:50:46 | 2026-09-09T15:32:38 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a5558e53face6d4d0` | detached `cbd224f023f6` | 0 | 138 | 138 commits ahead but detached HEAD (sha cbd224f0), no branch/PR to check | 2026-09-09T20:26:17 | 2026-09-09T17:35:02 | HOLD — cannot prove |
| `mcp-gateway/.claude/worktrees/agent-a789be86c8c8986b6` | `worktree-agent-a789be86c8c8986b6` | 0 | 5 | 5 commits ahead of origin/main; no PR found | 2026-09-14T12:10:43 | 2026-09-14T14:41:54 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-a8d6614e7e57e901d` | `feat/v4-workload-harness` | 0 | 29 | 29 commits ahead of origin/main; no PR found | 2026-09-16T17:40:57 | 2026-09-14T19:49:40 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-aa567effdf9c7d36d` | `work/nfr-workload-1-d` | 0 | 22 | 22 commits ahead of origin/main; no PR found | 2026-09-14T20:04:37 | 2026-09-14T20:32:10 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-ad2d9a22dbbb4861b` | `lane/roots-wiring` | 0 | 120 | 120 commits ahead of origin/main; no PR found | 2026-09-09T15:16:21 | 2026-09-09T15:56:00 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-adc064167cca1f31c` | `work/nfr-workload-1` | 0 | 21 | 21 commits ahead of origin/main; no PR found | 2026-09-14T13:08:18 | 2026-09-14T20:31:37 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-addd0edf8e609b355` | `stdio-keystone-rebase` | 0 | 15 | 15 commits ahead of origin/main; no PR found | 2026-09-14T19:07:55 | 2026-09-14T19:50:19 | HOLD — unmerged work |
| `mcp-gateway/.claude/worktrees/agent-af357ba01f09a457f` | `feat/v4-mrtr-bridge-wiring` | 1 | 6 | 1 dirty/untracked path(s) | 2026-09-12T20:39:29 | 2026-09-12T19:50:34 | HOLD — unmerged work |


## Proposed removals

None. No worktree met all three SAFE TO REMOVE criteria (clean status, zero
unpushed commits, merged/closed PR covering every commit) — see table above.
No `bin/safe-delete-branch` invocations are proposed.

## Class counts

- SAFE TO REMOVE: 0
- HOLD — unmerged work: 45
- HOLD — cannot prove: 1 (`mcp-gateway/.claude/worktrees/agent-a5558e53face6d4d0`, detached HEAD, no branch name for PR lookup)
