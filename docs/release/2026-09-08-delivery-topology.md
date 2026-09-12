# v4.0.0 delivery topology — what actually blocks the release

**Measured 2026-09-08.** Every number below came from `gh` or `git` in this session; the
commands are inline so a reader can re-run them rather than trust the prose.

## The finding

The v4.0.0 release is not blocked on code. It is blocked on **delivery chain steps 2 and 4**
(`quality-gates-dod.md` DELIVERY CHAIN): one line of work has no pull request at all, and
**not one of the thirteen open pull requests carries an approving review**.

```
gh pr list --repo MikkoParkkola/mcp-gateway --state open \
  --json number,headRefName,reviewDecision,mergeStateStatus --limit 20
```

13 open PRs, `reviewDecision` is `""` on all 13.

## Two independent delivery problems

### 1. The stack — eleven PRs behind one unreviewed keystone

Only #473 and #490 target `main`. The other eleven are stacked, and every one of them is
rooted at #473. Base refs, verbatim from `gh pr list --json number,baseRefName`:

```
main
├── #490  dependabot/trufflehog                        CLEAN
└── #473  fix/mrtr2-continuation-handle                UNSTABLE   <-- keystone
    ├── #499  codex/v4-task-signing-composition        DIRTY (conflict)
    ├── #500  codex/v4-account-task-integration        UNSTABLE
    │   ├── #501  codex/v4-rest-cache-delivery         CLEAN
    │   │   ├── #504  codex/v4-stdio-account-wiring    CLEAN
    │   │   └── #507  codex/v4-openwebui-adapter       CLEAN
    │   ├── #502  codex/v4-task-ci-cleanup             CLEAN
    │   └── #503  codex/v4-firewall-error-projection   CLEAN
    └── #505  codex/v4-protocol-account-reconciliation UNSTABLE
        ├── #506  codex/v4-meta-firewall-verdict       CLEAN
        ├── #508  codex/v4-task-clippy-increment       CLEAN
        └── #509  codex/v4-stacked-pr-ci               UNSTABLE
```

**Nothing in this stack can reach `main` until #473 merges.** #473's own gap is narrow and
was measured separately today: all seven required status checks pass, `strict` is false,
`required_pull_request_reviews` is null, and the branch ruleset list is empty — so
`mergeStateStatus: UNSTABLE` reflects a non-required check (CodeQL), not a blocking one.
The single unmet requirement is DELIVERY CHAIN step 4: its three bot reviews
(`copilot-pull-request-reviewer`, `github-advanced-security` twice) are all `COMMENTED`,
never `APPROVED`, so `reviewDecision` is empty.

`#499` is additionally `DIRTY` — a real merge conflict against its base, which will have to
be resolved whatever happens to the keystone.

### 2. `codex/v4-release-delivery` is an ancestor of the stack, not a second line

An earlier draft of this document treated this branch as a separate delivery line carrying
80,312 unmerged lines with no pull request, and recommended an operator decision about what
to do with it. **That was wrong**, and the check that disproves it is one command:

```
for b in fix/mrtr2-continuation-handle codex/v4-protocol-account-reconciliation \
         codex/v4-account-task-integration codex/v4-stacked-pr-ci; do
  git rev-list --count origin/$b..origin/codex/v4-release-delivery   # 0 for every branch
  git rev-list --count origin/codex/v4-release-delivery..origin/$b   # 246 / 431 / 298 / 432
done
git merge-base --is-ancestor origin/codex/v4-release-delivery \
                             origin/fix/mrtr2-continuation-handle   # true
```

Zero commits on `release-delivery` are absent from any stack branch. It is an **ancestor**
of all of them — an older tag on the same line of work, already superseded. The stack is not
a competing effort; the stack *is* this work, split and pushed further. Nothing needs to be
decided about the branch, and its 1447-commit divergence from `main` is simply the same
divergence the stack has, measured from an earlier point on it.

**Consequence: the three HIGH code-scanning repairs are already in the keystone PR.**

```
git show origin/fix/mrtr2-continuation-handle:src/config/mod.rs | rg -c reject_cleartext_credentials   # 3
git show origin/fix/mrtr2-continuation-handle:src/transport/http/mod.rs | rg -c require_secure_oauth_target  # 3
git show origin/fix/mrtr2-continuation-handle:src/capability/executor/mod.rs | rg -c redact_url        # 3
```

| alert | rule | repair | in #473 | on `main` |
|---|---|---|---|---|
| #90, #91 | `rust/cleartext-transmission` | `reject_cleartext_credentials`, `require_secure_oauth_target` | yes | no |
| #78 | `rust/cleartext-logging` | `redact_url` | yes | no |

The three alerts are open because #473 has not merged. They are not a backlog item, not a
dismissal decision, and not separate work. **Merging #473 is what closes them.**

`CHANGELOG.md:64` states the 2026-09-04 entry closed #90 and #91. Measured against `main`
that is false, and measured against the branch it is unverifiable until CodeQL analyses the
branch. That wording is being corrected in the change that owns it.

#### Size of the keystone

`#473` is 246 commits ahead of `release-delivery` and carries the bulk of v4.0.0. Against
`main` the whole line is 281 files and +80,312 / -1,502 lines, split by area:

| area | files | added | removed |
|---|---:|---:|---:|
| `src/` | 106 | 21,128 | 1,161 |
| `tests/` | 49 | 18,363 | 208 |
| `docs/` | 105 | 37,716 | 79 |
| other | 21 | 3,105 | 54 |

`git cherry origin/main origin/codex/v4-release-delivery` reports 1439 of 1447 commits as
`+` — no equivalent patch on `main` — and the history runs back to 2026-08-29.

That 1439 is an UPPER bound on unlanded work, not a count of it. `git cherry` compares
patch identities, and this repository squash-merges: a squashed commit on `main` has a
different patch id from each of the commits it absorbed, so every constituent commit of an
already-landed PR still reports `+`. The authoritative size measure is the tree diff above
(281 files, +80,312/-1,502), which compares content rather than patches.

## What this changes about the plan

Prior reading was that the release was gated on code gaps in the criteria ledger. The
ledger gaps are real, but they are downstream: even a fully green ledger cannot ship while
step 4 is unmet on every open PR and one delivery line has no PR at all.

Order that follows from the topology, not from preference:

1. **Approve or reject #473.** Eleven PRs sit behind it (twelve counting #473 itself) *and*
   all three open HIGH code-scanning alerts are closed only by the repairs on its branch.
   Every required status check on it passes; the only unmet requirement is an approving
   review. This is the shortest integration path, not a hard ordering constraint: a base
   branch can be retargeted, so a child could in principle be rebased onto `main` and
   reviewed independently. Nothing else closes those three alerts.
2. **Resolve #499's conflict** — independent of the keystone, and it will only get worse.
3. **Then the criteria ledger**, which is where the remaining scoped work lives.

Step 1 is an operator decision. Steps 2 and 3 are engineering and are already assigned to
lanes. `codex/v4-release-delivery` needs no decision: it is an ancestor of the stack.

## Honest limits

- Every count here was measured on 2026-09-08 against `origin` as fetched that morning
  (`main` at `28223230`, `codex/v4-release-delivery` at `0d4df3c0`). The PR set is live: it
  read 13 open when the topology was built and 14 an hour later. Re-run the commands rather
  than trusting the totals; the immutable SHAs are what make that re-run comparable.
- `mergeStateStatus` was read once, at one moment; CI on these branches is live and the
  `UNSTABLE`/`CLEAN` column will drift. The base-ref topology will not.
- The area split counts lines, which measures bulk and not risk: a generated fixture and a
  router change weigh the same in that table. It bounds the review job; it does not rank it.
- No claim here about whether the stacked PRs are individually correct. This document is
  about whether they can reach `main`, not whether they should. In particular, "one approval
  unblocks eleven PRs" is a statement about topology, not a suggestion that one review is
  sufficient scrutiny for 21,128 lines of `src/`.
- The first draft of this document asserted `codex/v4-release-delivery` was a separate
  unreviewed line needing an operator decision. It is an ancestor of the stack. The error
  came from measuring divergence against `main` only and never against the sibling branches;
  the correction is section 2 above. Recorded because the failure mode — a document asserting
  a state the source contradicts — is the one this release audit exists to catch.
