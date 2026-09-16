# Branch maintenance, 2026-09-13

`origin` carried 88 branches. It now carries 67. Twenty-one were deleted and
every one was proved lossless before deletion, not inferred from age, name or
inactivity.

## What the count was

The repository also holds 370 `pr/*` fetch refs. They are not branches and were
never part of the 88; any count that includes them (`git branch -r` unfiltered
returns 458) is measuring the wrong thing.

## The two tests

A branch was deleted only when one of these returned a provable zero.

1. **Merged-PR accounting.** Union the commit lists of *every* MERGED pull
   request for that head, then require every commit reachable from the branch
   and from no other remote ref to appear in that union. This is the test
   `bin/safe-delete-branch` implements; it exists because this repository
   squash-merges, so `git branch --merged`, `merge-base --is-ancestor` and
   `rev-list --not --remotes` all misreport a squash.
2. **Containment in the release line.** `git rev-list --count origin/<b>
   ^chore/v4-reconcile-main` returns 0 — every commit is already in the line
   v4.0.0 ships from, so deleting the handle loses no history.

Test 2 is the reason a *closed* pull request does not settle the question: seven
branches whose PR was closed unmerged had nevertheless landed their commits in
the release line by another route, and seven others with no pull request at all
were likewise fully contained.

Base for every containment check is `chore/v4-reconcile-main`, never
`origin/main` — main sits 2124 commits behind the v4 line, so `main` itself is
"fully contained" and a comparison against it would mark almost everything
deletable.

## Guards that fired

- `gh pr view --json commits` returns only the oldest 100 commits.
  `fix/authorize-at-dispatch` has 80 commits on no other ref and a PR list that
  hit exactly 100, so coverage could not be established. It was REFUSED, not
  deleted. A truncated list must never read as a complete one.
- An earlier run of the same check returned an empty commit list for all seven
  candidates with exit status 0, which would have scored every branch as
  unaccounted-for. The grader now refuses a branch whose PR list is empty rather
  than grading against it.
- `git rev-list --not --stdin` does not apply `--not` to revisions read from
  standard input; the exclusions must be written as `^ref`. The unguarded form
  reported 3348 unreachable commits for a one-commit docs branch.
- Under zsh an unquoted parameter does not word-split, so a batched
  `git push origin --delete $BRANCHES` expands to a single literal refspec and
  is rejected. It deleted nothing; the loop is now file-driven and per-branch.
- Every tip was archived under `refs/archive/by-tip/<sha>` before its branch was
  deleted. The archive does not prove nothing was lost; it makes the deletion
  recoverable either way.
- Scope limit on that recoverability, recorded because the first version of this
  document overstated it. Both the containment base and the archive refs are
  local; at the time of the deletions `chore/v4-reconcile-main` existed on no
  remote, so for the branches whose only proof was containment the commits were
  held on one disk. The base has since been pushed
  (`origin/chore/v4-reconcile-main` = `df3d2af`), so the containment proof now
  resolves against a ref that survives this machine. The archive refs remain
  local and are a convenience, not a backup.

## What remains, and why it is not cleanup debt

Of the 67 remaining, 44 have no pull request and carry commits absent from the
release line, and 17 have a closed pull request and carry between one and seven
such commits. These are unmerged work, not stale refs. Deleting them is a
decision about content, so the next step is `docs/release/branch-criteria-survey.md`,
which asks per branch whether it carries code satisfying a pending v4.0.0
criterion. A branch is only a cleanup candidate once that question has an answer.
