# Deferred to 4.1.0: ranking quality threshold freeze

`MIK-3274.RANKING.3` is removed from the v4.0.0 release scope by operator decision on
2026-09-12 and re-targeted at the next ranking change.

## Why it was removed rather than graded

The criterion required held-out selection quality, discovery turns, invalid invocations
and total completed-task tokens to meet thresholds "frozen after baseline measurement and
**before ranking implementation**", against a 3.5.1 baseline.

Ranking is already implemented. `src/ranking/mod.rs` shipped with roughly sixty tests, so
a before-implementation freeze cannot be produced on this branch by any means. The
supporting evidence is absent for the same reason and was re-verified on 2026-09-12:
`benchmarks/results/` holds one unrelated live-agent file, and
`RELEASE-4.0.0-performance-contract.md` freezes the workload latency rows only, with no
ranking-quality thresholds anywhere in it.

That makes the row unsatisfiable as written — a defect in the criterion, not in the code.

## Why not the alternatives

Grading it `not_met` and shipping would have been honest but would have left the release
ledger with a hole and no plan attached.

Rewriting it to freeze thresholds today against 3.5.1 would have closed the row and
destroyed its point. Thresholds chosen once the results are already visible are thresholds
chosen to be passed, which is the precise failure the original "before implementation"
wording exists to prevent. A criterion that can be satisfied by picking convenient numbers
measures nothing.

## What carries forward

The guarantee is preserved, not dropped. The next change to ranking freezes its thresholds
first, against a measured baseline, before any implementation lands — which is the
condition v4.0.0 can no longer meet and 4.1.0 still can.

Measurement route for that work: `benchmarks/live_agent_tool_selection.py`. The metrics the
row names require live-agent runs; `evaluate_offline` at `src/ranking/mod.rs:421` is a
fixture comparator over deterministic offline cases and cannot produce them.
