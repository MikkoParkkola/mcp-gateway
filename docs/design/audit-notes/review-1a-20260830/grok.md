I'll review the design and test-plan against the stated scope and the four questions, starting from the actual documents.I'll inspect the design, the test-plan rows, and the surrounding tree for dangling claims from the deleted prefix.FINDING
what: Decision 2 still requires an origin check before any key lookup, which is the cleartext prefix this repair deleted and which a non-origin replica cannot perform once origin stays sealed.
where: docs/design/2026-08-30-shared-continuation-state.md:195
crit: HIGH
prob: LIKELY
gate: NOW
impact: the next implementer rebuilds a client-controlled origin claim, or the production-constructor row that demands NotAuthentic fails a Decision-2 build
fix: repair Decision 2 to match section 2: non-origin refusal is AEAD NotAuthentic under this process's key, which is authenticity failure and not a redeemability decision
END

FINDING
what: The residual cites CHANGELOG as already stating the new mint-counter story, while CHANGELOG, DEPLOYMENT, Helm, the execution-plan 1a row, the PR body, and the MRTR wiring design still describe MIK-7312 as a shared store that stops cross-replica double-spend.
where: docs/design/2026-08-30-shared-continuation-state.md:212
crit: HIGH
prob: LIKELY
gate: NOW
impact: the next 1a implementer builds the store this design rejected, and operators keep being told two replicas can spend one continuation twice
fix: rewrite CHANGELOG.md:110-114, docs/DEPLOYMENT.md:125-142, deploy/helm/mcp-gateway/values.yaml:11-16, docs/requirements/RELEASE-4.0.0-execution-plan.md:118, and the matching PR-body/wiring sentences to per-process keys, as Decision 4 already promised for DEPLOYMENT.md
END

FINDING
what: The two-AppState concurrent MRTR.5 row asserts that the ledgers never consult each other, which is true by constructing two independent AppStates, and its uniqueness claim is false because the sequential production-constructor row already fails shared key material.
where: docs/requirements/RELEASE-4.0.0-test-plan.md:304
crit: LOW
prob: CERTAIN
gate: NOW
impact: a coverage row that cannot fail on its second conjunct and cannot fail independently of line 300 on its first
fix: delete the row
END

IMPROVEMENT
what: State in one sentence that MRTR.5 is met as no replica will accept a second spend, not as every replica can complete a first spend.
where: docs/design/2026-08-30-shared-continuation-state.md:37
value: the coin-flip retry cost stays a named operational consequence instead of being relitigated as an unmet MUST
cost: SMALL
END

IMPROVEMENT
what: Name how redeem tells a vanished legacy InFlight hold from a modern continuation that never had one, using the existing payload (RFC-0061 already puts the hold key in backend_request_state on the legacy path).
where: docs/design/2026-08-30-shared-continuation-state.md:143
value: the clause-3 pin stays implementable without adding a field or parking per-mint state that would fail MRTR.8
cost: SMALL
END

IMPROVEMENT
what: Mark the MRTR wiring design's shared-ledger paragraphs superseded from this document, rather than leaving two live designs for MIK-7312.
where: docs/design/2026-08-30-mrtr-wiring.md:126
value: wiring work stops targeting a store this design rejected
cost: SMALL
END

VERDICT: SHIP-WITH-FIXES -- Decision 2 still specifies the prefix check this repair deleted
grok-review: review output at /Users/mikko/.claude/data/reviews/runs/grok-20260830T203200Z-41526.md
grok-review: verdict SHIP-WITH-FIXES
