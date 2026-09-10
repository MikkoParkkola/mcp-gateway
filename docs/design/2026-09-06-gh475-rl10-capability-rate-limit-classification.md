<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# GH475.RL.10 — superseded

Status: **superseded, 2026-09-06**. Canonical:
`docs/design/2026-09-06-capability-rate-limit-budget-participation.md`.

This document was written without searching for an existing design on the same
criterion, and one already existed — larger, earlier, and correct where this was
not (H1/H2). Its three revisions diagnosed a defect that does not exist: an HTTP
error status never reaches the MCP envelope, because every capability executor
returns `Err` before a `ToolsCallResult` is built (`src/capability/executor/params.rs:45`,
`jsonrpc.rs:199`, `graphql.rs:255`, `credentials.rs:221`), and the `Err` arm of
`BudgetOutcome::of` (`src/gateway/meta_mcp/invoke.rs:3003-3010`) already runs the
shared rate-limit predicate over that message.

Its proposed remedy — marking capability results `is_error: true` on an error
status — is withdrawn along with the diagnosis, and its test plan was already
covered: `budget_outcome_classifies_only_unambiguous_rate_limits`
(`invoke.rs:4465`) pins the `Err`-arm classification in both directions, and
`a_real_capability_429_is_excluded_by_the_shared_rate_limit_predicate`
(`src/capability/executor_tests.rs:993`) drives a real loopback `429` through the
production formatter.

**What the criterion actually needs is not what this document proposed.**
`GH475.RL.10` asks that a typed rate-limit outcome need no text; the behaviour is
met and the *property* is absent, because the exclusion is a substring match on a
formatted message — the very thing the criterion says must not be required.
Closing it means a typed executor signal, which is a breaking change to
`capability::Error` and sits with the operator. See the canonical design and the
`GH475.RL.10` row in `docs/requirements/RELEASE-4.0.0-criteria-status.md`.

Kept as a stub rather than deleted: three commits in this branch cite it.
