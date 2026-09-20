<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# MIK-6746.CONTRACT.1 / C1: make inbound agent audience validation fail closed

## Scope

In scope: conjunct **C1 only** — the inbound gateway boundary. Explicitly out of
scope and not addressed here: C2 (already MET), C3 (the ADR-008 reconciliation
write-up), C4 (the six test cells), C5 (direct/meta parity) and C6 (the ordering
gate, which cannot clear while C3/C4/C5 are short). Landing C1 does not flip the
row to met and is not claimed to.

## The defect

`AgentDefinition.audience` is `Option<String>` (`src/gateway/oauth/agents.rs:45`)
and the audience check runs only inside `if let Some(ref expected_aud)`
(`src/gateway/oauth/jwt.rs:165-168`). An agent configured without an audience
therefore skips `check_audience_claim` entirely.

The consequence is not theoretical. The verification key is the agent's own
`hs256_secret` or `rs256_public_key`. Whenever that key is shared across more
than one relying party — the normal case for an enterprise IdP signing RS256
tokens for many audiences with one key pair — a token minted for a *different*
service verifies here and is accepted. Audience binding is the mechanism that
stops exactly that confused-deputy substitution, and today it is opt-in.

Every fixture in the tree sets `audience: None` (9 sites), so nothing currently
exercises the enforced path at the config boundary.

## The fix, in two layers

**Layer 1 — refuse the config.** Extend the existing `agent_auth` validation loop
in `src/config/mod.rs:895` with: an enabled agent that sets no `audience` is a
`ConfigValidation` error naming the agent's `client_id`. Empty and
whitespace-only values are refused on the same terms: a blank `aud` names no
relying party, so it distinguishes none, and accepting it would reopen the gap
through a config that merely looks filled in.

The loop is the right home — it already refuses an agent that sets both key
types, with the reasoning recorded in-line: *"`AgentDefinition` already documents
'exactly one'; refusing is what enforces it."* But the parallel stops there, and
the difference matters enough to state plainly: **this is a breaking change to
auth policy, not the enforcement of a contract already written down.** `audience`
is documented *optional* in both places it is defined (`agents.rs:43-45`,
`auth.rs:235-237`), and the worked example for an enabled agent
(`auth.rs:195-205`) omitted it entirely. A deployment that followed the
documentation as published will refuse to start after this change. That is the
intended outcome — such a deployment accepts tokens minted for anyone sharing its
signing key — but it is a policy reversal and the docs are corrected in the same
change so the field no longer reads as optional.

**Layer 2 — fail closed at verification.** In `validate_agent_token`, replace the
`if let Some(...)` with a binding that rejects when the agent has no audience.
It reuses the error `check_audience_claim` already returns for an absent `aud`
(`JwtError::JwtVerification(InvalidAudience)`, `jwt.rs:258-261`) rather than
adding a variant, so the verifier answers "audience did not check out" with one
error regardless of which side the gap is on.

That `src/gateway/server/mod.rs:1633` is the only production ingress is not
assumed. Every non-test `.register(` call site in `src/` was enumerated: the
others target the backend registry, the plugin registry, the session-lifecycle
registry or the A2A provider registry, and the RFC 7591 dynamic-registration
code in `src/oauth/client/` is the gateway registering *itself* with an upstream
provider, not an endpoint that accepts agent registrations. So layer 1 covers every
audience-less agent that arrives through config today. Layer 2 is not therefore
redundant: `AgentRegistry::register` is `pub` and validates nothing, and config
validation is skipped outright when `agent_auth.enabled` is false, so layer 2 is
what makes the invariant a property of the verifier rather than of one caller.

## Why the config boundary, and not verification alone

Enforcing only at verification turns an upgrade into a request-time outage: a
deployment with an audience-less agent would start cleanly and then reject every
token, discovered by traffic rather than by the operator. Enforcing at config
load surfaces it from `mcp-gateway validate` and from `upgrade --dry-run` —
both of which the release runbook already runs — before any traffic is served.

Failing closed is the correct direction regardless: refusing to start on a
config that cannot enforce audience is the safe reading, and `agent_auth.enabled`
defaults to false, so no deployment that has not opted into agent auth is
affected.

## What is deliberately not done

`audience` stays `Option<String>` on both `AgentDefinition` and
`AgentDefinitionConfig`. The tempting argument for a bare `String` — that `None`
would then be unrepresentable — rests on a claim that does not hold here: `None`
is *not* unreachable in production. Config validation is skipped entirely when
`agent_auth.enabled` is false (`config/mod.rs:895-897`), and
`AgentRegistry::register` (`agents.rs:88-90`) is `pub` and validates nothing, so
a construction path that never passes through config can still produce one.

The invariant the change actually establishes is narrower and is the one worth
stating: **a definition with no audience cannot successfully validate a token.**
Layer 2 is what guarantees it, at the only place it has to hold. Layer 1 is the
operator-facing half — it moves the failure from request time to startup. The
criterion note sizes C1 as "an `Option<String>` threaded through agents.rs and
every fixture"; that threading would buy a compile-time proof, but at the cost of
a breaking public-type change on top of the breaking policy change, and the
runtime invariant above is what the criterion is about.

## The sibling defect in `issuer`, deferred

`issuer` has the identical shape one line up (`jwt.rs:150-155`: `if let Some(ref
expected_iss)`, so an agent with no configured issuer accepts any `iss`). It is
deliberately not fixed here. The consequence is much weaker — the signing key
already pins who could have minted the token, so an unchecked `iss` does not by
itself admit a foreign signer — whereas an unchecked `aud` admits a token the
*correct* signer minted for someone else. Fixing both in one change would also
double the fixture churn for the weaker half. Recorded so it is a deferral on
the record rather than an oversight.

## Tests, red before green

Two rows go red before the change, not three — the permissive control the design
called for already exists as `audience_check_passes_when_matching`
(`jwt.rs:396`), paired with `audience_check_fails_when_mismatched`, so neither
arm of the new row can pass vacuously and no third row is written.

1. `validate_agent_token` rejects a **correctly signed, non-expired** token whose
   agent has `audience: None` — today that token is accepted.
2. Config validation rejects an enabled agent with no `audience`, naming the
   `client_id`, on a fixture whose key material is otherwise valid so an
   unrelated key error cannot satisfy the assertion. Covered for HS256 *and*
   RS256: the RSA branch exits the loop early, so a guard placed after it would
   leave every RS256 agent audience-less.

Fixture churn is smaller than the nine `audience: None` sites suggest, because
most of them share a constructor. Five edits cover it: the two JWT helpers
(`make_hs256_agent` and `hs256_token`, which now agree on one `FIXTURE_AUDIENCE`
constant), the `agent_config` helper and the sibling-agent literal in
`config/tests.rs`, the `agent_auth` YAML in `config_reload/tests.rs`, and the
`with_agent_secret` helper in `tests/agent_key_env_tests.rs`. The three
`audience: None` sites in `agents.rs` are registry lookup and replacement tests
that touch neither the verifier nor config validation; they are left alone.

## Falsifier

Delete the `audience` guard from the config loop and test 2 must go red; delete
the verifier guard and test 1 must go red. If either stays green with its guard
removed, the test is not covering the change.
