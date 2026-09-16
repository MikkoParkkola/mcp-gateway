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

## Design review of the fix, 2026-09-16

The fix for the firewall-gate finding was designed before any code was written
and reviewed by kimi (SHIP-WITH-FIXES). Two of its three findings are confirmed
at source, and one of them would have shipped a gate that covers a single round
of a multi-round exchange:

- **A gate placed before `InputBridge::run` covers the first round only.**
  `run` is `for _ in 0..self.bounds.rounds` (`src/gateway/input_bridge.rs:409`)
  and each round calls `self.backend.invoke(retry)` (`:421`), so rounds 2..N ask
  prompts built from a fresh backend result at `:419`. The gate has to run inside
  the loop, before every `ask`. The revised design adds a `ChallengeGate` trait
  next to the existing `BridgeObserver`, which is the same shape already in use.
- **A firewall refusal would be recorded as a backend failure.**
  `Error::is_pre_dispatch` (`src/error.rs:290`) matches only `CircuitOpen`,
  `BackendNotFound`, `ToolNotFound` and `TransportConnect`;
  `ResponseFirewallRefused` is not among them, so
  `classify_bridged_dispatch_error` (`src/gateway/meta_mcp/invoke.rs:937`) sends
  it down the `BackendFailed` path and settles the idempotency key as though the
  backend might have run. Nothing ran — the refusal happens before the question
  is shown. An explicit arm and a unit test close it.
- **Duplicate request ids are reported but NOT yet verified.**
  `InputRequired.requests` is `Vec<(String, Value)>`
  (`src/protocol/mrtr.rs:200`), so collecting it into a JSON object keeps only
  the last value for a repeated id while the bridge iterates the original vector.
  The parse site was not located, so whether the protocol layer already
  guarantees uniqueness is open.

gpt's review of the same design ran alongside kimi's.

### gpt's independent review, same design

gpt reviewed the same design in parallel and returned SHIP-WITH-FIXES on the
same CRITICAL: "Gating only before `InputBridge::run` leaves every challenge
returned by later retry rounds uninspected" (CERTAIN, gate NOW). Two
independent reviewers converging on one finding, against a design that reads
plausibly, is the reason the design gate exists.

gpt also raised a third finding the earlier review did not, and it is confirmed
at source:

- **A refusal converted into a generic bridge error loses its delivery-refusal
  projection.** `error_response_preserving_status`
  (`src/gateway/meta_mcp/mod.rs:232`) carries a dedicated
  `crate::Error::ResponseFirewallRefused` arm that builds
  `JsonRpcResponse::delivery_refusal_error`; every other error falls through to
  the ordinary `JsonRpcResponse::error`. The bridged-exchange failure path
  returns `Error::JsonRpc { code: -32003, .. }` (`invoke.rs:2247`), so a refusal
  that travels as a `BridgeError` arrives as an ordinary client-attributable
  error and the typed arm never runs. The gate's refusal has to stay typed
  across the bridge boundary rather than being flattened into the bridge's own
  error enum.

Both reviewers asked for the same two tests: an end-to-end two-round exchange
whose SECOND challenge carries blocked content, and a control proving a canary
present only in `request_state` is neither scanned nor delivered.
