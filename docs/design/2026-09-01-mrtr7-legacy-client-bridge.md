<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MRTR.7 — bridging a modern backend's question to a legacy client

`MIK-7212.MRTR.7` (`docs/requirements/RELEASE-4.0.0-requirements.md:143`), verbatim: *"Given a
modern backend returning `InputRequiredResult` and a legacy client, When the gateway bridges,
Then it MUST issue the equivalent server-initiated request on the client's connection and retry
the backend with the collected responses."*

`ASM.3` (`:288`) expects backends to adopt the revision before clients do, which makes this the
common direction rather than the rare one. `mrtr-wiring` says each bridge direction gets its own
design and the test plan (`RELEASE-4.0.0-test-plan.md:352`) says the same. This is that document.

## The mechanism is not missing. That is the whole finding.

The test plan records the gap as *"issuing them over the client's transport mid-call, which is
its own design"*. It is already built, one module over, and shipping:
`ProxyManager::forward_elicitation_with_response` (`src/gateway/proxy.rs:243`) registers a
pending id, sends a JSON-RPC request down the originating session's SSE stream, and awaits the
matching response under a timeout. `require_destructive_confirmation`
(`src/gateway/destructive_confirmation.rs:188`) is a shipped caller of it.

So MRTR.7 is a wiring problem with three specific edits, not an invention.

## 1. One generalisation, because the existing entry point is method-specific

`forward_elicitation_with_response` hard-codes `"method": "elicitation/create"` and a typed
`ElicitationCreateParams`. `Bridge::to_legacy_client` (`src/protocol/mrtr.rs:241`) emits
`OutboundRequest { key, method, params: Value }` — an arbitrary method with raw params, because a
modern backend may ask for sampling or roots and not only elicitation.

Add `forward_request_with_response(session_id, method, params: &Value, timeout)` and reduce both
existing functions to callers of it; they already differ only in the id prefix, the method string
and how params are serialised. The alternative — narrowing `to_legacy_client` to emit only
elicitation — is rejected: `MRTR.9` refuses per `inputRequest` method, and a bridge that can only
represent one method would make that refusal unreachable rather than unnecessary.

## 2. The session id at the call site names a backend, not a client

`src/gateway/router/backend_handlers.rs:98` (and `:926`, `:973`) builds
`format!("direct:{backend_name}")` and passes it as `session_id` to the firewall. That string is a
firewall correlation key. Handing it to `send_to_session` finds nothing and returns
`SamplingError::NoSession` — a bridge that silently never asks anybody.

The client's real session id must reach the bridge site. `MetaMcpCallerContext` already carries
shape-derived facts the ~500 lines from `handlers.rs:597` to the construction site (DE-4 in
`docs/design/2026-08-30-mrtr-wiring.md:418`), which is the established carrier, and the same
context is where `may_request_input` lives. Threading it there is the same edit twice, not two.

## 3. The neighbour's error handling is exactly wrong here, and copying it is the likely bug

`require_destructive_confirmation` maps `NoSession`, `Timeout` and every other delivery failure to
`ConfirmationOutcome::Unsupported` and **proceeds**. That is correct for a confirmation gate: the
MCP guidance is that a server must not break because a client omitted an optional capability.

It is catastrophic here. Proceeding means retrying the backend with no answers, and `retry_params`
(`src/protocol/mrtr.rs:264`) faithfully renders "no answers" as an omitted `inputResponses` — which
tells the backend its questions were never posed. The backend then either asks again or answers
without the input it required. MRTR.7 must fail the call on every one of those errors and report
the reason, never fall through. Recorded because the copy-paste is one line away and reads correct.

## 4. The retry loop is bounded, and the bound is not a tuning knob

A backend may return `input_required` again after being retried. Unbounded, a backend drives a
client into unlimited prompts on the gateway's authority — a legacy client cannot tell the
difference between the gateway asking and the backend asking, which is the point of the bridge and
also the abuse. Cap the rounds at a named constant, refuse past it, and count the refusal through
`NFR.OBS.4`'s `rejected` counter (`docs/design/2026-09-01-continuation-telemetry.md`).

## Refusals, before any of the above runs

A stdio caller has `may_request_input = false` (DE-4), and separately has no SSE session for a
server-initiated request to travel down. Two independent reasons, both refusals rather than
silent completion: the call fails with the reason, and the backend's interim result is dropped
rather than answered emptily.

## Unknowns

| unknown | state |
|---|---|
| Does the bridge site have the client's session id? | **Resolved.** Read `backend_handlers.rs:98`: it has `direct:{backend_name}`, a firewall key, not a session. Changed the design: §2 exists because of it. |
| Can `MetaMcpCallerContext` carry the session id to the site? | **Deferred.** Owner: the MRTR.7 implementation increment. Resolved by reading the construction sites at `handlers.rs:597` and `server/mod.rs:1733`. When: first line of the implementation. If it resolves badly: the id is threaded as a separate parameter, which is uglier and equally correct — so nothing downstream is blocked on the answer. |
| Is `may_request_input` sufficient to gate this? | **Resolved: no**, and already recorded. `mrtr-wiring` DE-4 states the bit cannot tell elicitation from sampling from roots, and is replaced by declared capability names in the increment that first reads it. MRTR.7 inherits that replacement rather than re-deriving it. |

## Out of scope

The legacy-backend/modern-client direction (`MRTR.6`'s forwarding half), which has its own
deferred question in `docs/design/2026-08-30-shared-continuation-state.md`. Nothing here changes
what a modern client is sent.
