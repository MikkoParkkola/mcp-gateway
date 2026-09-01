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

So MRTR.7 is a wiring problem, not an invention — but the wiring must decide four things the
existing caller never had to: what may be asked, over what, who may be asked, and how many times.

## 1. A closed request type, not a generalised method string

`forward_elicitation_with_response` (`src/gateway/proxy.rs:243`) hard-codes `"method":
"elicitation/create"` and a typed `ElicitationCreateParams`. `Bridge::to_legacy_client`
(`src/protocol/mrtr.rs:241`) emits `OutboundRequest { key, method, params: Value }` — an
arbitrary method with raw params, because a modern backend may ask for sampling or roots and not
only elicitation.

The obvious edit is `forward_request_with_response(session_id, method: &str, params: &Value, …)`.
**Rejected.** It forwards a backend-chosen string to a client on the gateway's authority, and the
gateway is the only party in the exchange that can tell the two apart. A compromised or merely
buggy backend then reaches any method the client implements, including ones the gateway has never
audited. Nothing downstream can re-impose the restriction, because by then the method is just a
string in a JSON-RPC envelope.

Instead the bridge carries a closed type:

```rust
enum ServerRequest {
    Sampling(CreateMessageParams),
    Elicitation(ElicitationCreateParams),
    Roots,
}
```

`to_legacy_client` maps each `inputRequest` onto a variant or refuses. Three properties follow
from the type rather than from a check somewhere:

- **The method string is ours.** Each variant names its own wire method. A backend cannot
  introduce a method the gateway did not compile.
- **The id prefix is ours, and the ingress gate knows it.** `handlers.rs:633` admits a POST-back
  only when its id starts with `sampling-` or `elicitation-`; a `roots-` reply would be dropped
  with `No pending request for response` after the caller had already timed out. The enum has one
  arm per prefix, and the gate is widened in the same edit — a variant that the ingress cannot
  resolve is a compile-time hole, not a runtime timeout.
- **`MRTR.9` stays reachable.** Narrowing the bridge to elicitation alone would make its
  per-`inputRequest`-method refusal unreachable rather than unnecessary; a closed set of three
  keeps the refusal meaningful for everything outside it.

### The helper returns an answer, not an envelope

`resolve_pending` is handed the whole client message (`handlers.rs:637`,
`request.clone()`) and `forward_elicitation_with_response` returns it verbatim
(`proxy.rs:278`, `Ok(Ok(response)) => Ok(response)`). So today a caller receives
`{"jsonrpc":…,"id":…,"result":{…}}` — and a JSON-RPC **error** reply resolves through the same
success arm.

For a confirmation gate that is survivable: the caller inspects the body it wanted and treats
anything else as "no confirmation". For MRTR.7 it is not, because the value goes straight into
`inputResponses` and is sent to a backend as the user's answer. The bridge helper returns
`Result<Value, DeliveryError>` where the `Ok` value is the response's `result` member and an
`error` member becomes `DeliveryError::ClientRefused { code, message }`. A reply carrying neither
is `DeliveryError::Malformed`.

## 2. The client's connection, not the client's SSE stream

`send_to_session` (`src/gateway/streaming.rs:254`) writes to the SSE multiplexer. Every existing
server-initiated request goes through it (`proxy.rs:211`, `:269`, `:313`, `:343`, `:372`), so a
design written against `send_to_session` inherits "HTTP+SSE only" without ever deciding it.

`MRTR.7` says *the client's connection*. It names no transport, and stdio is bidirectional
JSON-RPC by construction — the gateway already writes to a child server's stdin
(`src/transport/stdio.rs:856`), so the direction is not the obstacle. Refusing stdio here would be
a stated limit against a MUST, which is an unmet requirement wearing an explanation.

So the bridge takes a `ClientChannel` — send a request, await the correlated reply, or fail — with
an SSE implementation that is today's `send_to_session` path and a stdio implementation that
writes the request to the connection's outbound half. The pending-id map and its session ownership
check (`proxy.rs:466-533`) are transport-independent already and are reused unchanged.

## 3. The session id at the call site names a backend, not a client

`src/gateway/router/backend_handlers.rs:98` (and `:926`, `:973`) builds
`format!("direct:{backend_name}")` and passes it as `session_id` to the firewall. That string is a
firewall correlation key. Handing it to `send_to_session` finds nothing and returns
`SamplingError::NoSession` — a bridge that silently never asks anybody.

The client's real session id must reach the bridge site. `MetaMcpCallerContext` already carries
shape-derived facts the ~500 lines from `handlers.rs:597` to the construction site (DE-4 in
`docs/design/2026-08-30-mrtr-wiring.md:418`), which is the established carrier, and the same
context is where `may_request_input` lives. Threading it there is the same edit twice, not two.

## 4. The neighbour's error handling is exactly wrong here, and copying it is the likely bug

`require_destructive_confirmation` maps `NoSession`, `Timeout` and every other delivery failure to
`ConfirmationOutcome::Unsupported` and **proceeds**. That is correct for a confirmation gate: the
MCP guidance is that a server must not break because a client omitted an optional capability.

It is catastrophic here. Proceeding means retrying the backend with no answers, and `retry_params`
(`src/protocol/mrtr.rs:264`) faithfully renders "no answers" as an omitted `inputResponses` — which
tells the backend its questions were never posed. The backend then either asks again or answers
without the input it required. MRTR.7 must fail the call on every one of those errors and report
the reason, never fall through. Recorded because the copy-paste is one line away and reads correct.

## 5. Three bounds, because one of them is not a bound

A backend may return `input_required` again after being retried. Unbounded, a backend drives a
client into unlimited prompts on the gateway's authority — a legacy client cannot tell the
difference between the gateway asking and the backend asking, which is the point of the bridge and
also the abuse.

Capping *rounds* alone does not cap prompts: one `InputRequiredResult` may carry an arbitrary
number of `inputRequest` entries, so a single round reaches the same abuse with a larger array.
Three limits, each on the original call rather than on a round:

| bound | value | enforced |
|---|---|---|
| retry rounds | 3 | before re-invoking the backend |
| prompts in total | 8 | before sending any prompt of a batch that would exceed it |
| aggregate wall time | 120s | checked before each send, and as a deadline on the whole call |

The values are stated here rather than deferred to a named constant so that the boundary tests and
the implementation converge on one contract; they are named constants in code, and changing one is
a change to this document. The batch check runs *before the first send* deliberately: refusing
after prompt 8 of 20 has already asked the user eight questions the gateway then discards. Every
refusal counts through `NFR.OBS.4`'s `rejected` counter
(`docs/design/2026-09-01-continuation-telemetry.md`).

## 6. Nothing records what a legacy client said it could do

The gate on "may this client be asked" has to be the client's own `initialize` capabilities —
`elicitation`, `sampling`, `roots`. `rg 'client_capabilities|ClientCapabilities' src/` returns
`src/protocol/messages.rs` and `src/protocol/types.rs` only: the types are parsed and dropped.
There is no per-session store, so a design saying "inherit the per-request capability slice" would
inherit an empty one and refuse every legacy client — a bridge that reads as correct and never
asks anybody.

So the increment builds the store: on `initialize`, the declared capability object is retained
against the session id; the bridge looks the session up and refuses a variant the client did not
declare. A real addition, not a lookup — recorded because the requirement presupposes it and
nothing in the tree provides it.

## Refusals, before any of the above runs

Two, both explicit failures rather than silent completion: the client declared no capability for
the variant being asked (§6), or the call has no client session to reach at all. In each case the
call fails with its reason and the backend's interim result is dropped rather than answered
emptily. Transport is *not* a refusal reason (§2).

## Unknowns

| unknown | state |
|---|---|
| Does the bridge site have the client's session id? | **Resolved.** Read `backend_handlers.rs:98`: it has `direct:{backend_name}`, a firewall key, not a session. Changed the design: §3 exists because of it. |
| Can `MetaMcpCallerContext` carry the session id to the site? | **Deferred.** Owner: the MRTR.7 implementation increment. Resolved by reading the construction sites at `handlers.rs:597` and `server/mod.rs:1733`. When: first line of the implementation. If it resolves badly: the id is threaded as a separate parameter, which is uglier and equally correct — so nothing downstream is blocked on the answer. |
| Is `may_request_input` sufficient to gate this? | **Resolved: no.** `mrtr-wiring` DE-4 states the bit cannot tell elicitation from sampling from roots. Read the replacement it names and there is nothing to inherit: `rg 'client_capabilities|ClientCapabilities' src/` returns two type files and no store. Changed the design: §6 builds one, instead of citing a slice that would always be empty. |
| Does the response ingress admit a reply for a third request kind? | **Resolved: no.** `handlers.rs:633` gates on `sampling-` and `elicitation-` prefixes; a `roots-` reply is dropped after the caller has timed out. Changed the design: §1 makes the prefix set and the enum one closed set, widened in a single edit. |
| Does the helper hand back the client's answer? | **Resolved: no.** `handlers.rs:637` passes the whole message to `resolve_pending` and `proxy.rs:278` returns it verbatim, so a JSON-RPC `error` reply resolves through the success arm. Changed the design: §1 returns the `result` member or a typed `DeliveryError`. |
| Can a stdio client be asked at all? | **Resolved: yes.** stdio is bidirectional JSON-RPC and the gateway already writes to a child's stdin (`transport/stdio.rs:856`); only `send_to_session` is SSE-bound (`streaming.rs:254`). Changed the design: §2 replaces the transport refusal with a channel abstraction. |

## Out of scope

The legacy-backend/modern-client direction (`MRTR.6`'s forwarding half), which has its own
deferred question in `docs/design/2026-08-30-shared-continuation-state.md`. Nothing here changes
what a modern client is sent.
