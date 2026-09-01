<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# NFR.SEC.1 — inventory of the controls a 3.5.0 caller was constrained by

`NFR.SEC.1`: *no control that constrained a caller under 3.5.0 may become
inoperative for a modern caller; each MUST have a test that asserts refusal
when its input is absent.*

The criterion was uncheckable because nothing closed the SET. Four refusal
tests were cited against a criterion that says EACH, so four was a sample.
This file is the set, and — more usefully — the **rule that regenerates it**,
so a reviewer can answer "is this list complete?" by reading one function
instead of trusting this document.

## The derivation rule

> A row is a gate that a POST to `/mcp` traverses, in order, from the outermost
> axum layer in `src/gateway/router/mod.rs` to method dispatch in
> `meta_mcp_handler` (`src/gateway/router/handlers.rs:463`), and that refuses
> the request when its input is absent or unacceptable.

Re-run it by reading the layer stack at `src/gateway/router/mod.rs:253-307`
top-to-bottom, then `meta_mcp_handler` top-to-bottom. Every early return that
ends the request with an error is a row. Nothing else is.

This is deliberately not a grep for `fn .*(check|require|validate)`. That
search returns config validators and test names and misses gates written
inline, which is how the set stayed open.

### Two scope boundaries, stated so the set stays closed

1. **Request path only.** The criterion says "constrained a **caller**". A
   validator that refuses to *start the server* on a bad config file
   (`src/config/env_overlay.rs:338`, `src/skills/parser.rs:303`) never
   constrained a caller. Out.
2. **3.5.0-operative only.** A control introduced by 4.0.0 cannot have become
   inoperative for a modern caller — it never constrained a 3.5.0 one. Out,
   and listed separately below so the exclusion is visible rather than silent.

### Step (b): the baseline scan, and its result

Reading only the current handler can never surface a control that *became
inoperative* — the first clause of the criterion. So the rule has a second
step: enumerate the same gates at `v3.5.0` and map each to a current row. A
v3.5.0 gate with no current row is the thing the criterion is actually about.

Enumerated with `git show v3.5.0:src/gateway/router/handlers.rs` (1027 lines)
plus `v3.5.0:src/gateway/auth.rs` and `v3.5.0:src/gateway/router/mod.rs`.
Result, stated so it can be disagreed with: **every v3.5.0 gate maps to a
current row; none went missing.**

| v3.5.0 site | current row |
|---|---|
| `mod.rs:273` origin guard layer | 1 |
| `mod.rs:224` agent auth layer | 2 |
| `mod.rs:227` auth layer | 3 |
| `auth.rs` per-client rate limiter | 4 |
| `auth.rs` per-client circuit breaker | 5 |
| `handlers.rs:396` `validate_agent_identity` | 6 |
| `handlers.rs:404` 10 MiB `to_bytes` | 7 |
| `handlers.rs:417` `-32700` | 8 |
| `handlers.rs:435` Meta-MCP disabled | 9 |
| `handlers.rs:502` `parse_request` | 10 |
| `handlers.rs:465` `sanitize_json_value` | 11 |
| `handlers.rs:543` `is_admin_meta_tool` | 12 |
| `handlers.rs:572` `authorize_tool_target` | 13 |
| `handlers.rs:660` destructive confirmation | 14 |
| `handlers.rs:619` firewall | the blocked 15th |

Two v3.5.0 early returns are deliberately absent: `handlers.rs:160` and `:172`
gate the SSE handler on `streaming_config.enabled` and an
`Accept: text/event-stream` header. Different route, so out by the derivation
rule's first clause — recorded here because a reader re-running the scan will
hit them and should not have to guess whether they were missed.

## The set — 14 controls

| # | control | source symbol (file:line) | input whose absence must cause refusal | refusal test |
|---|---|---|---|---|
| 1 | Origin / DNS-rebinding gate | `origin_guard_middleware` — `src/gateway/router/mod.rs:304` | an `Origin` header that is on the allowlist | `src/gateway/router/tests.rs:2227`, `:2253` |
| 2 | Agent JWT validity | `agent_auth_middleware` — `src/gateway/router/mod.rs:255`, body at `src/gateway/oauth/mod.rs:113` | a bearer JWT that validates against the agent registry | NONE — see *Not closed* below |
| 3 | Authentication | `auth_middleware` — `src/gateway/auth.rs:894`, `:945` | a bearer token or API key | **`tests/nfr_sec1_controls.rs`** — NEW |
| 4 | Per-client rate limit | `client_preflight` — `src/gateway/auth.rs:956` | remaining budget in the client's window | **`tests/nfr_sec1_controls.rs`** — NEW |
| 5 | Client circuit breaker | `client_preflight` — `src/gateway/auth.rs:963` | a closed circuit for that client | NONE — see *Not closed* below |
| 6 | Agent identity allowlist | `validate_agent_identity` — `src/security/agent_identity.rs:141`, called at `handlers.rs:504` | an `X-Agent-ID` that is present and known | **`tests/nfr_sec1_controls.rs`** — NEW |
| 7 | Request body ceiling (10 MiB) | `handlers.rs:513` | a body within the ceiling | NONE — see *Not closed* |
| 8 | JSON well-formedness | `handlers.rs:526` | parseable JSON | NONE — see *Not closed* below |
| 9 | Meta-MCP surface enabled | `handlers.rs:541` | the surface being enabled | **`tests/nfr_sec1_controls.rs`** — NEW |
| 10 | JSON-RPC envelope shape | `parse_request` — `handlers.rs:648` | `jsonrpc`, `method`, `id` | `src/gateway/router/tests.rs:746`, `:761`, `:768` — on `parse_request` directly, not through the modern route |
| 11 | Input sanitization | `sanitize_json_value` — `handlers.rs:610` | input free of the injected shapes it strips | NONE — see *Not closed* |
| 12 | Admin gate on management meta-tools | `require_admin_tool_access` — `src/gateway/router/authorization.rs:84`, called at `handlers.rs:985` | an authenticated client with `admin: true` | `src/gateway/router/tests.rs:3207` (`ac_order_2_a_modern_caller_is_refused_gateway_set_profile`) — through the modern route |
| 13 | Tool-scope / tenancy / SSRF authorization | `authorize_tool_target` — `src/gateway/router/authorization.rs:98`, called at `handlers.rs:993` | an API key whose `allowed_tools` covers the target | **`tests/nfr_sec1_controls.rs`** — NEW (existing `tests.rs:1287`, `:1436`, `:1570` call the gate directly, not through the modern route). Its agent-scope branch (`authorization.rs:165`) is asserted at `tests.rs:1508`, also directly |
| 14 | Destructive-action confirmation | `require_destructive_confirmation` — `handlers.rs:1112` | someone to ask | `tests/mik_7215_acs.rs:630` |

Firewall / anomaly detection (`handlers.rs:1068`, `-32002` / `-32600`) is a
15th gate in the sequence. **BLOCKED**: every test of it needs
`src/security/firewall/**`, which another session owns and is editing now.
Not tested here, not edited here, recorded so the set is not silently short.

## Not closed, and why

| # | control | why no test |
|---|---|---|
| 2 | agent JWT validity | The middleware refuses a request carrying no bearer token, an unknown agent, or a JWT that fails validation. Driving any of those needs an agent registry and a signed token — a fixture this file does not own. `tests.rs:1508` was cited here in an earlier draft and does not reach this gate: it exercises `authorize_tool_target`'s agent-scope branch, which is row 13's symbol, and never crosses `mod.rs:255`. Row stands as a gap. |
| 5 | client circuit breaker | Refuses on a *trip count*, not an absent input. Driving it through the modern route means failing N calls first, which needs a backend that fails on demand — a fixture this file does not own. Row stands as a gap. |
| 7 | 10 MiB body ceiling | Refusal is `axum::body::to_bytes` returning `Err`; asserting it means shipping an 11 MiB fixture into the test binary. Cost outweighs the claim. |
| 8 | JSON well-formedness | Was recorded as "covered by 10". It is not: row 8 is `-32700` from `serde_json::from_slice` at `handlers.rs:526`, row 10 is `parse_request`'s envelope check ~120 lines later, and a body that fails row 8 never reaches row 10. The `-32700` assertions that exist (`tests.rs:911`, `:922`, `:981`) call `build_http_error_response`, the constructor, not the gate; `tests/stdio_tests.rs:254` asserts the stdio loop, not `/mcp`. Row stands as a gap. |
| 11 | input sanitization | Off by default (`sanitize_input: false`) and the refusal depends on what `sanitize_json_value` chooses to reject — a moving target this criterion does not pin. |

## Controls that are NOT in the set (new in 4.0.0)

These four have refusal tests, and those tests are the four the ledger cited.
They belong to `NFR.SEC.2`-shaped claims, not to this one: a control 4.0.0
introduced cannot have become inoperative for a modern caller.

| control | refusal test | code |
|---|---|---|
| unsupported protocol version | `tests/mik_7215_acs.rs:472` | `-32022` |
| undeclared capability | `tests/mik_7215_acs.rs:598` | `-32021` |
| missing / mismatched HTTP version header | `tests/mik_7214_acs.rs:787` | `-32020` |
| method removed or added by the revision | `handlers.rs:800`, `:828` | `-32601` |

That the four cited tests all cover *new* controls, and none covered a 3.5.0
one, is the substance of the defect — not merely that the list was short.

## Verdict

Set closed and derivable: 14 controls plus one blocked (firewall). **Nine**
carry a refusal test (rows 1, 3, 4, 6, 9, 10, 12, 13, 14); **five** are
recorded gaps with their reasons (rows 2, 5, 7, 8, 11); one — the firewall —
is blocked on a file this session must not touch.

An earlier draft of this table said twelve. It reached that number by citing,
for rows 2 and 8, a test that asserts a *nearby* claim rather than the row's
own. That is the same defect the ledger filed against the original four
citations, committed inside the document written to close it, which is why
both rows are now gaps and why each carries its disproof in the table above.

## Gate order is part of the claim

Removing one gate's input can land the request on an *earlier* gate, which
refuses — and the test goes green while the control it names never ran. This
is not hypothetical: the first draft of the control-13 test (API-key tool
scope) was refused at `-32020` by the mirrored-header check, three gates
earlier, because the frame did not mirror `mcp-name`. It "passed" as a refusal
and proved nothing about tool scope.

So each test in `tests/nfr_sec1_controls.rs` asserts its own gate's status and
error code, and carries an in-file falsifier: the same frame with the input
PRESENT must be served. A test that refuses in both halves is measuring
something other than the control in its name. The retrofit case needs this —
these controls already worked, so no test here could earn the free failure
that comes from writing the test before the code.
