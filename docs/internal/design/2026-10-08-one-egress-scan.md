# One egress scan for every outgoing frame (response-firewall-coverage family)

Status: proposed, 2026-10-08. Tickets: MIK-8139 (errors), MIK-8146 (prompts/get,
resources/read results), MIK-8112 (A2A results), MIK-8131 (blocked interim answer
keeps its slot), MIK-8155 (interim answer redacted on HTTP, refused on stdio).
PR: #3527.

## Problem

The response firewall decides per call site what to read, and each site reads
only `result` for a method list it hard-codes. Twelve sites today:

| Site | Route | Reads | Policy |
|---|---|---|---|
| `router/response_pass.rs:34` (`handlers.rs:1768`) | HTTP `/mcp` tools/call | result | Redact |
| `meta_mcp/response_security.rs:229` `finalize_content` | HTTP `/mcp` + stdio | result, only tools/call, tools/list | PreserveInputRequired |
| `router/direct_guards.rs:156` `response_blocked` | `/mcp/{name}` tools/call | result | Redact |
| `router/backend_handlers.rs:693` | `/mcp/{name}` tools/list | result | Redact |
| `task_service/execution/worker.rs:521` `inspect_settled` | tasks | result | Redact |
| `router/watch_poll.rs:120` | task watch poll | result | Redact |
| `meta_mcp/upstream.rs:458` | upstream task | result | Redact |
| `meta_mcp/mod.rs:1048` `inspect_discovery_value` | discovery | canonical value | Redact |
| `meta_mcp/response_security.rs:370` `enforce_firewall_challenge` | bridge question | challenge | Immutable |
| `events/services.rs:259` | event notifications | payload | Redact |
| `dispatch_guards.rs:290` `screen_backend_error` (this PR so far) | both, errors | message, data | Redact |

Consequences, one per ticket: an error's text is never scanned (MIK-8139); a
catalogue read's body is never scanned on either route (MIK-8146); the same
interim answer is redacted on HTTP (first pass, Redact, marks AlreadyInspected)
and refused on stdio (PreserveInputRequired) (MIK-8155); a blocked interim
answer's refusal happens where no async slot release can run (MIK-8131).
A2A (MIK-8112) is outbound only: an A2A agent is a backend whose reply the
translator turns into an MCP result (`a2a/translator.rs`), so it is covered
exactly when tools/call results are; it needs a proving row, not a code path.

## Design

### E1. One function decides what a frame is and how it is scanned

`MetaMcp::scan_egress(&self, frame: &mut JsonRpcResponse, at: &Egress<'_>) -> EgressOutcome`
in a new `meta_mcp/egress.rs`. `Egress` carries targets and correlation (who,
which backend, which method). It owns, in one place:

- **Parts.** A frame carries `result` or `error`, never both. `result` is
  inspected whole (every string leaf and key, as today: content items,
  `structuredContent`, A2A parts after translation, catalogue bodies). `error`
  is inspected as the artifact `{"message", "data"}`; a redaction is written
  back, a redaction that leaves no text message is a Block.
- **Policy per part, not per caller.** `result` that is an interim answer
  gets `PreserveInputRequired`: a finding inside the question or the handle
  refuses rather than rewrites. Every other part gets `Redact`. No caller
  passes a policy, so HTTP, direct, stdio and the task path cannot disagree
  (MIK-8155). "Interim" is not a second detector: `ResponseMutationPolicy::for_result`
  sits beside `protected_value_changed` (`security/firewall/response.rs:141`)
  and reads the same two top-level keys from one constant. Both eras carry
  them top-level (`invoke.rs:628`, `continuation.rs:117`, `chain_interim.rs:131`);
  `shape_modern_response` runs before `finalize_content` and does not move
  them, which the interim rows check on both eras.
- **Checks.** Response firewall on every part. D2 content inspection and
  context integrity on parts no dispatch gate already ran on (errors, catalogue
  results); a tools/call result already went through
  `apply_response_gates_effect` on both routes, and running D2 twice would
  annotate twice. The dispatch gate marks its response `content_gated`.
- **Outcome.** `Delivered | Rewritten | Refused { hold_key: Option<String> }`.
  `Refused` replaces the frame with the existing delivery refusal (-32600,
  "Response blocked by security firewall") and hands back the interim answer's
  in-flight hold key, read before the frame is replaced.
- **Once per frame.** `JsonRpcResponse::egress_scanned` replaces
  `discovery_inspected` and `DeliveryInspection::AlreadyInspected`; a marked
  frame is returned untouched. Discovery's canonical-value pass sets it. A
  delivery refusal is born marked. This keeps NFR.WORKLOAD.1 (one inspection).

### E2. One call per route exit, everything else deleted

| Route | The one call | Deleted |
|---|---|---|
| HTTP `/mcp` and stdio | `finalize_content`, for every method (the `tools/call` / `tools/list` filter goes) | `response_pass.rs` pre-pass, `handlers.rs:1768` block |
| `/mcp/{name}` | each of the 4 exits below, before `settle_direct_idempotency` (a replay serves the scanned copy) | `response_blocked`, `scan_direct_tools_list_response`, `screen_backend_response` |
| tasks | `inspect_settled` (stored result is the scanned one), watch poll, upstream recovery | `inspect_task_result` body becomes a call |

The direct route has 11 `build_http_response` calls under
`router/backend_handlers/`. Five, in 4 exits, carry backend-derived text and
take the scan:

1. `direct_dispatch.rs` `deliver_tail`: every success, the plain arm, the
   sanitized arm (`forward_sanitized` also ends in `finish_response`) and a
   cached replay.
2. `direct_failure.rs` `DirectFailure::answer`: a failed dispatch, from
   `answer_failure` and from `key_check.rs` (its `Err` arm). A cached failure
   (`direct_dispatch.rs:245`) replays what this exit settled, already scanned.
3. `key_check.rs:42` `Ok(Some(text))`: the undeclared-key refusal text.
4. `direct_caller.rs:437`: a failed notification forward answers with
   `e.to_string()`, which for a backend JSON-RPC error is the backend's text.

`direct_dispatch.rs:245` replays a failure exit 2 settled. The other 5
(`direct_caller.rs:231`, `direct_dispatch.rs:211, 274, 341`,
`direct_preflight.rs:151`) build gateway-own refusals before any dispatch. The completeness test (below) source-scans the directory and
fails on a new exit that neither scans nor is on that list.

Rejected: a `Scanned<JsonRpcResponse>` newtype that `build_http_response`
alone accepts. It is the stronger proof, but `build_http_response` has 17
callers across the router and the stdio writer has its own; the source-scan
test gets the same guarantee for this family at a fraction of the diff.

Kept as they are, because they are a different artifact, not a frame part:
the bridge challenge (Immutable, a question the gateway asks), event payloads
(notifications have their own kind and outbox), discovery's canonical value
(scanned before serialization, then marked).

Targets for methods other than tools/call: `(backend, method)` for a catalogue
read (as `BackendCall::catalogue`), `(gateway, method)` for the gateway's own
methods. Gateway-own frames are scanned too (no exemption list: an exemption
list is the defect); rows assert they come out unchanged.

### E2b. Notifications a backend streams during a call

A fifth unscanned frame, found by the frame inventory: `notifications/*` an
HTTP backend streams on its response, and `notifications/progress` from a
stdio or WebSocket backend, reach the `/mcp` and stdio clients verbatim
(`params` whole: `message.data`, `progress.message`, any custom method). The
only checks are the level filter and the tenant judge, which is a cross-tenant
read check, not a content scan. All three paths pass through
`transport/notification_sink.rs` (`publish` :148 and the progress deliver
:232). The direct route drops notifications (`backend_handlers.rs:382`).

Fix at that one point: the sink's task-local scope, opened by `POST /mcp` and
the stdio server, also carries the egress scanner (firewall handle plus
correlation). Each notification's `params` is inspected as its own artifact
(a new `ResponseArtifactKind::Notification` variant for the audit log, `Redact`); a Block drops the frame and
counts it, as a full sink does. A notification is never delayed by a call
into the async world: the scan is synchronous, as `check_response_artifact` is.

Not frames for this family, with the reason:

| Frame | Why it stays |
|---|---|
| Bridged `sampling/createMessage`, `elicitation/create`, `roots/list` | Already scanned, `Immutable`, before each round (`bridge_dispatch.rs:185`) |
| `tools/list_changed` | Constant frame, no backend text |
| Upstream listen notes | Webhook only, scanned at `events/fanout.rs:149` |
| `notifications/tasks` | Carries the stored result, scanned at settlement |
| Gateway `emit_log` | Gateway-built text |
| Server-to-client requests a backend sends itself | Refused and dropped (`stdio.rs:545`, `sse_decoder.rs:268`) |

### E3. MIK-8131

`finalize_content` returns the `Refused` hold key; the async HTTP and stdio
callers free that slot with the release helper #3451 (MIK-8078, open) adds.
That piece lands after #3451 merges; until then the row is written and red.

## Test plan (red first, on #3527)

One table test, `egress_matrix_tests.rs`:

- Routes: HTTP `/mcp` (gateway_invoke and native method), `/mcp/{name}`, stdio
  dispatch, task settle then `tasks/get`, an A2A backend through `/mcp`.
- Methods: derived, not typed: every arm of the HTTP `/mcp` dispatcher,
  `stdio_catalogue::METHODS` and the stdio arms, and the direct route's
  forwarded methods. That includes the list methods (prompts/list,
  resources/list, resources/templates/list), whose descriptions are backend
  text.
- Notification rows: a backend streams `notifications/message` and
  `notifications/progress` with a credential mid-call, over HTTP and stdio
  backends, to `/mcp` and stdio clients; the secret never arrives.
- Parts: result content text, a non-content result leaf, error.message,
  error.data, a failed dispatch, interim `inputRequests`, interim
  `requestState`, an A2A data part.
- Each cell: the backend plants a credential in that part. Assert the secret
  never reaches the caller, the outcome (redacted vs refused) is the same on
  every route for that method x part, and the backend was called once.
  Interim cells assert refused (MIK-8155) and no in-flight slot held (MIK-8131).
- Clean cells: the same frames without a secret come out byte-identical.
- Completeness: a source scan lists every method arm of the HTTP and stdio
  dispatchers and the direct route and fails if one is missing from the table,
  so a new method cannot skip the scan.
- Single inspection: the inspection counter reads 1 per frame on every route
  except tasks, which read 2: once at settlement (the stored result every
  read sees) and once at delivery. Kept on purpose: the stored row outlives a
  config reload, and the second pass over already-redacted text is a no-op
  rewrite. Marking a stored row would need a persisted flag for no safety gain.

Mutants: parts dropped one at a time, the interim policy flipped to Redact,
the egress call removed per route, the mark ignored.

## Risks

- Gateway-own text tripping a detector (false positive on `initialize`
  instructions). The clean rows catch it; the fix would be the detector, not
  an exemption.
- File ceiling: `relay.rs` and `backend/ops.rs` are at 800 lines; the new
  module takes the code the deletions free.
- #3451 ordering for E3, above.

## Acceptance criteria to rows

| Ticket | Criterion | Row(s) | Closed by #3527 |
|---|---|---|---|
| MIK-8139 | error text screened, both routes, one dispatch | error.message, error.data, failed dispatch x every route | yes |
| MIK-8146 | CATSCAN.1 same firewall + D2 for prompts/get, resources/read | catalogue methods x result x routes | yes |
| MIK-8146 | CATSCAN.2 red rows per route, clean body unchanged | same, plus clean rows | yes |
| MIK-8155 | POLICY.1 same outcome for interim answers on every route | interim inputRequests / requestState x routes x eras | yes |
| MIK-8155 | POLICY.2 completed answer keeps Redact | completed result rows | yes |
| MIK-8112 | AC1 A2A reply scanned like an MCP result | A2A backend x tools/call x text and data parts | partly |
| MIK-8112 | marked untrusted, cannot trigger a privileged call, ADR-001 vs OWASP doc | none here | no: stays open unless scoped in |
| new (filed with this design) | backend notifications streamed mid-call scanned | notification rows | yes |
| MIK-8131 | FW.1-FW.3 blocked interim answer frees only its slot | interim refused rows assert `in_flight().len == 0` | after #3451 merges |
