# Firewall response enforcement

Status: design and test plan approved by independent GPT and Grok reviews on
2026-09-06; executable tests are in progress and implementation remains pending. Release owner:
Codex integrator.

## Scope and value

FOR: make an enabled response firewall's Block decision prevent disclosure on
the existing HTTP and stdio tool-result and tool-discovery surfaces, scanning
each final response once and applying any refusal before message signing.

This is a required P1 repair within full 4.0 delivery. The mandate is the
operator's instruction to close all release gaps, the existing firewall action
contract, and response integrity. It is not a new optional release feature.
Tracked delivery issue: [MIK-7407](https://linear.app/parm/issue/MIK-7407/40-enforce-response-firewall-block-on-every-served-result).
The benefit is concrete: a response recorded as blocked must not be returned to
the client. Security-mandated work does not use an invented revenue estimate.

Authorization context is the existing 4.0 scope discussion and the operator's
explicit handoff: "now you are taking over the mcp-gateway 4.0 release delivery"
and "close all the gaps, implement everything needed for that release" under the
development process and DoD. The release integrator assigned this P1 repair and
approved the shared response boundary and signing/Tasks dependencies. The
remaining choices here implement that mandate: retain existing error/request
semantics, preserve discovery rules, enforce existing Block, and choose the
existing firewall error family. They do not resolve an unasked business-policy
preference. No new requester decision or repeat approval is required for those
engineering choices; a new intent/policy tradeoff would return to the operator.

OUT: changing request-firewall rules, caller identities or authorization;
changing injection patterns or credential recognition; new signing algorithms;
undoing a completed backend action; scanning JSON-RPC error data; new resource,
prompt or task methods; repairing every NFR.SEC.1 inventory row. Tasks that later
return retained tool results must reuse the final-response enforcement boundary
as part of the task increment; this document does not claim that integration.

The request-firewall fifteenth control in
`docs/requirements/nfr-sec1-control-inventory.md:98` remains separately open.
This finding predates 4.0: the v3.5.0 meta HTTP and direct handlers ignore the
same response verdict. Do not describe it as a new modern-protocol regression.

"One inspection" here means one invocation of the Firewall response-inspection
pipeline per artifact. Existing D1 response-contract, D2 response-inspection and
context-integrity policies remain distinct controls and are not removed or
represented as duplicate calls to this Firewall pipeline.

## Readiness and measured constraints

The ticket's stable acceptance IDs map one-to-one to local release aliases
`NFR.RESPONSE.1` through `.5`; all are traced to `NFR.SEC.1`'s firewall
population and final response integrity. These aliases are not duplicate
obligations and do not replace the baseline criterion. Tests and ticket closure
use `MIK-7407.RESPONSE.*`; the integrator carries the evidence into the release
acceptance record without claiming the separate request-side control passed.

| ID | Required outcome |
|---|---|
| MIK-7407.RESPONSE.1 | Given a response Block verdict, delivery produces a generic JSON-RPC error with the original request ID, no result, and no blocked payload or finding fragment. |
| MIK-7407.RESPONSE.2 | Given any existing meta/direct HTTP or stdio tool-result or discovery path, its completed response enforces the same response verdict. |
| MIK-7407.RESPONSE.3 | Given enabled response scanning, each final response is inspected/redacted once and emits one response audit event, including multi-target responses; strongest applicable decision wins. |
| MIK-7407.RESPONSE.4 | Given Allow, disabled scanning, Warn or permitted redaction, existing documented behavior is retained; existing request-firewall semantics remain unchanged. |
| MIK-7407.RESPONSE.5 | Given enabled signing, refusal/replacement and redaction precede signing; a blocked response is unsigned and a signed allowed result verifies over the exact final value. If transparency logging is enabled, one delivery-attempt record hashes the final JSON-RPC output after signing without claiming client receipt. |

Observed in the delivery worktree before this change:

- `Firewall::check_response`, `src/security/firewall/mod.rs:610–664`, scans,
  redacts, resolves an action, sets `allowed = action != Block`, then audits.
- Four production consumers ignore that Boolean: HTTP meta
  `router/handlers.rs:1194`, direct call `router/backend_handlers.rs:942`, direct
  list `:989`, aggregated discovery `meta_mcp/mod.rs:757`.
- The HTTP meta consumer loops over request-derived backend targets and scans
  the entire response repeatedly. Aggregated discovery scans inside four
  `search.rs` paths (`:600,629,707,781`) before response wrapping.
- `Gateway::dispatch_single_with_sink`, `server/mod.rs:1830`, invokes the common
  MetaMcp tool dispatcher for stdio but has no response scan. `build_meta_mcp`
  already attaches a firewall at `:742–762`, so stdio needs no new config path.
- `router/authorization.rs:19` already extracts targets for surfaced tools,
  `gateway_invoke` and Code Mode. Other meta-tools currently yield no targets.
- `Firewall::resolve_action` uses first matching rule for a tool only when
  findings exist, otherwise Allow; default High/Medium/Low means Block/Warn/Allow.
- Existing firewall integration tests call the engine directly. Existing
  discovery scanner tests prove redaction/no-op, not served Block enforcement.

These are source observations, not execution evidence. A runtime baseline is
scheduled below; the current tree also contains unrelated intentional test reds.

## Chosen response boundary

One shared crate-private `MetaMcp::finalize_response_for_delivery` takes a complete
`JsonRpcResponse` and server-owned delivery context. The context carries the
actual external operation, response policy targets, correlation and the already
validated request nonce/origin needed by the signing owner. No payload field can
select a bypass or forge the signing origin. The operation owns this order:

1. Its adapter first completes all body-producing work: normal dispatch wrapping,
   direct normalization/provenance, pure modern response shaping where applicable,
   and final caller request-ID restoration.
2. The shared finalizer calls `enforce_firewall_response` once for covered tool
   results/discovery. Its exact scan allow-list is RPC tools/call and tools/list
   only; list/search
   meta-tools are covered inside tools/call with the discovery target mapping.
   initialize, ping, resource/prompt operations are not Firewall scan targets.
   This internal operation mutates the final result or replaces
   it with the generic refusal. Errors/no-result skip Firewall inspection. Disabled
   or absent Firewall is a no-op with no response inspection/audit.
3. Only literal external gateway_invoke origin calls the signing owner's
   `finalize_gateway_invoke_response` primitive, consuming the final allowed,
   redacted or refused response. Errors/no-result remain unsigned.
4. A signing primitive failure replaces the whole output with code `-32603`,
   exact message `Response signing failed`, preserved final ID, no result and
   no error.data. Increment the signing-failure metric without exposing payload
   or canonicalization details.
5. Record the immutable final delivery-attempt hash, then return the completed
   response to mutation-free transport serialization. No scanner, shaper or
   content/provenance writer follows the finalizer.

The Firewall owner implements the shared ordering helper and enforcement. The
signing owner implements the signing primitive and pure modern-shape extraction.
Root serializes overlapping HTTP/stdio/builder hunks and CONTROL.3 integration.
`build_modern_response` currently changes resultType, cache hints and
_meta.serverInfo at `router/handlers.rs:1404–1461`; those changes must become pure
pre-finalization shaping. Its final serialization path must not add those fields
after scanning/signing/hashing. A modern response with pre-populated metadata is
not evidence that this real late-shaping path was exercised.

The two production MetaMcp tools/call consumers are HTTP
`router/handlers.rs:1173` and stdio `server/mod.rs:1839`. Each waits for the complete
raw dispatcher response, shapes it, and enters the common finalizer once. This
catches every surfaced/retry/cache/idempotency return without extracting a new
`handle_tools_call_raw` wrapper. `handle_tools_call`, internal `invoke_tool`, raw
list builders and intermediate search helpers do not scan final external output.
Remove the old HTTP postscan and four aggregate-discovery scans. A direct call to
the raw dispatcher is not evidence of served response enforcement or signing.

Standard tools/list uses the same finalizer after HTTP's URL/filter shaping or
stdio's list building. Direct HTTP normalizes lists and stamps applicable
provenance first, then uses the same finalizer. The direct tools/call branch
trigger is `!backend.passthrough()` passed to request sanitization: sanitized
early return at `backend_handlers.rs:797` versus passthrough fallthrough at `:850`.
Both independently support forwarded headers/identity; those are orthogonal
fixture dimensions. Neither direct result branch may serialize before finalization.

Keep feature-on and feature-off implementations of the Firewall operations with
the same boundary contract. The shared finalizer's signing and transparency calls
remain outside the optional Firewall gate. Construct one `Arc<Firewall>` from the
existing evaluated config/license decision and reuse it in MetaMcp and AppState;
do not retain separate request/response engines or audit writers. Request checks
and budget semantics remain unchanged. The builder hunk is coordinated with
MIK-7406 signing and session-expiry changes.

The coordinated [MIK-7377 signing design](2026-09-06-mik-7377-message-signing.md#delivery-and-authenticated-envelope-version-2)
removes the old miss-only invoke_tool_traced signing block. The version-2 MAC
covers the final delivered result with only top-level _signature removed,
including wrapped content text and _meta, and binds the typed outer request ID.
No inner JSON copy is reparsed/signed. Named/internal origins remain unsigned.
The finalizer signs after pure modern shaping and the final Firewall decision;
reinstating inner signing or late shaping would violate MIK-7377.SIGNING.3.

This boundary does not change pre-dispatch authorization or request checks. It
does not represent a backend side effect as cancelled: a withheld result may
follow an already completed effect, and the refusal introduces no automatic replay.

Task integration is an explicit dependency: the Tasks owner must enforce the
completed retained backend result through the same secured finalization before
disclosure. Scanning a task-admission acknowledgment does not scan the later
backend result, and must not be recorded as doing so. Transport-delivery scans
must not re-scan an already finalized retained result; task lifecycle ownership
must designate its single finalization point and test it before task acceptance.

### Refusal provenance and client accounting

Add a distinct server-only `JsonRpcResponse.delivery_refusal` marker, following
existing confirmation_refusal's serialization protection. It is skipped when
serializing and explicitly initialized false by the custom Deserialize and
ordinary response constructors. Backend JSON fields, messages or error codes
cannot set it. The finalizer sets it only when it itself withholds a response
for Firewall policy, invalid target wiring, immutable-challenge mutation or a
signing failure; it preserves a previously set trusted marker. One crate-private
JsonRpcResponse::delivery_refusal_error constructor creates marked errors for
both finalizer and typed Error projection. A shared excludes_client_accounting
predicate owns the confirmation_refusal OR delivery_refusal check. Neither is
callable through request data.

The challenge helper returns dedicated `Error::ResponseFirewallRefused` with the
exact message `Response blocked by security firewall` and -32600 mapping. Bridge
adapters preserve this typed error;
`error_response_preserving_status` projects it into the exact generic refusal,
no error.data, and the trusted delivery_refusal marker. Do not flatten it to
Error::JsonRpc or recognize it from remote text. This is the only new error
projection seam; preexisting D1/D2/context and request errors keep their behavior.

For HTTP meta and both direct response branches, finalization precedes client
outcome accounting. If confirmation_refusal or delivery_refusal is set, skip BOTH
record_client_failure and record_client_success. A security refusal neither
adds a client strike nor erases existing strikes. Other dispatch outcomes keep
existing accounting. Telemetry records the final wire error independently from
client blame. Stdio carries the same trusted marker internally but has no HTTP
client breaker. Serialization and attempt hashing omit both internal markers.

FWR-01/FWR-03 require repeated blocked backend outputs under a small configured
failure threshold without client lockout, plus a seeded nonzero-strike control
proving refusals do not reset prior failures. An ordinary backend error whose
wire payload spoofs delivery_refusal must still follow ordinary failure
accounting. Signing failure has the same no-strike/no-reset control in FWR-13.
Error/response-type and shared adapter hunks remain coordinator-serialized.

### Bridge challenge admission dependency

The bridge's `MIK-7212.WIRE.21` admission gate owns D1/D2/context policy before
any client question or retry. Its client-visible challenge must not bypass the
same configured Firewall. The exact shared crate-private interface is:

```rust
pub(crate) struct ResponsePolicyTarget {
    pub server: String,
    pub tool: String,
}
pub(crate) struct ResponseCorrelation<'a> {
    pub session_id: &'a str,
    pub caller: &'a str,
    pub external_server: &'a str,
    pub external_tool: &'a str,
}
// MetaMcp method; crate::Result uses the existing gateway Error family.
pub(crate) fn enforce_firewall_challenge(
    &self,
    challenge: &serde_json::Value,
    targets: &[ResponsePolicyTarget],
    correlation: &ResponseCorrelation<'_>,
) -> crate::Result<()>;
```

Types are available through MetaMcp-module re-exports in feature-on and
feature-off builds; proposed owned module is `meta_mcp/response_security.rs`.
The feature-off method is a no-op, leaving the distinct D1/D2/context policies
intact. Correlation supplies the operation without a duplicate method argument.
Callers derive it from the authenticated dispatch context, not challenge fields.

`challenge` is the full client-visible `inputRequests` Value, including every
raw question field; opaque backend `requestState` is excluded. The helper runs
the shared Firewall once on a clone. Block, an invalid target mapping, or any
required mutation/redaction refuses with the established generic security error;
Warn/Allow passes only an unchanged challenge. Do not silently change the backend
question. Reduce the immutable-challenge constraint into the final action BEFORE
the one audit event, so a refused redaction is not falsely logged as Warn/Allow.
No challenge signature, delivery-attempt log, or raw question in error data is
created here.

The artifact kind is server-derived: this helper emits `bridge_challenge`, while
the external response boundary emits `final_response`. Only internally consumed
legacy bridge prompts use this helper. A modern InputRequired returned as an
external result uses the external response boundary once, not both paths.
At that one external scan, inputRequests and opaque requestState are immutable:
scan a clone of the final shaped result, and reduce any required mutation of
either protected value into Block BEFORE the one final_response audit. An
allowed modern response preserves both exactly. Legacy challenge input excludes
opaque state; no second bridge_challenge scan is introduced for modern delivery.
Bridge D1/D2 use meaningful canonical challenge text rather than the existing
`extract_text_from_result`, which returns empty for bare inputRequests; the
context policy also admits the question before exposure. Their observe/action
behavior and completed-effect idempotency checkpoint remain bridge-owned.
WIRE.21 proves zero client frames, pending IDs and retries on first refusal, and
zero further prompt/retry after a blocked later challenge. FWR-20 proves the
shared helper's real engine behavior; a final-result FWR-02 pass is not challenge
evidence. Both increments stay blocked on their own reviewed tests.

### Policy targets and a single scan

Reuse the existing target extractor, moving its read-only extraction responsibility
to a shared crate-private location if needed; keep request authorization callers
and semantics unchanged. Deduplicate `(server, tool)` target pairs. For direct
calls use their real backend/tool. Sealed retry targets come from the validated,
server-authenticated continuation's original backend/tool, never from its opaque
retry tool name or caller-provided replacement fields. This target projection is
part of the bridge dependency and FWR-02's exact-rule retry test. Discovery
takes precedence over the ordinary
extractor and fallback: every standard or direct `tools/list`, aggregate
`gateway_list_tools`, `gateway_search_tools` and Code Mode `gateway_search`
response uses the existing logical `tools/list` policy target. For a
non-discovery meta call with no extracted target use its external meta-tool name
as a logical target. This defines the previously
unscanned population without pretending that request parsing knows every dynamic
playbook step. Rules for those results match that logical external tool; discovering
all dynamically executed tools is outside this bounded repair. Operators who
want a Block rule for playbook output must match `gateway_run_playbook` (or the
actual external meta-tool name); inner backend tool rules are not inferred for
such unextracted results. This limitation must accompany operator-facing docs.

Split response scanning from policy reduction inside the existing Firewall
implementation: gather injection/credential findings and redact the result once;
resolve the same findings against each distinct policy target using the existing
per-tool rule semantics; combine Block before Warn before Allow. One Allow cannot
override another applicable target's Block. Reuse the scanner and redactor;
introduce no second pattern engine. The original public single-target
`check_response` delegates to this implementation with one target, preserving its
API and behavior for existing consumers/tests. An empty policy-target vector is
an internal wiring defect, never an Allow fold over no rules: the dispatcher must
supply discovery or logical fallback. The reducer returns an explicit invalid-target
error before inspecting an empty-target input; the enforcer emits the same generic
refusal without exposing content. Record a diagnostic warning, not a malformed v2
response-audit event with an empty array. Unit tests pin this error and public
fallback tests prove every valid route supplies nonempty targets.

Audit once using the external operation as the event's server/tool correlation
label and the final combined verdict. Include the distinct policy targets as a
structured `policy_targets` field in the response audit record, preserving the
current fields for existing readers. Exact response-audit v2 shape adds
`"schema_version": 2`, server-derived `"artifact_kind": "final_response"` or
`"bridge_challenge"`, and `"policy_targets": [{"server": "...", "tool": "..."}]`;
each element has only those two string fields. Sort the array lexicographically
by `(server, tool)` after deduplication. The array is present and nonempty for
every enabled v2 response event; it is not an omitted/empty Allow signal. Old
response events without these new fields remain version 1. Request events omit
all three fields and retain their existing schema. Disabled response inspection emits
no response event. Discovery uses the logical target `(gateway, tools/list)` for
aggregate/standard gateway lists and `(backend-name, tools/list)` for direct
lists; ordinary actual backend targets and non-discovery `(gateway, external-tool)`
fallback remain explicit. Never include response values, request arguments or new
raw secret fields in this metadata. Request audit emission stays unchanged. Tests count only
response events, not request+response totals. The reducer's targeted unit tests
prove per-target policy; public route tests prove audit and enforcement. Add a
per-Firewall test-only observation seam at the actual response inspection and
configured detector/redactor invocation points. It observes the real engines,
never replaces them or supplies a verdict. Unit/dispatch tests require one
inspection per final response and one invocation per enabled detector/redactor;
disabled engines require zero. Keep counters instance-local and isolated between
tests. Real spawned-stdio tests additionally verify one response audit event;
the observation seam must not become a production bypass or global deduper.

### Refusal and error shape

On Block replace the entire result with `JsonRpcResponse::error` using the same
ID, code `-32600`, and fixed message `Response blocked by security firewall`.
Do not insert the original result, scanner matches, rule reason, backend error or
signature into `error.data`. HTTP follows the existing JSON-RPC response transport
status behavior; this increment adds no status stamp inferred from the code.
For the covered meta/direct HTTP tool-result and discovery fixtures, that means
HTTP 200 with the generic JSON-RPC error, pinned explicitly in FWR-01/FWR-03/04.
This does not change other authorization refusals that already carry HTTP status.
The code is a gateway security-policy refusal consistent with its existing
firewall family; it does not assert that the incoming JSON was malformed.

Warnings remain allowed and logged without echoing match fragments to the client.
Redaction is still in-place before allowed output is serialized; an explicit Warn
or Allow override can permit a redacted credential finding. A Block rule with no
findings remains Allow, as it is today.

### Transparency records describe the correct stage

`invoke.rs:1832–1852` currently hashes an inner value while its comment claims
the caller's actual received response. Preserve these per-target invocation
records and their existing schema/hash semantics, but correct documentation and
comments: they record the backend/inner invocation stage before outer wrapping,
firewall enforcement and signing. Do not remove internal target accounting or
rewrite historical log entries into claims they never established.

The release integrator selected a separate delivery-attempt event, reusing
`TransparencyLogger::append_event` (`src/security/transparency_log.rs:257`).
Proposed shared operation `MetaMcp::record_response_delivery_attempt` takes the
final immutable `JsonRpcResponse` and existing caller/operation/correlation
metadata. It appends `event = "response_delivery_attempt"`,
`response_stage = "transport_finalized"`, `response_hash_encoding = "sorted-json-v1"`
and `response_hash = "sha256:" + sha256_hex(to_vec(to_value(response)))`
to the existing hash chain. `sorted-json-v1` means the repository's existing
deterministic JSON-value serializer, not RFC 8785; it includes the final ID,
result or error, and final signature when present. For a stdio batch, emit one
event for each actual response item, hashing that item exactly; batch assembly neither re-scans
nor emits a second event. Notifications without responses have no response scan
or delivery-attempt record. No raw response, credentials
or match fragments are added. Test the digest with an independent calculation
over the parsed final output, including a redacted success and a Block refusal.
Use checked `serde_json::to_value`/`to_vec` results; do not use an empty-string
fallback as evidence of a finalized response. Encoding failure follows the
existing nonfatal log-warning path without appending a false hash record.

No event is emitted when transparency logging is disabled. Append failures keep
the existing nonfatal transparency-write behavior: warn without response values;
do not replay or rewrite the finalized output. The event proves what the server
attempted to send, not client receipt or durable acceptance. Separate transport
outcome evidence may be linked if an existing mechanism reports it; neither
serialization nor a successful write is relabeled as receipt. CONTROL.3 release
acceptance remains integrator-owned and must consume this stage distinction.

## Alternatives and risks

- Add `if !allowed` to every old caller: smaller initial diff but leaves stdio
  unscanned, aggregate behavior inconsistent and multi-target duplicate scanning.
- Scan every backend result inside `invoke_tool`: fails to cover discovery and
  final wrapping, risks multiple scans of aggregated content and signing stale data.
- Replace Block with Warn or redact everything: changes policy rather than
  enforcing it; rejected under the full-scope release instruction.
- New middleware scanner: cannot see stdio and duplicates existing patterns.

STRIDE: preserve caller/request IDs rather than attributing a result to a UI
label; do not allow a target's Allow to downgrade Block; log the combined verdict
once; remove payload/fragment disclosure; avoid repeated scans on multi-target
responses; preserve the existing authorization boundary and licensed firewall
feature. No new crypto, dependency, durable store or global state is required.
The signed-result ordering is checked jointly with the signing increment.

Risk/cost: moving finalization changes early-return control flow and list paths.
The planned touch set is firewall engine/audit, MetaMcp dispatch and search,
shared target extraction, HTTP direct/meta dispatch and stdio dispatch, plus
focused tests. This is a critical security slice. Sequence scanner/reducer and
boundary-wiring commits, keeping each reviewable; expected implementation effort
is moderate because it reuses all detection machinery. No calendar or measured
LOC claim is inferred from this estimate.

## Scheduled checks and DoR

| Unknown/check | Owner, trigger, resolving result and fallback |
|---|---|
| Does the route release a response that the engine blocks? | MIK-7407, first test stage: counted-backend fixture through meta/direct HTTP and stdio; require an assertion-level red with backend count 1 before refusal implementation. A request rejection or timeout is not the baseline. Fix fixture if it never reaches response enforcement. |
| Can any adapter bypass or duplicate finalization? | MIK-7407, before adapter wiring: verify the enumerated production consumers and assert one final_response inspection/event for Code Mode/playbook/surfaced/ordinary/cached/stored calls. Internal dispatch remains raw; add any newly found external adapter to the matrix and block its wiring until its test is reviewed. |
| Can transport shaping mutate a signed/hashed value? | MIK-7407 and MIK-7406, before modern HTTP finalization wiring: run actual modern resultType/serverInfo/cache-hint shaping before the common helper; independent wire signature/hash must match after it. A mismatch blocks that integration; do not solve it by pre-populating a fixture or repeating shaping after signing. |
| Does body wrapping preserve redacted semantics and signatures? | MIK-7407 and MIK-7406, before final review: public result parsed and signature verified after redaction; failure blocks signing/firewall integration. |
| Does transparency describe the actual final output? | MIK-7407, MIK-7406 and MIK-7215.CONTROL.3, before their combined finalization integration: independent final-response hash for redaction/refusal/signed success must match exactly one delivery-attempt event while per-target invocation records remain. A mismatch blocks integration; a write failure preserves the existing warning path and never claims a receipt. |
| Does sealed retry return through the secured boundary? | MIK-7387/MIK-7388 and MIK-7407, before FWR-02/bridge acceptance: drive the actual sealed retry named-tool return with a counted dangerous backend result; require one scan/audit and refusal. If the bridge fixture is not ready, keep FWR-02 retry coverage pending and block that bridge acceptance, never infer it from surfaced-tool coverage. |
| Can a bridge question escape before policy admission? | MIK-7388 / MIK-7212.WIRE.21 and MIK-7407 / FWR-20, before any bridge send/retry implementation: D1/D2/context and real Firewall challenge refusal must produce zero client frame, pending request or retry. Later-round refusal stops further exposure. Unavailable fixture blocks bridge admission implementation; no final-only scan is accepted as evidence. |
| Where are retained task results finalized? | MIK-7407 with Mikko Parkkola as accountable release owner, before task-result implementation/acceptance: designate one stored-final-result enforcement point and demonstrate dangerous completed output is withheld, benign output delivered, admission acknowledgment not counted as backend-result evidence, and subsequent retrieval not re-scanned. If lifecycle ownership cannot prove this, retain the result undisclosed and leave Tasks acceptance pending. |
| Does optional audit metadata preserve old fields? | MIK-7407 component-test review verified no production Firewall audit reader exists in this repository. A strict typed v2 test consumer validates exact additive fields; a typed consumer of the existing eleven fields parses untouched v2 output and a fixed v1-schema golden event. This is a regression model of the emitted schema, not evidence about an external deployed reader. |

Design readiness: requirements, scope, owners and discriminatory tests are
specified; request-side work is explicitly separate. Canonical DoR B1–B5 is the
backlog checklist, not the separate DoD Agent Stack Bets checklist.

| Canonical DoR | Evidence and status |
|---|---|
| B1 issue | MIK-7407 exists, UUID `a03cac25-59fc-4ec7-a5db-6e160fe52bdf`; created and read by release integrator on 2026-09-06. |
| B2 fields | In Progress, High (2), estimate 5, assignee Mikko, project mcp-gateway, team Mikko (`1201daa3-35d8-4d9c-8700-1a131346902e`). Labels are verified `[]`: N/A because no mandatory project label was identified. Release integrator independently verified get_issue fields and existing v4.0.0 milestone (`de21432a-e3bf-41fe-b51c-1c1c10437d29`) in authenticated Linear UI on 2026-09-06. No active team cycle exists, so cycle is N/A. |
| B3 dependencies | Signing MIK-7406/MIK-7377 consumes this boundary; bridge MIK-7387/MIK-7388 owns the retry/stdio integration fixture; Tasks owns retained final results. Issue description records dependencies and release order. Standalone safety issue: parent N/A, not a duplicate or unrelated portfolio child. |
| B4 acceptance | MIK-7407.RESPONSE.1–5 above map to named FWR cases. Integrator independently verified the exact description checkbox IDs and local aliases on 2026-09-06; local aliases are not used as substitute ticket evidence. |
| B5 position | Required P1 security repair in the 4.0 release delivery order; integrator visibly verified Set milestone → existing v4.0.0 in authenticated Linear UI on 2026-09-06. |

Additional applicable DoR evidence (design-stage declarations do not stand in
for pending runtime checks):

| Gate group | Evidence / applicability |
|---|---|
| G0–G5 | Required P1 security repair under the full 4.0 mandate; positive disclosure-prevention outcome, bounded scope, alternatives and cost estimate below. NPV/ROI follow the mandate exemption. |
| T0–T5 | Existing Rust infrastructure/security class; reuse the actual firewall, scanner, redactor, JSON-RPC types, target extractor and transparency append primitive at cited source paths. Considered a second middleware/pattern engine and rejected it because it cannot cover stdio and creates duplicate semantics. No new framework, crypto primitive or dependency is selected; framework novelty and PQC change gates are N/A. |
| G6–G12 | Alternatives, failure risks and ordered checks above. Highest-risk check is counted public response refusal; source evidence is recorded, its runtime discriminator remains scheduled before dependent implementation. Reviewer/source analysis is not claimed as a passing runtime test. |
| G13–G14, G18, G20–G21 | Novel-capability/moat, emerging-tech kill metric, performance-only profiling and novelty claims are N/A to this mandated repair. Existing gateway policy reuse is the platform benefit. |
| G15–G17, G19 | Premortem: bypassed early return, wrong policy target, stale signed/hashed content. Mitigations are the common finalizer, exact-rule matrix and final-output verification. Existing source is authoritative prior art for this repair; no external market/comparison claim. Changes are reversible code/config behavior with no schema migration or new one-way deployment. Outcome: Block discloses no result on every listed surface. |
| C1–C6, C8–C12, C14–C15 | Shared boundary and scanner, scoped source seams, protocol error contract, existing trusted caller metadata, STRIDE and test plan recorded. Split scanner/reducer and wiring into reviewable commits; no unrelated large-module refactor. GitNexus analysis precedes source-symbol edits. C13 is the explicitly deferred DoD mutation gate below. |
| C7, C16–C17 | One inspection avoids request-target multiplied work; actual overhead measured at integrated release gates. Existing ownership and backend timeouts remain; no replay or rollback is implied by response refusal. Failed audit append remains nonfatal under the existing logging contract. |
| P1–P8 | Existing audit/transparency channels, feature-off compatibility and request semantics retained; required route/signing regressions precede release. Existing firewall config allows disabling response scanning; this is a security-policy choice, not an automatic rollout fallback. No new service/SLO, persistent migration or capacity subsystem. |
| L1–L7, T6 | No new library/license, AI model, cross-border transfer, device processing, crypto primitive or numerical kernel. Existing license gating remains. Logs add hashes and structured targets only; existing finding-retention policy is not expanded. New dependency/SBOM work is N/A for this slice; repository-wide release checks remain root-owned. |
| O1–O4 | Two focused linked design documents and an existing tracked release issue; implementation updates the existing firewall/operator/transparency docs in its own change. No parallel ADR or duplicate release record. |

DoR accounting snapshot: the canonical file declares **84 total / 64 required**
but its named groups enumerate **72 IDs** (including C13, explicitly moved to
DoD). The review does not invent twelve unnamed gates or a missing required-ID
subset. This design records **51 design-evidence judgments, 18 justified N/A,
and 3 scheduled runtime checks** over those 72 named IDs; design evidence is not
an executed code-gate pass.

| Verdict | Named IDs | Evidence / reason |
|---|---|---|
| Design evidence (51) | G0–G10, G15, G17, G19; B1–B5; T0, T1, T2, T4, T5; C1–C6, C8–C12, C14–C17; P1–P4, P7–P8; L1, L2, L5; O1–O3 | E1: scope/ownership/contracts/risks ledger above. E2: cited actual engine/router/stdio/transparency sources and independently verified MIK-7407 tracker fields. E3: actual review-process receipts and document discriminator checks, explicitly not runtime proof. E4: these two frozen design/test-plan artifacts and their manifests. T1 considered a new middleware detector and formal policy modeling; both add machinery without covering a missing transport, while the existing total-order reducer can be pinned with real-engine/property tests. |
| N/A (18) | G13, G14, G16, G18, G20, G21; T1b, T1c, T3, T6; C13; P5, P6; L3, L4, L6, L7; O4 | No novel capability/moat, new selected technology, independent algorithm/third-party component, performance-only claim, numerical kernel, new service/SLO, persistent data migration, AI model/cross-border/device/crypto distribution, or irreversible decision. Existing-source reuse settles prior art for this bounded wiring repair; no market/arXiv claim is made. C13 is a DoD mutation gate, not waived. |
| Scheduled runtime checks (3) | G11, G12, C7 | MIK-7407 owns counted baseline and critical fixture discrimination before dependent production code; single-inspection counters before boundary wiring. Actual performance measurement belongs to the integrated critical-path gate. Until its dependent checks run, the corresponding code gate is pending, never silently passed. |

Summary: DoR security-mandate path; NPV/ROI N/A; estimated cost $2.40; canonical
nominal 84/64, auditable named population 72 with statuses above. Evidence classes
E1–E4 are all indexed in the ledger/review record. The SSOT count discrepancy is
reported to the release integrator; it is not redefined in this repository.

Readiness for source/test implementation is not yet certified by the
uncompleted review. Cost planning estimate for the next
design closure, test and code increments is 60,000 input plus 20,000 output tokens
including review overhead, $2.40 at canonical $15/$75 per million rates; this is
an estimate, not measured billing. Benefit follows the security mandate path;
deadline is before the 4.0 release gate closes.

For the distinct DoD Agent Stack Bets assessment, existing Rust/firewall/caller
types are reused (Bet 4), actor metadata stays platform-owned (Bet 1), no new
memory surface (Bet 2 N/A), and no new durable mission/task behavior is introduced
by this slice (Bet 3 N/A; the dependent Tasks increment owns that work). New language/framework,
emerging inference/crypto, numerical kernels and dependency-selection gates are
N/A: this fixes existing Rust control flow with unchanged primitives. Data/privacy
impact is reduced disclosure; existing response-audit finding policy is retained.
Canonical gate sources for review are
`/Users/mikko/.claude/rules-source/workflows/development-process.md`,
`/Users/mikko/.claude/rules-source/workflows/quality-gates-dor.md`, and
`/Users/mikko/.claude/rules-source/workflows/quality-gates-dod.md`.

Proceed through reviewed design, reviewed test plan, reviewed failing tests,
implementation, self-QA/improvement, two independent code-review legs and a
separate functional pass. Final implementation needs critical coverage/mutation,
fmt/clippy, relevant suite and all release gates; this document certifies none of
those executions. GitNexus impact analysis precedes source-symbol edits.

## Review record

Round 1 reviewed the actual design and test plan together, explicitly asking
both plan Q1 (coverage) and Q2 (non-vacuous falsifiability). All three wrapper
processes exited 0; authoritative ledgers record `process_status: ok` and
`SHIP-WITH-FIXES`. The canonical pair is GPT plus Grok; Kimi is additional
independent evidence, not a substituted required leg.

Identical scope: `Firewall response enforcement design and test plan v1`.
Scoped material: 76,850 bytes, SHA-256
`0c61dddc348533b5ca66db71f5535c9ac7c42aa644d84be750193c569eef0c07`
(wrapper convention: scope + NUL + actual payload).

| Vendor / observed model | Timestamp UTC | Authoritative ledger line | Run output |
|---|---|---|---|
| GPT / gpt-5.6-sol from CLI header; ledger codex-default | 2026-09-06T13:53:21Z | `/Users/mikko/.claude/data/gpt-review-ledger.jsonl:3169` | `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T134859Z-97931.md` |
| Grok / ledger grok-default | 2026-09-06T13:49:30Z | `/Users/mikko/.claude/data/grok-review-ledger.jsonl:1954` | `/Users/mikko/.claude/data/reviews/runs/grok-20260906T134016Z-75181.md` |
| Kimi / synthetic:hf:moonshotai/Kimi-K3 | 2026-09-06T13:44:44Z | `/Users/mikko/.claude/data/kimi-review-ledger.jsonl:1128` | `/Users/mikko/.claude/data/reviews/runs/synthetic-20260906T134015Z-75182.md` |

Frozen payload, wrapper logs and copied receipt rows are preserved outside the
repository at
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/firewall-response-review/`.
The copied `v1-receipts.json` indexes the authoritative sources; it does not
replace their authority.

| Finding | Source check and repair/disposition |
|---|---|
| GPT: transparency hash predates enforcement | Confirmed in invoke.rs:1832. Root selected truthful inner-stage records plus one final delivery-attempt event; added immutable final-response hash contract and FWR-15. No client receipt claim. |
| GPT/Kimi: scan count lacks executable proof | Confirmed audit count alone is insufficient. Mandatory observation at actual inspection/detector/redactor calls and duplicate-call mutant now supplement audit assertions. |
| GPT/Kimi: false/missing DoR backlog evidence | Confirmed original B labels confused DoD bets with DoR backlog gates. MIK-7407 independently populated/verified by integrator; ticket IDs, dependencies, position and canonical gate ledger now explicit. |
| GPT: generic unknown owners | Confirmed. Named issue/person ownership and dependent implementation blocks now accompany every scheduled check. |
| GPT: requester interview missing | Existing user release mandate and integrator boundary decisions now recorded. Remaining choices preserve current error/request policy and implement Block rather than settle unasked operator preferences; root confirmed no further question is needed for these engineering choices. No invented interview is recorded. |
| Grok: old inner signing conflicts with finalizer | Old call is real, but the coordinated signing increment explicitly removes it. Added exact linked version-2 final-result contract and removal ownership. Retaining inner signing would violate MIK-7377.SIGNING.3; no second signing owner is introduced. |
| Grok: discovery target ambiguity | Confirmed. tools/list explicitly precedes extractor/fallback for all discovery, with exact-rule fixtures. Logical fallback is non-discovery only. |
| Grok: stdio tools/list missing | Compound FWR-05 did not name the real spawned dispatch clearly. Added explicit FWR-06 stdio list negative/control and operation-by-transport matrix. |
| Kimi: review authority record pending | These actual first-round receipts are now recorded; closure receipts remain pending until their processes complete. |

All bounded low-cost improvements were incorporated: exact policy patterns,
explicit retry/Tasks deferred rows, early-return mutant, operator fallback-policy
note, semantic error assertions, feature-off path and request-ID wording.
Focused finder-closure on the amended frozen material remains pending. Source and
new executable tests are unchanged; neither design approval nor implementation
validation is claimed yet.

### Round 2 finder closure

All three finder processes returned SHIP-WITH-FIXES with exit 0 and authoritative
process_status ok on identical scope
`MIK-7407 firewall response design and test plan v2 finder closure`,
125,174 scoped bytes, SHA-256
`da32b0673b7269f64de38fb8f98c1e93f3ac836f4b70035b233eedfef189dd67`.
Actual receipt copies and frozen document hashes are in `v2-receipts.json` and
`v2-manifest.json` under the review evidence directory above.

| Finder | UTC timestamp | Authoritative ledger | Run output |
|---|---|---|---|
| gpt / codex-default | 2026-09-06T14:08:50Z | `/Users/mikko/.claude/data/gpt-review-ledger.jsonl:3175` | `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T140147Z-25060.md` |
| grok / grok-default | 2026-09-06T14:10:50Z | `/Users/mikko/.claude/data/grok-review-ledger.jsonl:1966` | `/Users/mikko/.claude/data/reviews/runs/grok-20260906T140148Z-25054.md` |
| kimi / synthetic:hf:moonshotai/Kimi-K3 | 2026-09-06T14:10:37Z | `/Users/mikko/.claude/data/kimi-review-ledger.jsonl:1129` | `/Users/mikko/.claude/data/reviews/runs/synthetic-20260906T140147Z-25055.md` |

Kimi explicitly reports the round-1 boundary/signing, discovery, observation,
backlog and ownership repairs landed; GPT and Grok returned the remaining
findings below. No runtime stage was reviewed. Remaining
round-2 repairs are now specified: FWR-16 names the exact logical-playbook rule
falsifier; FWR-17/18 prove actual cache/idempotency hits; every non-deferred test
precedes its production behavior; B2 includes verified-empty labels and team;
canonical nominal versus named gate counts are reported honestly; response audit
v2 defines exact target schema/ordering/omission. Added per-transport executable
IDs, real stdio batch coverage, an independent hash path, and the exact scanner
pattern citation. Root approved sharing one Arc<Firewall> through both builders.

Post-freeze source QA also corrected the direct-branch fixture selector
(sanitized versus passthrough, with identity orthogonal), moved direct provenance
before inspection in the intended order, and refreshed the dependent signing
contract to bind the typed request ID. These small corrected contracts, not
already-completed code, are part of the next frozen finder-closure packet.
Approval remains pending that focused closure. No source/new test edits or
executable acceptance are claimed.

The final v3 integration refinement follows signing-source evidence: modern HTTP
body shaping occurs after raw dispatch today, so the agreed finalizer now lives
at each adapter's complete-response tail. The premature inner wrapper extraction
is removed from the plan. HTTP/stdio/direct adapters share enforce → sign →
immutable attempt-log ordering, followed only by serialization. Legacy bridge
challenge admission has its separate agreed helper and WIRE.21/FWR-20 trace;
modern external InputRequired is inspected only at the external boundary.

Pending v4 closure repairs: GPT and Kimi independently identified client-breaker
contamination after finalization; the server-only marker and typed challenge
error preserve that distinction through meta/direct/bridge dispatch. Coordinated
signing errors use the same accounting rule and their exact safe envelope.
Modern InputRequired question/state immutability is now explicit at its sole
external scan. These are design corrections, not implemented or validated code.

Scope-receipt update: the already-approved MRTR bridge exposes backend questions
before a final tool result. Covering those existing challenge artifacts is
necessary to enforce the same NFR.SEC.1 response policy before disclosure, so
this repair now explicitly includes challenge admission in addition to final
results. It adds no new prompt method or requester policy. Root approved the
shared dependency; legacy bridge and modern external artifacts are distinct,
each inspected once. Existing OUT boundaries and pending runtime gates remain.

### Round 3 authoritative receipts and narrow closure

Scope: `MIK-7407 firewall response design and test plan v3 focused closure`; actual scope+NUL+stdin digest
`20de57791e17722cd4bb95ef9a62eece65e4ff766cbc7728de3704dede1e328e` (152039 bytes).
The first local manifest calculation used a newline instead of the wrappers'
NUL separator; only the manifest was corrected. Frozen input/documents never
changed. All three processes exited 0 and their ledgers report process_status ok.

| Reviewer | Timestamp UTC | Verdict | Ledger line | Authoritative output |
|---|---|---|---|---|
| gpt / codex-default | 2026-09-06T14:57:56Z | SHIP-WITH-FIXES | `/Users/mikko/.claude/data/gpt-review-ledger.jsonl:3204` | `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T145403Z-65605.md` |
| grok / grok-default | 2026-09-06T15:06:55Z | SHIP | `/Users/mikko/.claude/data/grok-review-ledger.jsonl:1992` | `/Users/mikko/.claude/data/reviews/runs/grok-20260906T145404Z-65606.md` |
| kimi / synthetic:hf:moonshotai/Kimi-K3 | 2026-09-06T14:57:37Z | SHIP-WITH-FIXES | `/Users/mikko/.claude/data/kimi-review-ledger.jsonl:1130` | `/Users/mikko/.claude/data/reviews/runs/synthetic-20260906T145403Z-65607.md` |

GPT and Kimi independently found that new finalization errors would poison the
HTTP client breaker; Grok returned SHIP and confirmed Q1/Q2 and prior repairs.
The dedicated server-only marker/error and repeated-refusal/prior-strike tests
above are the focused repair, including both direct response branches. The
specified Deserialize must reset a remote marker false; that behavior is still
an implementation and test obligation, not existing delivery_refusal code.
Modern InputRequired, exact signing failure, direct final hashes, differing
replay IDs, multi-target served refusal and serializer-conformance controls
complete the small coordinated improvements. Prefetched lists use real schema
load evidence rather than an impossible per-request backend count. Actual
idempotency/signing fixture dependencies remain named and blocking.

Canonical evidence-class snapshot through completed round 3: **E1=1, E2=14,
E3=10, E4=2** distinct indexed items. E1 is this scoped readiness declaration.
E2 is the ten actual source files in v3-material (firewall, authorization,
HTTP handlers, direct handlers, stdio server, MetaMcp, invoke, response_inspect,
transparency_log, response_scanner), the three active canonical SSOT files and
the verified MIK-7407 issue. E3 is nine authoritative completed reviewer outputs
plus the static document discriminator command recorded in v3-manifest; none
is a runtime product test. E4 is the two owned frozen design/test-plan artifacts;
packets/manifests index those artifacts rather than inflating the count. Gate
judgments remain inferred where based on one source/context; this item count is
not a claim that all 84 nominal gates or runtime acceptance passed.

The amended design/test plan awaits focused closure of those exact repairs.
Source/tests remain unwritten by this increment; root has authorized proceeding
to reviewed tests and implementation once that design gate is satisfied.

### Round 4 receipts and final plan falsifiers

The fixed design is unchanged: each served tool/discovery artifact reaches one
shared finalizer after shape, with typed refusal provenance, protected modern
questions/state and one final attempt hash. Round 4 Kimi returned SHIP; GPT and
Grok closed the prior design defects but found three missing executable
falsifiers. The plan now requires FWR-21 to RUN signing/hash behavior without
the Firewall feature, FWR-12 to hash ordinary tool/discovery dispatch errors on
all three transports, and FWR-20 to project the real typed challenge error and
prove its marker/code/message plus actual HTTP no-strike/no-reset accounting.
These additions eliminate the named observation blind spots without changing
release policy. Finder closure returns to GPT and Grok for their own findings;
Kimi's SHIP remains additional evidence. No executable acceptance is claimed.

Scope: `MIK-7407 firewall response design and test plan v4 refusal-accounting closure`; digest
`fbcb89bcb4ad686b9dcd5e9a6a2560f0419ee92ba37aae2e83f81199347a7747` (139613 bytes),
identical actual scope+NUL+stdin for all vendors; all processes exited 0.

| Reviewer | Timestamp UTC | Verdict | Ledger line | Authoritative output |
|---|---|---|---|---|
| gpt / codex-default | 2026-09-06T15:17:56Z | SHIP-WITH-FIXES | `/Users/mikko/.claude/data/gpt-review-ledger.jsonl:3216` | `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T151211Z-16356.md` |
| grok / grok-default | 2026-09-06T15:21:09Z | SHIP-WITH-FIXES | `/Users/mikko/.claude/data/grok-review-ledger.jsonl:1998` | `/Users/mikko/.claude/data/reviews/runs/grok-20260906T151211Z-16355.md` |
| kimi / synthetic:hf:moonshotai/Kimi-K3 | 2026-09-06T15:14:42Z | SHIP | `/Users/mikko/.claude/data/kimi-review-ledger.jsonl:1131` | `/Users/mikko/.claude/data/reviews/runs/synthetic-20260906T151211Z-16357.md` |

### Round 5 design and plan closure

Both original finders returned SHIP on the same immutable scope and material:
`MIK-7407 firewall design and test plan v5 finder-only falsifier closure`,
SHA-256 `ab27df47e3434a19da3da32b3d7978c3bb85645e0dfce97b7da5091adc440b34`,
149636 scoped bytes (scope + NUL + 149564-byte stdin). Both authoritative rows
record `process_status: ok`, and both actual wrapper processes exited 0.
The stable change identity remains
`0c61dddc348533b5ca66db71f5535c9ac7c42aa644d84be750193c569eef0c07`.

| Reviewer | Timestamp UTC | Verdict | Ledger line | Authoritative output |
|---|---|---|---|---|
| gpt / codex-default | 2026-09-06T15:32:09Z | SHIP | `/Users/mikko/.claude/data/gpt-review-ledger.jsonl:3227` | `/Users/mikko/.claude/data/reviews/runs/gpt-20260906T153007Z-61238.md` |
| grok / grok-default | 2026-09-06T15:35:16Z | SHIP | `/Users/mikko/.claude/data/grok-review-ledger.jsonl:2007` | `/Users/mikko/.claude/data/reviews/runs/grok-20260906T153007Z-61237.md` |

`v5-receipts.json` in the evidence directory above indexes these source records
and observed process exits. This closes design/test-plan review only. No runtime
acceptance or implementation completion is claimed. The nonblocking review
refinements add FWR-12's .5 trace, give FWR-20's typed-error projection a distinct
component test name, and explicitly require the exact firewall message in the
HTTP accounting fixture so a confirmation refusal cannot satisfy that oracle.

### Executable test stage: component increment

The first real-engine run (`cargo test --lib security::firewall::response_tests
-- --nocapture`, release integrator's isolated Spark lane) compiled and returned
exit 101: six controls passed and one assertion failed because response audit
`schema_version` was absent. This is the intended FWR-14 baseline discriminator,
not a compiler or fixture failure. The log is
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/mcp-gateway-v4-firewall-engine-red-r1.log`.
Nine warnings concerned shared scaffolding; no clean release build is claimed.

The initial separately reviewed test increment contains 13 real-engine cases in
`src/security/firewall/response_tests.rs` and five actual JSON-RPC/projector
cases in `src/gateway/meta_mcp/response_security_tests.rs`. Minimal compilable
baseline declarations preserve old first-target scanning, unmarked refusal
construction and old wildcard error-code mapping, so the missing behavior can
fail assertions. Test-only instance counters observe the actual existing
inspection/detector calls without replacing their verdicts. These declarations
are temporary test-stage scaffolding and cannot satisfy implementation DoD.

This bounded component gate covers the reducer/audit/immutable-artifact and
trusted marker primitives only. It cannot close finalizer wiring, signing,
transparency, real bridge-error origin, HTTP accounting, any route-matrix cell,
feature-off integrity or the release. Those corresponding executable cases
must receive their own tests review before their dependent implementation.

### Component test review round 1 and bounded repair

Both reviewers returned SHIP-WITH-FIXES for the same frozen test material:
`MIK-7407 firewall engine and refusal component tests r1`, SHA-256
`f601557df78998c6c2eec865a9799e396f17c76944910adfa60158e16166691b`,
181348 scoped bytes. GPT used actual model `gpt-5.6-sol`; Grok used its wrapper's
explicit `grok-default` model convention. Both authoritative rows have
`process_status: ok` and both wrappers exited 0. Exact ledger/output references
are indexed by `tests-r1-receipts.json` in the evidence directory.

The compiled expanded baseline run `cargo test --lib firewall_response_ --
--nocapture` returned exit 101: eight controls passed and ten assertions failed
for the intended missing audit/reducer/immutability/refusal behavior. Its raw
log is `mcp-gateway-v4-firewall-components-red-r2.log` in the scope-review
evidence directory. These are expected assertion failures, not a green gate.

The repair adds a Warn-over-Allow test (14 engine cases plus five marker/projector
cases), exact complete v2 audit assertions for both artifact kinds and combined
Block targets, a same-tool/different-server deduplication fixture, and a separate
confirmation marker assertion. Empty target wiring now has an explicit typed
error oracle and diagnostic warning check, matching the already approved design.
The temporary test-only API still exposes the old Allow baseline until this test
gate closes. The former untyped, key-deleting audit roundtrip is replaced with
typed consumers of untouched v2 output and a fixed v1-schema golden fixture.
There is no production Firewall audit reader in this repository; external reader
compatibility is not claimed. Fresh assertion-red execution and finder closure
remain pending for this repaired test increment. Production enforcement is
unchanged; integration and release gates remain open.

### Public-route test gate: bounded refusal probes

The twelve real production-binary HTTP/stdio probes in
`tests/firewall_response_enforcement.rs`, `tests/firewall_response_discovery.rs`
and `tests/firewall_response_stdio.rs` have matching independent SHIP receipts.
Scope: `MIK-7407 real HTTP and stdio refusal route tests r1`; SHA-256
`a0355a689fa4311f945bf550be9f9349a9440ea2841830f443a6e2432aa7dbfd`,
190105 scoped bytes. GPT ledger line 3258 records 2026-09-06T16:38:58Z and
`gpt-20260906T163551Z-66947.md`; Grok ledger line 2033 records
2026-09-06T16:47:28Z and `grok-20260906T163551Z-66939.md`. Both rows have
`process_status: ok`; both actual wrapper processes exited 0. Exact records are
in `wire-tests-r1-receipts.json` under the scope-review evidence directory.
The shared process fixture was frozen at SHA-256
`e95ec752bbcba7e44219a5916e65aefdc472d6b1b56f1a884b8e7f55930a60d2`.

This closes only the reviewed refusal-probe test gate. Current runtime behavior
still leaks the dangerous result in all twelve tests; no implementation or
full FWR row acceptance is claimed. Signing, hashes, accounting, sealed retries,
cache/idempotency, bridge journeys and feature-off execution remain required.

The component r2 Grok finder closed its repaired test oracles with SHIP at
2026-09-06T16:56:08Z on SHA-256
`e6ce57ca5bb2aeee97aebad68329100a90ec69874142f54aa5ed05e1b4bc27ea`,
195334 scoped bytes, with actual exit 0. The paired GPT process exited 1 on
account quota, producing no verdict. That failed receipt is retained. After the
release integrator verified restored GPT availability with a fresh successful
review, the exact immutable component material was resubmitted for finder
closure. The separate four-case challenge suite compiled with one disabled-mode
control passing and three expected missing-admission assertion failures; its
independent tests review is pending. No gate treats the quota error as a pass.

### Component test gate closure and first implementation slice

The resumed GPT finder returned SHIP at 2026-09-06T17:35:22Z, ledger line 3269,
`gpt-20260906T173121Z-10782.md`, actual model `gpt-5.6-sol`, actual exit 0.
Together with Grok's retained r2 SHIP this closes the nineteen-component tests
gate on the same `e6ce57ca…` material and unchanged change identity. The earlier
quota-error receipt remains visible in `tests-r2-receipts.json`.

Implementation now extracts the one response content scan into
`src/security/firewall/response.rs`, evaluates canonical distinct targets with
Block > Warn > Allow while preserving each tool's existing first-match rules,
restores immutable payloads when inspection would rewrite them, and writes one
complete v2 event after the final decision. The public one-target API delegates
to that pipeline. The typed native refusal maps to -32600 and the real projector
sets only the private delivery marker; ordinary constructors/deserialization
remain unmarked. Request rules and the existing HTTP429 mapping are preserved.
Focused execution is green: 14 response engine tests, 5 native projection tests,
and 135 broader Firewall tests pass. After the test-only logger instrumentation,
the engine's 14 and existing transparency's 20 regressions still pass. Shared scaffold
warnings remain; this is not the release's clean-build gate. Code review and
public adapter integration are still pending.

### Challenge admission test closure and implementation

The repaired five-case challenge test run compiled with one disabled control
passing and four missing-admission assertions failing. The actual source hash
`71fb81a425bff70a79ed2a9a7f122c5ed4a9429f15ea91f80cde0861d5194e47`
matches `focused-delivery-r13-source-manifest.json`. The positional fixtures
exercise dangerous first and later questions independently; no claim is made
that a failing loop executed every later iteration.

Grok's r2 SHIP is authoritative ledger 2059 at 2026-09-06T18:19:15Z
(`grok-20260906T181150Z-14825.md`, actual exit 0). GPT's finder-only r3 repair
closure returned SHIP at 2026-09-06T18:29:06Z, ledger 3294,
`gpt-20260906T182709Z-52573.md`, actual model gpt-5.6-sol and exit 0. The r3
scoped material is 69904 bytes with digest
`c42c5d3a7e8003abed182267947ed80aa1bc33ca20ada03ad26cc51a84615a72`.
The original change identity and paired review history remain unchanged.

`enforce_firewall_challenge` now calls the shared real Firewall once with
BridgeChallenge/Immutable and projects Block or invalid targets as the native
refusal error. Feature-off and absent Firewall remain no-ops. Its focused run
passed all five tests, actual exit 0, in
`scope-review/mcp-gateway-v4-firewall-challenge-green-r1.log`. Real bridge
WIRE.21 client-frame/retry integration remains pending.
The final-delivery helper remains an identity declaration until its separate
test gate closes; it will not silently omit the signing dependency.

### Measured dependency: partial transparency append recovery

The finalizer's entry-level error hook proves one-attempt caller handling and
one-shot fault reset. It does not prove recovery after partial OS writes.
The real-binary probe in
`scope-review/firewall-response-review/probe-logger-partial-write.py` exercised
that existing logger behavior separately on Spark using an immutable copy of
binary SHA256
`43a4b5ec439d0c96f9e48a02edaff13d3f4291131835c30b18646133fda18ce1`.

With SIGXFSZ ignore verified in the child, a child-only RLIMIT_FSIZE cap forced
exactly 64 bytes of a target audit append after a valid one-entry baseline.
Backend execution and client results succeeded. Restoring the limit and
appending in the same process produced duplicate counter 2; the actual audit CLI
failed with `counter gap at entry 2: expected 3`. A separate restart after the
partial write still left invalid JSON after the next successful client call.
Authoritative raw results and logs are under
`/home/mikko/codex/mcp-gateway-v4-logger-probe-_s3ovvz2/` and the local evidence
directory's `logger-partial-write-results.json`.

Root accepted this as a required MIK-7407.RESPONSE.5/CONTROL.3 delivery repair,
not a new product feature or ticket. It gets its own scoped design and failing
tests before production changes. Preserve fail-open client behavior, never
replay pending buffered bytes as a new committed entry, and preserve the
existing MIK-6710 bounded 4 MiB recovery constraint. A failed writer must restore a
committed boundary or explicitly refuse subsequent appends; recovery must not
silently repair a tampered complete record. Generic finalizer test repairs
continue independently, while release audit-integrity acceptance remains open.
The separate [logger design](2026-09-06-transparency-append-recovery.md) and
[test plan](2026-09-06-transparency-append-recovery-test-plan.md) define the
required AUDIT.1–7 supporting criteria. They are under paired design review;
logger production behavior is unchanged.

### Final-delivery finder status and corrected engine receipt

The repaired 15-case finalizer run compiled with one uncovered-method control
passing and fourteen expected missing-behavior assertions failing, actual exit
101. Source pins are `focused-delivery-r14-source-manifest.json`. Both r2 finder
processes exited 0 on scoped digest
`0e0e1024d98d06201965db3d76b782a73dd10446ae0e313474fde1a547e51d0f`
(237115 bytes): Grok SHIP at 2026-09-06T19:09:43Z, ledger 2073; GPT
SHIP-WITH-FIXES at 2026-09-06T19:03:49Z, ledger 3307. The latter correctly
requires native protected-state coverage and a nonzero engine receipt.

`mcp-gateway-v4-firewall-engine-green-r2.log` selected zero tests and is invalid
as regression evidence; it remains in the history without a green claim.
The distinct corrected `mcp-gateway-v4-firewall-engine-green-r3.log` collected
and passed all 14 engine tests, actual exit 0. Existing broader Firewall 135
and transparency 20 runs remain separate evidence; shared scaffold warnings
are not a release clean-build pass.

The next test source preserves all 15 cases and adds native InputRequired
state/question protection plus allowed unrelated metadata redaction, and
uncovered-method attempt logging. Its 17 cases also pin exact attempt fields
and required timestamp and the full absent-logger refusal envelope. Fresh
compiled red and GPT finder closure remain pending. No finalizer implementation
is claimed; the common ordering helper remains an identity declaration.
