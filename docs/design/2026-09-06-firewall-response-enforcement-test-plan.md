# Firewall response enforcement test plan

Status: plan approved by independent GPT and Grok reviews on 2026-09-06;
cases remain specifications until executed. See the companion design round 5
record for authoritative receipts. Companion: [design](2026-09-06-firewall-response-enforcement.md).

Each `MIK-7407.RESPONSE.*` clause maps one-to-one to the release's local
`NFR.RESPONSE.*` alias and the existing firewall control population and final
response integrity. No case here closes the separately open request
firewall or entire NFR.SEC.1 inventory.

## Fixtures and assertion rules

Use a real counted loopback backend with benign empty request arguments and a
tool returning `ignore all previous instructions`. The production response
scanner recognizes this phrase through `INJECTION_PATTERNS`' direct instruction
override regex, `src/security/response_scanner.rs:52–56`; pin recognition with the
real engine so pattern/config drift cannot become an unexplained route red.
Configure response scanning and a Block rule
matching only the exact backend tool name for calls, `tools/list` for all
standard/direct/aggregate discovery variants, or the named logical non-discovery
meta-tool for fallback cases. Do not use a catch-all in policy-target acceptance
fixtures; an incorrect target must make the case fail. Disable request scanning
for the response-specific fixture so an earlier
request refusal cannot satisfy it. Prove the backend was called once and a
response-stage audit event exists. Keep a separate request-firewall regression
fixture enabled; no response fixture is evidence for that earlier control.

The negative fixture must fail on absent final refusal / leaked result, not on
compilation, authentication, unknown tool, missing backend, timeout or signature
setup. Register and successfully invoke a benign tool under the same route and
identity before claiming the blocked case is drivable. Response-cache and
idempotency shortcuts are disabled for counted-backend tests unless explicitly
testing a cache hit. Use synthetic canary credentials only.

Do not stub Firewall or manually construct its verdict in route acceptance tests.
Engine unit tests may drive the real scanner/reducer directly. For enabled audit,
use an isolated temporary NDJSON file, parse response events only, and verify their
correlation metadata. Audit count alone cannot prove detector call count. Add a
mandatory per-Firewall test-only observation seam at the real response inspection
and configured detector/redactor calls. It records invocations without replacing
the engine or supplying a verdict. Unit/dispatch tests assert one inspection and
one call per enabled detector/redactor, zero for disabled ones, and a fresh count
for each repeated/concurrent operation. Real spawned-stdio tests also require one
response audit event. Keep instrumentation instance-local, with no global dedupe
or production bypass.

Count `artifact_kind=final_response` and `artifact_kind=bridge_challenge`
separately. One legacy call can legitimately require admitted challenge artifacts
and a later final result; those are not duplicate inspection of one artifact.
Modern InputRequired returned externally uses only final_response. D1/D2/context
checks are distinct existing controls, not Firewall invocation-counter events.

Tool-call fixtures require one actual backend execution unless the case
explicitly covers cache/idempotency replay. Standard/list discovery may use
metadata prefetched at startup: prove the configured backend supplied the exact
dangerous schema and the gateway loaded it, then assert no description escapes
at the public list boundary. Do not demand a per-request tools/call count of one
for a list that intentionally reads cached schemas.

## Criterion mapping

The abbreviated `.1` through `.5` AC column means `MIK-7407.RESPONSE.1` through
`MIK-7407.RESPONSE.5`. Each executable test must carry its stable ticket ID.

| Case | AC | Level/type | Stimulus and observable | Why it fails / control |
|---|---|---|---|---|
| FWR-01 | .1, .2, .4 | HTTP system/security negative | Real modern POST /mcp gateway_invoke gets blocked backend result; backend count 1, same JSON-RPC request ID, error -32600 with exact generic message, result absent, no phrase or finding fragment in serialized response. | Current handler returns result although audit says Block. Pin HTTP 200 for this unstamped policy error. Benign same-route call proves backend/authorization setup. Repeated blocked calls under a small client-breaker threshold must not lock out the client or reset a seeded prior strike; ordinary backend-error controls still count failures. |
| FWR-02 | .1, .2 | HTTP system/compatibility | Repeat FWR-01 through a legacy initialized session and configured surfaced tool; include sealed retry's named-tool dispatch when bridge fixture is available. | Catches adapter finalization bypass after a dispatcher early return. Legacy and modern benign controls remain callable. Retry case is owned by bridge integration if unavailable at this test stage; cannot be marked covered by surfaced case alone. |
| FWR-03 | .1, .2, .4 | HTTP system/direct-route | Real /mcp/{backend} tools/call; exercise each successful forwarding return branch (sanitized early return with passthrough:false and passthrough:true fallthrough); same ID/no result/generic error, HTTP 200, backend count, final delivery-attempt digest, and repeated-block/no-strike/no-reset client-accounting controls. | Both existing scanner sites ignore Block. Identity/header isolation is orthogonal: both response branches support it. Prove each real branch via explicit passthrough config and backend count; do not mistake per-user identity for the branch selector. |
| FWR-04 | .1, .2 | HTTP system/discovery | Direct tools/list backend description carries scanner phrase; normalized result must be withheld as HTTP 200 with a generic JSON-RPC error, not partial/empty success; independently verify its final delivery-attempt digest. | Current direct list scan returns disallowed metadata. Benign same-schema list passes. |
| FWR-05 | .1, .2 | HTTP/stdio system/discovery matrix | Aggregate gateway_list_tools all/single-backend, gateway_search_tools and Code Mode gateway_search return a matching dangerous description; assert generic failure with no discovered result. Include standard tools/list with dangerous surfaced schema description, filtered list and URL Code Mode branch if any backend content survives that branch. | Covers four removed inner scans and public list boundary. An entirely fixed/first-party URL Code Mode list uses benign success plus event-count control; do not fake backend content into a branch that cannot contain it. |
| FWR-06 | .1, .2 | Stdio system/security | Spawn real gateway stdio process with configured backend/firewall; initialize, invoke dangerous tool, read a complete JSON frame with original ID and error only; benign call still returns normally. Separately send standard tools/list with dangerous surfaced schema metadata under the exact tools/list Block rule; require the generic error and no result, with benign list and one-event controls. | Current stdio tools/call and the distinct tools/list dispatch arm lack final response enforcement. Drive real writer/reader rather than HTTP dispatch or direct handle_tools_call fixture alone. |
| FWR-07 | .3 | Engine component/reducer | One dangerous response, two distinct targets: matching Allow and Block rules, then reversed target order; both yield Block. Duplicate target is not a second event. | Catches last-target-wins/Allow downgrade. Single Warn and no-finding Block-rule controls pin existing rule semantics. |
| FWR-08 | .3 | HTTP/stdio integration/ownership | Multi-target Code Mode returns dangerous output with an exact rule matching only one target as Block and another as Allow; require combined route-level refusal in both target orders. It and ordinary/surfaced/discovery calls emit exactly one response event per completed external response with distinct target metadata and final action. Repeated identical calls emit one each; concurrent IDs remain distinct. | Catches retained HTTP postscan, nested discovery scan and global dedupe. The mandatory real-engine observation seam also counts one inspection and one call per enabled detector/redactor in unit/dispatch tests; separate real-process stdio audit assertions cross-check boundary wiring. |
| FWR-09 | .4 | Public routes/positive | Same dangerous result with firewall absent, master disabled and response scanning disabled (separate cases) reaches client; no response audit. | A blanket refusal fails; a fixture never reaching backend fails count/content control. |
| FWR-10 | .4 | Public routes/policy | PI match under default Medium→Warn and explicit Warn remains delivered; benign content under Block rule remains delivered; exactly one allowed/warn event. | Catches treating all findings as Block or treating a matching rule as unconditional. |
| FWR-11 | .4 | Public routes/redaction | Synthetic credential under explicit Warn/Allow is replaced with existing redaction marker, surrounding text preserved, original credential absent, one event. Default Block/High is independently withheld. | Catches dropping redaction or returning a raw pre-scan copy. Verify both content and structuredContent where wrappers expose both. |
| FWR-12 | .4, .5 | Compatibility/integration | Existing JSON-RPC error retains its pinned code/message/data object and restored request ID, remains unsigned and emits no response-scan event, but emits exactly one delivery-attempt event independently matching the final error JSON-RPC hash. Exercise ordinary tool/discovery dispatch errors on meta HTTP, both direct branches and real stdio, using their pinned existing error envelopes; existing request-firewall refusal test still prevents backend dispatch. | Catches scanning/error rewriting or request gate bypass introduced by extraction. Focused real Deserialize/Serialize/constructor cases prove delivery_refusal starts false, cannot come from wire fields and never appears on wire. A backend error with forged delivery_refusal/confirmation_refusal fields cannot acquire the server-only marker or evade ordinary client failure accounting. Request control is regression coverage, not the full NFR.SEC.1 inventory. |
| FWR-13 | .5 | HTTP/stdio integration/signature | Configure real signing with valid key and nonce. Block result is an unsigned error; allowed redacted gateway_invoke verifies against exact delivered result and typed outer request ID. Modern HTTP must traverse actual late resultType/_meta.serverInfo shaping before finalization, not a pre-populated fixture. Modifying delivered redacted content, shaping fields or response ID invalidates signature. | A signature made before redaction fails verification; signing the refused response fails absence assertion. Signing startup worker owns primitive setup; no fake signature helper. A real-primitive finalizer component case uses a non-object result or invalid defensive nonce to produce exact -32603 / Response signing failed / current ID / no result/data and the trusted marker; it increments its metric and records one final attempt. This defensive shape is not reachable through valid wrapped gateway_invoke wire input and is not claimed as such. Pair with real-wire pre-admission rejection. A router-level component test passes the real finalizer error through the actual HTTP response builder and requires HTTP 200 with the pinned error envelope; it does not invent a valid wire trigger for the defensive signer failure. Verify allowed payload redaction preserves a real gateway-authored provenance receipt under the existing attestation verifier. |
| FWR-14 | .3, .4 | Audit compatibility/component | A strict typed test consumer pins the emitted response schema_version:2, server-derived artifact_kind final_response/bridge_challenge, and required nonempty policy_targets array of exactly server/tool string objects, deduplicated and sorted by (server,tool). The repository has no production Firewall audit reader. Feed both an untouched emitted v2 event and a fixed pre-v2-schema golden event through a typed consumer of the existing eleven fields; do not delete new keys or parse only into Value. Old response without these fields remains readable as v1; request event omits all three and keeps its old shape. | Catches additive-field parser assumptions, missing/empty/unsorted target metadata, mixed artifact counting and response/request schema conflation. |
| FWR-15 | .5; MIK-7215.CONTROL.3 | HTTP/stdio integration/transparency | Enable real transparency logging. Independently hash parsed final JSON-RPC output using a separate Python compact sorted-key serializer and SHA-256 over fixture strings/arrays/objects/exact integers (no call to the Rust hash/serializer helper) for allowed redaction, Block refusal and signed success; require one matching response_delivery_attempt event with stage/encoding fields, final request ID and signature included where present. Keep original per-target invocation records, verify the complete chain, and assert no raw payload/credential in the new event. Disabled logger produces no event; write-error fixture preserves finalized output and does not claim client receipt. | Catches pre-enforcement/pre-sign hashing and accidental loss of inner target accounting. Original blocked-result hash must differ from the generic-error hash. A delivery-attempt event is not transport receipt. |
| FWR-16 | .1, .2, .3 | HTTP/stdio integration/logical fallback | Real gateway_run_playbook invokes a counted backend returning the dangerous phrase. An exact gateway_run_playbook-only Block rule yields the generic refusal, one actual scan and one event with nonempty logical target. The same dangerous result remains allowed under only an inner-backend-tool Block rule; benign playbook also succeeds. | Omitting fallback and folding empty targets must fail. An empty-target reducer call independently fails closed; no manually constructed verdict. Request scanning is disabled only in these response-specific fixtures. |
| FWR-17 | .1–.5 | HTTP/stdio integration/response-cache hit | Enable the real response cache. First backend execution stores a dangerous raw result before final refusal; use different outer request IDs while repeating the same actual cache identity and prove backend count stays 1. Hit is still scanned once, refused, unsigned, and audited/final-output-hashed. Separate benign hit with valid fresh signing nonce verifies its final signature without another backend dispatch. | Cache-hit origin cannot bypass the common adapter finalizer. Prove the actual cache path from configuration, hit evidence and dispatch count; no result-returning cache stub. |
| FWR-18 | .1–.5 | HTTP/stdio integration/idempotency hit | Disable response cache, enable real idempotency storage, and use different outer request IDs while repeating an exact idempotency key after a completed counted invocation stored the dangerous result. Count remains 1; replayed stored result is inspected once, withheld, unsigned, and audited/final-output-hashed. A benign stored result with a fresh valid signing nonce verifies at final delivery. | Isolates idempotency from response-cache proof and kills completed-entry bypass. Changing the key proves a new backend dispatch rather than global response dedupe. |
| FWR-19 | .1–.5 | Real stdio system + paired dispatch component/batch | Send one real stdio batch containing dangerous tools/call, benign tools/list, a no-response notification and an allowed signed call. Inspect the parsed response array: original IDs, expected refusal/allow/signatures, no response for notification, exactly one audit/delivery-attempt hash for each response item, no batch-level duplicate. A paired in-module call through production dispatch_batch_with_sink with the same payload and real engine observer counts one inspection per response item. | Catches bypass in dispatch_batch_with_sink/assembly and false receipt semantics. Notification is not counted as a response. Hash each parsed response item independently and preserve existing batch transport shape; audit count is not substituted for the component inspection counter. |
| FWR-20 | .3, .4; MIK-7212.WIRE.21 | Real-engine challenge helper/component + modern HTTP and bridge wire dependency | Component executable firewall_response_challenge_error_projection drives enforce_firewall_challenge with complete inputRequests including dangerous text only in a raw unknown parameter. Exact backend-tool Block refuses with typed Error::ResponseFirewallRefused and exact Display text Response blocked by security firewall; take that actual error through production error_response_preserving_status and require delivery_refusal=true, code -32600, exact generic message, current ID, no result or error.data. A unit assertion independently pins Error::to_rpc_code so its wildcard -32603 cannot pass. Drive repeated real legacy challenge refusals through HTTP accounting using the bridge fixture and the titration below; unchanged Warn/Allow passes; permitted credential redaction that would mutate the question instead refuses, with one real Firewall inspection and one final Block action audit tagged bridge_challenge. Disabled helper is a no-op. Original Value stays unchanged in every case. A distinct real modern HTTP InputRequired case preserves inputRequests and minted requestState on Allow/Warn, refuses question redaction, and records one final_response inspection/audit and zero bridge_challenge inspections. A real-engine finalizer component case separately pins refusal of a synthetic credential in the protected opaque state field; it does not pretend such a string is a valid minted continuation token. | Kills empty challenge-text extraction, unsafe rewrite, Warn audit followed by hidden refusal and duplicate scan. WIRE.21 / mik_7212_wire_interim_admission_precedes_question owns actual zero frames/pending IDs/retries for first/later refusal; modern external InputRequired must not also call this helper. Removing only the typed-error projector marker must fail the projection and HTTP titration checks; no manually marked response substitutes for the real Firewall error. Bridge fixture unavailability blocks this HTTP acceptance and its dependent bridge wiring. |
| FWR-21 | .4, .5 | Executed feature-off HTTP + real stdio integration | Build and RUN a dedicated integration target under --no-default-features with real signing and transparency configured. Ordinary gateway_invoke dangerous content is delivered unchanged (Firewall absent), final signature verifies against actual result and current ID, one independent final-output hash matches the attempt event, and no Firewall response audit exists. Execute both HTTP and real stdio cases, with actual collected test names/counts in the receipt. | Kills accidental cfg(feature=firewall) around signing/logging or a zero-test gated target. tests/firewall_optional_integrity.rs and its common fixture are compiled without a blanket Firewall cfg; a compile-only pass or zero collected tests fails. Depends on the same actual signing fixture as FWR-13 and must precede cfg integration acceptance. |

All five ACs have positive and negative cases. Baseline .1/.2 failures are owed
runtime evidence, not inferred test passes. FWR-07/FWR-14 may need compilable
declarations before their first assertion-red run; no implementation is called
proven by a missing method. Introduce only the minimal API skeleton needed to run
them, then demonstrate the incorrect reducer/ownership behavior explicitly.

### Operation-by-transport execution matrix

Every row needs a separate named executable case or an explicit tracked
unresolved fixture. A group label or another transport's passing case is not its
evidence. All dangerous cases use exact policy rules and a same-path benign
control. FWR-08 checks one scan/event for these paths; FWR-13/FWR-15 add final
signing/transparency checks where applicable.

| Operation | HTTP meta executable IDs | HTTP direct executable IDs | Real spawned stdio executable IDs | Policy target / FWR |
|---|---|---|---|---|
| gateway_invoke tools/call | fwr01_http_modern_invoke; fwr02_http_legacy_invoke | N/A | fwr06_stdio_invoke | Actual backend tool; FWR-01/02/06 |
| Surfaced named tools/call | fwr02_http_modern_surfaced; fwr02_http_legacy_surfaced | N/A | fwr06_stdio_surfaced | Actual backend tool; FWR-02/06/08 |
| Sealed retry named tools/call | fwr02_http_sealed_retry | N/A | fwr02_stdio_sealed_retry | Actual backend tool; tracked bridge dependency |
| Direct backend tools/call | N/A | fwr03_http_direct_sanitized; fwr03_http_direct_passthrough | N/A | Actual backend tool; FWR-03 |
| Direct backend tools/list | N/A | fwr04_http_direct_list | N/A | tools/list; FWR-04 |
| Standard tools/list | fwr05_http_list_normal; fwr05_http_list_filtered; fwr05_http_list_surfaced; fwr05_http_list_url_code | Covered by direct list row | fwr06_stdio_list_normal; fwr06_stdio_list_filtered; fwr06_stdio_list_surfaced | tools/list; FWR-05/06; URL override is HTTP-only |
| gateway_list_tools, all backends | fwr05_http_list_all | N/A | fwr05_stdio_list_all | tools/list; FWR-05 |
| gateway_list_tools, one backend | fwr05_http_list_backend | N/A | fwr05_stdio_list_backend | tools/list; FWR-05 |
| gateway_search_tools | fwr05_http_search_tools | N/A | fwr05_stdio_search_tools | tools/list; FWR-05 |
| Code Mode gateway_search | fwr05_http_code_search | N/A | fwr05_stdio_code_search | tools/list; FWR-05 |
| Multi-target Code Mode execution | fwr08_http_code_multitarget | N/A | fwr08_stdio_code_multitarget | Distinct actual targets; FWR-07/08 |
| Playbook/unextracted meta result | fwr16_http_playbook_fallback | N/A | fwr16_stdio_playbook_fallback | Logical gateway_run_playbook; FWR-16 |
| Response-cache hit | fwr17_http_response_cache_hit | N/A | fwr17_stdio_response_cache_hit | Actual backend tool; FWR-17 |
| Completed idempotency hit | fwr18_http_idempotency_hit | N/A | fwr18_stdio_idempotency_hit | Actual backend tool; FWR-18 |
| Mixed stdio batch | N/A | N/A | fwr19_stdio_batch_finalization | Each item's target; FWR-19 |
| Modern InputRequired immutable delivery | fwr20_http_modern_immutable_challenge | N/A | N/A, current stdio is legacy | Actual backend tool; FWR-20 |
| Legacy challenge refusal accounting | fwr20_http_legacy_challenge_accounting | N/A | N/A, no HTTP client breaker | Typed Firewall error through bridge/projector; FWR-20 |
| Ordinary dispatch error final hash | fwr12_http_meta_error | fwr12_http_direct_sanitized_error; fwr12_http_direct_passthrough_error | fwr12_stdio_error | No Firewall scan, one attempt event; FWR-12 |
| Integrity without Firewall feature | fwr21_http_without_firewall | N/A | fwr21_stdio_without_firewall | No Firewall scan, real signing/hash; FWR-21 |

Before FWR-15 execution, compare checked repository JSON-value serialization
with independent Python `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False, allow_nan=False)` over the fixture's restricted strings,
arrays, objects and exact integers. Pin escaping/Unicode/nested-key cases.
A mismatch is a serializer-contract fixture failure, not evidence that final
hash ordering passed or failed. This conformance check does not replace hashing
actual final response bytes independently in each FWR-15 route case.

Client-accounting titration (FWR-01/03/13/20): use the existing CONFIRM.1a
recipe in tests/mik_7215_acs.rs:923. Configure threshold 2; one ordinary failing
dispatch seeds the breaker, then repeated real policy refusals must neither trip
nor reset it; one more ordinary failure must trip it. A clean-breaker repeated
refusal case detects strike accumulation independently. A benign-success control
between ordinary failures must reset strikes and avoid that trip. For the
challenge path, produce the error through the real Firewall and typed projector,
then run the real legacy HTTP route and assert the exact error message
`Response blocked by security firewall` on every policy refusal, so a
confirmation refusal cannot satisfy the fixture; do not hand-set the marker or test a
replica accounting branch. The defensive signer-failure component proves the
same production marker/predicate path; valid-wire pre-admission failures remain
a separate case and are not evidence of a post-dispatch signing failure.

## Sequence and ownership

1. Review this plan as a plan: Q1 every AC has cases; Q2 each case can fail without
   replacing or bypassing the behavior it observes.
2. Write every non-deferred FWR-01–21 case and required matrix cell before the
   production behavior it specifies. Start with FWR-01/FWR-03/FWR-06 as fail-fast
   probes, then the remaining route/reducer/cache/idempotency/audit/hash cases.
   Run against current behavior and record assertion-level reds where the defect
   exists plus meaningful benign controls. Existing behavior that already passes
   is recorded as regression green, not an invented red. Minimal compilable API
   declarations may precede the new-unit API's first assertion-red; no behavior
   implementation precedes its reviewed test. Review all tests as tests before
   implementing those behaviors. Explicitly deferred bridge/signing integration
   cases keep their named dependency blocked until fixtures are written, run and
   reviewed; a later implementation cannot waive that order.
3. Implement scanner/reducer + refusal operation, then wire the common finalizer
   after actual adapter shaping and remove obsolete scan sites in owned commits.
   Keep modern/legacy/direct shape construction before it and serialization after
   it; scan only tools/call and tools/list (discovery meta-tools are tools/call),
   never initialize/ping/resources/prompts. No raw dispatcher wrapper extraction
   or second adapter scan. Coordinate
   with signing finalization;
   no competing edit to the signing helper or DELETE-session handler.
4. Execute route matrix and FWR-01–21, then focused old firewall, router, stdio,
   discovery/schema and signing regressions. Compile both the normal feature set
   and `--no-default-features`; execute FWR-21 under the latter to prove feature-off
   enforcement no-op and independent signing/transparency behavior. Compilation
   or an empty filtered test run alone cannot satisfy it. A blocked response is not evidence
   that a backend effect was undone; count proves it already executed.
5. Mutate enforcement to ignore Block, retain an obsolete scan, choose last target,
   skip the surfaced-tool/sealed-retry early-return boundary, sign before
   redaction, hash the pre-enforcement output, remove the logical playbook fallback,
   bypass inspection for stored cache/idempotency results, and restore modern
   body shaping after finalization in isolated copies. For challenge admission,
   omit raw unknown parameters or silently accept a mutating redaction. Also
   drop only the typed challenge-error projection marker (FWR-20), gate signing
   or logging behind Firewall (FWR-21), and skip attempt logging for ordinary
   errors (FWR-12). Each must fail its named executable case.
   Each must fail its named check (FWR-01, FWR-08, FWR-07, FWR-02, FWR-13,
   FWR-15, FWR-16, FWR-17/18, FWR-13/15 and FWR-20 respectively). Restore and
   rerun green. Critical coverage/mutation and full
   release checks follow on integrated code, not this plan's existence.

Fail-fast command names will use the repository's actual test target after tests
are added; proposed names are `firewall_response_` unit tests and
`tests/firewall_response_enforcement.rs` for process/HTTP tests. No exact pass count
is promised before those tests exist. FWR-18 is blocked on the actual
MIK-7272.SUB.4 idempotency fixture; the signing halves of FWR-17/18 share the
MIK-7406 signing fixture dependency with FWR-13. These cases must be written,
run and reviewed before their dependent production integration. Cache-hit
refusal in FWR-17 remains a non-deferred counted baseline. Missing reference fixtures and upstream
bridge/signing dependencies remain visible acceptance work, not silent N/A.

## Review record

Design and plan review closed in round 5 with authoritative GPT and Grok SHIP
receipts on identical actual material, recorded in the
[design review record](2026-09-06-firewall-response-enforcement.md#review-record).
The separate executable component-test review returned SHIP-WITH-FIXES in its
first round; its bounded oracle repairs await fresh assertion-red execution and
original-finder closure. Real HTTP/stdio route probes have separate execution
receipts and still require their own tests review. No route-matrix row, product
acceptance or release completion is claimed from these partial gates. Final
implementation additionally requires two code-review legs and an independent
functional pass under the active canonical process.

### Next executable component slice: legacy challenge admission

`src/gateway/meta_mcp/response_challenge_tests.rs` began as a separate four-case
component gate. `firewall_response_challenge_error_projection` uses the actual
MetaMcp helper with a shared real Firewall, projects its returned native error
through the existing production projector, and checks exact wire envelope and
distinct server-only provenance. Companion cases cover unchanged Warn/Allow,
clean content under a Block rule, refusal when credential redaction would rewrite
a raw unknown question parameter, and disabled/absent no-op controls. Real
engine/scanner/redactor counters and one `bridge_challenge` v2 audit pin its
artifact semantics. The initial cfg(test)-only helper is a no-op declaration so
missing admission can fail assertions before implementation; it is not a test
verdict generator or evidence of enforcement. Execution and tests review are
pending. The separate actual legacy bridge WIRE.21 frame/retry and HTTP accounting
requirements remain open.

Challenge test review found one real fixture gap: a single request cannot catch
an implementation that inspects only the first question. The repaired fixture
now places a clean question first and the dangerous/redactable question second.
It requires actual detector finding types and adds a fifth case for invalid
empty-target mapping to the generic native refusal with no scan/audit. Fresh
assertion-red execution and finder closure are pending; the original Grok SHIP
and GPT SHIP-WITH-FIXES receipts are retained.

### Next executable component slice: final delivery and attempt hash

`src/gateway/meta_mcp/response_delivery_tests.rs` contains ten cases for the
shared synchronous finalizer: complete shaped Allow output and typed current ID;
permitted credential redaction before digest; generic marked Block replacement;
ordinary tools/call and tools/list errors without content scanning; empty-target
refusal; server-selected immutable wrapped InputRequired; disabled scans with
logging still active; absent logging with enforcement active; unrelated-method
no-scan controls; and preserving the existing inner invocation record while
extending its hash chain with the final attempt. These map to FWR-09–12/15/16/20
and MIK-7407.RESPONSE.1/3/4/5. The hash oracle uses independent Python JSON/SHA-256
on parsed output; a fixed UTF-8/escaping/integer golden is verified before the
first expected missing-finalizer assertion.

The first actual run compiled: one unrelated-method control passed and nine
assertions failed for missing enforcement/logging, actual exit 101. The Python
golden passed, so the hash fixture is usable. The helper remains a cfg(test)
identity declaration until its separate test review. Signing branch tests are
owned by the signing slice using its independent v2 verifier. Real adapter
shaping, failed append behavior, feature-off execution and global CONTROL.3
acceptance remain explicit pending work; these component tests cannot close them.

### Final-delivery test review repairs and real I/O dependency

The first expanded 11-case run compiled with one uncovered-method control pass
and ten missing-enforcement/logging assertions failing. GPT r1 ledger 3289 and
Grok r1 ledger 2062 both returned SHIP-WITH-FIXES on the same 193600-byte material
digest `f833a54577cbca8b8bea1b7200e965eaa5d5b24b72b12bb1b6bebcc0b1c10d39`.
The repaired source now has 15 cases: explicit/default Warn, order-reversed
multi-target policy and exact typed v2 correlation, successful tools/list
inspection/refusal with a benign control, and absent Firewall are all explicit.
The log oracle whitelists permitted fields and rejects a benign sentinel that
survives response redaction; nested structuredContent credentials and surrounding
text are checked. Their compiled run collected all 15 cases: one control passed,
fourteen missing-behavior assertions failed, actual exit 101. Grok r2 returned
SHIP; GPT r2 requires a real top-level InputRequired protection case and corrected
nonzero engine evidence. The zero-test engine r2 receipt is invalid; the distinct
engine r3 run passes all 14 tests.

The next source retains those 15 cases and adds native PreserveInputRequired
state/question refusal, clean and unrelated-metadata-redaction controls, plus
uncovered-method attempt logging. Exact attempt keys/timestamp and the complete
absent-logger refusal are also pinned. This 17-case repair awaits its fresh
compiled red and GPT finder closure; the finalizer remains an identity scaffold.

The entry-level append fault case is named
`firewall_delivery_failed_append_preserves_output_and_consumes_one_shot_fault`.
It establishes real append_event call/error handling, no replay, and one-shot
reset. Arbitrary OS-write recovery is not its claim. A separate real-binary
RLIMIT_FSIZE probe reproduced partial-write corruption and restart failure;
see the design's measured dependency. That logger repair requires its own
scoped design/test gate and real write-fault/restart falsifiers before
MIK-7407.RESPONSE.5 and global CONTROL.3 can close.
The supporting [AUDIT.1–7 test plan](2026-09-06-transparency-append-recovery-test-plan.md)
is under separate design review, without logger production changes.

### Transport implementation checkpoint — 2026-09-07

The shared finalizer now runs in HTTP and stdio before lease completion and
serialization. Ten HTTP and two real stdio cases pass across three retained runs
with identical hashes for all 451 production source files. This is composite
case evidence, not a single full-suite zero exit: the first runtime run retained
nine passes and a modern admission-fixture failure; separate runs passed stdio
and the repaired modern case. `firewall-transport-root-verification-r1.json` in
the release evidence directory verifies the twelve named passes and source
binding. The earlier compile failure is retained and its lease borrow ordering
was repaired before these runtime runs.

The modern echo fixture now declares its exact backend/tool as operator-owned
read-only policy. This supplies the prerequisite introduced by SUB4 admission;
all existing benign, backend-count, refusal, payload and single-audit assertions
remain intact. This fixture-only compatibility delta must accompany the final
implementation review; the earlier P2 receipt binds the previous fixture source.

These results do not close signed-output, authenticated-continuation target,
current-policy replay, accounting, stdio-discovery or logger-recovery acceptance.
Static and final implementation gates remain open; no release criterion is
promoted solely by this checkpoint.
