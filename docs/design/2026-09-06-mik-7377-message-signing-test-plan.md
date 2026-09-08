# MIK-7377 message signing — discriminating test plan

Status: design/test-plan and initial wire/config/nonce/finalizer tests have retained approvals. Current checkpoint: configuration17 and nonce25 component checks pass; production startup and initial HTTP/stdio signing integration now pass the five initial wire tests, 148 related regressions and 29 public CLI probe checks. Full signing acceptance and implementation quality gates remain open; details and retained failures follow.
Contract: [design](2026-09-06-mik-7377-message-signing.md).

Tests must use the production `Gateway::build_meta_mcp` seam (private in-module
test module is acceptable) or real gateway startup, never manually call
`enable_message_signing` to prove configuration wiring. A loopback backend
returns a stable object and increments a dispatch counter. Signing and cache
configuration come from the same `Config` used by normal startup. Response-cache
tests omit the client idempotency key; idempotency tests disable the response
cache and retain the same idempotency key. Both hold backend arguments fixed.
Wire assertions cover the `JsonRpcResponse.result` after tool wrapping, actual
modern protocol shaping where applicable, and final firewall disposition. Use real HTTP and stdio dispatch paths; calling the
inner MetaMcp invoker alone cannot satisfy wire-signing acceptance.

Dependency: SUB.4 production idempotency is not yet wired in the current builder.
An interim component fixture may attach its existing cache after the production
builder to exercise the finalizer, explicitly labeled component-only. Final
SIGNING.3 acceptance requires coordinator-owned SUB.4 wiring and rerunning the
unmodified production-builder path; manual installation is never release proof.

| AC | Case and discriminator | V-model level / type | Planned evidence |
|---|---|---|---|
| MIK-7377.SIGNING.1 | Real builder with enabled valid key followed by production stdio dispatch produces version-2 MAC at result._signature. Current code returns no signature. Missing/short key rejects builder before any call; the same invalid config through YAML startup rejects. Real HTTP startup uses a key found only in its env-file overlay, exercising load/evaluate/with_env sequencing. | Integration / positive and negative | Focused signing transport suite plus CLI startup exit/error capture. |
| MIK-7377.SIGNING.2 | Matrix current/previous keys: literal, `env:`, `${VAR}`, default expansion; missing, empty, 31-byte, nonzero 32-byte and all-zero 32-byte values; blank key ID and zero window. Env-file overlay differs from ambient environment, proving the evaluated source wins. | Unit + config integration / boundaries, negative | Signing config suite with resolved sentinel values AND raw reference tokens absent from error and Debug output; zero-only rejection maps to live PORTSEC.VAL.1. |
| MIK-7377.SIGNING.2 | Literal load/save keeps both reference spellings byte-for-byte at the field value and does not serialize resolved sentinel keys; runtime load uses the resolved keys. | Integration / regression | Temporary config fixture round trip and independent verification with env-file key. |
| MIK-7377.SIGNING.2 | Mutate enabled/key/previous-key/nonce policy/window/key-ID settings during real reload; also rotate an env-file key with byte-identical config. Refuse before applying an accompanying backend change or publishing config/overlay. Unchanged and unrelated reload controls succeed. | Integration / startup-only control | Reload outcome is a safe error naming restart; snapshots of the live Config, live EnvOverlay, signer/key identity, and backend set plus next signed response prove old settings remain authoritative; unchanged signer alone cannot hide changed overlay publication. |
| MIK-7377.SIGNING.3 | Miss then response-cache hit using distinct nonces and no client idempotency key. Verify both delivered MACs independently, assert each nonce matches its request, dispatch count remains one, real ResponseCache.stats hit count increments without a miss on the second lookup, and `mcp_cache_hits_total{kind=response}` increments without an idempotency hit. Separate cfg(test)-only counters inside actual JCS and HMAC helpers each increase exactly once per delivery, not merely once per finalizer entry. Preserve the final trace/provenance/guarded body in the verified MAC input. | Integration / cache path, security regression | Production builder/backend suite; a test that disables caching or permits idempotency hits cannot satisfy this row. |
| MIK-7377.SIGNING.3 | Response cache disabled; production idempotency installed by SUB.4; same operation key and distinct nonces. Dispatch counter is one, `mcp_cache_hits_total{kind=idempotency}` increments, both outputs independently verify and identify their delivery nonce, and actual JCS and HMAC helper counters each increase once per delivery. | Integration / deduplication path | Depends on SUB.4; interim manual-cache component fixture is labeled and cannot close this row. |
| MIK-7377.SIGNING.3 | Backend returns `isError:true` envelope and preexisting forged `_signature`; final result carries exactly one valid top-level gateway signature. Inner backend text is not a gateway signature authority. Guard/projection output remains inside the authenticated body. Non-object JSON-RPC result at the finalizer rejects signing. | Integration + unit / negative | Object envelope with meaningful changed fields; private non-object finalizer invariant probe. |
| MIK-7377.SIGNING.3 | Real HTTP gateway has response credential redaction enabled; backend returns a synthetic recognizable credential. Delivered text contains the replacement but not the sentinel, and result._signature verifies over that redacted text. Modifying the replacement afterward rejects. Stdio signs its actual wrapped content too. | Integration / final delivery boundary | Both transport outputs and independent verifier; a pre-redaction or inner-object MAC fails the assertion. Exercise BOTH real legacy and modern HTTP; modern request dispatch itself must add resultType/serverInfo before shared finalization, not a pre-populated fixture. Real stdio follows the same helper. Changing final modern fields or request ID rejects independently. Actual final shape→one scan→one JCS/HMAC→one delivery-attempt event→serialization order is asserted; no later field mutation. CONTROL.3 hashes that final whole response and never asserts client receipt. |
| MIK-7377.SIGNING.3 | Drive the actual enabled signing primitive through the shared finalizer with a defensive non-object result or invalid defensive nonce; this is a component fixture because valid wire dispatch wraps results and rejects invalid nonces before dispatch. Pair it with wire pre-admission nonce rejection; no fake signer. Final response has exactly code -32603, message Response signing failed, original ID, no result/error.data/payload sentinel/signature; failure metric increments and one final delivery attempt is recorded. Repeated firewall/signing finalization refusals neither lock out the authenticated client nor reset a preexisting nonzero strike count; ordinary success and dispatch failure preserve existing accounting. | Component + integration / fail-closed and caller isolation | Real-wire repeated firewall refusals prove HTTP accounting; the real signing-failure component proves the same marker/accounting helper without claiming a valid-wire signing failure. Server-only delivery_refusal marker never serializes and deserialization of a forged marker cannot grant exemption; shared firewall owner's accounting fixtures plus signing fault seam. |
| MIK-7377.SIGNING.3 | Real stdio batch contains two gateway_invoke requests with distinct IDs/nonces, a replayed nonce item, a named tool and a notification. Each responding successful invoke independently verifies; replay rejects; named result stays unsigned; notification emits no response. | Integration / batch adapter | Actual dispatch_batch_with_sink per-item path and emitted stdout; one JCS/HMAC per successful responding invoke, one delivery attempt per finalized response, no batch-tail mutation. |
| MIK-7377.SIGNING.4 | Fixed key/body/typed-request-ID/nonce/timestamp/key-ID known answer from independent Node JCS/HMAC implementation. Include supplementary Unicode keys, nested sort order, escapes, fractions, negative zero, exponent boundaries, and safe-integer boundaries. Reject out-of-range exact integers and canonicalization errors. Include string ID, numeric ID, numeric1 versus string1, i64 extrema encoded as typed decimal strings, and explicit null ID finalizer fixture. Absent notification ID is distinct from present-invalid ID; include a notification-method request with an invalid ID. Raw-wire i64::MAX+1, u64::MAX, below-i64::MIN and non-integral numeric IDs reject -32600 without dispatch/admission or wrapped IDs on HTTP and stdio. A separate real HTTP/stdout raw-wire case sends i64::MIN/MAX IDs and uses an independent lossless ECMAScript parser/verifier to reconstruct the typed decimal value from received bytes; ordinary JSON.parse rounding cannot satisfy it. Mutate body, outer request ID, and each metadata field individually; original verifies and every mutation rejects. | Unit / cross-language known answer, tampering | Hard-coded independently generated vectors; verifier must not call signer or share its MAC-input builder. |
| MIK-7377.SIGNING.4 | Relabel a previously delivered envelope with a new request nonce and set the verifier's expected nonce to that forged nonce; nonce matching therefore passes and only the MAC can reject the unchanged-body forgery. Version absent/1, unsupported algorithm, missing jsonrpc or outer jsonrpc other than2.0, and simultaneous result+error reject even with an otherwise valid result MAC. The independent RESPONSE verifier rejects every duplicate object member at every nesting depth before parsing can erase ambiguity (including id/result/error/_signature and signature metadata); the verifier returns the one verified parsed object. | Integration / replay forgery regression | Independent test verifier requiring version2, key ID, expected nonce, timestamp policy; emitted current wall-clock timestamp gets its own round-trip test. With valid MACs and injected verifier time, age301 seconds and future31 seconds reject; exact age300/future30 boundaries accept under the documented reference policy. |
| MIK-7377.SIGNING.4 | Optional-nonce call yields a valid null-nonce signature; relabel the outer request ID and set the verifier expected ID to that forged value. Expected-ID equality passes while the original MAC rejects. Numeric1 relabeled as string1 also rejects. | Integration / request correlation | Independent verifier reconstructs typed MAC ID from outer response, preserving exact i64 numbers or using string IDs. |
| MIK-7377.SIGNING.5 | Pause actual background cleanup after selecting elapsed entries and probe the same real storage guard before concurrent same-nonce readmission; no artificial outer mutex. Old split collect/remove can erase the fresh registration, whereas the shared-state implementation serializes both and keeps the fresh nonce replay-protected. Separately advance an injected monotonic test clock across old/new expiry deadlines after re-admitting the same nonce under another principal. | Unit / deterministic concurrency and expiry replacement regression | Real storage nonblocking guard evidence, exact one live nonce, old principal quota reclaimed, new principal quota retained, old expiry cannot remove current registration, new expiry releases it. Clock/pause seams are cfg(test); implementation tests use actual production state/queue. |
| MIK-7377.SIGNING.5 | Required missing nonce, present null/non-string/empty/257-byte nonce and a valid nonce reused across separate requests reject before dispatch argument cloning, transparency canonicalization/hash, backend/cache/idempotency use. This row does not require a new duplicate-member REQUEST parser. Include 64 four-byte Unicode characters (256 bytes, succeeds) and 65 (260 bytes, fails despite only 65 characters), plus ASCII256/257. Optional absent nonce signs with null; optional malformed present nonce rejects. | Integration / boundaries and negative | For every negative input on warm and cold stores: cfg(test) counters inside actual parse_tool_arguments and transparency canonicalization/hash work remain unchanged with logging enabled, unchanged backend count, real in-memory ResponseCache.stats hit+miss snapshots (a hits-only Prometheus counter is insufficient), idempotency admission/lookup/completion/removal observers and state snapshots. Valid positive controls increment actual clone/hash and cache access/reservation/mutation counters; large arguments exercise the rejected work path. |
| MIK-7377.SIGNING.5 | Prepared 1 MiB and 3 MiB argument trees through actual owned stdio dispatch allocate under 16 KiB for malformed/replayed nonce rejection. Actual HTTP handler with sanitization enabled stays within independently measured necessary body-parse/sanitizer allocation + 16 KiB. Isolate request scanning off only for this allocation discriminator; verify its existing policy separately. Also put payload-sized values separately in retry siblings and multiple stdio batch items so every ownership site is exercised. Warm/cold stores, real allocator bytes, actual adapter paths; restoring any params/argument/target/retry clone before admission fails. | Integration / resource falsifier | Dev-only allocation-counter in isolated current-thread test process; no spawned work in measurement, forced whole-tree clone positive control costs at least input length. Maximum allowed HTTP body rejection/replay with sanitizer AND request scanning enabled separately records total allocations and latency; no zero-allocation or no-policy-work claim. |
| MIK-7377.SIGNING.5 | Existing AUTHZ.20 plus capability-admin, identity-grant, attestation and profile policy refusals consume no nonce or dispatch clone/hash work; an authorized retry with the same nonce succeeds, then reuse rejects. A later credential/operational failure consumes its admitted nonce and requires a fresh retry. | Integration / authorization order | Existing authorization regression rerun and actual admission/hash counters; do not refund a nonce after the admission boundary. |
| MIK-7377.SIGNING.4 / MIK-7377.SIGNING.5 | Real default-sanitized HTTP sends distinct valid nonce/ID strings containing zero-width and stripped control characters, including a NUL nonce within the byte bound. Each exact original nonce and typed ID round-trips and independently verifies; distinct originals never collapse, and exact reuse rejects. The protocol nonce and a DIFFERENT nested backend argument also named nonce prove exact field ownership: the nested one still receives existing sanitization/forwarding and never selects admission or MAC metadata. The same backend string argument still receives its existing sanitization/rejection. Sanitized method/name aliases cannot become gateway_invoke origin; alias nonce keys cannot replace absent raw nonce. Disabled signing retains its existing sanitizer behavior. | Integration / raw protocol metadata | First a table exercises actual capture/restore helper across raw method/name/id/nonce values, ZWSP keys, minted origins, NUL, alias collisions; then real legacy and modern HTTP wire, backend received-argument capture, independent verifier matching exact original metadata; stdio equivalent context path and nonce checks. |
| MIK-7377.SIGNING.5 | Capacity fixture admits exactly each bound, rejects the next distinct nonce, retains all live replay entries. Pause an admitted caller inside the production critical section using a cfg(test)-only hook, start a second admission, and prove it cannot acquire the state lock; release, then assert exactly the capacity succeeded. A second deterministic inside-lock fixture races the SAME nonce and proves exactly one admission succeeds and exactly one replay refusal occurs; capacity cannot be the rejection reason. Deterministic time advances test expiry, replacement and quota decrement, and zero-count principal bucket removal; rejected admissions leave no empty principal buckets. A full-but-expired store admits a new distinct nonce immediately without waiting for a sweeper. Controlled-clock burst/sustained cases verify the documented default10k-per-300s capacity and rollover. | Unit / concurrency, resource bounds | Synchronization at the protected boundary plus lock exclusion and state/count assertions; an outer barrier or sleeps alone do not prove the race. |
| MIK-7377.SIGNING.5 | Alice fills her principal quota, Alice's next nonce rejects, and Bob can still admit. Distinct valid API keys with identical names, OAuth clients with identical agent names, OIDC issuer/subjects with identical labels, and certificates with identical CN/display names each retain separate quota buckets. Certificate fingerprints come from distinct verified DER fixtures, not manually changed labels; API-key full hashes are derived by real authentication and differ from the old 12-hex audit principal. The separately configured primary bearer has its own full digest and cannot be starved by anonymous traffic. Forged session/agent fields cannot create more quota buckets. Reusing Alice's live nonce as Bob still rejects. Temporary and delegated OIDC tokens for the SAME issuer/subject share one cap: temporary tokenA fills it, separately minted temporary tokenB and separately verified delegated bearerC both reject fresh nonces, while another subject still succeeds. Credentials must come from actual mint/verification paths, not copied context. Dashboard handles share a dedicated authenticated operator bucket; filling anonymous quota cannot deny dashboard, while public unauthenticated traffic reaches only anonymous quota. Real public AND protected HTTP paths recognize configured primary bearer, API key, temporary and delegated OIDC credentials and retain the assigned quota; missing/invalid public credentials fall back anonymously, and delegated-disabled input never mints an OIDC quota identity. With auth.enabled=false, presented static/API/OIDC credentials do not mint quota identity (separately active verified OAuth/mTLS controls retain authority). Public fallback and anonymous_client share the same anonymous bucket despite different labels. CountingAuthorizer preserves its wrapped quota identity, and all pure fixture authorizers explicitly return None. | Integration / cross-principal starvation and identity | Real authenticated caller contexts, controlled small capacity; credential identity extraction, anonymous fallback, and global nonce uniqueness independently asserted; existing short audit principals remain unchanged; Debug/error output omits full quota digests and raw keys. |
| MIK-7377.SIGNING.5 | `tools/list` advertises nonce string/length constraints; enabled required mode includes nonce in required fields; optional/disabled modes do not. Missing required/replay errors retain -32001 and their specified existing messages; malformed present nonce is -32602 / Invalid signing nonce; principal/global quota is -32001 / Signing nonce capacity exceeded. Assert exact messages without display prefixes, no data/result/nonce. Rejected replay/quota cases increment the right aggregate metric and expose neither principal nor nonce labels. | Integration / schema and operational behavior | Wire-level tools/list plus metrics recorder, aggregate occupancy returns to zero after expiry. |
| MIK-7377.SIGNING.6 | Disabled signing with unusable dormant references starts. Two calls with same nonce work; gateway adds no signature and keeps its existing payload shape. | Integration / disabled compatibility | Dedicated disabled fixture, independent of every enabled-signing assertion. |
| MIK-7377.SIGNING.6 | With signing enabled and nonce required, surfaced/named tool, code-mode and playbook calls still work without nonce and preserve schemas that prohibit extra fields. Assert explicit absence of a gateway _signature on named, code-mode, playbook, discovery, direct-route and protocol-error outputs. Caller-supplied origin-like fields cannot bypass external nonce enforcement. | Integration / origin separation | Explicit external match-arm positive control plus all shared internal call-site variants. |
| MIK-7377.SIGNING.6 | Signing is enabled with different valid current and previous keys. Delivered output independently verifies under the current key and rejects under the previous key. | Integration / sender rotation | Dedicated enabled two-key fixture; disabled mode cannot satisfy this row. |
| MIK-7377.SIGNING.6 | Review amended ADR/config docs against observed output: version2/JCS, sender-only rotation, explicit restart refusal, and unsigned protocol errors/discovery/direct/internal routes are all described correctly. | Acceptance / documentation review | Non-author checklist with exact document lines and wire behavior; no drift-prone prose-string unit test. |
| MIK-7377.SIGNING.1 / MIK-7377.SIGNING.5 | Finalizer failure, occupancy above80%, and principal/global exhaustion each fire the named alert at its specified evaluation window; quiet inputs stay quiet and recovery resolves. Build without firewall still signs the same gateway_invoke result. | Integration + operational / configuration variants | Finalizer failure metric assertion, promtool alert cases, default and no-firewall signing runs; real receiver routing remains coordinator's before-production check. |
| MIK-7377.SIGNING.6 | Non-author drives built revision over HTTP: configured sign, valid invocation, fresh-nonce cached invocation, duplicate nonce rejection, disabled run. Follow ADR verification instructions independently. | System / functional acceptance | Revision, commands, wire responses with synthetic keys, and AC verdicts in release evidence. |

Before implementation, obtain a red result at the expected assertions for
configuration rejection, builder signing, metadata binding, and replay bounds.
A compile/import/port-start failure is a broken fixture, not a red behavioral
test. Existing behavior tests may already be green; record that separately.

Existing body-only MAC tests are contract-change rewrites, not unchanged
regressions: `sign_response_mac_covers_body_without_signature_field` and
same-body equality assertions move to pinned timestamps and version2 input.
The old all-zero secret success fixture becomes a rejection under PORTSEC.VAL.1.
Keep the independent RFC8785/HMAC vector fixed; do not drop timestamp coverage
to make two separate wall-clock calls produce identical signatures.

The wire body's inner backend result is serialized text. A backend's exact
large integer therefore remains exact text and must not be rejected or rounded
by the outer JCS input validator. Verify this through HTTP with the original
digits intact. Actual out-of-range numeric members at the finalizer's JSON
result boundary reject in the dedicated finalizer fixture. This distinguishes
wire-domain validation from parsing and altering a second inner JSON copy.

After implementation: focused new suite, still-valid existing `message_signing`
regressions and migrated AUTHZ.20 through the external gateway_invoke path,
`cargo fmt --check`, focused compilation/lints, then coordinator's
broader release gates. Move existing all-five-method CACHE.1a/1b hint assertions onto the extracted modern shaper. Measure security-path coverage and mutation outcomes per
DoD; report missing tooling or surviving mutants instead of assuming coverage.

Test-review questions: does every AC have a reachable case; can each named case
fail for the claimed defect; do cache and idempotency fixtures prove their own
path by dispatch count and configuration; is the verifier independent; does the
capacity race actually stage exclusion inside the protected admission boundary?

Both vendors' rounds1–7 findings source-checked and disposed; duplicate-member REQUEST-parser inference explicitly rejected as outside this RESPONSE-verifier contract; design approval complete. Initial red-test evidence is recorded below; the full matrix remains required. The v2 primitive is implemented; startup/admission/delivery wiring remains pending. The shared adapter-tail finalizer
runs only after modern shaping, then applies the final firewall disposition,
signs external gateway_invoke, records the immutable delivery attempt, and
returns to serialization only. No-firewall mode still reaches signing.

Initial source: `tests/message_signing_delivery.rs` and `tests/common/signing_gateway.rs`. Rustfmt parser/formatting and whitespace checks pass. Five tests cover startup signing, enabled current-key validation, oversized-ID rejection, malformed nonce rejection and disabled compatibility. Spark r2 compiled and ran these exact files: actual exit 101, one disabled pass and four intended semantic assertion failures in 0.38s. Numeric 2^63 wrapped to i64::MIN; present null nonce reached the backend; enabled startup lacked a delivered signature; the first short-key case was accepted. Later elements of failing loops are not claimed independently executed. The strengthened disabled test proved both exact payload envelopes survived. 25 current shared scaffold warnings remain outside these files; no warning-free release claim is made.

Initial test-source approval: retained Grok `mcp-v4-signing-initial-tests-20260906-r1` SHIP (`grok-20260906T160309Z-47855.md`) plus GPT finder-only `mcp-v4-signing-initial-tests-20260906-r2-finder` SHIP (`gpt-20260906T162648Z-29959.md`). Actual subprocess exits 0 and authoritative ledger scope/HEAD/lineage/material bindings were verified. GPT closure material SHA256 `08cb0d1f31b82c8036fd5ed9d4b2adcc004b139a8287f606a5418754db20ceeb`, 35,816 scope+NUL+stdin bytes. Frozen test hashes are `d7ce8265ed4175675a29a1f6fb53bd31785231a9ddd045b450b935704b2915ae` (delivery) and `e95ec752bbcba7e44219a5916e65aefdc472d6b1b56f1a884b8e7f55930a60d2` (fixture). Spark r2 log SHA256 `5765f3ec50fa708434dc19344af6f18538da4e32cd2cce01b84007a8dbf68670`. Full receipts are under `~/.claude/data/review-evidence/mcp-v4-signing-initial-tests-20260906-r2-finder/`; root's copied run log is `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/mcp-gateway-v4-signing-red-r2.log`.

Nonblocking closure advice is carried to the next material wire-test increment: positive-response HTTP status checks and exact disabled request-ID/two-dispatch assertions. A blanket success-status assertion in the shared JSON-RPC call helper would also affect intentionally refused requests, so per-case expected status is the appropriate later control. No extra rebuild is required merely to restate that advice.

Configuration source: `tests/message_signing_config.rs` covers effective current/previous references and defaults, production literal persistence, missing/empty/short/all-zero references, UTF8 byte minimum, previous-key and operational validation, disabled dormant settings, and env-file authority against conflicting child-process ambient values. It uses public Config/EnvOverlay APIs without production scaffolds. The original r1 short-key fixtures were miscounted (33/34 bytes rather than 31/32); that evidence is withdrawn. Repaired r2 compiled fourteen tests: two controls passed and twelve assertions failed, actual exit 101. All four effective NUL-key fixtures passed the real overlay canary before incorrect validation acceptance. The ambient child ran exactly one test, preserved its before/after environment, and then failed on unresolved effective material; its completion marker correctly remains unreached. The actual writer preserved literal references. Log `mcp-gateway-v4-signing-config-red-r2.log` has SHA256 `3abe65ee808f42d8f14172b2bfe93a7fc352746dbdc6483c42a89755530a5ccb`.

Config r2 finder receipts are `gpt-20260906T180414Z-94424.md` and `grok-20260906T180415Z-94590.md`, both SHIP-WITH-FIXES, actual process exits 0 and exact authoritative ledger binding verified. Both require identifying the affected field, and Grok additionally requires literal valid current-key controls in the operational table. Those repairs are written in source SHA256 `d4fae7ea1ab554d943e185b2787e547935878d25e4173bd49d55304bfb0fca1a`; repaired r3 execution compiled fourteen tests (two controls pass, twelve semantic failures; actual101). Both r3 finder reports are SHIP with exact authoritative ledger and process receipts verified: `gpt-20260906T184115Z-95665.md`, `grok-20260906T184117Z-95819.md`, bound SHA256 `03f10fd4ebe8abd5eb17fc8da75e4df8425671166e51734a3570bfe067e6f431`, 46,981 bytes. The original configuration source gate is closed. Real gateway env-file startup, reload state preservation, and the remaining wire/security/resource matrix remain required and are not implied by these config tests.

Vector source: `src/security/message_signing_v2_tests.rs` uses independent Node verification in `tests/common/signing_verifier.mjs`, whose separate self-tests pin canonical inputs and known-answer MACs. Original Rust run compiled ten tests with one error control pass and nine missing-v2 failures, actual exit 101. Grok vector r1 SHIP (`grok-20260906T174605Z-54126.md`) is retained; GPT r1 SHIP-WITH-FIXES (`gpt-20260906T174552Z-53596.md`) requires a closed signature-member set, boolean-result rejection, and nested integer boundaries. Both actual exits and authoritative ledger bindings were verified. Repairs include those three requirements plus recursively frozen verified objects, pinned Unicode/extrema vectors and independent per-row nonce/timestamp verification. Sixteen Node self-tests pass; the exact repaired tests run against the frozen original verifier fail precisely the extra-member and mutable-object assertions (14 pass/2 fail), so the oracle repair has a discriminating falsifier. Process batching is a nonblocking later efficiency improvement; no runtime correctness or release criterion is waived.

Shared-finalizer signing tests live in `src/gateway/meta_mcp/signing_delivery_tests.rs`: twelve component cases cover external/internal origin, optional/required nonces, disabled compatibility, safe accessor/primitive failure, exact-once failure metrics, firewall-before-signing, existing-error short-circuit, and an independent final-attempt hash that includes signature and request ID. Their explicit component context and supplied shaping do not prove production adapter classification or modern shaping. Twelve nonce tests in `src/security/message_signing_nonce_tests.rs` exercise quotas, UTF8 bounds, expiry, global uniqueness and actual guarded-storage exclusion. Their limits/principal declarations delegate to the old implementation; only cfg(test) pauses enter the actual DashMap entry guard. No test-only global mutex manufactures the missing global admission boundary. Both test-source gates remain open.

V2 implementation evidence: retained Grok vector r1 SHIP plus GPT vector r2 finder SHIP (`gpt-20260906T182223Z-40171.md`, bound SHA256 `907180179b30bf79f89ebcf2ce6cebd4bae2aeed7c08eb5fa795ad72647ebd5b`, 69,094 bytes) closed the test-source gate. Root r14 executed `cargo test --all-features --jobs 4 --lib security::message_signing::v2_tests -- --nocapture`: ten pass, actual0, 0.17s. `src/security/message_signing_v2.rs` uses borrowed input and RFC8785 canonicalization. Its implementation/code review remains open; this component pass is not production builder or wire proof. Nine current shared scaffold warnings remain in the log.

The shared finalizer signing repair adds complete refusal envelopes, independent final-attempt hash/correlation/allowed-field assertions for every defensive signing failure, the missing-required-nonce metric row, no-result bypass and one firewall→MAC→attempt chain. Root r14 signing13 compiled: two unsigned/disabled controls pass and eleven semantic assertions fail, actual101, 0.08s. Existing-error and no-result exact preservation and zero metrics pass before missing log entry fails. All three refusal log assertions remain behind their real safe-refusal positive controls; they are not claimed executed yet. Grok branch r1 SHIP is retained; GPT-only finder closes the repaired source next.

The one-pass configuration addendum is `tests/message_signing_config_once.rs` (two cases). An env-file supplies current key bytes beginning `env:` and previous key bytes containing `${...}`, with a different resolvable inner variable. Exact overlay canaries precede runtime evaluation assertions. Follow-up validation/clone use preserves opaque bytes, serialization exposes exactly the existing six configuration fields, and mutation invalidates only its key's resolution identity. Actual execution and source review remain pending; no cache implementation is authorized by parser checks alone.

Dependency repair evidence: canonicalizer0.3.2 and transitive ryu-js1.0.3 archive hashes match Cargo.lock. Existing chacha20 0.10.0 was yanked for an SSE2 RNG undefined-behavior defect; the lock now selects only its compatible 0.10.2 fix. The configured rand0.10.2 dependency enables that rng path. `cargo fetch --locked --target aarch64-apple-darwin` succeeds, and `cargo audit --json` returns actual0 with zero vulnerabilities and zero warnings. Only the three changed dependency license rows were refreshed from checksum-verified crate manifests because local `cargo license` is unavailable; full release SBOM regeneration remains a coordinator gate. ARM test success is not evidence of executing the x86 SSE2 path.


## Configuration and nonce implementation checkpoint (2026-09-07)

The shared resolver/validator is wired into effective loading and
`Config::validate_with_env`. Private serde-skipped SHA-256 identities preserve
opaque effective bytes independently for current and previous keys. Disabled
settings remain dormant and literal rewrite paths retain references. The
reviewed configuration14, opaque-key two and initial enabled-key validation
case pass 17/17, actual exit0, in `signing-config-root-green-r3.*`.

The production nonce store now uses one mutex for its nonce map, per-principal
counts and monotonic expiry queue. Admission consumes the elapsed queue prefix,
refuses invalid/replayed/over-capacity nonces before allocation, and never evicts
live protection. Expiry removes zero-count principal buckets. The existing
compatibility entry point uses the bounded anonymous bucket; authenticated
transport principal selection remains unwired and is not implied by these tests.
All18 new nonce cases plus seven existing cases pass 25/25, actual exit0, in
`signing-nonce-core-green-r2.*`. That remote source snapshot remained unchanged
during the run.

Both passing runs used isolated task-model snapshots with explicitly pinned root
files, not a full-root integration build. The coordinator verified all seven
reported root source/test hashes against current files; commands, exact exits
and log digests are in `signing-foundation-root-verification-r1.json` in the
delivery evidence directory. The work remains local and uncommitted.

Retained failures and compatibility deltas:

- The first config attempt failed at compilation because the copied snapshot
  lacked two idempotency config dependencies. After copying those exact files,
  the same selection passed15. Its security-file hash differs from current
  code by a formatter line wrap plus the later opaque-key implementation; the
  fresh17-case run binds the final implementation. No compiler failure counts
  as behavioral RED.
- The first opaque-key Grok review failed with a600-second inference idle
  timeout and no verdict. The unchanged tests then received Grok SHIP in
  `mcp-v4-signing-config-once-tests-20260907-r2`; original GPT SHIP is retained.
- The nonce finder required actual principal-bucket cardinality observations.
  The new case compiled and failed at zero versus two buckets after three real
  registrations. GPT-only finder r3 closed it. The implementation observer now
  reads the actual guarded count map; it has no test-only counter.
- The first nonce runtime run passed24 and failed one old fixture that expected
  two already-expired entries to survive a second admission. Immediate expiry
  reclamation is required by the approved design. Its fixture now freezes the
  clock, admits and asserts two live entries, advances beyond expiry, explicitly
  evicts and retains the zero-entry assertion. The separate zero-window
  readmission control is unchanged. All25 pass in the final run.

The test-source gates are closed for these slices. Startup/reload enforcement,
raw external request classification and nonce/principal admission, HTTP/stdio
delivery and replay signing, metrics/resource qualification, coverage/mutation,
final code and independent functional gates remain required. These component
passes close no full-release acceptance row by themselves.

### Root startup/transport checkpoint — 2026-09-07 11:54 UTC

`tests/message_signing_delivery.rs` is unchanged from its approved source.
A refreshed root baseline compiled with two passing controls and three behavioral
failures; after integration all five pass. SIGNING.1 now exercises configured
production startup through actual HTTP delivery; SIGNING.4 refuses both out-of-i64
IDs without dispatch; SIGNING.5 exercises every malformed nonce loop element and
its exact safe refusal. SIGNING.2 and disabled SIGNING.6 controls remain green.

The common builder resolves signing with its evaluated overlay before shared
setup and installs the current/previous signer and bounded nonce store. HTTP and
owned stdio request/batch dispatch capture raw IDs and bounded nonce state in
private context. Policy/attestation/profile checks precede nonce admission, and
outer execution admission runs afterwards. Internal invocation does not consume
an external nonce. Adapters pass that same context to final response security;
retained execution results exclude gateway-owned signatures and obtain a fresh
signature at delivery. The old inner body-only signing path is removed.

Library signing/nonce/stdio/authorization regressions pass 82 (one existing ignored
stdio retry test); real HTTP/stdio firewall and execution-admission targets pass
66. AUTHZ.20's old direct internal-call fixture failed its replay assertion. Its
fixture now uses real raw-context capture and external preparation, retains the
same refusal/allow/replay requirements, and additionally asserts exact backend
counts 0/1/1. This is a boundary adaptation, not a waiver of its replay oracle.

The standalone `signing-wire-probe-r1.py` exercises production CLI HTTP and stdio
with an actual counted backend and the existing independent Node verifier. All
29 checks pass, including raw control-character/decomposed Unicode metadata,
fresh cache-hit MACs without redispatch, exact nonce errors, HTTP routing and
nonce aliases, and unsigned discovery. These are coordinator-run functional
smokes, not independent final implementation approval or a full signing matrix.
Evidence: `signing-wire-root-verification-r1.json`, associated source manifests,
raw logs and subprocess receipts in the release evidence directory.

Still required: full credential-authority quota ports (the transport currently
uses the bounded anonymous bucket), transactional reload refusal/preservation,
borrowed envelope/target views and owned params/arguments/retry extraction,
required-nonce discovery schema, explicit-key idempotency/continuation and signed
modern shaping/accounting cases, resource metrics, quantitative gates and final
code/DoD reviews. Existing scope remains mandatory; no release row is closed.

Strict all-feature library Clippy ran and remains blocked: 81 initial diagnostics,
79 after repairing the new signing module documentation/import diagnostics.
The final tested-source delta is only those two non-behavioral repairs, verified
by reconstructing the pinned tested hash. All 561 current source/fixture/manifest
file hashes match the Spark snapshot. The complete errors remain in
`signing-wire-clippy-r2.log`; no zero-warning or final code-approval claim is made.

### Reload refusal tests — 2026-09-07

`tests/message_signing_reload.rs` now contains 15 compiled tests against the
actual `ReloadContext` transaction. Three compatibility controls pass; twelve
signing-change refusals are behaviorally red. They cover all six settings,
both enable directions, current/previous env rotation, equal-effective reference
changes for both keys, reference-to-literal identity, and unchanged/disabled
controls. The previous-key alias exists with its final value before startup;
that case changes only the config reference and performs no env-file edit.
Each refusal first validates its candidate, then checks repeated refusal,
unchanged live config/environment objects, exact backend objects/membership,
and unchanged candidate files. It does not claim candidate-file rollback.

The initial harness compile error (`ReloadOutcome.applied` is not a field) and
the disabled-backend positive-control error were corrected before review; neither
counts as a product failure. Compiled r3: 14 tests, 3 pass/11 behavioral failures.
Grok r1 SHIP is verified. GPT r1 required a previous-key equal-effective reference
case; r2 required a stable startup alias to eliminate an env-rotation ambiguity.
Both findings were source-verified. Repaired r6: 15 tests, 3 pass/12 behavioral
failures, source `23b4bf6f42dd998d30fde6fbb6242e34d26335e9ee4ec8ee034835889c7ac5dd`.
GPT r3 finder SHIP is verified against its actual0 process and authoritative
ledger; the reload test-source gate is closed with retained Grok r1 SHIP. Raw source, process exits, logs and ledger receipts
are retained under the corresponding `signing-reload-red-r*` and
`mcp-v4-signing-reload-tests-20260907-r*` evidence names.

### Reload runtime checkpoint — 2026-09-07 12:31 UTC

The configured-key source fingerprints and pre-publication guard are implemented.
All 15 reviewed reload cases pass; current configuration14 and opaque-key2 pass
unchanged. Existing writer/config preservation44 and config-reload/debug83 pass.
The configured-reference tests explicitly reach the empty-patch branch on the old
behavior; they now refuse before it can publish the candidate environment.

An extended public CLI probe passes 38 assertions. HTTP checks verify exact
restart-required field refusal for a changed key ID combined with backend removal,
old-key MACs and live backend use afterwards, nonce replay state preservation,
a successful restored-config reload, refused effective env-file key rotation, and
old-key MACs afterwards. It also retains the HTTP/stdio signing/cache/nonce controls.
Stdio had no reload context in production startup at the time of this probe; shared-builder wiring was still required, and this probe does not claim stdio hot-reload coverage. Later local stdio ReloadContext attachment is recorded in the 2026-09-07 Grok checkpoint below; that later work is outside this probe's original scope.

Two nonce implementation lint findings are repaired, with nonce25 passing again.
Strict all-feature library Clippy remains blocked by 77 diagnostics across the
unfinished tree. Final code/quantitative and remaining integration gates stay open.
Evidence is source-bound in `signing-reload-root-verification-r1.json`; no commit,
push, published release or production deployment is claimed.

### Static-credential quota increment — 2026-09-07

The initial static subset of SIGNING.5 is in
`tests/message_signing_static_quota.rs`. Three actual CLI/HTTP scenarios fill
the production 10,000-nonce per-principal limit: protected same-label API keys,
public anonymous versus valid static credentials, and authentication-disabled
fallback. Exact quota/replay errors, fresh delivered signatures, global nonce
replay, backend non-dispatch on refusal, and caller-controlled agent labels are
checked. The local gateway policy declares the fixture tool read-only.

Baseline `signing-static-quota-red-r5.process.json` records actual exit 101:
one compatibility control passes and two intended isolation cases fail. Earlier
fixture failures (required modern headers, read-only policy, HTTP error status)
are retained separately and do not count as behavioral-red evidence. The frozen
test hash is `10b31b01e45f9e40551bd448f3ed2c5bb234ad7d8d71c373d8d73ef77c41e195`.
Test-source review is closed: retained Grok r1 SHIP and GPT r2 finder SHIP
(`mcp-v4-signing-static-quota-tests-20260907-r2-finder`). The only test repair
makes the shared fixture module public, eliminating four dead-code diagnostics;
strict test compilation passes. Current test SHA256 is
`504aa43df7448f483dbc88c397596712805f30b32a0e2aa70c092172974edb50`.

Production authentication now assigns a private, redacted full-digest quota
principal after successful primary-bearer/API-key verification. Router and
authorizer propagation reaches the existing per-principal nonce store; disabled
authentication and invalid public credentials stay anonymous. The existing
short audit principal is unchanged. `signing-static-quota-green-r2.process.json`
records all three quota cases plus 22 authentication/tool-scope regressions
passing, actual exit0. Another31 session, delivery and reload checks pass.
These functional cases prove isolation, not the structural full-digest property.

OIDC, OAuth, certificate, dashboard, structural full-digest/redaction,
wrapper-delegation, quantitative and final code-review cases remain required.
The pinned root build still has76 strict Clippy diagnostics in unfinished
integration code; this increment does not close the whole signing criterion.

### Nonce discovery schema checkpoint (2026-09-07)

Grok-authored, uncommitted: `src/gateway/meta_mcp_tool_defs.rs` (`build_invoke_tool`, `require_gateway_invoke_nonce`), discovery overlay in `src/gateway/meta_mcp/mod.rs` `handle_tools_list_for_session`, tests `tests/message_signing_nonce_schema.rs`. Shared fixture `tests/common/signing_gateway.rs` read-only. P2-reviewed test/fixture hashes unchanged (`green-source-hashes.json`).

`gateway_invoke` always advertises optional `nonce` (`string`, `minLength` 1, `maxLength` 256; description contains `at most 256 UTF-8 bytes` and that `maxLength` is a character ceiling). Effective `required` includes `nonce` only when `signing_enabled() && require_nonce`. Optional, disabled (`enabled=false` with dormant `require_nonce=true`), and disabled-default (`both false`) never require it. Other tool schemas, Code Mode search/execute, and exposure-hidden tools are unchanged.

Matrix: four signing modes on public HTTP and stdio; static Code Mode; `?codemode=search_and_execute` URL override; exposure hide-then-keep. Twelve independent tests.

Updated RED (pre-runtime): actual exit 101, 2 Code Mode tests passed, 10 expected failures on missing `gateway_invoke.nonce`. GREEN (Spark lane1, `cargo test --test message_signing_nonce_schema -- --test-threads=1`): actual exit 0, 12 passed, 0 failed, 2.13s. Existing `meta_mcp_tool_defs` regressions are a separate coordinator run; not claimed here.

P2 authoritative GPT finder closure: runid `grok-nonce-schema-p2-closure-20260907`, ledger SHIP, `process_status` ok. Evidence: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/grok-nonce-schema-20260907`.

No release, P4, or full-Clippy claim. About 60 inherited compile warnings outside this slice remain root's broader validation gate. This schema/test slice produced no warnings. Tests and implementation remain uncommitted.

### Sender-only rotation checkpoint (2026-09-07)

Grok-authored, uncommitted, P2-reviewed test only: `tests/message_signing_sender_rotation.rs` SHA256 `446330add8f10bfc4ea8cb73d1dbd97f2911211bbb3806da550b4bb626ed8887`. Shared fixture/verifier read-only (`signing_gateway.rs` `bd6bb8ad731bac3f6190e5ec49e872a5a6318f61b40538414694b50efe43425e`, `signing_verifier.mjs` `0de27057f0d089b275504185512cf24da0bbc882db0e9a596bd5b2bb717771a7`). No permanent runtime edit. Evidence: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/grok-sender-rotation-20260907`.

Contract (test-plan row 48): enabled signing with distinct valid current/previous keys; one raw HTTP `tools/call` wire; independent Node oracle (v22.23.2) verifies under current and rejects under previous. Same typed string ID `{kind:"string",value:…}`, nonce, `key_id`, and `now` on both checks; only `key` differs. Not verifier-grace expiry, unknown key IDs, rapid rotation, or full SIGNING.6/DoD/release closure.

Baseline2 (`baseline2-result.json`): `cargo test --test message_signing_sender_rotation -- --test-threads=1` actual exit 0, 1 pass. Current-key oracle exit 0; previous-key exit 1, stderr exactly `MAC mismatch\n`. Strict test target (`strict-test-target.log`): `cargo rustc --test message_signing_sender_rotation -- -D warnings` actual 0. Public fixture module avoids dead-code. About 60 inherited library warnings remain root's gate; no full-Clippy claim.

P2 ledger SHIP, run_id `grok-sender-rotation-p2-20260907`, wrapper actual 0 (`p2-review-result.json`). Advisory to bind fixture/verifier hashes as well as test/builder was implemented in the external runner.

Isolated remote falsifier in authorized/frozen `Gateway::build_meta_mcp`: first `MessageSigner::new` argument selected previous bytes; `key_id` and previous argument unchanged. Unique original backup outside source. `wrong-signer.log`: cargo actual 101, current-key assertion stderr `MAC mismatch`, no compile error. Builder restored, mtime advanced, rebuilt. `restored-green.log`: same cargo command actual 0, 1 pass, 0.34s. `falsifier-result-local.json` runner actual 0; final hashes unchanged (builder `dbfd24e8b57799d45acbfbeacabd56b8c93ca59493b837386217852b9e303cb1`, test/fixture/verifier as above). Never a local runtime edit.

Earlier `baseline.log` actual 101 was typed `expectedId` harness mismatch (`unexpected request ID`), corrected before P2; not runtime RED and not the falsifier. Two source compile defects (`Option<&Value>::is_object`) were fixed before first compile.

Permanent runtime implementation is not needed: production already signs with the current key. Local P4 review is closed: the source-bound slice receipt (`slice-receipt.json`) records P2 and P4 SHIP, actual 0, over the wrong-signer and restored-GREEN evidence above. Local/uncommitted.

### Dashboard operator quota checkpoint (2026-09-07)

Claude-authored, uncommitted: five real `auth_middleware`/store tests plus a real CLI bootstrap-cookie integration. Validated: every dashboard handle shares one dedicated operator quota; caller labels and cookie values never open a new bucket; static bearer and API-key principals stay separate; an anonymous fill cannot starve the dashboard; invalid, missing and disabled-auth handles remain anonymous; live nonce uniqueness stays global. The dedicated kind reuses the existing SHA256 length-prefixed domain machinery, and raw session handles never enter the bucket. Runtime is nine constructor/doc lines in `auth_quota.rs` plus one `dashboard_client` field; approved tests and fixture are unchanged.

Genuine RED: component 3 PASS / 2 FAIL, CLI 0 PASS / 1 FAIL with the exact capacity error after an anonymous fill. P2 GPT (`gpt-5.6-sol`) SHIP, actual 0, source-bound (`p2-verified.json`). GREEN, source-bound with identical before/after hashes: `dashboard-auth-green-r1` actual 0, 33 passed; `dashboard-wire-green-r1` actual 0, 1/5/3 passed. Strict new-integration compile actual 0; strict library diagnostics 72 baseline against 72 current, none new and none owned; not a full clean and not a release claim.

OIDC, OAuth and certificate identity ports explicitly remain pending. Bounded local P4 review is closed for this dashboard slice: actual GPT `gpt-5.6-sol` SHIP, process exit 0 in 231.63s, bound material SHA256 `0eef9f6eebecb64f812643dfe0e6e89c283b31e581b6cf44944d1f22ff262b57` over 45,179 bytes, verified receipt `code-verified.json` in the evidence directory below. No full SIGNING.5, DoD or release completion is claimed. Local, uncommitted and unpushed. Evidence: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-dashboard-quota-20260907`.

### OIDC credential quota checkpoint (2026-09-07)

Claude Opus 5 authored a 467-line Linux-only real-CLI test target, then bounded
runtime in `auth_quota.rs`, `key_server/mod.rs` and `auth.rs`. Validated: one
verified issuer/subject owns one nonce quota across minted temporary tokens A
and B and delegated JWT C; a distinct subject or issuer stays independent; both
public and protected paths recognise real OIDC credentials; invalid and missing
public input falls back anonymously; delegated-disabled JWTs and auth-disabled
credentials never mint authority; nonce uniqueness stays global; static and
dashboard behaviour is unchanged. Credentials come from the existing real HTTPS
JWKS fixture and actual RFC 8693 exchange via child-local `SSL_CERT_FILE`, no
verification bypass; approved tests and fixtures are unchanged since P2. Type
docs broadened to validated credentials and sessions; static/dashboard
constructors untouched.

Genuine RED 1 pass / 3 fail, actual 101 in 17.89s; strict new-target compile
actual 0 in 3.04s. P2 GPT `gpt-5.6-sol` SHIP, actual 0 in 254.36s, binding
`762cedbc…6354e846` over 61,125 bytes. GREEN actual 0, 135 total: 92
auth/key-server, 13 wire (dashboard 1, delivery 5, OIDC 4, static 3), 30
verified admission. Runtime author run actual 0 in 216.70s. Strict library
Clippy actual 101 with exactly 72 baseline against 72 current, none new and none
owned. OAuth-client and certificate identity ports remain pending. Local,
uncommitted and unpushed; no full SIGNING.5, DoD or release claim. Evidence:
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-oidc-quota-20260907`.

### OAuth-client and certificate quota checkpoint

Production CLI OAuth `client_id` and certificate full-DER quota keys are validated as separate identities: same names remain distinct identities, the same identity shares one cap across generations and connections, global replay is unchanged, and auth remains independently active when `auth.enabled=false`. Local evidence: RED 1 PASS / 2 FAIL; GREEN 260 components + 16 wire = 276 PASS; strict library exit 101 with the same 72 baseline diagnostics, none new or owned, and new test-target strict 0. Final review status is in [the source-bound slice receipt](/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-oauth-cert-quota-20260907/slice-receipt.json). Source remains local and uncommitted.

## Local checkpoint (Grok, 2026-09-07): public stdio reload

Verified local evidence that `Gateway::run_stdio` now attaches the existing `ReloadContext` when the config path exists. Acceptance rows, SIGNING close, DoD, and release remain open. The original 2026-09-06 probe still does not claim stdio coverage.

**Author:** actual Grok. Runtime process 0. Patch header counts mechanically normalized. No supervisor Rust changes.

**Runtime SHA:** `1dc9fb2e92044390e3ad7ee7a765eab2a64c6fa7003814ae2f569b67d1e5c0dd`

Startup `LiveConfig`; same registry, failsafe, cache TTL, and evaluated live env; same retained Meta-MCP surface. No new watcher.

**Target:** `tests/message_signing_stdio_reload.rs` (489 lines). SHA `e877bc61a134ecc435cef1a0b00423bc7a32dca20de7fc5c9c656d2f83a818ca`.

Genuine compiled RED: 0 pass / 8 fail. Required P2 initial-MAC-before-reload gap repaired by actual Grok in one await. Same GPT finder: SHIP 0 / 73.53s, binding `14f27d616881dfa0408cd86a0b5cb6019c3f6de2a22993507a8ea95fe08e4bb6` / 13946. Then GREEN: 8 pass.

Public stdio coverage: raw initial and post-reload Node MAC oracle; six signing-config changes paired with A->B backend candidate; byte-identical config combined with current+previous env-file rotation refusal and recovery; ordinary backend reload; replay with no backend effect. Private env/config snapshots remain the existing 15-component evidence and are not claimed from public stdio.

**GREEN commands**

- `cargo test --all-features --jobs 4 --test message_signing_stdio_reload`: 8 pass, 0 fail, 27.65s
- existing six targets `stdio_tests`, `nfr_compat_2_stdio_client_session`, `message_signing_nonce_schema`, `message_signing_reload`, `message_signing_delivery`, `message_signing_sender_rotation`: 47 pass, 0 fail, 6.01s
- total 55 passes
- strict new-target compiler: 0
- `cargo clippy --all-features --jobs 4 --lib -- -D warnings`: actual 101 / 16.45s; identical inherited 72 diagnostics (one elsewhere in server mod); no new
- source manifest: 15 files, stable

Work is local, uncommitted, unpushed. Outstanding full release gates remain. Full source, process, and hash receipts: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/grok-stdio-reload-20260907` and `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/grok-stdio-reload-20260907/slice-receipt.json`. Prior P2 advisories remain observations (`p2-advisory-dispositions.md`).

Final review (gpt-5.6-sol), verified:

Verified SHIP, actual process 0 / 163.54s, binding `f7b79be4477fafc07112b498b9f42760b04d48ed336de07ea9bf9d01caba11df` / 28551. Report: `/Users/mikko/.claude/data/reviews/runs/gpt-20260907T185628Z-72131.md`. The two optional P4 improvements (shared constructor and no-config-path reload refusal test) remain observations, not fixes in this slice.

## Local checkpoint (Claude, 2026-09-07): nonce telemetry and redaction

Bounded nonce occupancy/rejection telemetry with the two capacity alerts. Tests
were authored before runtime and are frozen. Scope is telemetry and redaction
only; rows 39-42 (admission, cache, dedupe, allocation proof) remain explicitly
pending, and every other approved scope item is unchanged.

**Paths.** Runtime: `src/security/message_signing.rs` (metric helpers plus call
sites in `check_and_register_for_principal` and `evict_expired`),
`src/gateway/meta_mcp/signing.rs` (one raw-invalid counter at the
`prepare_signing_invocation` boundary, after policy),
`deploy/prometheus/mcp-gateway-alerts.yml` (two rules appended; the existing rule
unchanged). Tests: `src/security/message_signing_nonce_metrics_support.rs`,
`src/security/message_signing_nonce_metrics_tests.rs`,
`src/gateway/meta_mcp/signing_nonce_metrics_tests.rs`,
`tests/message_signing_nonce_metrics_export.rs`,
`deploy/prometheus/mcp-gateway-alerts-test.yml` (cases appended; existing cases
unchanged). Prose: `docs/DEPLOYMENT.md`.

**Validated.** One aggregate label-free occupancy gauge published under the store
lock on admission, admission-side reclamation and expiry cleanup; one increment
per refusal on `mcp_message_signing_nonce_rejections_total` with `reason` as the
only label over `replay | invalid | principal_capacity | global_capacity`;
existing error precedence, messages and replay/quota/expiry semantics unchanged;
a raw nonce refused at the signing boundary counted once there and not on
repeated `delivery()` inspection; policy refusal not counted as a nonce
rejection; export reaching `metrics::render()`. Quota algorithms are untouched,
and the full-digest, domain-kind and redacted-`Debug` controls pass.

**Receipts.** P2 finder SHIP (Grok), source-bound `p2-verified.json`, material
SHA256 `de07881878d325a9bb80832cf31bfd99ce837810eef6e08f61cba685cdccd50e` over
23,151 bytes. Runtime author run actual 0 in 314.68s. Unit 91 pass / 0 fail (28
new plus 63 existing); export and `message_signing_delivery` 6 pass / 0 fail;
default-minus-metrics check actual 0. Strict library diagnostics 72 before
against 72 after, none added and none removed, and the release diagnostics they
represent remain unresolved. promtool 3.13.3: production rule parse actual 0 over
3 rules, complete alert fixture actual 0. The principal-only fixture case kills a
precise global-only rule mutant (fails 1). The occupancy timing expectation was
confirmed by an official promtool sample probe against the `for: 5m` rule; no
timing or series was changed. Lock-order and expiry falsifier mutants completed
remote-only with unconditional source restoration, runner actual 0: M1
(publication moved outside the admission guard) actual 101, both admission
witnesses failing; M2 (publication moved outside the eviction guard) actual 101,
the eviction witness failing; M3b (admission-side reclamation skipped) actual 101,
two occupancy failures reporting 3 against an expected 2. Each restored run is
actual 0, the final run is 28 pass, and the final source hash
`0269f71e125df2273157b6119e059acacef6bfd469b34b5fab45cc979f1e31b7` matches the
frozen GREEN source. Receipt: `spark-falsifiers/falsifier-process.json` in the
evidence directory below.

Local, uncommitted and unpushed. No full SIGNING.5 acceptance, DoD or release
completion is claimed. Evidence:
`/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-nonce-telemetry-20260907`.

Nonce telemetry P4: verified SHIP (Grok), actual process 0 / 373.14s, binding `1b5b014c041781e5fada40e5f200349d5624b022e25b675e1008db4ce530b3b0` / 62378. Report: `/Users/mikko/.claude/data/reviews/runs/grok-20260907T202818Z-18469.md`. Exact slice receipt: `/Users/mikko/Documents/Codex/2026-09-06/mcp-gateway-v4-scope-review/claude-nonce-telemetry-20260907/slice-receipt.json`. Five optional P4 observations are retained in `p4-advisory-dispositions.md`; no extra coverage or fixes are claimed.

## Checkpoint — SIGNING.5 row39, cache/admission observers (qualified locally)

- Scope of this checkpoint only: existing live cache statistics and cfg(test) admission counters on the signing-refusal nonce path plus the required-nonce embedded production modern-HTTP-router controls. The approved scope stays rows 39–42; nothing else here is closed or waived.
- Source behaviour is unchanged: additions are cfg(test) counters and the lookup bindings needed to reach them; all S1/S2 task functions untouched; shared observer hooks were explicitly authorized by the task owner.
- Legacy idempotency is `None` on the production route — asserted directly, not inferred from a zero counter.
- Runs: baseline 8 PASS (exit 0, 63.51 s); final 8 PASS (exit 0, 0.59 s); existing 15 Sync controls PASS (exit 0, 60.53 s). 23 unique passes; repeat executions are not counted as unique.
- Falsifiers ran against the real path: (A) `admit_meta_sync`/drop before the nonce check → exit 101 (56.57 s), expected admits 1 / lookups 3 / misses 2 / reservation 1 / abandon 1 / removal 1, cache and backend 0, final store empty; (B) `ResponseCache.get` before the nonce check → exit 101 (58.71 s), cache_misses 1 with all admission and backend counters 0. Both restored clean (exit 0, 59.55 s and 60.94 s).
- Integrity: source hashes before and after match across 17 files exactly; the frozen manifest carries 18 entries, the 18th being the read-only hash added for the controls leg.
- Lint posture: 7 inherited lib-test warnings, none in owned paths. No whole-repo-lint claim is made.
- Different-author gate: Grok **SHIP**, actual exit0/513.75s; run `signing-refusal-observers-p2-final-grok-20260907-r1`, exact material `f459ac1bdbe60edd22903cabd27f6aca4a8b00b02219e670a9af3281e243a688` /132478 bytes. Authoritative ledger and all18 source hashes independently verified. No mandatory findings; advisories retained in `claude-signing-refusal-observers-20260907/slice-receipt.json`. This is one test-only P2/final gate, with parent integration qualification separate.
- Still open in row39 and later rows: `parse_tool_arguments` and transparency canonicalization/hash counters with positive controls; optional/disabled modes, complete warm/cold boundaries and stdio legs; owned stdio/HTTP allocations (1 MiB / 3 MiB / <16 KiB) above necessary parse/sanitize work; siblings, retries, batch, max-body; policy-refusal nonce preservation, authorized retry and later operational consumption; raw-nonce vs typed-ID Unicode/control/sanitizer/alias/nested-business-nonce wire MAC and stdio equivalence.


### Local checkpoint: dispatch clone and transparency request-hash refusal (2026-09-08)

The embedded modern HTTP production-router checkpoint is qualified locally: seven new
nonce/refusal tests, eight unchanged cache/admission controls, and two existing hashing
controls pass (17 unique tests). Counters observe the real dispatch-argument clone and
canonicalization/digest operations inside the annotated transparency request-hash block.
Accepted requests prove actual work and a completed invocation record; refused requests
preserve the entire parsed log-entry sequence. This is a work observer, not an allocator.

Two independent isolated falsifiers preserved the nonce refusal while exposing an early
argument clone, then an early canonicalization/hash (5,072 bytes). Each was restored and
rerun GREEN; all 20 source hashes matched afterward. Actual Claude authored the tests and
hooks. The different-vendor Grok review returned SHIP (actual exit 0), bound to material
`d437d1cf90fe8423015d4cf067779195882e4191deefc8a7d3892bd96230eabc` (75,663 bytes).
The initial compiled baseline's five failures were incorrect one-log-line expectations;
the repaired record-level oracle passed without a production behavior repair.

Evidence: `claude-signing-clone-hash-20260907/slice-receipt.json` in the local scope-review
archive. Reviewer advisories are retained there. Allocation limits, unannotated/response
hash work, stdio/other transport modes, retries/siblings/batches/max-body, and the remaining
policy/metadata proofs in rows 39–42 remain open. This checkpoint does not close SIGNING.5,
whole-foundation qualification, repository-wide strict lint, CI, or release acceptance.
