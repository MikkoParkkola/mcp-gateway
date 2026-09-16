# 4.0 personal accounts test plan

Status: independent increments 1–3 have reviewed plan closure; hosted consent
remains blocked as specified below. No tests or execution results are claimed by
this document. Companion [design](2026-09-06-personal-accounts.md), including its review receipts,
and [approved release criteria](../requirements/RELEASE-4.0.0-scope-update.md)
are authoritative for expected behavior. Keep per-criterion verdicts in the
release ledger, with exact revision and executed evidence.

## Acceptance map

| Acceptance criterion | Cases | V-model level / type | Current execution evidence |
|---|---|---|---|
| MIK-6744.STORE.1 | S01–S07, S12, S15 | Unit + integration / security, persistence, migration | Pending implementation and execution |
| MIK-6744.STORE.2 | S07–S15, R05 | Integration + system / concurrency, crash recovery, revocation | Pending implementation and execution |
| MIK-6745.JOURNEY.1 | C01–C07, A07, L01–L04 | Integration + acceptance / consent, usability, provider interoperability | Pending; real configuration is not yet acceptance evidence |
| MIK-6745.JOURNEY.2 | R01–R05, L01–L04 | System + acceptance / tenant isolation, negative authorization | Pending implementation and execution |
| MIK-6745.JOURNEY.3 | R01–R09, M01–M05, A01–A05 | Integration + system / public-route parity, protocol, authorization | Pending implementation and execution |
| MIK-7334.CATALOGUE.1 | M01–M06, R05 | Integration + system / metadata and result isolation, concurrency | Pending implementation and execution |
| MIK-6746.CONTRACT.1 | A01–A06, R03, R07 | Unit + integration + system / gateway audience, client adapter, route parity | Pending implementation and execution |

Increment readiness is separate from release acceptance. S01–S15, R01–R09,
M01–M06 and A01–A05 define the independent storage/resolver/catalogue review
boundary; their actual code/tests still need their own reviews. A06 awaits the
installed client-route check. **C01–C07 and A07 are blocked requirements pending
the same-principal browser-bridge decision**; they are not approved test
implementations or permission to substitute state possession for browser auth.
All remain required for the complete JOURNEY.1 live flow. Removing an increment
dependency from an AC map does not waive any release test case.

## Fixture contract and test honesty

The decisive fixture is an HTTP OAuth provider plus MCP and REST backends that
record actual received credentials. Alice and Bob have identical display labels
but different verified subjects. Add same-subject/different-authority, same
principal/different-resource and same-resource/different-issuer variants. Carla
has gateway access but no account grant. A tempting operator token is installed
as the leak discriminator; a separate explicitly shared backend is the positive
control. No test may remove the operator token simply to make fallback impossible.

Mocks replace external provider/backend I/O only, never the resolver, public auth
middleware, store, metadata cache or pool under test. Expected tokens/accounts
come from independently seeded provider fixtures, not a production key helper.
Use real HTTP entry points for route assertions; directly constructing a verified
context is acceptable only in separately labeled unit tests.

Concurrency is staged with barriers at provider response and pre-publication
boundaries, not timing sleeps. Prove the overlap occurred, then assert external
request counts, durable records, result content and forbidden cache entries.
Crash tests use a child process and real restart; resetting a struct is a unit
test, not restart evidence. Every negative scenario has a nearby valid positive
control so permanently refusing all requests cannot pass the matrix.

## Storage and lifecycle cases

| Case | Setup and decisive assertion |
|---|---|
| S01 | Save distinct A/B records; load exact tuple only. Changing label preserves identity; changing subject/authority/backend/resource/issuer does not. Test delimiter-ambiguous inputs and reject invalid empty fields. |
| S02 | Search persisted/temp bytes and captured diagnostics for recognizable full synthetic access/refresh secrets and account IDs; none appear. Check owner-only creation and atomic replacement, not permissions tightened afterwards. |
| S03 | Move ciphertext between keyed paths; mutate ciphertext, nonce, schema or key ID; wrong/missing key and malformed/missing authority return errors, not absence/connect-ready. Independently change the token AAD's accounts.instance_id or store epoch while keeping its ciphertext/key/account tuple fixed: each AEAD open fails; the original values decrypt. Neither adapter installation_id nor a nested account-key domain may substitute for the specified token AAD fields. Startup cannot auto-initialize. Offline init works only on empty roots, refuses previous state, and does not import a token. Unmodified same-key record decrypts. |
| S04 | Inject write, sync, rename and parent-sync failures. Previously acknowledged record remains intact or startup reports an explicit durability failure; no success is returned before required durable operations complete. |
| S05 | Explicit offline Local/shared migration with current epoch and source digest succeeds, decrypt-verifies, and survives restart. A/B personal first-use and daemon startup cannot import it. Missing/old epoch and wrong source digest refuse; malformed/read-denied source stays byte-identical; no migration marker is emitted on failure. |
| S06 | Rotate current key and keep old decrypt key: old and new records read; new writes use current key. Attempt removing a needed key, invalid lengths, symlink paths or unsupported schema: fail before token disclosure. |
| S07 | Concurrent expired-token calls produce one provider refresh for the same account; different principals refresh independently. Preserve refresh token and granted scope when omitted; explicitly changed scope cannot broaden access. Never replace them with another principal's. |
| S08 | Hold refresh response, durably revoke, release response: compare-and-swap rejects it; new dispatch refuses; restart cannot resurrect either token. |
| S09 | Hold old refresh, revoke and reconnect to a new generation, then release old refresh: new grant survives unchanged and remains usable. Hosted-callback replacement is C05, not part of this independent store fixture. |
| S10 | Kill child process before/after atomic commit and restart using the same encrypted store/key. Observe only a complete accepted generation, or explicit unavailable/corrupt failure; never silently empty data. |
| S11 | Start two writer processes on the same directory: second fails clearly within one second rather than blocking on the lock; releasing the first permits startup. Platforms without real locking reject enabled shared custody, not silently pass this test. |
| S12 | Revoke a migrated grant and restart with untouched legacy source still present: durable migration marker prevents re-import. Snapshot/restore rehearsal preserves keys and revoke history; rollback never converts to shared plaintext. |
| S13 | Save valid pre-revoke ciphertext, revoke durably, replace the token record with saved bytes, then restart. Latest independent authority still refuses it; no downstream call occurs. Also migrate a legacy source, revoke, lose authority, initialize recovery with fresh roots/key/epoch, then replay the old config/migration input while retaining the old source unchanged: no import or dispatch occurs. A fresh fixture-seeded grant remains usable; fresh explicit epoch-bound migration authorization is a separately recorded operation. Restoring token records preserves current authority; a full old authority snapshot cannot be a recovery path. |
| S14 | Render/run shipped Helm/Kubernetes/Compose validation with managed custody plus two replicas, HPA, ephemeral store or rolling overlap: reject. One persistent process with Recreate passes. Two distinct directories do not count as a successful lock-based cluster isolation test. |
| S15 | Start the actual gateway for each one-field configuration mutation in the vector table below; assert its field-specific sanitized diagnostic and failure before listening/dispatch or token creation. Run the matching valid control first. Separately measure the actual store capacity and durable-commit workload below. |

S11 lifetime regression (Unix only): use File::try_clone on the guard's private
File to retain its exact open-file description as a deterministic witness of
fork inheritance. A second open of the same path/inode is not this witness.
Each acquisition constructor creates an owner; all contenders use try_acquire
and must return WouldBlock while that owner lives. After Drop, a new nonblocking
acquisition must succeed while that
duplicate remains open and verifiably references the lock file. Non-panicking
unlock error handling remains a reviewed Drop policy; this fixture does not
force LOCK_UN to fail and cannot prove that policy dynamically. This does not
replace the separate two-process/crash S11 cases.
The Linux FIFO S03 case must still pass concurrently with the original account
reopen and shared lock tests. Run at least 40 four-thread repetitions with zero
immediate-reacquire failures, matching the observed 2/40 baseline. This is an
additional soak; the deterministic duplicate-descriptor oracle supplies the
decisive red/green proof. Serial-only green cannot close the observed defect.

The next immutable-authority read slice refines S01/S03/S13 without claiming
durable writes or revocation. Independently encrypted fixtures cover all five
account axes, genuine absence, exact accepted candidate selection, a missing
candidate despite an authentic orphan, ignored foreign orphans, revoked and
reconnect-required states with old ciphertext retained, and each of generation,
token revision, authorization epoch and descriptor revision disagreeing between
an authentic record and its authenticated manifest. A separate same-version
authentic token replacement must fail the accepted-ciphertext checksum. Unsafe
basename fixtures include dot/parent paths reaching a valid record and malformed
single-component names containing its exact ciphertext, so missing-file or AEAD
failure cannot accidentally supply the refusal. Record symlinks, public modes,
oversize and directories require physical-storage refusal with original/restored
valid controls. Whole-manifest entry validation remains a separate required case
before that behavior is completed.
These read fixtures do not prove a durable revoke, CAS, crash or migration.

Lookup checkpoint 2026-09-07: the four mandatory findings from the store-lookup
test review are answered by authored tests, with production source unchanged.
The bounded record-FIFO case now exists as a child-process oracle
(`s03_fifo_record_refuses_promptly_without_blocking_lookup`), Linux only and
unexecuted, so its behavior stays open until a Linux lane runs it; other
platforms leave that path unexecuted, never passed. An invalid account key must
be refused rather than reported as connectable absence, on every axis for both
an empty and an oversized field, beside the retained valid absence control.
Revoked and reconnect-required states are asserted with the unreferenced record
retained, removed and corrupted; removed and corrupted are equivalent falsifiers
against an implementation that still globs `{digest}-*.json` after revoke, and
count as one caught fault rather than two. An authentic record planted for a
never-committed tuple must still resolve Absent, proved authentic through
`open_token` first so the assertion cannot pass on an AEAD failure.
Against the stub these cases were executed red on Linux: eleven failures, one
ignored bounded-child entrypoint, compile clean in 43.03 s, and both review legs
returned SHIP with recorded ledger rows.

`PersonalAccountStore::lookup` and its bounded private record reader are now
implemented against that red evidence. Lookup validates the whole five-field
tuple before consulting the authority; a missing manifest entry is the only
absence; a tombstone answers from the manifest alone, so a retained, deleted or
corrupt record cannot change it; and a connected account reads only the single
accepted basename, as a bounded, symlink-refusing, non-blocking, owner-only
regular file whose exact envelope digest, configured key, account-bound
associated data and record-versus-manifest version must all agree. There is no
fallback, initialization, candidate search or orphan adoption on this path.
Green, coverage and mutation for that implementation are NOT claimed here and
remain pending their reserved lane.

Primitive boundary assertions also cover each empty AAD configuration field,
tokens of 65536/65537 bytes, absent versus empty refresh tokens, exact lowercase
generation/descriptor formats, nonzero revisions, sorted unique scopes, exact
262144-byte plaintext and its next byte, and one-field invalid store configuration
mutations. Each test added after primitive implementation must demonstrate a
falsifier against its corresponding surviving generated fault, with a restored
passing control. Duplicate rejection checks may produce equivalent mutants;
record the concrete equivalence reasoning separately instead of calling those
mutants caught. Keep platform-only refusals and unexecuted paths explicit.


S15 uses a valid mixed external/Vault configuration as its primary control; R03
proves actual strategy choice, and omission of `accounts` preserves legacy safe
behavior. Each slash-separated item below is a distinct one-field mutation, never
a combined invalid fixture. Preserve all other valid inputs and name the expected
field/reason; failure at an unrelated check does not satisfy the vector.

| S15 vector | One changed field or condition |
|---|---|
| enablement | managed descriptor with accounts.enabled=false |
| required | remove deployment / instance_id / current_key_id / authority_dir |
| paths | authority_dir equal to store_dir / nested within it / its parent / a symlink alias |
| ownership | enable shared-account flag / add static authorization override to personal backend |
| references | unknown account ID / REST provider mismatch / duplicate backend identity strategy |
| strategy | external descriptor strategy=Vault / required=false |
| bounds | zero limit / overflowing limit / invalid key length |
| inbound OAuth | missing resource / resource-verifier mismatch / query-bearing resource / empty-query delimiter / fragment / userinfo / missing AS / AS without verifier |
| endpoint trust | attacker token URL differing from metadata / authorization endpoint mismatch / revocation endpoint mismatch / metadata issuer mismatch / missing token endpoint / discovery unavailable / redirecting discovery / prohibited endpoint network target |

The endpoint positive control uses independently frozen Google's issuer and exact
cross-origin endpoint values in the design, served by an isolated metadata test
fixture; it must pass the same endpoint validation. The negative changes only the
token endpoint to an attacker URL and asserts zero client-secret/token disclosure.
An offline test fixture does not claim that live Google discovery was exercised.
Use an origin-only and a path-bearing issuer to assert the design's exact
RFC 8414/OIDC request order, fallback after 404, and terminal rejection of invalid
received metadata instead of accepting a later conflicting document.

For capacity, retain tombstones while admitting the largest valid authority at
the count/byte limits, then refuse one extra grant without losing acknowledged
state. Separately lower the byte cap so it is the binding limit on valid entries;
do not manufacture unsupported padding. On the pinned Spark persistent volume,
offer 11 refreshes/second across distinct live grants after a 5-second warmup,
then measure a fixed 120-second window. Pass requires at least 1200 durable
completions inside that window, at least 100 completions in every sliding
10-second interval sampled each second, and p99 completion latency <=250 ms
including queue wait and fsync, no correctness failure, and authority load/record
reconciliation <=5 seconds. Retain every offered/completed timestamp so queueing
cannot disappear from the distribution. Use both the count-binding and
byte-binding fixtures, report actual bytes/count/disk/version, and separately
measure discovery/network startup cost. Completions after the fixed window cannot
satisfy throughput; drain them only to include every offered request in the
latency/error assertions. The 11/s offered rate avoids an exact-window boundary
artifact while testing the required 10/s floor. These are targets pending execution.
S02/S12/S15 capture removal of unreferenced token payloads, secret-free retained
authority/audit evidence, and token restore preserving separate authority.
Terminal journey-secret deletion is the dependent C04 lifecycle assertion.

## Resolution and route cases

| Case | Setup and decisive assertion |
|---|---|
| R01 | Interleave A/B calls through meta invoke and direct MCP routes; backend records A and B only and returns distinguishing data. Same-name tools are independently resolved. |
| R02 | Carla calls personal MCP/REST routes with operator token available: JSON-RPC -32001 or HTTP 403 with code account_not_connected, secret-free account-specific guidance, and zero downstream requests; separate explicit shared backend succeeds. Independent resolver tests require reconnect guidance; a working connect_url is required when increment-4 journey service is enabled and is proved by C01/L02. |
| R03 | Mix broker/exchange and managed-fallback backends in one gateway; each receives its configured strategy's correct credential. Failed required personal resolution never selects static credentials. |
| R04 | A/B use REST capabilities referencing the same `oauth:provider`; cold/warm/refresh paths reach distinct fixture account IDs. Exercise execution through normal server routing, not only `fetch_oauth_token`. |
| R05 | Revoke while a call/result fill or transport lease is staged; no new lease or stale publication succeeds. Already dispatched side effects are counted separately; no claim of provider-side rollback. Provider revoke outage still blocks local use. |
| R06 | Repeat authorization through prompts/get, resources/read, subscription delivery and task initiation where supported; each downstream request/result retains context. Missing identity fails before request. |
| R07 | For each of meta invoke, direct MCP tools/call, REST capability execution, tools/list, gateway_list_tools, gateway_search_tools, schema retrieval, prompts/list and prompts/get, resources/list/templates/list/read: exercise expired grant, denied policy, backend config revision change and absent identity. Advertise prompts/resources in the fixture so these cannot be silently N/A. Also cover configured task/subscription routes; any N/A needs exact absent capability and separate release-package evidence. |
| R08 | Credential-incapable transport fails before mint/dispatch. This negative belongs here; successful isolated stdio process/session behavior is proved by MIK-7387 and the [legacy bridge design](2026-09-01-mrtr7-legacy-client-bridge.md), not assumed from header support. |
| R09 | Complete or start a task/write with request key K, refresh the token without scope change, and retry/query after refresh and restart. Same-key retry performs no extra side effect and the owner can still access its task. Scope reduction rechecks replay/read authorization and refuses disallowed access; it must not dispatch a fresh write under K. |

R07 is a Cartesian matrix over the named routes and these outcomes:

Use an explicitly targeted personal backend/capability for refusal assertions.
For aggregate discovery, retain independently authorized public/shared entries
and omit the refused personal partition, with zero unauthorized fetches. Exercise
both forms so a global "reject everything" filter cannot satisfy the matrix.

- Expired access token with live grant and usable refresh token: one serialized
  provider refresh, then one intended downstream operation with the new token;
  no use of the expired or operator token. Concurrent duplicate K stays deduplicated.
- Expired/revoked grant or invalid_grant refresh: account_not_connected or
  reconnect_required refusal, zero backend operations, and no stale cache return.
- Denied tool policy or missing verified personal identity: forbidden or
  authentication_required refusal before mint/refresh/backend dispatch; zero
  token-provider calls and no metadata/result leakage.
- Account-affecting backend config revision change (resource, issuer, account
  reference or scopes): old leases/caches are invalidated and reconnect_required
  refusal occurs before backend dispatch. An independently fixture-seeded new
  grant under the new descriptor is the positive control. An unrelated backend's
  revision does not evict or reauthorize this account.

## Metadata and cache cases

| Case | Setup and decisive assertion |
|---|---|
| M01 | A/B see different tool names and conflicting schemas for the same name. Interleave tools/list, gateway_list_tools, search and schema retrieval cold and hot; each sees only their own entries. |
| M02 | Personal prompts/resources/templates and pagination cursors differ by caller. Swap cursors and attempt list/read/get cross-user; reject. An invariant public catalogue remains cacheable as the positive control. |
| M03 | Block A's metadata fetch, revoke/rotate generation, then release it. Stale content is not published or returned; B and the new A generation continue independently. |
| M04 | Global prefetch/warm-up, direct exact lookup and search fallback cannot reveal personal entries. A personal miss stays a miss; it cannot fall through to the shared `server:tool` index. |
| M05 | Same tool/arguments/idempotency key for A/B returns their own data and uses separate entries; same-user replay is deduplicated. Revoke prevents old cached responses from returning. |
| M06 | Drive catalogue partition capacity/TTL with many synthetic identities and list-changed notifications. Memory/entry count stays within configured bounds; eviction and notification fan-out affect only authorized contexts. |

## Consent and client boundary cases

C01–C07 and A07 below are blocked pending the browser-identity bridge. They
record required behavior for later plan finalization, not currently ready tests.

| Case | Setup and decisive assertion |
|---|---|
| C01 | An authenticated A creates a journey, authenticates its browser as A, completes PKCE hosted flow and returns to a same-origin completion page. Only A's account activates; status returns no tokens. |
| C02 | A-created link opened as B, missing browser login, swapped cookie, cross-origin start/revoke or forged principal field: no provider exchange/credential commit. A correct same-browser A flow succeeds. |
| C03 | Expired state, replayed callback, two racing callbacks, wrong issuer/redirect or replaced config: at most one valid exchange; invalid paths commit no grant. Check state consumption by restart as well. |
| C04 | Provider/browser cancellation and provider error leave the old grant unchanged; no fake success; display sanitized reason and reconnect guidance without raw provider error URLs. Inspect persistence after success/cancel/error/expiry: terminal journey code/state/verifier bytes are removed while sanitized status remains available. |
| C05 | Callback from a journey started before revoke/re-consent cannot overwrite the current generation. Provider grants missing required scope or unexpected token form do not activate. |
| C06 | Journey creation beyond per-user/global limits refuses with retry guidance. Expiry releases capacity; a new journey invalidates only that principal/account's predecessor. |
| C07 | Exercise real router start/status/callback/revoke endpoints. Anonymous status/revoke and owner swap cannot disclose account identifiers. Missing audit durability blocks grants/dispatch; revoke still invalidates and reports failure. |
| A07 | Verified same-principal browser bridge is exercised from actual OWUI login before hosted Google consent. A link alone or an email-only identity match must fail. This case is blocked until the design's browser-bridge check resolves. |

## Gateway OAuth and client adapter cases

A01–A05 belong to independent increments 1–3. A06 separately awaits the installed
client-route check; these cases do not depend on the blocked consent table above.

| Case | Setup and decisive assertion |
|---|---|
| A01 | Wrong gateway audience, expired bearer, issuer swap and backend-audience bearer receive HTTP 401 before routing; a valid gateway-resource token succeeds. For both origin-only and path-bearing resources, unauthenticated GET at the RFC 9728 path-inserted metadata URL returns 200 JSON with the exact resource and nonempty authorization_servers matching verifier issuers. A 401 at that MCP resource has a Bearer resource_metadata challenge pointing to the exact configured metadata URL; fetching it returns the same document. Exercise every advertised AS: fetch standard metadata, verify exact issuer and accept its gateway-resource token; the fixture advertises at least two. Spoof Host and downstream-account issuer cannot change discovery. Unknown path aliases refuse; empty/mismatched OAuth config fails S15. API-key-only mode reports metadata unavailable, not success with an empty list. |
| A02 | Supply raw backend token through legacy/custom passthrough path on the standard MCP interface: refused, not forwarded. A configured backend exchange/custody path is the successful alternative. |
| A03 | Use actual OWUI v0.9.6 signed-header construction via a synthetic client path: expected installation/issuer/subject/time and separate gateway client auth produce the right principal. No manually injected `GrantSubject` can pass this system case. |
| A04 | Missing/wrong signature, algorithm confusion, future/expired/excessive lifetime, absent subject, wrong client or unsigned fallback headers all refuse personal use. Two installations with identical `iss/sub` but different configured authority remain separate. |
| A05 | Conflicting OIDC and adapter identities, mutable role/email fields and attacker-controlled identity headers cannot replace verified ownership. Stable subject with changed email still owns the same grant. |
| A06 | Native Open WebUI Streamable HTTP route preserves identity across discovery and calls/reconnect. Record actual headers with secrets redacted; prove mcpo absence or presence from traffic, not container inventory. |

Additionally A01 asserts exact `bearer_methods_supported:["header"]`; neither
query/body bearer methods nor a path-resource document at the origin-only root
alias may be advertised. For the path-bearing fixture the root alias returns 404.

## Live acceptance and completion gates

L01: Pin gateway revision/artifact, OWUI 0.9.6 image digest, actual adapter route,
Google app/config revision and exact HTTPS callback. Use two designated test
accounts and an unconnected user, with least-privilege scopes. Do not dump env,
databases, tokens or personal documents as evidence. The already healthy Spark
installation establishes availability only.

L02: An independent driver uses the running release candidate as a user: connect
A, read a deliberately seeded account discriminator, connect B and repeat, then
interleave calls and discovery from both. Carla sees an actionable connect/refusal
journey and no operator account data. Record observations and sanitized screenshots
or request transcripts, not just expected assertions.

L03: Drive actual Open WebUI-to-Google cancelled consent, refresh, revoke,
reconnect and gateway restart. Real provider refresh and browser cancellation
are required evidence for MIK-6745.JOURNEY.1; mock outcomes cannot substitute.
Observe natural Google token expiry or use a documented test-account-only early
refresh that still calls Google's token endpoint and uses the returned token
through Open WebUI. Show A's
revocation cannot affect B and that A's old token/session/cached data cannot return.
Use a controlled provider fixture for destructive outage/concurrency faults that
cannot safely be induced on Google; label those integration evidence, not live
Google results. Real connect/use/refresh/revoke/cancel remains required.

L04: Restore a backed-up test setup, exercise documented rollback on the copy,
and confirm the live canary configuration only exposes designated users. Record
resolved setup blockers and preserve residual provider-side revoke outcomes.

Fail-fast sequence: review this plan's AC coverage and whether each fixture can
fail; write and review failing tests per increment; run exact focused Rust tests;
run relevant route/integration suites, format and clippy; then run security,
mutation/coverage, NFR and live-client checks required by the canonical DoD. A
compile/import error is a prerequisite failure, not assertion-level red evidence.
Snapshot-based legacy regressions require a safe pre-fix falsifier in an isolated
fixture, never overwriting another agent's active source.

For every case attach command, exact revision, exit code and relevant assertions.
Missing runtime, unavailable provider setup, failed review tool or incomplete
functional pass remains pending/blocked evidence. No account criterion becomes
met merely because this plan contains its ID or a helper test passes.
