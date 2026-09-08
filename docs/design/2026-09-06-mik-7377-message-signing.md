# MIK-7377: make configured response signing effective

Status: design and test plan awaiting review; no implementation evidence yet.

## Purpose, authority, and boundary

FOR: close the gateway part of MIK-7377 for 4.0 by making enabled message signing
validate at startup and authenticate every delivered `gateway_invoke` result,
including cached and deduplicated results.

The operator approved the gateway signing obligation in
[`RELEASE-4.0.0-scope-decisions-2026-09-06.md`](../requirements/RELEASE-4.0.0-scope-decisions-2026-09-06.md),
then requested: “close all the gaps, implement everything needed for that
release.” This design selects the capability implementation allowed by
`MIK-7377.SIGNING.1`; no additional product scope decision is needed.

OUT:

- Signing JSON-RPC protocol errors, discovery responses, or direct backend routes.
  The product contract is successful `gateway_invoke` result envelopes, including
  backend `isError` results returned as envelopes.
- Request message authentication, client SDK implementation, asymmetric keys,
  multi-hop provenance, and changes to provenance receipt signing.
- Cluster-wide or restart-persistent replay protection. Nonces remain
  process-local; this limitation must be explicit in operator documentation.
- Portfolio dependency cleanup and MIK-7377 obligations outside this repository.

## Definition of Ready and measured starting point

Value is security-mandated by the approved 4.0 scope: remove a falsely enabled
control. The measurable floor is zero unsigned successful delivered results when
signing is enabled, and zero backend dispatches for invalid/replayed nonces.
This is a reliability/security increment, not a new cryptographic primitive.

Search performed before creating this increment:

- `docs/adr/ADR-001-inter-agent-message-signing.md` is the existing proposed ADR;
  amend it during implementation rather than create a competing ADR.
- `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md`
  explicitly leaves signing to another owner; no signing design exists there.
- `src/gateway/server/mod.rs::Gateway::build_meta_mcp` constructs the invoker for
  both network and stdio startup but does not enable message signing.
- `src/config/mod.rs::Config::validate_with_env` does not validate message
  signing. Neither documented `${VAR}` keys nor `env:VAR` keys are resolved for
  this configuration.
- `src/gateway/meta_mcp/invoke.rs::invoke_tool_traced` signs only the live-fetch
  exit. `invoke_tool` is a shared `GuardedValue` delivery boundary also reached
  by named backend tools, code-mode calls, and playbooks. Those callers have no
  gateway nonce field, so signing requires an explicit server-owned origin.
- `src/security/message_signing.rs::sign_response` authenticates the body but
  leaves its nonce, timestamp, algorithm, and key ID unauthenticated. A copied
  signature can have its freshness metadata relabeled.
- `MessageSigner.previous_secret` is retained but has no production verification
  consumer. The existing ADR's “try both keys” claim is false for this sender.
- `MetaMcp::handle_tools_call` wraps the inner result into a text-content envelope
  through `wrap_tool_success`; HTTP then calls `fw.check_response`, which can
  redact that envelope in place. Signing before these steps would authenticate
  a different value from the one a wire client receives.

Initial GitNexus query returned `Repository "mcp-gateway" not found. Available:
hebb`. The coordinator subsequently provided isolated index
`mcp-gateway-v4-delivery`. Impact on `invoke_tool` returned LOW/zero callers,
contradicted by six production source call sites in `mod.rs`, `search.rs`, and
`support.rs`; those callers remain part of the validation blast radius.
`sign_response` impact returned MEDIUM/six direct dependents. Further changed
symbols still require impacts before editing; graph absence is never safety.

Target ownership: signing-only helpers and validation in `src/config/mod.rs`,
signing installation in `Gateway::build_meta_mcp`, the `invoke_tool` delivery
origin and old miss-only block, `src/security/message_signing.rs`, signing
config documentation, `src/gateway/meta_mcp_tool_defs.rs` nonce schema,
`src/gateway/router/handlers.rs` post-firewall finalization, the stdio tools/call
delivery in `server/mod.rs`, `Cargo.toml`/`Cargo.lock` for JCS, and focused tests.
Credential quota identity plumbing also touches the `ToolAuthorizer` port, its
HTTP/stdio implementations, validated API-key credential construction, and
`CertIdentity::from_der`; include key-server validated token constructors and
explicit public-anonymous/dashboard identities. Labels and authorization policy do not
change. The coordinator approved this narrow identity plumbing after reviewing
the CRITICAL shared-struct impact; current audit/session principals stay intact. Other
agents own unrelated symbols in these broad files; the release coordinator
serializes overlapping edits.
The reload preflight in `src/config_reload/mod.rs` is also owned for signing-only
restart refusal. SUB.4 production idempotency wiring is a named dependency owned
by the release coordinator; the signing increment does not duplicate it.

## Alternatives and selected behavior

1. Reject every enabled signing configuration at startup. This satisfies the
   narrow scope fallback, but leaves an already implemented capability unavailable.
2. Wire the existing signer without changing the envelope. This leaves cache
   bypasses and forgeable freshness metadata and cannot meet the claimed control.
3. **Selected:** wire validated settings, sign once at delivery, and version the
   authenticated envelope. Reuse HMAC-SHA256 and the existing nonce-store
   abstraction; use interoperable canonical JSON and correct rotation claims.

Asymmetric/PQC signatures would introduce a new trust-distribution contract and
larger signatures without solving a needed requirement here. The canonical DoR
symmetric-only fast path applies to existing HMAC-SHA256; no encryption/key
agreement or new primitive is introduced. This control provides authenticity to
holders of a shared key, not non-repudiation or independent backend identity.

## Contract

| ID | Acceptance criterion |
|---|---|
| MIK-7377.SIGNING.1 | Enabled signing reaches the production builder; valid settings produce verifiable delivered signatures, while invalid settings reject startup before serving calls. |
| MIK-7377.SIGNING.2 | Current secret and every configured previous secret resolve through the evaluated environment, meet the existing 32-byte minimum, and are not all-zero bytes; missing references, blank key ID, and zero replay window reject without exposing secret contents. Literal config rewrites preserve the original reference strings. Reload refuses signing-setting or effective-key changes before publishing configuration/environment or changing backends. |
| MIK-7377.SIGNING.3 | Exactly one gateway signature authenticates the actual JSON-RPC result envelope after wrapping and the final firewall disposition, on miss, response-cache hit, and idempotency hit. Each delivery uses its caller's nonce and current timestamp, never a stored caller's signature. |
| MIK-7377.SIGNING.4 | Versioned MAC input uses RFC 8785 and binds the result body, typed JSON-RPC request ID, and freshness metadata. Tampering with the body, request ID, nonce, timestamp, key ID, algorithm, or version fails independent cross-language verification. |
| MIK-7377.SIGNING.5 | Required missing nonces, malformed present nonces, and replayed nonces reject before backend/cache/deduplication use. A pre-admission policy authorization refusal still consumes no nonce (the exact boundary is defined below). Replay-state admission and nonce size are bounded globally and per authenticated principal, fail closed without evicting live protection, and are observable without identity labels. The advertised schema exposes the nonce and whether it is required. |
| MIK-7377.SIGNING.6 | Disabled signing remains compatible: no gateway signature or nonce enforcement, and unused unresolved signing placeholders do not prevent startup. Named tools, code mode, and playbook steps remain unsigned and usable with required-nonce signing enabled. Documentation states sender-only rotation, restart requirements, and the exact protected surface. |

### Configuration and startup

Resolve and validate through one signing-specific helper using `EnvOverlay`.
Support literal secrets, an exact `env:NAME` reference, and the existing
`${VAR}` / `${VAR:-default}` expansion grammar. A missing required reference is
an error; a configured previous reference that resolves empty is also an error.
Only a literally empty previous-secret field means no previous key configured.
Do not serialize resolved values onto the rewrite path: validation may inspect
the resolved value but literal loads retain literal references.

Resolved signing key bytes are opaque, including bytes that themselves begin
with `env:` or contain `${...}`. Resolve each field once per literal value;
validation and builder use must not recursively interpret an effective key.
The narrow implementation seam is a private, serde-skipped per-key resolution
identity on `MessageSigningConfig`: SHA-256 of each effective string, without a
second raw-key copy. Reuse only when that field still matches its identity;
programmatic mutation invalidates only that field, and a clone retains the
identity. Deserialize starts with no identities; YAML/JSON and custom Debug
never expose them. Literal load/save remains reference-preserving and carries
no effective-key marker. The type lives in a private configuration module and
has no external named struct-literal callers in this repository. Two focused
config tests pin opaque key bytes, subsequent validation without original env,
clone/serialization behavior, safe mutation failure and independent per-key
resolution. This is a narrow resolution-order repair, not a new config option.

At startup `Gateway::build_meta_mcp` calls the helper before constructing shared
components, then installs the current-key signer and nonce store. This also
covers programmatic `Config` construction that did not use a YAML loader.
The evaluated config/environment is the authority; do not read a second process
environment at invocation time. Settings and key material are startup-only.

Enforce that startup-only contract in `ReloadContext::reload_outcome_locked`
immediately after candidate evaluation and before the empty-patch shortcut,
backend application, or environment publication. Compare both the configured
signing section and effective resolved settings against the startup config and
startup overlay. A changed setting or env-file rotation returns a field-only
restart-required refusal; the running signer, config, overlay, and backends stay
unchanged. Existing generic pending-restart reporting already detects the
`security` section, but still publishes the wanted snapshot. This slice chooses
the stricter explicit refusal for signing to prevent false enabled/key state.
Byte-identical/effectively-identical reloads and unrelated backend changes
remain permitted. A refused rewrite may already have written an authorized
candidate to disk; do not claim disk rollback or next-start validation beyond
the checks actually run.

Implementation detail for configured/effective comparison: retain a private,
serde-skipped SHA-256 fingerprint of each configured key string beside its
existing effective-key resolution marker. The resolver records it before the
one permitted expansion; clones retain it, fresh deserialization does not, and
mutating a public key invalidates only that key's identity. This distinguishes
an operator reference edit from equal effective bytes without rereading the
startup file after it may have changed or storing another raw secret copy.
The reload guard compares all six settings and these configured/effective key
identities against `LiveConfig::running()` and `LiveEnv::startup()`, returning
only the changed field name. This supplies the already-required comparison;
it adds no setting, scope exception, or hot-reload capability.


When disabled, return without resolving or validating dormant placeholders.
When enabled, require both key materials (if present) to be at least 32 bytes
and reject all-zero bytes, as the live ticket's `PORTSEC.VAL.1` requires.
The helper documents minimum length and zero-key rejection, never entropy
measurement; do not introduce a Shannon-entropy scorer. Also require
a nonblank key ID, and a strictly positive replay window. Reject errors using
field names, never resolved values or raw references. A supplied previous key is
validated for safe configuration, but is not used to sign: only the current key
signs. Clients keep old keys for their independently bounded verification grace
period; restart with the new current key and key ID. The gateway has no response
verification API and cannot promise automatic dual-key verification.
The runtime `MessageSigner` retains only its current key: remove the unused
previous-key field while preserving config parsing/validation compatibility.

### Delivery and authenticated envelope version 2

An explicit private invocation origin distinguishes the external
`gateway_invoke` match arm from shared internal dispatch. It is set by the
server's dispatch code, never parsed from request arguments or inferred from
whether a nonce is present. Only the external origin admits a nonce and signs
the delivered envelope. Named backend tools, code-mode operations, and playbook
steps use the ordinary unsigned origin and preserve their output schemas. The
origin travels to the shared traced implementation to keep authorization before
nonce admission. `GuardedValue::into_inner` remains the projection boundary,
but is not the final wire boundary.

Use one shared `MetaMcp::finalize_response_for_delivery(response, context)`
after the adapters finish their result transformations. The server-owned
context identifies the actual method/literal tool and retains the bounded
request nonce; it cannot be supplied as an origin flag in request arguments.
The helper runs exactly this sequence:

1. Apply the single response-firewall disposition to the completed result.
2. Call signing-only `finalize_gateway_invoke_response` for the external literal
   `gateway_invoke` result, authenticating its final body and typed request ID.
3. Call non-mutating `record_response_delivery_attempt` on the final whole
   JSON-RPC response, including any signature, before transport write.

Errors/no-result responses stay unsigned. A signing error replaces the result
with code `-32603`, message exactly `Response signing failed`, preserved final
caller ID, no result and no error data before the one delivery-attempt record.
The shared helper marks this as a server-owned delivery refusal. The signer
call stays outside the optional firewall feature block. No signature or audit
hash precedes refusal/redaction, and no scan follows signature insertion.

Exact adapter ordering, verified against every production caller:

- HTTP `meta_mcp_handler` awaits complete dispatch, including `handle_tools_call`
  early results. Extract `build_modern_response`'s mutation into pure
  `shape_modern_response(&mut JsonRpcResponse, method)` and run it here when the
  validated request is modern. It preserves `resultType` and adds serverInfo
  and any applicable cache hints BEFORE shared finalization. After the helper,
  compute telemetry and HTTP status from the final result, then call a
  serialization-only modern/legacy response builder. Client breaker accounting
  skips BOTH success reset and failure strike when `confirmation_refusal` or
  `delivery_refusal` is set. The firewall owner adds the server-only
  `JsonRpcResponse.delivery_refusal` marker: omitted by serialization and reset
  false by custom Deserialize, so a backend cannot forge the exemption. Firewall
  and signing finalization failures set it; ordinary dispatch outcomes preserve
  existing accounting. A refused delivery cannot lock out the caller or erase
  their existing strikes. `build_modern_response`
  must no longer add fields after signing.
- Stdio `Gateway::dispatch_single_with_sink` awaits complete dispatch, performs
  any protocol shaping required by the revision it actually serves, calls the
  same helper, and only then calls `to_value_lossy`/writes. Current production
  stdio is legacy; signing does not invent modern stdio support. Any bridge
  adapter revision changes must preserve this same finalization ordering.
  `dispatch_batch_with_sink` delegates each item to this single-item path, so
  each responding item is finalized exactly once before batch serialization;
  notifications still produce no response.
- The source has only two production `handle_tools_call` consumers: these HTTP
  and stdio adapters. Do not extract `handle_tools_call_raw` or scan inside that
  dispatcher. Named/internal calls retain their existing origin and schemas;
  external named results still receive the firewall owner's response policy,
  while signing stays scoped to external literal `gateway_invoke`.

The firewall owner aligns the standard-list and direct-route adapter boundaries
with this same final-result enforcer and removes all old inner/HTTP postscans.
There is no intermediate sign-after-old-scan release path: the modern shaping
repair and shared finalizer are one required integration before wire signing
can pass. Signing never invokes `check_response` itself. The coordinator owns
shared helper/CONTROL.3 integration; signing owns its primitive and the modern
shape extraction, with source patches serialized by the coordinator. Retain the
existing all-five-method cache-hint tests against the extracted shaper.

The signing-only primitive has this crate-private interface:
`finalize_gateway_invoke_response(&self, response: &mut JsonRpcResponse,
nonce: Option<&str>) -> crate::Result<()>`. Disabled/error/no-result cases are
no-ops. Enabled successes defensively check nonce shape/requirement, canonicalize
and sign once, and add the result signature. The primitive does not scan, access
caches, or register a nonce again. It counts and returns any signing error; the
shared helper performs the exact safe replacement and sets delivery_refusal.

CONTROL.3 hashes the canonical final whole JSON-RPC response, stores no raw
payload/credentials, preserves truthful inner invocation-stage events, and
never calls the delivery attempt a client receipt. Nothing may mutate the
result or its request ID between shared finalization and serialization/write.

Remove the old signing block in `invoke_tool_traced`; neither `invoke_tool` nor
any response/idempotency cache stores a signature. Provenance, warnings, trace
metadata, context-integrity projection, and backend error information are
covered within the returned result exactly as wrapped, protocol-shaped and redacted. Keep the
existing `gateway_invoke` text envelope intact; append `_signature` as a sibling
of its `content` at `response.result._signature`. Do not parse and sign a second
copy of the JSON embedded in `content[0].text`.

An enabled signing finalizer that cannot sign fails the whole JSON-RPC delivery with an
internal error; it must never return an unsigned success. The shared helper has
both transport callers in production. A test invoking only `MetaMcp` without
the transport finalizer does not prove wire signing.

Keep `_signature.alg = hmac-sha256`; add `_signature.version = 2`. The canonical
MAC input is a JSON object with exactly these members:

- `domain`: literal `mcp-gateway-response-v2`;
- `body`: the JSON-RPC `result` with its top-level `_signature` removed;
- `request_id`: JSON null for an absent ID, or an object with exactly `kind` and
  `value`: `kind` is `string` or `number`; `value` is the original string or the
  canonical base-10 signed i64 decimal string (no plus sign or leading zeros);
- `alg`: literal `hmac-sha256`;
- `version`: integer `2`;
- `nonce`: request nonce string or JSON null;
- `ts`: server Unix timestamp in whole seconds;
- `key_id`: configured current key ID.

The transmitted signature block contains `alg`, `version`, `nonce`, `ts`,
`key_id`, and lowercase hexadecimal `sig`. `domain` is fixed by version;
`request_id` is reconstructed from the outer JSON-RPC `id`, not copied from an
untrusted extra signature member. The typed encoding distinguishes numeric `1`
from string `"1"`, preserves every i64 ID without JCS rounding, and binds even
optional-null-nonce responses to their request. Clients preserve the exact ID
with a lossless parser or use string IDs; a JavaScript parser that rounds a
large numeric ID cannot verify it. No-ID notifications produce no wire response;
an internal finalizer fixture may still cover the explicit null encoding.
The shared request-ID extractor must use checked i64 conversion: numeric IDs
above i64::MAX (including i64::MAX+1 and u64::MAX), below i64::MIN, or non-integral
numbers are invalid requests, never cast/wrapped or coerced into strings.
Reject before policy/admission/backend work with JSON-RPC -32600 and no invented
numeric ID; a missing notification ID keeps existing notification behavior.
Boundary tests include valid i64 extrema and raw invalid numeric values on both
transports; signed typed-ID fidelity is only claimed within the supported domain.
Canonicalization is [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html),
using the MIT-licensed
[`serde_json_canonicalizer` 0.3.2](https://docs.rs/serde_json_canonicalizer/0.3.2/serde_json_canonicalizer/).
The existing private `canonical_json` is only `serde_json::to_string` and is
not an interoperable signing format. Do not change that shared cache/hash helper;
use JCS solely for this versioned signing envelope. The selected dependency adds
`ryu-js`; pin the resolved lockfile and audit both before delivery.

Apply the JCS/I-JSON input domain: reject nonfinite numbers or integers outside
the interoperable exact range `[-9007199254740991, 9007199254740991]` instead of
silently rounding tool data. Large exact identifiers must be strings. Failure
to canonicalize is an error, never an empty-string MAC or unsigned success.
Publish independent Node/ECMAScript vectors covering supplementary Unicode keys,
nested ordering, escapes, fractions, exponent boundaries, and exact-integer
boundaries. No Unicode normalization is applied. The ADR specifies the input
and independently generated known-answer vectors. Clients must first require JSON-RPC `2.0` and exactly one `result` with no `error`,
then require signature version 2 and compare the MAC in constant time, match the outstanding typed request ID and nonce, and enforce their
clock-skew policy. The reference verifier uses a 300-second maximum age and
30-second future-skew allowance, with valid-MAC stale/future fixtures tested
against an injected current time. These client bounds are explicit reference
policy, not an assertion that the sender enforces response age. A body
signature alone is never evidence of freshness. Legacy body-only signatures are
not emitted or silently accepted by the documented version-2 verifier.

The deterministic test seam accepts an explicit timestamp and creates the same
versioned MAC input as production. The wall-clock entry calls that seam with
the current server timestamp. Known-answer vectors pin time; a separate
wall-clock round trip checks that the emitted timestamp is current. A relabel
forgery test supplies the forged nonce as the verifier's expected nonce, so a
nonce-equality check cannot hide missing cryptographic nonce binding. Likewise,
the null-nonce request-ID relabel test gives the verifier the forged expected
ID, so expected-ID equality cannot mask omission of ID from the MAC.

The gateway signs object result envelopes. A non-object JSON-RPC result at the
enabled finalizer is an internal error, rather than an unsigned success. This
is a fail-closed invariant; no new wrapper changes the disabled wire format.

### Replay bounds and ordering

For the external `gateway_invoke` origin, a present nonce must be a nonempty
string of at most 256 UTF-8 bytes. Missing is allowed only when `require_nonce`
is false. Treat it as opaque protocol metadata, without Unicode normalization
or control-character stripping. A reused nonce across separate requests is a
replay; this is unrelated to duplicate object member names in raw JSON.

HTTP currently recursively sanitizes string values AND keys before parsing.
For signing-enabled external literal `tools/call` / `gateway_invoke`, capture the
raw routing identity, exact typed request ID and nonce state before that pass.
Move the exact `id` and `params.arguments.nonce` values out of the owned request,
classify nonce as absent / bounded valid string / invalid without copying a large
invalid value, then sanitize the remaining request. Restore the original ID
for existing request-ID parsing and carry the nonce state in private server
context through admission and final signing; do not re-read a sanitized nonce.
Remove any sanitizer-created nonce alias from that external argument envelope.
The rest of the backend arguments keep their existing sanitizer, including a
nested backend argument named nonce. Non-signing routes retain current behavior.
A sanitized method/name that becomes external gateway_invoke from a different
raw routing identity is rejected as an invalid request; sanitization cannot
mint the privileged origin. Raw canonical routing must still match after the
pass. Stdio captures the same typed context without the HTTP sanitation step.

Use one signing-owned `SigningInvocationContext` in `src/gateway/meta_mcp/signing.rs`, with private Internal versus
external-gateway-invoke classification and captured nonce state. Both adapters
use the same constructor over the raw canonical method/tool and ID; HTTP alone
adds the sanitize/restore step. The shared response finalizer borrows
`Option<&SigningInvocationContext>` and asks its checked external-origin/nonce
accessor before calling the primitive. The checked accessor exposes only a
bounded `Option<&str>`; Invalid cannot silently become optional missing.
Non-signing direct/list contexts use None. No response field or nonce presence
can manufacture an origin.

The complete pre-admission ownership inventory is:

| Current copy / work | Signed external path disposition |
|---|---|
| `parse_request` clones params in router/helpers.rs | Share envelope validation through a borrowed request view; classify/observe the untouched request first, then take its params by ownership. The compatibility wrapper may retain its old owned return for other consumers. |
| `extract_tools_call_params` clones outer arguments | Take tool name and arguments from the owned params object; do not clone the whole tree. |
| Router `target_from_invoke_arguments` copies backend arguments | Use the existing borrowed ToolTarget for literal gateway_invoke policy/scanning; no OwnedToolTarget copy of its argument tree. |
| `RetryFields::from_params` clones inputResponses/state/key | Add same-semantics owned extraction after modern classification/telemetry, moving retry siblings from params. Preserve malformed-presence flags, pair/idempotency semantics and _meta until classification. |
| Stdio batch borrows each request before parse | Consume the parsed batch array and each item through the owned single-item dispatcher, preserving order/notification behavior without cloning each item. |
| `parse_tool_arguments` and transparency argument serialization/hash | Run only after policy checks and successful nonce admission, as detailed below. |

Keep `handle_tools_call`'s owned Value interface: ownership has moved from the
transport, rather than being copied before that call. Its external literal
match arm borrows that value through policy/admission. Named/internal dispatch
retains its behavior, and existing reserved-meta-name filtering prevents a
surfaced tool from shadowing gateway_invoke. This is a view/take refactor of
already parsed JSON Values, not a new raw JSON deserializer or an admission
preflight that repeats authorization/attestation. Necessary raw-body parsing,
HTTP sanitization and existing request-firewall policy scanning remain bounded
pre-admission work; we make no zero-allocation claim for those operations.

Classifying a nonce does not reject it or mutate replay state before policy
checks. In `invoke_tool_traced`, complete borrowed target extraction, existing
ToolAuthorizer/capability-admin/identity-grant checks, tool-name syntax,
attestation and active-profile policy checks first. Then validate the captured
nonce and atomically admit it, BEFORE `parse_tool_arguments`, `_full`/`_claim`
processing, optional transparency request canonicalization/hash, cache or
idempotency work. Preserve the policy decisions and attestation auditing.
Necessary transport parsing/sanitization is bounded by existing request limits;
this ordering claim concerns additional dispatch work, not zero input parsing.
Backend credential resolution/minting and operational kill/budget/backend
failures remain after admission and consume the admitted nonce. There is no
refund after that boundary; a retry needs a fresh nonce even when the operation
is safely deduplicated. Tests distinguish pre-admission policy refusals from
later credential/operational failures.
`tools/list` always describes the optional nonce input and byte limit; when
signing and `require_nonce` are enabled the effective `gateway_invoke` schema
also lists nonce as required. JSON Schema `maxLength` counts characters, so use
it as a coarse ceiling and explicitly document the stricter UTF-8 byte limit.
Other tool schemas do not acquire this field.

Bound each process's nonce store at 100,000 live entries and each principal at
10,000. With the default 300-second replay window this admits at most 10,000
fresh nonce-bearing signed requests per principal per window, about 33.3/s sustained; it still
allows a burst up to the cap. Publish this capacity limit explicitly, and use
controlled-clock sustained-rate/burst/expiry cases to verify it. The short-window
benchmark profile is not a production tuning recommendation. Reuse verified OIDC identity's issuer/subject `stable_actor_id` when
available. Both key-server temporary-token and delegated-OIDC construction MUST
also put that verified issuer/subject `stable_actor_id` in the quota port, never
the temporary token's digest. Two independently minted tokens for the same
issuer/subject share one bucket, even if their audit/session credential revisions
differ; rotating or minting tokens cannot replenish that actor's quota.
Otherwise a `ToolAuthorizer` credential-principal port carries the verified
static configured-bearer/API-key credential digest, OAuth `client_id`, or verified certificate
DER fingerprint. Use domain-separated full SHA-256 for configured-bearer,
API-key and certificate quota digests: the
existing 12-hex-character API-key principal stays unchanged for audit/session
compatibility and is not this quota authority. Precompute static configured-bearer/API-key quota digests when resolving
configuration, publish them only after successful credential validation, and
compute the certificate digest in `CertIdentity::from_der`; never derive either from labels. Domain-separate the
identity kind and encode components without ambiguous concatenation. Preserve
the actual HTTP credential-resolution order: validated dashboard session,
static primary bearer/API key, key-server temporary token, then delegated OIDC.
The existing delegated-bearer feature and JWT-shape gates remain in force.
Quota extraction takes the authenticated client's assigned quota identity;
otherwise it uses the separately verified OAuth agent identity or certificate.
Never confuse that extraction choice with permission to reorder authentication. A validated dashboard session uses one dedicated
process-local dashboard-operator bucket, independent of the anonymous bucket;
all its session handles share that same bucket. Public-path traffic without a
validated credential uses the anonymous bucket; a valid presented credential
still gets its authenticated bucket on public paths. Stdio/test authorizers
explicitly supply no credential principal unless the test supplies a validated
fixture. Authorizer wrappers such as CountingAuthorizer must delegate the
quota port to the wrapped authorizer; do not give the trait a default anonymous
implementation that can swallow an identity. Pure allow/deny fixtures implement
explicit None. The quota-principal newtype has redacted Debug and no raw Display;
errors and diagnostics must omit full credential digests as well as secrets.
Keep these rules in the credential authority/port, never re-derive from labels.

Complete constructor and route inventory (source self-audit):

| Production authority / constructor | Quota identity and required discriminator |
|---|---|
| `ResolvedAuthConfig::validate_token`: configured primary bearer | Full SHA-256 in a configured-bearer namespace; anonymous exhaustion cannot deny it. |
| Same method: configured API key | Full SHA-256 in an API-key namespace; same labels on different keys remain distinct, and the full key is not the old 12-hex audit fingerprint. |
| `KeyServer::validate_token`: temporary token | Verified issuer/subject `stable_actor_id`; two minted tokens and a delegated bearer for that subject share one cap. |
| `KeyServer::verify_bearer_identity`: delegated OIDC | Same issuer/subject identity as temporary tokens; no credential-revision bucket. |
| `dashboard_client` after validated session lookup | One authenticated dashboard-operator bucket across handles; never anonymous. |
| `anonymous_client` / public fallback literal | Shared anonymous only when no active auth layer verified an identity. Auth-disabled static resolution stays disabled; separately verified OAuth/mTLS identities retain their authority. |
| `agent_auth_middleware` validated `AgentIdentity` | Registry-validated `client_id`, never agent display name. This additive layer is not reordered or bypassed. |
| Verified TLS peer chain → `CertIdentity::from_der` | Full DER SHA-256, never CN/OU/SAN/display labels; policy matching unchanged. |
| Stdio `ToolPolicyAuthorizer` | Explicit process-local anonymous identity; existing local authorization unchanged. |

Refactor the existing complete static → temporary → delegated resolution into
one helper reused before the public-path anonymous fallback and on protected
paths. A public path removes the credential requirement, not verification of a
present valid credential. Publish the same `AuthenticatedClient` and verified
OIDC extensions as the protected branch, preserving policy resolution and
existing feature/shape gates. Missing or unrecognized credentials on a public
path retain its anonymous fallback; protected paths retain their rejection.
Do not change dashboard precedence, OAuth/mTLS middleware, scope policy or
existing rate/circuit preflight placement in this signing change. The existing
public static shortcut skips that preflight; this design neither claims that
adjacent behavior is fixed nor relies on it to prove nonce-capacity protection.
Integration tests cover static bearer, API key, temporary OIDC and delegated
OIDC through BOTH actual public and protected HTTP middleware paths, as well as
missing/invalid public controls and delegated-disabled controls. The shared
resolver remains below auth.enabled=false's early return: presented static/API/
OIDC credentials cannot mint a quota identity while that auth layer is disabled.
Separately enabled verified OAuth/mTLS layers retain their existing authority.
The public fallback named public and anonymous_client named anonymous must map
to the SAME anonymous bucket; display names never split that quota.

Never use `caller_name`, CN/OU/SAN display labels, session IDs, request-supplied
`agent_id`, display arguments, or unverified headers as quota authority. Identical
labels on distinct valid credentials must yield separate quotas. Missing
authenticated identity uses one explicit anonymous quota, protecting identified
callers while not claiming isolation among anonymous clients. Global nonce
uniqueness is retained: a nonce cannot be reused by changing caller identity.

Existing `PrincipalWindow` was inspected and rejected for reuse because it
evicts live observations and can undercount, which is unsafe for replay state.
Use one mutex-protected state inside the existing nonce-store abstraction, with
nonce entries, per-principal live counts, and a monotonic expiry queue. Expiry,
quota checks, insertion, and accounting occur under the same lock. This removes
the observation/reservation race rather than attempting a new split atomic-map
admission protocol. Expiry consumes the queue's expired prefix; do not scan all
100,000 entries on every request. No lock crosses an await or cryptographic work.

At either capacity, reject new nonces with a safe resource-exhaustion error
before dispatch. Never evict an unexpired nonce to admit another. Replacement
and cleanup cannot interleave with admission, and quota accounting drops when
entries expire. Rejected admissions must not retain zero-count principal
buckets, and expiry removes the last empty bucket, so the principal-count map
cannot grow without live replay entries. Both per-principal and global limits are required; one principal
must be unable to exhaust the whole process's capacity. Tests use small private
limits with the same production critical section and deterministic clock.

Keep stable refusal payloads, with the caller's valid ID and no result or
error data. Missing required nonce retains code -32001 and message
`Nonce required when message signing is enforced`; replay retains code -32001
and `Nonce replay detected`. Malformed present nonce uses -32602 and
`Invalid signing nonce`. Either principal or global capacity refusal uses
-32001 and `Signing nonce capacity exceeded`; only the bounded metric reason
distinguishes the exhausted capacity. The error conversion must preserve these
exact wire messages without an Error Display prefix or secret/nonce details.

Expose aggregate occupancy gauge and rejection counters classified only by
`replay`, `invalid`, `principal_capacity`, or `global_capacity`; no nonce or
principal metric labels. Emit the state gauge while holding the admission lock
so concurrent observations cannot publish stale occupancy in reverse order.

Add `mcp_message_signing_failures_total` for enabled finalizer failures,
`mcp_message_signing_nonce_entries` for aggregate live occupancy, and
`mcp_message_signing_nonce_rejections_total{reason}` for the bounded rejection
classes above. Extend the existing `deploy/prometheus/mcp-gateway-alerts.yml`
and its promtool fixture, not a second alert stack:

- `McpMessageSigningFailure`: failure-counter increase over 5 minutes exceeds
  zero; critical immediately, because an enabled control has lost delivery.
- `McpSigningNonceCapacity`: global occupancy exceeds 80,000 continuously for
  5 minutes; warning before the hard 100,000 bound.
- `McpSigningNonceCapacityRefusal`: any principal/global capacity rejection
  increase over 5 minutes; warning immediately. Replay/invalid traffic alone
  is counted but does not page on every adversarial request.

Use `category=security` and the deployment's gateway operator receiver. The
release coordinator owns binding that label to the real receiver and verifying
delivery in the production environment before rollout; this document does not
invent an existing Alertmanager receiver or send an external message. Failure
to find a functioning receiver blocks production rollout, not local tests.
The runbook's owner is the gateway operator, Mikko Parkkola. It directs checking
rejection class, startup key/schema state, and coordinated client/server
rollback; never clear live nonce entries merely to stop an alert.

All contention pause hooks, finalizer/HMAC invocation counters, and idempotency
access observers exist under `cfg(test)` only. Count actual canonicalization and
HMAC invocations separately inside the primitive helpers, not entries into the
finalizer. Successful miss, response-cache hit and idempotency-hit delivery each
increment each primitive-work counter once;
a single resulting `_signature` field alone cannot prove absence of duplicate
canonicalization/HMAC work. The response-cache order test reuses its real hit/miss counters;
the idempotency order test observes admission/completion/removal through its
actual methods, with positive controls proving the observer sees a valid call.
Warm and cold fixtures assert zero access, hits, reservations, and mutations
before malformed or replayed nonce rejection. Tests must not replace the caches
or the production authorization/nonce chokepoint with permissive substitutes.

Allocation evidence measures bytes, not only call counters. Use the dev-only
[`allocation-counter` 0.8.1](https://docs.rs/allocation-counter/0.8.1/allocation_counter/)
thread-local measurement API in an isolated focused test process/current-thread
runtime; it installs its allocator only in the linked test executable, adds no
production allocator/API, and requires no handwritten unsafe implementation.
Audit/pin this test dependency before implementation. On prepared 1 MiB and
3 MiB single-string argument fixtures, actual rejected stdio dispatch must
allocate less than 16 KiB after ownership entry. HTTP uses its actual handler
with sanitization enabled: independently measure the unavoidable body parse +
existing sanitizer baseline for that same fixture, then require actual rejection
allocation to remain within baseline + 16 KiB, with request-firewall scanning
disabled only in this allocation isolation fixture. Normal policy decisions are
preserved and separately tested with scanning enabled. Replay and malformed
cases on warm/cold stores must meet the bound; measuring only the extraction
helper is insufficient. Runtime/background noise is excluded by the isolated
current-thread fixture, not by subtracting arbitrary observed samples. A forced
whole-argument clone positive control must increase allocated bytes by at least
the payload length; restoring any pre-admission clone must fail the bound.
Record maximum-request-size HTTP rejection/replay latency and allocation with
sanitization AND request scanning enabled as a separate adversarial profile;
that reports the real bounded parsing/policy cost and does not claim it is zero.

## Security, operation, and validation obligations

| Threat | Decision / verification |
|---|---|
| Spoofing | Existing auth/mTLS remain authority; HMAC proves shared-key membership, not unique actor identity. Preserve auth-before-nonce regression. |
| Tampering | Version-2 input authenticates body and all interpretation/freshness metadata; independent tamper matrix. |
| Repudiation | HMAC is not non-repudiation; no new claim is made. Existing trace/audit attribution remains. |
| Information disclosure | Redacted configuration debug/errors; reference-preserving rewrite fixture; no logging of keys or nonce contents. |
| Denial of service | Bound nonce bytes, global and per-principal live capacity; expiry and admission share one critical section; reject invalid settings and requests before expensive work; signing linear in response size. |
| Elevation | No new authenticated principal, token acceptance, policy bypass, or direct-route privilege. Sign only the already authorized/guarded result. |

B1 uses the existing caller identity and authorization. B2 adds no knowledge
store. B3 replay protection is explicitly process-local; durable task semantics
are unchanged and owned elsewhere. B4 reuses gateway construction, `EnvOverlay`,
HMAC, existing caches, and the nonce-store abstraction. JCS introduces one MIT
dependency with its pinned transitive numeric formatter; no new crypto primitive.

Startup logging reports enabled state, version, and replay limits without
secrets. Aggregate occupancy/rejection metrics and existing request errors
provide exhaustion visibility. Rollback is
explicitly disable signing and restart; clients requiring signed responses must
be changed in the same rollback and will otherwise fail closed. Hot key reload
is not promised. Existing key-management/vault deployment remains operator-owned;
no real key is created by this increment.

The test plan is
[`2026-09-06-mik-7377-message-signing-test-plan.md`](2026-09-06-mik-7377-message-signing-test-plan.md).
Cheapest discriminator is a production-builder plus stdio-dispatch wire
signature assertion that fails on the current unwired code, plus enabled
missing-key startup rejection. Run
them red before implementation. Security mutation falsifiers must survive the
test review: remove builder wiring, skip a cache exit, omit nonce from the MAC,
and move admission outside the protected critical section. A surviving mutant
blocks this slice; an external-start barrier alone is not a race proof.

Final evidence includes focused tests, formatter/linter, real revision-driven
network invocation by a non-author, and parent release security/performance
gates. This design does not mark the release scope ledger met.

Performance workload: compare enabled/disabled delivered envelopes of 1 KiB,
16 KiB, and 256 KiB at concurrency 1, 16, and 64, including live misses, response
hits, and SUB.4 idempotency hits. Use a local deterministic backend, fixed
response sizes, and fresh nonces; report p50/p95/p99, throughput, process memory,
and admission-lock time. Each paired enabled/disabled run warms for 10 seconds,
measures for 30 seconds, and repeats five times with order alternated. Publish
all per-run samples and median paired ratios; coefficient of variation above
5% for p99 or throughput invalidates the comparison and requires noise diagnosis
and a rerun, never selective sample deletion. Bound the admission workload below
its configured quota: use replay window 1 second and at most 5,000 requests/s
per authenticated principal, identically rate-shaped in enabled/disabled runs.
This performance profile measures the signing path without capacity refusals;
the default 300-second window/quota exhaustion remains a separate saturation
fixture. Report actual nonce occupancy and zero unexpected capacity refusals.
Compare against release budgets (p50 +5%, p99 +10%, memory +5%); do not infer a
pass from HMAC throughput alone. Fixed cross-language JCS vectors remain the interoperability authority;
bounded property tests additionally exercise nested values and numeric/Unicode
input boundaries without sharing a verifier implementation.

## Canonical DoR evidence ledger

Canonical source:
`/Users/mikko/github/claude-elite/rules-source/workflows/quality-gates-dor.md`.
This is a security/reliability increment. NPV/financial ROI are N/A under its
mandate-justified path, grounded in the operator-approved 4.0 scope and live
MIK-7377 High-priority security ticket. No new service, device contribution,
machine-learning feature, or cross-border data transfer is introduced.

Live ticket read on 2026-09-06 via Linear `get_issue(MIK-7377)`:
[MIK-7377](https://linear.app/parm/issue/MIK-7377/roimandate-fix-wire-mcp-gateway-message-signing-and-drain-product-high)
is Backlog, priority High (2), estimate 8 points, team Mikko, labels
`mcp-gateway`, `claude-elite`, `trvl`, `botnaut-client`, `tech-debt`, and
`P1-application`. No assignee/project/cycle/milestone/parent or relation was
returned. Its explicit ordering says gateway first, other portfolio repositories
afterward. These are parent-ticket facts, not a claim of missing child ownership.

The coordinator created and re-fetched the gateway-only child
[MIK-7406](https://linear.app/parm/issue/MIK-7406/40-wire-and-validate-gateway-response-signing),
UUID `79fe7c60-f1a3-4f32-b9ae-c57bce2cc0c2`, under MIK-7377: In Progress,
High (2), estimate 5, assigned to Mikko Parkkola
(`953be644-a4ed-4046-9e8e-c1d1a85507ea`), project mcp-gateway
(`497de76c-868e-4cbe-8303-70d5e0ee71dd`). Its body carries the SIGNING.1–6 to
PORTSEC mapping and DoR/DoD obligations. The coordinator's current team-cycle
query returned no cycles, so cycle is N/A. The existing v4.0.0 project milestone
is verified (`de21432a-e3bf-41fe-b51c-1c1c10437d29`). The coordinator completed
the association in the authenticated Linear UI and verified the MIK-7406
Properties value changed from “Set milestone” to “v4.0.0”. Ownership and milestone
fields are complete; the later dependency-link evidence is recorded below. Execution owner is the release
coordinator; the wider parent remains unchanged.

Ticket AC mapping: `PORTSEC.WIRE.1` maps to SIGNING.1/.3/.4/.5;
`PORTSEC.VAL.1` to SIGNING.2, including all-zero bytes;
`PORTSEC.DOC.1` to SIGNING.6. `PORTSEC.QL.1` alert triage is owned by the overall
release coordinator, outside this signing increment. Portfolio ACs stay outside
the authorized gateway slice. The parent ticket is not closed by this slice.

A focused re-fetch independently verifies MIK-7406 updated at
`2026-09-06T14:15:47.769Z`: milestone v4.0.0, recorded ownership fields, and
`blockedBy = [MIK-7272, MIK-7407]`. MIK-7272 is the existing SUB.4 parent;
its idempotency slice is the named dependency, not all unrelated parent work.
The child now carries the exact original `MIK-7377.SIGNING.1`–`.6` checkbox
texts including typed request-ID binding. PORTSEC.WIRE.1 maps directly to
SIGNING.1/.3 (with .4/.5 supporting integrity/replay proof), VAL.1 to .2, and
DOC.1 to .6. The former reversed short aliases and missing relation state are
resolved. Exact connector evidence is retained beside r4 review material as
`ticket-relation-receipt.json`; this later administrative fact does not rewrite
the immutable r4 packet that honestly recorded pending work.

| Gates | Verdict and evidence |
|---|---|
| G0, G4–G5 | PASS: release scope explicitly includes the ineffective signing control; six stable ACs and the matrix bound the work. |
| G1–G3 | Security mandate path. NPV/ROI N/A; remaining planning budget estimate is 50,000 input + 20,000 output tokens including next review/test iteration, $2.25 at the canonical $15/$75 per million rates. This is an estimate, not measured billing. E3: r1 reviewed 34,214 bytes per vendor; r2 reviewed 138,922 bytes per vendor with successful process receipts. Context/review overhead is visible, not omitted. |
| B1, B4–B5 | PASS: live existing issue, explicit gateway-first priority, mapped tracker ACs and operator-approved release placement. |
| B2 | PASS: child MIK-7406 ownership, project, priority, estimate, parent and AC body verified by the coordinator; v4.0.0 association verified in authenticated Linear UI. Team cycle N/A because none exists. |
| B3 | PASS: independent connector re-fetch verifies MIK-7406 blockedBy MIK-7272 (SUB.4) and MIK-7407, exact original ACs, and the named release owner. Relation receipt and update timestamp are recorded above. Implementation status of those dependencies remains a final integration gate. |
| T0, T1, T1c, T2–T5 | PASS: security/reliability class; existing Rust/HMAC platform reused. Considered ML-DSA signatures and rejected new asymmetric key distribution for a shared-key contract; symmetric-only PQC fast path applies. JCS dependency source, MIT license, numeric semantics and transitive formatter reviewed; actual lock resolution/SCA remains a delivery gate. |
| T1b, T6, G13–G14, G18, G20–G21 | N/A: no emerging-tech bet, quantization/collective, optimization novelty, or moat claim; this repairs a mandated existing control. |
| G6–G9, G15–G17 | PASS: three alternatives, named dependencies, spoofing/interoperability/capacity premortem, existing ADR plus RFC8785/library prior art, opt-in rollback. This is no new cryptographic one-way door. |
| G10–G12 | PASS for design readiness with ranked resolved assumptions below; actual red fixtures, SUB.4 production wiring and receiver delivery remain explicitly staged gates, never presumed results. |
| G19 | PASS: operator enabling signing receives verifiable wire results or explicit startup refusal; baseline zero production enable callers, target one production builder plus final transport boundary. |
| C1–C6, C8–C15 | PASS at design stage: existing abstractions and Rust runtime, stable wire v2/JCS, trust/STRIDE table, scoped targets and full matrix; no broad cleanup of existing large modules. Small signing helpers/modules rather than growing unrelated router logic. Coverage/mutation are execution gates; no pre-implementation pass claimed. |
| C7, C16–C17, P1–P4, P6–P8 | PASS at design stage: bounded O(expired-prefix) replay maintenance, no await under lock, shared result finalization, alerts/runbook, restart refusal and opt-in rollback. Final measurements and deployed alert routing still required. |
| P5 | N/A: no new service or SLO surface; existing release SLO budgets and workload above apply. |
| L1–L2, L5, L7 | Design assessment recorded: existing enterprise signing license retained, new JCS/formatter MIT dependencies, no new key-agreement/crypto export class. Keys stay local, never logged; nonce memory bounded/expired. Actual lockfile audit/SBOM and delivery export/license checks remain coordinator gates. |
| L3–L4, L6 | N/A: no new AI feature, cross-border transfer or participating device. |
| O1–O4 | PASS at design stage: prior-art search precedes work; amend existing ADR-001 and repository alert rules; two linked design/plan files. No parallel signing implementation or orphan ADR. |

Ranked assumptions and fail-fast results:

1. **Critical:** signing point covers delivered data — source reads disproved
   the original `invoke_tool` boundary because wrapping/redaction follow it;
   corrected to final JSON-RPC result after firewall disposition.
2. **Critical:** current MAC authenticates freshness — signer source disproved
   this; v2 binds nonce/time/key/algorithm/version and cross-language bytes.
3. **High:** builder reaches deduplication — source reads disproved it; SUB.4
   remains a release-blocking dependency and interim fixtures are component-only.
4. **High:** existing bounded principal ledger is safe for replay — source
   shows live eviction; reuse its identity authority, not its unsafe eviction
   semantics. One nonce-state lock makes reservation atomic.
5. **Medium:** actual JCS implementation is available — official crate docs
   confirm 0.3.2, MIT, and RFC8785 contract; pinned lockfile audit and independent
   vectors are the next fail-fast before this dependency can ship.

DoR summary: mandate-justified value; estimated remaining cost $2.25; financial
ROI N/A; applicable named gates assessed above. Child ownership and milestone
association, dependency links, and exact child AC alignment are verified.
Reviewed technical approval still blocks source implementation.
Execution/deployment gates
are scheduled, not asserted as passed. Do not convert grouped gate coverage into
an invented “84/84” score.

## Unknowns and review receipt

- Resolved: production constructor seam — `rg`/scoped reads of
  `Gateway::build_meta_mcp` and its callers show network and stdio share it;
  therefore one wiring path covers both.
- Resolved: existing signatures protect nonce — read `sign_response` and
  ADR-001; they do not, requiring versioned MAC input before wiring the feature.
- Resolved: previous-key verification exists — symbol search and field comment
  show no verifier; remove the false sender rotation claim rather than build an
  unused verification API.
- Resolved: graph availability — isolated index is available; source caller
  inventory supplements its incomplete `invoke_tool` reachability. Required
  impacts for further modified symbols remain an implementation precondition.
- Deferred: complete network fixture reachability — owner signing agent; run
  focused production-builder and HTTP harness tests after design/test review but
  before implementation; a fixture unable to reach the call rejects the test
  plan and must be repaired before source edits.
- Deferred: runtime latency budget — owner release coordinator; measure signing
  enabled/disabled on the final revision before release; a p99 increase beyond
  the release budget blocks release and triggers profiling, not a claim waiver.

Design/test-plan review verdicts: pending. Implementation is not authorized by
this receipt until the release coordinator records reviewed design approval.

### Round 1 receipt amendment

GPT review `gpt-20260906T130227Z-83934` identified a wrong shared delivery scope,
non-interoperable serialization, missing schema, a cache test that could take
the wrong path, weak race staging, and starvation by one caller. Each is
confirmed at source and incorporated above. The purpose is unchanged; the
owned source list now includes origin plumbing, nonce tool-schema publication,
and the JCS dependency needed for that original verifiable-message contract.
The capacity design eliminates split check/insert races with one critical
section; tests must prove exclusion at that boundary. The optional suggestion
to deprecate previous-secret configuration is deferred as unnecessary scope:
preserve loading compatibility and validate explicit configured key material,
while correcting its sender-only meaning.

Additional source audit confirmed two transformations after the proposed
`invoke_tool` boundary: `wrap_tool_success` stringifies the inner result, then
HTTP firewall response checking redacts the wire envelope. The receipt therefore
moves signing to one finalizer called by both transport delivery sites, after
all transformations. This preserves the original “delivered signature” AC
rather than narrowing it to an internal object. HTTP redaction and both
transport calls become explicit discriminating tests. The coordinator was
notified of the separate existing post-response firewall Block disposition gap;
its policy repair belongs to the overall release security work, not MAC scope.

Grok review `grok-20260906T130228Z-83935` confirmed production idempotency is
unwired and a combined disabled/rotation fixture cannot prove key selection.
The test plan now records SUB.4 as a dependency and separates those fixtures.
While SUB.4 is pending a component-only test may enable the existing idempotency
cache after the real builder solely to exercise the signing finalizer's dedup
exit. It cannot satisfy release acceptance; the final test must reach a genuine
production idempotency hit after coordinator-owned wiring. Grok's improvements
are included: deterministic timestamps, MAC-isolating nonce forgery, immediate
expiry admission, enforced hot-reload refusal, and explicit documentation review.
Both round-1 reviews are SHIP-WITH-FIXES; revised approval remains pending.

### Round 2 receipt amendment

Both r2 reviewers exited zero and wrote matching ledger receipts for
`4c7d945c8d94e31ef33c7b62bd657e562bbd982e6d4c1b8d9d07d7373793d176`
(138,922 scope+material bytes), retaining r1 change identity
`cc68c58204c9e536de579ddc6558eebd8f1f0c38f0c653a983345cbfea2a0292`.
GPT identified unobserved cache/idempotency accesses before nonce rejection;
the matrix now uses real cache hit/miss counters and test-only idempotency
access observers, with warm/cold cases and positive controls. Grok identified
old body-only assertions and ASCII-only nonce boundaries; those become explicit
v2 pinned-time rewrites and multi-byte Unicode boundary tests. The live ticket
read also recovered its explicit all-zero key rejection, now mapped into
SIGNING.2. The DoR ledger, capacity/failure alert rules and workload are recorded.
Unused previous keys are removed from runtime signer storage while config
compatibility remains.

Grok's suggested rejection of large integer data inside backend text is not
applicable to the final wire JCS domain: `wrap_tool_success` serializes the
backend JSON into a string. Tests instead preserve those exact text digits and
reject only non-interoperable numeric members in the actual signed JSON object.
The firewall owner's accepted common wrapper now explicitly precedes the
finalizer. These changes preserve the original delivered-signature obligation;
they do not move unrelated firewall implementation into signing ownership.

### Round 3 receipt amendment

Both r3 reviewers exited zero and wrote matching ledger receipts for
`3668dc12ddf8e1b60504369b7675e909f0e8120d11abf09756fed3b48cf313c5`
(44,686 scope+material bytes), preserving the same immutable r1 change identity.
GPT's optional-null-nonce relabel finding adds the typed outer request ID to the
MAC and an independent relabel falsifier. Its display-name quota finding is
confirmed: `caller_name` contains API-key/OAuth/certificate labels. The revised
port carries verified full credential digests or stable issuer/subject/client
identity without changing existing audit/session names. `RequestId` supports
string and i64, so typed decimal-string numeric ID encoding avoids JCS rounding.
The coordinator approved the narrow identity plumbing after the following
GitNexus impacts: ToolAuthorizer HIGH (six implementations), AuthenticatedClient
CRITICAL (30 direct constructors/fixtures), CertIdentity HIGH (four literal
fixtures), and from_der MEDIUM (12 direct callers). Source inventories include
key-server temporary/delegated credential construction and anonymous/dashboard
fallbacks; compilation and auth/session regression checks remain required.

Grok's finalization-order finding is source-confirmed: current HTTP still scans
after `handle_tools_call`. The contract now explicitly places signing after that
existing scan during any intermediate patch and after the completed common
wrapper once the firewall increment lands. Final release evidence requires the
wrapper/refusal integration. CONTROL.3 records the immutable whole final response
after signing and before write, with delivery-attempt rather than receipt semantics.
Both vendors' small improvements are included: exact live EnvOverlay snapshots,
real ResponseCache.stats hit and miss snapshots, test-only one-signing-work
counter, stale/future valid-MAC checks, raw-reference secrecy, and reproducible
benchmark intervals/variance. Tracker dependency links and child alias alignment
are coordinator-owned follow-ups; neither is claimed complete here.

### Round 4 receipt amendment

Both r4 reviewers exited zero and wrote matching ledger receipts for
`5a43c1b0f6e58214590df7ae90bbb407a56a52d10ff673a41a6c575f85ee3a3a`
(74,546 scope+material bytes), preserving the immutable r1 change identity.
GPT identified one stale narrative sentence contradicting pending B3; all
readiness prose now reflects the subsequent independently verified actual
blocked-by relations and exact child ACs. This is administrative closure with
live connector evidence, not a waived readiness gate.

Grok identified an ambiguity that would allow temporary-token credential
revisions to become OIDC quota owners. Source confirms key-server audit/session
principals use token digests. The quota contract explicitly uses verified
issuer/subject for temporary and delegated credentials, and same-subject tokens
must share a tested cap. Static API keys retain full credential-based buckets;
existing audit/session identities do not change. A dedicated authenticated
dashboard bucket is distinct from public anonymous traffic and shared across
its handles. Debug for the new opaque quota identity is redacted. Independent
verification rejects malformed outer JSON-RPC envelopes and includes lossless
raw-wire i64-extreme ID tests. Actual JCS/HMAC invocations, rather than finalizer
entries, are counted. The optional second typed-pipeline abstraction is declined:
reuse the already coordinated shared firewall wrapper, signer finalizer, and
non-mutating audit hook with real transport order/count tests; adding another
pipeline would duplicate those owned boundaries without a new requirement.

### Round 5 receipt amendment

Both r5 processes exited zero with matching scope/material/head/lineage ledger
receipts for `ec6f7a8288b3cf2bd93e46f6249de707510c8e015dde76bc0d0175d6e73ec1f2`
(43,195 bound bytes). Grok returned SHIP; GPT returned SHIP-WITH-FIXES.
GPT found the actual modern HTTP tail mutates results in build_modern_response.
Source confirms resultType/serverInfo follow the previously proposed signing
point. Signing and firewall owners jointly moved to one adapter-tail helper:
complete dispatch, pure modern shaping, one firewall disposition, signing,
delivery-attempt hash, then serialization only. There are only two production
tools/call consumers, so the previously proposed raw-dispatch extraction adds no
coverage and is dropped. This preserves the original delivered-message contract
and resolves the earlier optional pipeline suggestion through one shared helper.

The full constructor/route inventory confirms configured primary bearer needs
its own full digest and public paths skip key-server resolution today. The
coordinator explicitly approved complete existing credential resolution before
public anonymous fallback rather than weakening per-principal protection.
Resolution order/gates/scopes and existing preflight placement are preserved;
this is not a public-auth-requirement change. Both public/protected routes and
all seven AuthenticatedClient constructors now have explicit identity cases.
Cross-kind temporary-plus-delegated same-subject tests, full-versus-short digest
assertion, absent-jsonrpc rejection and published default sustained capacity
incorporate reviewer improvements. Grok's suggestion to retain anonymous OIDC
on public paths is declined under that explicit coordinator direction.

The optional duplicate-member verifier improvement is addressed by requiring
the raw-wire reference verifier to reject duplicate id/result/error/_signature
member names before validation and return the one verified parsed object for
consumption; clients must not independently reparse an unverified interpretation.
This adds no production request parser or client SDK. Legacy and modern HTTP raw
wire plus stdio must verify; pre-populated modern fields are not that evidence.


### Round 6 closure disposition (design and test plan)

Both r6 processes exited zero, with matching authoritative scope/head/lineage,
material hash `9ef03ca5d9d3c334a9195ea9b03ef3cd34a860a3b10963c6371a9938b642be9e`
and 71,489 bound bytes. Grok returned SHIP; GPT returned SHIP-WITH-FIXES.
The two source-confirmed GPT request-boundary gaps are repaired in this
contract: exact nonce and typed ID bypass HTTP protocol-metadata sanitization,
and policy-first admission precedes the extra argument clone/transparency hash.
The matrix now measures actual hash work with a positive control and exercises
opaque control/zero-width nonce and ID values through real HTTP.

GPT's duplicate REQUEST-member finding is not adopted: it misread the plan's
reused nonce across separate requests as duplicate member names. The separate
raw-wire duplicate-member case is explicitly the independent RESPONSE verifier,
not either production request parser. The r5 contract already stated no new
production request parser. For that reference response verifier, reject all
duplicate object members before interpreting/consuming the verified object,
including nested authenticated metadata; no production parser scope is added.

The 10,000-per-principal cap remains a published bounded-capacity choice with
controlled-clock and performance gates. No 100 requests/s default-window
service guarantee was made; adding capacity configuration is not needed to
close the identified signing defect and would expand the startup/reload API.
Static quota digest precomputation, explicit unsigned-origin assertions,
auth-disabled/public-anonymous controls, wrapper delegation, all-five-method
modern-shaper regression coverage and stdio per-item batch finalization adopt
the other r6 improvements. The shared firewall dependency now excludes final
refusals from both client-breaker success resets and failure strikes while
retaining final-result telemetry and the immutable delivery-attempt event.


### Round 7 closure disposition (design and test plan)

Both r7 processes exited zero and authoritative ledger bindings matched
`255f00c4dce72342eca0b7efb222990c17892ac38e7da9343eb640e936da9c60`
(64,827 bound bytes). Grok returned SHIP; GPT returned SHIP-WITH-FIXES.
GPT's source-confirmed adapter copies and unchecked u64-to-i64 conversion are
now covered by the complete ownership inventory, real byte-allocation falsifiers
and raw-wire unsupported-ID cases. The necessary parser/sanitizer/request-policy
work is explicitly separated from redundant copies and post-admission hashing.
The existing owned MetaMcp dispatcher interface remains; no second authorization
or raw request parser subsystem is introduced. Shared metadata constructor,
concurrent same-nonce exclusion, nested backend nonce separation, capture-state
table and stable refusal envelopes adopt both vendors' improvements. The root
coordinates shared router/stdio/RetryFields hunks with the bridge owner; original
retry semantics and classification ordering are dependencies, not redesigned.


### Design/test-plan approval receipt

The r8 finder-only closure follows canonical development-process repair item6;
Grok r7 SHIP is retained, rather than restarting materiality review. GPT r8
returned SHIP with actual exit0 and authoritative matching scope/head/lineage:
`37f62c9d95ef1c069442245b46d5f07782a936e475a849f73f299ea1f5e4cbf3`
(48,311 bound bytes), output `gpt-20260906T154156Z-86925.md`. The frozen full
snapshots remain under `~/.claude/data/review-evidence/mcp-v4-signing-design-20260906-r8-finder/`.
There are no remaining design/test-plan NOW findings. Implementation and test
execution have not passed; tests-first/red evidence is the next gate.

Accepted nonblocking test refinements: use payload-sized retry siblings and
batch items to discriminate each moved ownership site independently, and test
present-invalid IDs on notification methods separately from absent IDs.
The existing checked-ID rejection contract requires that distinction; absence
must not erase malformed presence. Keep the already coordinated optional
ResponseDeliveryContext carrier with private Internal/External signing context;
a new third-level public enum would churn the shared interface without closing
a current finding. Registry-wide surfaced-name deduplication is adjacent cleanup
and deferred; existing construction rejects gateway_invoke name collisions.
