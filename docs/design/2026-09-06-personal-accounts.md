# 4.0 personal accounts: isolated fallback custody and routing

Status: independent increments 1–3 have reviewed design/test-plan closure;
dependent hosted-consent and live-acceptance increments remain proposed. Scope is
approved; implementation and live acceptance are not claimed here. This amends
[ADR-008](../adr/ADR-008-multi-user-oauth-isolation.md), which preserves history.

Review receipt: paired `mcp-v4-accounts-design-20260906-r5` reviewed material
`7ef75f469d64a92eaf39c5730b0c0e2b2d8314e8ea40481709197c7ac7142efa`
(30698 bytes): Grok SHIP; GPT SHIP-WITH-FIXES with one AAD-field naming finding.
Finder-only `mcp-v4-accounts-design-20260906-r6-closure` accepted its repair and
direct S03 falsifier: GPT SHIP, material
`70cd724aed223e684d5ebbb71b4c38b134f2ad1686ee3d2675b3eac449291535`
(10128 bytes). Each actual command exit was 0 and authoritative ledger process
status was `ok`; earlier rounds and their dispositions remain cumulative. This
status/receipt annotation follows those reviews and changes no reviewed contract.

## Purpose and readiness

FOR: let users of one gateway connect and use their own downstream accounts,
including clients that need gateway-managed OAuth, without cross-user credentials,
connections, discovery metadata or results. The operator-approved reference is
Open WebUI 0.9.6 on Spark → gateway → Google Workspace. All seven ACCOUNTS
criteria in the [scope update](../requirements/RELEASE-4.0.0-scope-update.md)
remain gating; the [test matrix](2026-09-06-personal-accounts-test-plan.md) is the
falsifiable acceptance map.

OUT: making the gateway a chat proxy, silently assigning shared accounts to users,
replacing Open WebUI, building a general identity provider, raw bearer-token
passthrough as MCP conformance, and transparent multi-replica credential custody.
Single-process recovery is required; unsupported shared-store process topologies
must reject configuration, not quietly weaken revoke semantics.

Value is the accepted capability expansion and removal of known account-isolation
gaps. Success floor: two users concurrently reach their own accounts; an
unconnected third user causes zero downstream personal calls; revoke prevents new
dispatch and stale refresh/cache publication. This is an adoption/security change,
not a speculative performance or cryptographic novelty claim.

Readiness evidence, checked 2026-09-06:

- `src/oauth/storage.rs::TokenStorage::load` returns `None` on malformed or
  unreadable data; the legacy key is backend/resource and saved JSON is plaintext.
  Preserve legacy readers for declared single-user/shared use, but do not extend
  that error-to-absence contract into the personal store.
- `src/capability/executor/credentials.rs::fetch_oauth_token` caches by provider
  and calls `storage.load(provider, provider)`. The caller identity carried in
  `CapabilityExecutionContext` does not select that credential. An ownership
  authorization check is not proof that the stored OAuth token belongs to it.
- `src/gateway/meta_mcp/invoke.rs::resolve_caller_credential` and direct backend
  routing already enforce credential/audit boundaries. Its optional propagation
  failure can return an empty credential and select static credentials: personal
  account policy must reject this transition.
- `src/backend/pool.rs` has per-user connections and per-slot failsafes. The
  no-identity path currently selects `Shared`; personal resolution must finish
  successfully before choosing a slot.
- `src/backend/mod.rs` owns global tools/resources/templates/prompts caches;
  `src/tool_registry.rs` indexes `server:tool`. They cannot store a personal
  catalogue in a global entry and filter it safely afterwards.
- `src/gateway/router/handlers.rs` derives `GrantSubject` from verified issuer
  and subject. Reuse this namespace; exclude mutable display labels from keys.
- `src/gateway/server/mod.rs` selects a single configured minting strategy. The
  account resolver must choose a strategy per backend descriptor and not treat
  a global strategy as proof of backend-specific authorization.
- `src/gateway/router/well_known.rs::build_protected_resource_metadata` currently
  leaves `authorization_servers` empty; tests expect omission. This is not
  sufficient for the current MCP OAuth discovery contract and must change.
- Existing `ring::aead` AES-256-GCM use in `src/protocol/continuation.rs`, secret
  temporary-file helpers in `src/oauth/storage.rs`, and `src/fs_lock.rs` provide
  reuse points. The non-Unix lock implementation is a no-op; it cannot establish
  cross-process generation safety on that platform.

GitNexus query returned `Repository "mcp-gateway" not found. Available: hebb`.
This is an unavailable graph, not proof of low impact. This stage edits docs only.
Source owners must attempt symbol impacts and record scoped callers before edits.
The coordinator serializes shared config, dispatch and metadata files against
other 4.0 work; this document does not confer ownership of another agent's files.

## Decisions and alternatives

1. Keep refusing thin-client accounts: safe but fails the approved capability
   journey and MIK-6744/6745. Rejected.
2. Reuse the operator's OAuth files and merely check caller ownership: small but
   does not bind a token to that caller and cannot survive refresh/revoke safely.
   Rejected.
3. Extend current identity/credential/pool boundaries with a small isolated store,
   account service and contextual catalogues. Selected. Existing external brokers
   remain usable; managed custody is opt-in per backend/provider.

Rust remains the daemon implementation language. No new crypto dependency or
asymmetric primitive is needed: use existing AEAD and CSPRNG. Symmetric-only
cryptography follows the DoR T1c fast path. No alternate language, database, new
service framework or general-purpose vault is justified for this increment.

### Identity and token boundaries

The canonical account key is the versioned, unambiguously encoded tuple
`(principal_authority, principal_subject, backend_id, resource, oauth_issuer)`.
Encode the domain string `mcp-gateway/account-key/v1` and then each tuple field
in the stated order as UTF-8 bytes preceded by its unsigned 32-bit big-endian
byte length. Require nonempty fields, each at most 4096 bytes. The filename stem
is the full lowercase hexadecimal SHA-256 of these bytes. No JSON serialization,
delimiter concatenation, Unicode normalization or legacy truncated hash enters
the key. Authority and subject compare exactly.
Account keys, descriptor revisions and AEAD bindings share one length-prefix
encoder with explicit domain constants; do not duplicate serialization helpers.
Resource canonicalization follows the backend descriptor; issuer comparison does
not normalize away distinctions. Include a backend configuration revision and
granted-scope fingerprint in the authorization context.

Gateway access authentication and downstream account authorization are separate:

- Inbound OAuth bearer validation checks gateway audience, issuer and expiry.
  Publish gateway protected-resource metadata for that boundary.
- Downstream credentials come from the configured external broker/exchange or
  the verified caller's managed grant. Backend credentials never become the
  gateway's inbound bearer, and gateway tokens are not forwarded downstream.
- An explicitly shared service account is a separately configured mode and
  remains available as a positive compatibility control. It is not a fallback
  after personal authorization fails. Ambiguous personal-plus-shared config fails.
- A shared API key authenticates the client application, not every end user.
  Personal mode requires verified user context. `Local` migration is allowed only
  for a declared single-user installation. Do not infer uniqueness from key count.

This is a project design derived from the current
[MCP authorization boundary](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
not a claim that the account service itself is specified by MCP.

For standard inbound OAuth, publish unauthenticated metadata at the RFC 9728
path-inserted location: resource `https://gateway.example/mcp` has metadata at
`https://gateway.example/.well-known/oauth-protected-resource/mcp`. Origin-only
resources use the existing root well-known route. For a path-bearing resource,
the origin-only root route returns 404 instead of publishing an invalid alias.
Metadata returns 200
application/json with `resource` exactly equal to configured `auth.oauth_resource`,
nonempty `authorization_servers` from `auth.authorization_servers`, and
`bearer_methods_supported:["header"]`. Resource and advertised issuers must match
the actual gateway bearer verifier configuration. Preserve resource path segments;
do not infer either value from Host headers or downstream account descriptors.
Configured authorization servers must serve their own valid RFC 8414/OIDC metadata
and issue gateway-resource tokens; the gateway need not itself be an authorization
server. OAuth-enabled startup rejects missing/mismatched resource/issuer settings.
For API-key-only deployments, do not emit a success document claiming standard
OAuth discovery with an empty issuer list; return metadata-unavailable (503).
OAuth 401 responses at the configured MCP resource include a Bearer challenge
whose `resource_metadata` is the configured path-inserted metadata URL. This
project selects both discovery mechanisms; the RFC permits the challenge and
requires the derived well-known location. Validate the exact resource URI,
including its path, against both discovery methods; reject query (including an
empty query delimiter), fragment, userinfo and
unconfigured resource aliases. Neither Host nor forwarded headers construct it.
This follows [RFC 9728 sections 3 and 5](https://www.rfc-editor.org/rfc/rfc9728.html#section-3)
and the current [MCP discovery requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery).

### Managed store and account service

Introduce a private `personal_accounts` module with storage and service submodules,
then a narrow crate-internal interface consumed by existing route/credential code.
Do not widen `TokenStorage::load` into ambiguous optional personal semantics.
Use explicit outcomes: absent, connected, revoked, and storage/key/schema failure.
Storage failure refuses; only actual absence can offer a connect journey.

The envelope is versioned (`personal_accounts.v1`) and records key ID, random
nonce and authenticated ciphertext. AEAD associated data binds schema version,
key ID, `accounts.instance_id`, store epoch and the five canonical account-key
tuple fields in order, so moving a valid file to another identity or
backend fails authentication. Token material, refresh tokens and provider account
identifiers stay encrypted. A dedicated 256-bit key comes from a configured
secret reference; never reuse API keys, the Open WebUI key, or signing keys.
Missing or invalid key material rejects enabled personal custody at startup.

Persist by owner-only exclusive temporary creation, file sync, atomic rename and
parent-directory sync; reuse existing helpers where their semantics fit and add
the missing directory durability explicitly. Reject unsafe symlink paths. Enforce
one writer process per configured personal-store directory with a held lifetime
lock acquired nonblocking; a second process fails promptly with a sanitized
store-instance/lock diagnostic. Unsupported lock semantics fail startup for this
feature. Blocking file I/O runs off async executor workers. No network call holds
the mutation/file lock.

Implementation finding (2026-09-06): the new FIFO child-process regression exposed
intermittent failure of the existing immediate lock reacquire checks. With the
same source, 2/40 four-thread account runs failed and 0/40 serial runs failed;
one failure was the shared helper's own release assertion. Linux `flock` locks
belong to an open file description and a fork/dup reference can retain them after
the owning guard closes its descriptor. The bounded repair makes the guard's
normal Drop explicitly request `LOCK_UN` before File closes. Constructors,
blocking/nonblocking acquisition, held-guard exclusion and non-Unix behavior
stay the same. No raw descriptor or duplicate is exposed by the public guard.
Unlock failure during Drop cannot be returned and must not panic; closing the
owned File still occurs. A crash remains kernel-managed and this repair makes no
new guarantee about an independently retained child descriptor after a crash.
The direct falsifier keeps a duplicate open, proves exclusion while the owner
lives, drops the owner, and then requires immediate reacquisition while the
duplicate still lives. Static caller checks include OAuth storage, control-plane
store/audit operations, protocol-revision telemetry, and the new personal store.
They receive regression checks alongside config-preservation tests.
This is a refinement of the existing lifetime-release contract, not permission
for two live owning guards or a retry that hides contention. Review receipt and
actual command evidence stay in the existing account package.

The foundation source review passed both vendor source legs on the frozen
136213-byte packet (`39527dd424e5245087befe0f93f9fb301bbb6dcbbeaec323f077bd0c568cfd8a`),
with actual command exit zero and matching authoritative ledger rows. This is
not complete store or release acceptance. Two findings remain required before
production: enforce disjoint resolved roots, including filesystem/ancestor
identities that lexical comparisons miss; and validate every authenticated
authority entry's key, versions, basename, checksum and state/pointer combination.
The account-store owner closes these with separate falsifiable tests before
implementing the corresponding repairs. Alias checks belong before custody is
accepted; manifest validation belongs before startup-ready or record disclosure.
If a platform cannot supply trustworthy custody/identity checks, managed custody
must refuse there. These refine existing path and authority invariants; they do
not introduce a new operator approval gate or reduce the release scope.

Generated mutation measurement also exposed missing test assertions for empty
AAD configuration fields, token/metadata validity and exact size boundaries.
The existing implementation and its original passing tests are preserved while
the account-store owner adds boundary controls and runs each surviving fault
against those controls. An incomplete mutation run or a source-review SHIP is
not a critical-path mutation/coverage result. Quantitative gates remain open
until current-source evidence and explicit survivor dispositions are recorded.

This lock does not detect separate directories on different replicas. Managed
custody additionally requires explicit `deployment: single_process` and a stable
store instance ID. Shipped Helm/Kubernetes/Compose validation must reject this
mode with replica count other than one, autoscaling, ephemeral personal storage,
or rolling-update overlap; use a persistent volume and Recreate replacement.
The existing two-replica enterprise defaults remain valid only when managed
custody is disabled. Custom deployment operators must make the same explicit
single-process declaration; the binary cannot discover an unrelated private
store on another host. That undetectable topology is unsupported, not a claimed
cluster-wide revoke guarantee.

An encrypted authority manifest is separate from replaceable token records. It
holds the highest committed revision/digest and grant tombstone for each account,
plus store epoch and migration markers. Token records are immutable candidates
named `<account-digest>-<random-128-bit-hex>.json`; the manifest names the accepted
candidate. After writing/syncing a candidate record,
atomically commit/sync the manifest pointer; only this last step acknowledges the
change. The previous accepted candidate stays readable until that commit; cleanup
of unreferenced candidates happens afterwards. Orphans are ignored. Load verifies
exact manifest revision and digest
before decrypt/use; replaying an old valid record or deleting it causes refusal,
not adoption as the current grant. Revoke changes the manifest first and may then
remove token bytes. Record replacement can never roll back this authority.

The authority volume is not replaced during token-record restore. If its latest
state is unavailable, recovery initializes a fresh epoch/key and requires fresh
consent; it must not restore an older complete authority snapshot and reuse its
grants. Preserve this rule in backup tooling and tests. Arbitrary privileged host
rollback of both live authority and keys is outside the local store's trust
boundary; AEAD does not detect it and this design does not claim otherwise.

Each account record has a random grant generation and a monotonic token revision.
Consent/re-consent creates a new generation. Refresh snapshots `(generation,
revision)`, is single-flight per key, and replaces tokens only by compare-and-swap
after the network response. Preserve the old refresh token when the provider
omits its replacement; preserve the granted scopes when the refresh response
omits `scope`, following [RFC 6749 sections 5.1 and 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6).
Explicit changed scope is validated and advances the authorization epoch; it
cannot silently broaden access. Invalid-grant becomes reconnect-required, never
static fallback. Ordinary refresh advances token revision only. Revoke durably
tombstones the generation before success,
then invalidates token caches, connections, catalogue fills, results and tasks
that can initiate new credential use. A late old refresh or callback cannot
overwrite a tombstone or a newer generation, including after restart.

Dispatch rechecks the generation/revision under the account service's lease
boundary immediately before handing credentials to transport. Revoke bars new
leases and cache publication and retires connections. Already dispatched provider
side effects cannot be undone; revoke reports this honestly. Provider-side token
revocation is best-effort with a separately recorded outcome; local invalidation
is mandatory even when the provider is unavailable. Do not retry prior writes.

Migration reads legacy data only after a declared `Local`/shared owner mapping;
never on the first personal user's request. Write and decrypt-verify the new
record before changing migration state, and retain the old source unchanged on
any failure. Record an explicit migrated marker so restart/revoke cannot import
the legacy token again. Ambiguous data remains readable by the legacy mode and
requires explicit owner mapping to migrate; no silent deletion or relabeling.
There is no configured or daemon-start migration retry. Migration is an explicit
offline operation whose owner-mapping input names the current random store epoch
and legacy source digest. It is consumed once and recorded in that epoch's
authority. A mapping for an older epoch is invalid even when its source file and
account descriptor are unchanged. Fresh/recovery initialization grants no
migration permission; a recovery-created epoch therefore cannot re-import a
previously revoked legacy source by reusing old config, command input or markers.
It uses fresh consent unless a new explicit epoch-bound migration authorization
is supplied. This is an operation contract, not a new user approval gate for
synthetic implementation.

### One authorization context across public routes

An account resolution returns a credential lease and separate bindings. The
stable authorization binding covers account key, grant generation, authorization
epoch/scopes and backend revision. The volatile lease guard adds token revision.
Routine refresh with unchanged authorization preserves the stable binding while
replacing the token and retiring obsolete credential-bearing connections. It
must not change task ownership or defeat idempotency. Task owners bind stable
principal/account/grant; retrieval checks current policy and grant liveness, not
token revision. Idempotency operation identity remains principal/account/grant
plus request key across refresh, while replay authorization is rechecked against
the current authorization binding. Scope reduction refuses disallowed replay
instead of making the same request key dispatch a fresh side effect.
Persist the descriptor revision with each grant. Changing its account reference,
mode, resource, issuer, OAuth client ID or requested scopes invalidates old leases
and caches and marks the grant reconnect-required before dispatch; a fresh grant
under the new descriptor is required. The revision is SHA-256 of domain
`mcp-gateway/account-descriptor/v1` followed by the same length-prefixed encoding
over descriptor ID, mode, resource, issuer, client ID,
then sorted unique requested scopes. Token refresh or an unrelated backend's
config change does not change this revision. Scope narrowing in a provider's
refresh response changes authorization epoch, not the configured descriptor.
Refusal is structured and secret-free, with a gateway-created connect URL only
when the verified caller is allowed to connect that configured account.
This applies to a targeted personal operation. Aggregate discovery can still
return independently authorized public/shared partitions while omitting refused
personal partitions; it must not fetch or expose their data. An explicit request
for the refused personal backend/account returns the structured account refusal.

Thread this context through meta and direct MCP tools, REST execution, discovery,
prompts, resources, subscriptions and task dispatch. Existing grant/policy checks
still apply; possessing a downstream credential grants no extra tool permission.
REST `oauth:<provider>` resolves a configured account descriptor and consumes the
same lease; it must not consult provider-only caches for personal calls. Prompt
and resource reads cannot bypass the resolver because their JSON-RPC method is
different. Unsupported credential-carrying transports fail before contacting a
backend. Any stdio account isolation must use the separately reviewed bridge and
per-principal process/session mechanism; headers alone do not isolate stdio.

Per-user pool keys include the volatile lease guard. Identity-dependent tools,
schemas, prompts, resources, templates, pagination cursors and search indexes live
under the stable authorization binding. A cold fetch uses the caller's current
dedicated connection; an
unauthenticated canonical warm-up cannot populate a personal catalogue. Keep the
existing global registry for declared invariant metadata only, with contextual
lookup as a separate partition. A personal miss is not a global-index fallback.
Generation/authorization checks also guard fill completion, list-changed
notification fan-out, response/idempotency cache hits and prefetch. A refresh with
unchanged scopes does not discard authorized metadata or deduplication history.
Use one contextual-partition owner for invalidation/capacity across these caches,
rather than independently re-encoding the identity in each subsystem. Bound partition count and entries
with configured capacity/TTL; do not key on raw credential bytes or log labels.

### Hosted consent and the Open WebUI adapter

This section and C01–C07/A07 are requirements for the dependent increment 4,
not permission to implement its unresolved browser bridge. The independent
storage, resolver and catalogue increments require separate readiness verdicts.

The gateway owns a versioned hosted API under `/accounts/v1`: authenticated create
journey, caller-owned status, browser start, provider callback and authenticated
revoke. Mount routes in the normal gateway router with access controls; the
existing local CLI callback listener is not the shared hosted service. Requests
accept configured account IDs, never arbitrary issuer/redirect/token URLs.

A journey binds principal, backend/resource/issuer/config revision, requested
scopes, expected grant generation, browser binding, PKCE S256 verifier, random
state and expiry. Use at least 256 bits of random opaque state, persisted only as
a keyed digest; store verifier and sensitive journey data encrypted. Five-minute
expiry, at most one active journey per principal/account, per-principal creation
limits, and a global configured capacity bound resource use. A new journey
invalidates its predecessor. Return URLs are same-origin allowlisted paths.

The browser must authenticate as the same gateway principal before provider
redirect; cookie flags are Secure/HttpOnly/SameSite=Lax, with CSRF and Origin checks
on mutations. A tool-created link alone is not browser authentication. Do not
link principals by matching email or accept a principal in a query/body. Consume
state atomically before code exchange; duplicate, expired, wrong-browser,
wrong-owner, cancelled and issuer-mismatched callbacks issue no credential.
The callback never returns tokens in URL, page, log or client response. Validate
provider response and exact registered redirect before encrypted commit, then
display connected status. Cancellation leaves an existing grant unchanged.
Refresh/revoke failure statuses are actionable and distinguish reconnect from
temporary unavailability. Google uses the configured hosted web-server OAuth
flow and least-privilege selected scopes; provider-specific resource parameter
support is explicit in its descriptor, not inferred from MCP requirements.

Open WebUI's [v0.9.6 header source](https://raw.githubusercontent.com/open-webui/open-webui/v0.9.6/backend/open_webui/utils/headers.py)
mints an HS256 assertion with issuer `open-webui`, stable user ID and times, but
no audience. Thus enable it only as an explicit adapter trust configuration with
a dedicated per-installation secret, expected issuer, short maximum lifetime,
clock skew, fixed header and independently authenticated gateway client. Namespace
authority by the configured installation ID, not only the generic issuer. Reject
unsigned fallback user headers, signature/algorithm failures and conflicting
identity sources. Never accept its role/email as authorization or gateway bearer.
Protect the route from unrelated clients with client binding/network policy;
the missing audience cannot silently relax standard OAuth validation.

Open WebUI has [native Streamable HTTP MCP support](https://docs.openwebui.com/features/extensibility/mcp/).
Do not insert mcpo merely because containers exist. Prove the actual native route
and signed user header with synthetic accounts before configuring real accounts.
Browser identity needs a same-principal login/reauth bridge in addition to the
tool-call assertion; the current signed-header source does not establish that
bridge. Its load-bearing check is recorded below and blocks the dependent hosted
adapter increment, not the independent store/resolver implementation.

The version-pinned [session-user route](https://raw.githubusercontent.com/open-webui/open-webui/v0.9.6/backend/open_webui/routers/auths.py)
uses authenticated session context and returns the stable user ID. It is a reuse
candidate for a same-origin bridge, not proof that one is installed. Its response
also contains a session token and profile fields: extract only the validated ID
and expiry, and never log, persist or return the full response to the gateway's
MCP client. The bridge must not send an Open WebUI session token to the MCP route.

## Versioned configuration, storage and HTTP contracts

These field names and types are the increment interfaces. Unknown fields and
conflicting declarations reject startup; omitted `accounts` preserves existing
behavior and enables no managed custody.

| Configuration field | Type and rule |
|---|---|
| `accounts.schema_version` | Required literal `accounts.v1` when the block exists |
| `accounts.enabled` | Boolean, default false; required true for any `personal_managed` descriptor |
| `accounts.deployment` | Literal `single_process` for managed custody, explicitly set |
| `accounts.instance_id` | Stable nonempty installation identifier, distinct across independent stores |
| `accounts.store_dir` | Absolute persistent token-record directory; no implicit legacy OAuth path |
| `accounts.authority_dir` | Absolute persistent manifest/lock directory, excluded from token snapshot replacement; same volume allowed but resolved paths must be disjoint, neither equal nor nested, with no symlink aliases |
| `accounts.current_key_id` | Nonempty key ID present in `accounts.keys` |
| `accounts.keys` | Map key ID → `env:VARIABLE` secret reference resolving to a base64-encoded 32-byte key; literals/empty/invalid material reject; old entries read-only |
| `accounts.descriptors` | Map configured account ID → descriptor below; this ID is the logical `backend_id` in the account key |
| Descriptor `mode` | Exactly `shared`, `external` or `personal_managed`; no mode inference from exposure or user count |
| Descriptor `provider` | Nonempty logical OAuth provider ID, e.g. `google`; does not itself select a token |
| Descriptor `resource`, `issuer` | Explicit absolute resource and exact trusted OAuth issuer; immutable within a configuration revision |
| Descriptor `authorization_endpoint`, `token_endpoint`, `revocation_endpoint` | HTTPS URLs exactly equal to corresponding authenticated issuer metadata values under the validation below; revocation optional only when unused, never caller-supplied |
| Descriptor `client_id`, `client_secret_ref`, `redirect_uri`, `scopes` | Explicit hosted registration, optional `env:` client secret, exact HTTPS callback, and nonempty deduplicated scope list for managed mode |
| Descriptor `send_resource_parameter` | Required boolean per provider; true for MCP OAuth resources; Google REST behavior explicit |
| Descriptor `external_strategy` | Existing `IdentityPropagationConfig` type from `src/identity_propagation/mod.rs`, restricted to signed_assertion/token_exchange and required=true; present only for external mode; all existing audience/session/endpoint validation applies |
| MCP backend `account` / REST capability `auth.account` | Configured descriptor ID; explicit references from both consumers to the same account descriptor when intended |
| REST capability `auth.key` | `oauth:<provider>` must match its referenced descriptor's provider; never auto-join solely by provider name in personal mode |
| `accounts.limits` | Positive integer bounds: `journeys_total` default 1024, `journeys_per_user` 8, `starts_per_minute_per_user` 10, `catalogue_contexts` 1024, `metadata_entries_per_context` 10000, `metadata_bytes_total` 67108864, `store_entries` 10000, `authority_bytes` 16777216; reject zero/overflow; enforce both per-context and global bounds |
| `accounts.adapters` | Explicit list, default empty; each Open WebUI adapter has kind `openwebui_signed_header`, unique `installation_id`, fixed `header`, `issuer` literal `open-webui`, `hmac_secret_ref` using env:, nonempty `allowed_api_key_names`, `max_lifetime_seconds` default 300 and `clock_skew_seconds` default 30 |
| `auth.oauth_resource` | Absolute canonical gateway resource URI, HTTPS except explicit loopback HTTP, no query (even empty), fragment or userinfo; required whenever standard inbound OAuth is enabled and matched by the bearer verifier's audience checks |
| `auth.authorization_servers` | Nonempty unique list of trusted gateway AS issuer URIs for inbound OAuth; each backed by an actual configured verifier and gateway audience; unrelated downstream issuers are forbidden |

For managed descriptors, discover metadata using the [MCP-defined priority](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/authorization-server-discovery):
first RFC 8414 `/.well-known/oauth-authorization-server` inserted before the issuer
path, then OIDC `/.well-known/openid-configuration` inserted before that path,
then, for path-bearing issuers, OIDC appended after the issuer path. Deduplicate
identical URLs for an origin-only issuer. Try the next location after retrieval
failure; certificate/SSRF failure, redirects and received metadata with an invalid
issuer or endpoint binding reject configuration without trying to hide that
failure behind another document. Google uses the second, origin-only OIDC
location. A fixture with a path-bearing issuer pins request order and prevents
accidental path loss. Fetch using certificate-validated HTTPS and the
existing SSRF/DNS policy. Do not follow redirects. Require metadata `issuer` to
equal the configured issuer exactly, then compare each configured endpoint
string exactly with its metadata field. Missing fields, unavailable metadata,
issuer mismatch or endpoint mismatch fail account configuration before serving;
never fall back to an unverified endpoint. Apply the same URL/network policy to
discovered endpoints. Metadata is fetched without any client secret or account
credential. The accepted descriptor snapshot pins these endpoints until an
explicit configuration reload validates a replacement. An issuer-origin equality
rule would be incorrect: [Google's authenticated metadata](https://accounts.google.com/.well-known/openid-configuration)
binds issuer `https://accounts.google.com` to authorization endpoint
`https://accounts.google.com/o/oauth2/v2/auth`, token endpoint
`https://oauth2.googleapis.com/token` and revocation endpoint
`https://oauth2.googleapis.com/revoke`. These cross-origin values are the positive
control. Changing only the token URL to an attacker host is the negative control.
An HTTP loopback issuer exists only inside isolated test fixtures under the
existing explicit test network policy; it does not relax production HTTPS rules.

Build both verifier and protected-resource metadata from one validated inbound
OAuth configuration snapshot. The fields above are its public configuration
interface, not independent discovery overrides; every advertised issuer must
have a corresponding live verifier for the same gateway resource. The existing
origin-stripping `server.public_url` metadata builder cannot publish a second
resource identity; `auth.oauth_resource` is the only resource source.

Adapter assertions are considered only after successful gateway authentication
with a named API key in that adapter's allowlist; other auth modes do not match
this adapter contract implicitly. Both iat and exp are required, exp must exceed
iat within maximum lifetime, and current time must fit the bounded skew window.
The configured assertion header cannot be Authorization or a reserved gateway
identity header. Use at least 32 random secret bytes; reject secret reuse with
gateway authentication or store keys. Browser-bridge configuration remains an
explicit unresolved increment-4 interface and cannot be simulated by these fields.

Personal references require existing shared-account flags to be false, no shared
static authorization override, and required per-user credential/session behavior.
Explicit `shared` mode requires the existing shared-account flag to agree; an
external personal failure never falls through to it. Legacy personal OAuth
capabilities without a descriptor remain refused, even if the operator has a
provider token. No existing backend begins storing tokens merely because it
already has `oauth` configured. Compile `personal_managed` to the existing
`PropagationStrategyKind::Vault` at the current resolver and pool chokepoints;
do not add another runtime strategy enum or parallel authorization pipeline.
An explicit account reference conflicts with a second backend
`identity_propagation` declaration; use the descriptor as its single source.
Managed personal backends do not instantiate the legacy global OAuth client.
Replace process-wide `validate_single_minting_strategy_kind` and
`configured_minting_strategy_kind` selection with backend-descriptor dispatch in
the shared resolver installation. Mixed external and Vault backends must coexist
without substituting the one globally installed strategy. Snapshot tooling copies
only validated token basenames from `store_dir`, never its parent or authority.

Storage records use JSON envelopes with exactly `schema_version` (literal
`personal_accounts.v1`), `key_id`, `nonce` (base64 of 12 random bytes), and
`ciphertext` (base64 AEAD ciphertext/tag). Token AEAD associated data is domain
`mcp-gateway/account-token-aad/v1`, then length-prefixed schema version, key ID,
`accounts.instance_id`, store epoch, and the five account-key fields in canonical order.
Use the shared encoder; all domain constants are literal ASCII bytes and every
following field is UTF-8 with its u32 big-endian byte length. Decrypted token payload fields are `generation`
(random 128-bit lowercase hex), `token_revision` (u64), `authorization_epoch`
(u64), `descriptor_revision` (SHA-256 hex), `scopes` (sorted unique strings), `access_token`, optional `refresh_token`,
`token_type`, `expires_at` (UTC Unix seconds), optional `provider_account_id`, and
`client_id`. Tokens must be nonempty and at most 65536 bytes each; decrypted
records are bounded to 262144 bytes. Overflow and unknown versions refuse.

The authority envelope uses `personal_accounts.authority.v1`, its own nonce/AAD,
and encrypted `instance_id`, random `store_epoch`, monotonic `commit_revision`
and an `entries` map keyed by full account digest. Each entry records current
generation, token revision, authorization epoch, descriptor revision, accepted record basename,
record ciphertext SHA-256 and
state (`connected`, `revoked` or `reconnect_required`), plus an optional immutable
legacy-migration marker. Absent map entry alone means never connected; missing or
invalid authority is storage failure, not an empty store. Normal daemon startup
never auto-initializes the authority. Explicit offline
`mcp-gateway accounts init-store --config PATH` creates a fresh empty authority
only when both configured roots contain no previous records or manifest; it
refuses existing state and never migrates tokens. Loss-of-authority recovery uses
new empty roots and a new key, then reconnects accounts; the old files stay intact.
The offline migration owner mapping also requires `store_epoch` and
`legacy_source_sha256`; neither can be inferred or defaulted by the daemon.
A revoked entry needs no ciphertext pointer. Manifest updates and record digests
are checked under the single authority lock; per-account refresh single-flight
does not substitute for this commit boundary.
Count tombstones in store capacity. Refuse an over-capacity new grant before
acknowledgment without evicting authority or another user's grant. S15 benchmarks
the largest valid authority admitted by both configured limits and separately a
byte-binding configuration; do not pad the schema with ignored fields to claim a
larger valid fixture. On the pinned Spark persistent-volume deployment, the
design thresholds are p99 durable mutation completion at most 250 ms, at least
10 durable refresh commits/second sustained for 120 seconds, and authority
load/reconciliation ready within 5 seconds after process start. Mutation latency
includes serialization, queue wait, AEAD, record/manifest sync and publication,
but excludes provider network latency; startup timing excludes external OAuth
discovery and records it separately. Measure actual completion counts and all
latencies, without coordinated-omission sampling. Ten commits/second supplies
more than threefold headroom for refreshing 10000 hourly grants; the startup
budget bounds store recovery downtime. These are unmeasured acceptance targets,
not results. A manifest rewrite is proportional to its size: if the thresholds
fail, change persistence implementation or justify measured supported limits in
the design review before advertising them. Existing release wire-workload budgets
of at most 5% P50 and 10% P99 regression against 3.5.0 remain separately required;
this new store benchmark does not replace them.
Authority AAD is domain `mcp-gateway/account-authority-aad/v1`, then length-prefixed
schema version, key ID and configured instance ID in that order; its
store epoch is encrypted payload, subsequently used in token-record AAD. Validate
record basenames against the fixed digest/random-suffix format; reject paths,
symlinks and a basename whose account digest differs from the manifest entry.

All hosted API JSON uses `schema_version: "accounts.v1"`; request bodies reject
unknown fields. Principal comes exclusively from verified auth, never JSON.

| Route | Request | Successful response |
|---|---|---|
| `POST /accounts/v1/journeys` | `{account_id, return_path}`; scoped authenticated caller, same-origin/CSRF for cookie auth | 201 `{schema_version, journey_id, connect_url, expires_at, status:"pending"}`; opaque random ID and gateway-created URL |
| `GET /accounts/v1/journeys/{journey_id}` | Original authenticated owner | 200 `{schema_version, journey_id, account_id, status, expires_at}`; status pending/connected/cancelled/expired/failed; no provider profile or tokens |
| `GET /accounts/v1/journeys/{journey_id}/start` | Same-principal verified browser, active journey | 303 to configured provider; browser-bridge mechanism remains blocked, not delegated to a query parameter |
| `GET /accounts/v1/callback` | OAuth code/state or provider error; recorded issuer validation and browser binding | 303 to allowlisted completion page after atomic consumption/commit; no credentials in redirect |
| `DELETE /accounts/v1/connections/{account_id}` | Authenticated owner, CSRF-protected if cookie auth | 200 with schema version, account ID, status revoked, and provider_revocation enum confirmed/pending/unsupported after durable local revoke; already revoked is idempotent |

Error envelope: `{schema_version, error:{code, message, retryable, correlation_id}}`,
plus `connect_url` only for authorized missing/reconnect-required account. Codes
are `authentication_required` (401), `forbidden` (403), `not_found` (404 for
unknown or other-owner journey), `invalid_request` (400), `journey_expired` (410),
`journey_conflict` (409), `rate_limited` (429 plus Retry-After), `account_not_connected`
(403), `reconnect_required` (403), `provider_unavailable` (503), `storage_unavailable`
(503), `audit_unavailable` (503), `capacity_exceeded` (503). No raw provider/path/crypto errors appear.
An audit error after local revoke also reports `local_status:"revoked"`; it never
reports the token still usable. MCP account refusal uses existing JSON-RPC
`-32001` with the same secret-free `error.data` fields; transport gateway-auth
failure remains HTTP 401. All journey/account pages and responses set
Cache-Control: no-store and Referrer-Policy: no-referrer. Callback access logs
omit query strings; this includes code/state/error values.

## Personal data flow and retention

This is the deployment data-handling contract, not an additional approval gate.
It implements the selected, authorized account journey. The gateway deployment
operator determines processing purposes and the applicable lawful basis under
their existing service relationship; OAuth authorization proves permission to
access the provider account and is not, by itself, a legal-compliance verdict.
No new legal basis, processor agreement or cross-border transfer mechanism is
invented by this software design. The relevant framework is
[GDPR Articles 5, 6, 25, 28 and Chapter V](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng);
deployment-specific obligations remain with the operator's existing governance.

| Data | Flow and minimization | Retention/deletion behavior |
|---|---|---|
| Verified principal and adapter assertion | Open WebUI/auth provider → gateway; use authority/subject, discard mutable profile fields | Raw assertion only for request validation; no token/profile-body logs or persistence |
| OAuth code/state/verifier and account tokens | Browser/provider ↔ gateway hosted service; tokens go only gateway → configured backend/provider over TLS | Journey secrets expire after five minutes and are removed after terminal outcome; active tokens encrypted until revoke/replacement; revoked/unreferenced token files deleted after authority commit |
| Backend metadata and results | Provider → gateway → authorized client; account-binding partition enforced | In-memory personal metadata/result caches expire by configured TTL, capped at five minutes for this mode; immediate invalidation on revoke/authorization change; no new disk result archive |
| Authority/tombstone/migration markers | Local persistent authority; keyed account digest and generations, no provider profile or token bytes | Minimal pseudonymous security record while old credentials/backups or migration sources could be replayed; not claimed anonymous; independent of token-file restore |
| Account audit events | Existing protected audit sink; opaque subject/account IDs, event/time/reason/correlation only | Existing operator-configured security-audit retention applies; no new indefinite raw credential/profile log |
| Backups | Operator-controlled encrypted token-file copies and separately retained current authority/key custody | Test evidence/snapshots expire after the test run; durable operational retention follows the configured backup policy; old authority snapshots never reactivate grants |

Gateway code introduces no telemetry export of personal content and no new data
destination beyond configured Open WebUI, gateway, OAuth provider/backend and
audit/backup sinks. Spark's physical location and Google's processing regions are
not inferred from hostnames. Use existing configured destinations and deployment
transfer arrangements; do not silently create a new region or external sink.
Erase/revoke removes active token payloads and cached personal data immediately
after durable invalidation. Remaining minimal security markers and governed audit
or backup copies have their stated security/retention purpose; erasure reporting
must distinguish them, and provider-side data deletion is not implied by revoke.

Implementation and fault injection use synthetic IDs, credentials and documents.
Live acceptance uses the selected explicitly connected test accounts and seeded
discriminators, never arbitrary personal documents. Evidence contains versions,
outcomes and redacted request identifiers; delete temporary provider fixtures,
journey material and account payloads after the run while retaining secret-free
test evidence. Actual browser account consent is part of the user journey, not a
new speculative compliance signoff. Any concrete deployment setting that changes
destinations or retention is recorded before applying that setting.

## Delivery increments, risks and validation

| Increment | Target areas; boundary | First decisive check |
|---|---|---|
| 1. Storage/service | New private module, minimal module export/config; reuse existing atomic/lock helpers; S14 owns managed-mode guards in `deploy/helm/mcp-gateway/{values.yaml,templates/deployment.yaml,templates/configmap.yaml}`, `deploy/kubernetes/enterprise-alpha/base/deployment.yaml` and `deploy/single-node/docker-compose.yaml` plus their configuration examples | Two principals and issuer/resource swaps; ciphertext relocation; missing key; CAS loses to revoke across restart |
| 2. Resolution/wiring | Existing router/direct/meta credential boundaries, backend descriptor, REST executor, server strategy installation | Real mock HTTP backend records A/B tokens; unconnected C sends no request, even with operator token present |
| 3. Contextual metadata | Backend metadata/cache, pool, tool registry and discovery; coordinate with search owner | A/B return different names and same-name different schemas; stale fill after revoke is rejected |
| 4. Consent/client | Gateway hosted routes plus verified OWUI browser identity bridge | HTTP/browser exchange rejects stolen/cancelled/replayed journey; same principal succeeds through actual client route |
| 5. Release proof | Real-account fixture, operator docs/config example, migration/rollback rehearsal | Exact release candidate on Spark passes two-account and unconnected-user journey; independent driver records results |

Each increment follows reviewed design → reviewed test plan → failing tests
reviewed as tests → implementation → targeted checks → self-QA → independent
code and functional review. The coordinator records authoritative review ledger
rows and exit codes; prose or this document alone does not establish a verdict.

DoR cost receipt (reasoned planning budgets, not measured token use or billing):

| Increment | Implementation input/output tokens | Test input/output tokens | Review input/output tokens | Formula cost |
|---|---:|---:|---:|---:|
| 1. Storage/service and topology guards | 160000 / 35000 | 120000 / 25000 | 120000 / 15000 | $11.63 |
| 2. Resolver/public routes | 160000 / 30000 | 160000 / 30000 | 120000 / 15000 | $12.23 |
| 3. Contextual metadata | 120000 / 25000 | 120000 / 25000 | 100000 / 12000 | $9.75 |
| 4. Consent/client bridge | 200000 / 40000 | 160000 / 30000 | 140000 / 18000 | $14.10 |
| 5. Release proof/docs | 80000 / 12000 | 160000 / 22000 | 80000 / 10000 | $8.10 |

Formula is the canonical G2 comparison rate, $15/M input plus $75/M output;
these budgets include paired reviews and targeted reruns, not a price quotation.
The store and public-route increments carry the largest test costs because real
crashes and route matrices need independent fixtures. Context-switch overhead is
one source-owner handoff at each boundary plus coordinator serialization of
shared files; keep fixture reuse and the single resolver to limit it. Actual
costs/review rounds belong in this package's evidence, not bookkeeping tickets.
Value is the approved release's required security/adoption outcome; no invented
revenue, NPV or measured ROI is claimed. Source-specific impact checks and reviewed
red tests remain start gates. Increment 4 additionally awaits the browser bridge;
increment 5 awaits exact candidate and live fixture readiness. This receipt does
not declare all canonical gates passed.

STRIDE risks: forged identity (verified authority plus bound adapter client),
tampered/moved storage (AEAD associated data), unaudited changes (durable sanitized
account events), metadata/credential disclosure (context partitions and no
secrets in logs), consent flooding (bounded state and rate limits), elevated
shared fallback (explicit mutually exclusive modes). Also test late refresh
resurrection, callback account substitution and revoked cached results.

Emit existing structured audit events for connect, cancel, refresh, revoke and
refusal using opaque subject/account IDs, correlation ID, generation and reason
codes. Record latency/error counts without per-user metric labels. Durable audit
failure bars new token disclosure/dispatch; local revoke still invalidates and
reports audit failure rather than restoring a credential. Key rotation uses key
IDs and an explicitly configured read-old/write-current keyring; removal of the
last decrypting key fails before migration. Retain tombstones/migration markers
while any old record could be replayed, and document backup/key retention together.

Before production configuration, snapshot the relevant config/store/key reference;
exercise restore on a copy. Rollback disables personal routes and preserves the
encrypted store, never maps personal grants back to shared plaintext credentials.
Canary only the designated test users before broader exposure. Compare account
resolution and hot/cold discovery latency and bounded memory against the release
NFR budgets; attach measured results rather than estimating improvement.

## Unknowns and evidence ownership

| Question | Status/owner | Decisive check and trigger | If it fails |
|---|---|---|---|
| Which reference client and service? | Resolved by operator; linked scope decision | Open WebUI on Spark → gateway → Google Workspace, two accounts plus unconnected user | No re-selection is required |
| Does OWUI support native MCP and emit a stable signed subject? | Resolved at v0.9.6 source, links above; installed request path unverified | Coordinator checks installed code/version and captures synthetic gateway-bound request before A06/live JOURNEY.1; source-pinned A01–A05 can proceed independently | Use a minimal explicit adapter; preserve user identity; do not trust unsigned headers |
| How does the consent browser authenticate as that same OWUI principal? | Deferred to release coordinator; blocks hosted adapter design finalization | Inspect version-pinned browser auth routes and test a same-session identity bridge before increment 4 test review | Implement a small authenticated bridge or provision a verified gateway-login identity link; never replace it with email matching/state possession |
| Are the Google OAuth app, exact HTTPS callback and two test users ready? | Deferred to release coordinator/operator-owned setup; blocks live consent only | Inspect non-secret deployed configuration before real-account run; request one missing setup decision at a time if needed | Keep synthetic tests valid and live acceptance pending; do not use operator's existing shared token |
| Are all source callers/context paths mapped? | Deferred to each implementation owner | Required impacts and scoped callers before editing that increment | Repair design/test map before source changes; unavailable GitNexus is reported explicitly |

References: [Google hosted OAuth guidance](https://developers.google.com/identity/protocols/oauth2/web-server),
the version-pinned Open WebUI source and current MCP specification linked above,
and the repository paths in the readiness audit. These constrain the design;
none constitutes evidence that the release implementation passes.
