<!--
SPDX-FileCopyrightText: 2026 Mikko Parkkola
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
-->

# Per-user OAuth accounts — the full connect and revoke surface

**Criteria**: MIK-6744.STORE.1, MIK-6744.STORE.2, MIK-6745.JOURNEY.1, MIK-6746.CONTRACT.1
· **Operator ruling**: 2026-09-20, build the full surface for 4.0.0
· **Supersedes**: `docs/design/2026-09-20-store2-self-revoke.md`
· **Status**: design reviewed by two external reviewers, both SHIP-WITH-FIXES;
fixes applied (§15). This revision re-reviewed by both, both SHIP-WITH-FIXES;
each found one NOW defect, both fixed (§15.5). No code written.

The per-user OAuth machinery — storage, custody, fencing, cache binding — is
built and unit-tested. Nothing is reachable from outside the process. This
designs the reachable surface: consent initiation, the callback, cancelled and
expired consent, refresh, self-revoke, administrative revoke, and the
authorization model that decides who may act on whose grant.

**Read §14, then §7.** §14 separates the three OAuth systems this repository
runs and shows why the shipping one cannot be promoted to multi-user by
configuration. §7 is the only section where a mistake lets one user take or
destroy another's grant; every other section is plumbing around it.

**Two blockers, both found by external review, both confirmed at source. Neither
is resolved by this document:**

| # | What | Blocks | Section |
|---|---|---|---|
| 1 | The origin guard refuses the provider's redirect, so no browser can complete consent | Stage 2 — it is an edit, not a question | §2.6 |
| 2 | No caller can hold both admin standing and a verified identity | Stage 3 — it is an operator decision (#10) | §6.5, **narrowed by §16.2** — shipped role mapping resolves admin standing *from* a verified identity, so the question is which mechanism confers admin, not whether the combination can exist |

| Brief item | Section |
|---|---|
| 1 Consent initiation | §1 |
| 2 The callback | §2 |
| 3 Cancelled / expired consent | §3 |
| 4 Refresh | §4 |
| 5 Self-revoke | §5 |
| 6 Administrative revoke | §6 |
| 7 Authorization model | §7 |
| 8 Must not be reimplemented | §8 |
| 9 `expect(dead_code)` inventory | §9 |
| 10 Test plan | §10 |
| 11 Staging | §11 |
| — Decisions for review | §12 |
| — Proposed status-file text | §13 |
| — The three OAuth systems | §14 |
| — External review findings | §15 |

---

## §0. Corrections to the briefed premise

Every factual claim in the brief was checked at source. Four hold exactly as
written; five things the brief did not say are load-bearing and are corrected
or added here.

### 0.1 Confirmed, no correction needed

* **Served routes.** `.route(` appears eight times in the served router:
  `/.well-known/jwks.json` (`src/gateway/router/mod.rs:217`), the
  protected-resource metadata (`:232`), `/health` (`:248`), `/api/costs`
  (`:249`), `/mcp` (`:250`), `/mcp/{name}` (`:256`), `/sse` (`:257`), `/mcp` SSE
  (`:262`) and `/metrics` (`:321`). A case-insensitive search of that file for
  `account`, `consent`, `revoke` or `connect` returns nothing.
* **No meta-tool names an account.** The dispatch arms at
  `src/gateway/meta_mcp/mod.rs:2160-2178` are nineteen `gateway_*` names, none
  of them an account name.
* **`account_rest_tests.rs` is outbound.** Restated from the prior doc's §0.1,
  which was correct: it tests a REST capability dispatching as the verified
  caller, not an inbound management API.
* **`commit_grant*` outside `personal_accounts` is the policy store.**
  `control_plane::store::commit_grant_audited` is an unrelated subsystem.

### 0.2 Correction — the `expect(dead_code)` inventory is twenty-five sites, not four

The brief names four symbols. The production annotation set is **twenty-five**,
spanning eight files, with **three different cfg gates** plus ungated sites. A
change that removes the four and stops leaves the build red. The full inventory
is §9. This is the single most likely way to get the implementation stage wrong.

### 0.3 Correction — a full OAuth client with PKCE already exists, and cannot be reused as-is

`src/oauth/client/mod.rs` already implements the complete authorization-code
flow: `generate_pkce()` (`:1160`), `generate_state()` (`:1175`), an authorize-URL
builder that sets `state`, `code_challenge` and `code_challenge_method=S256`
(`:702-715`), a token exchange that presents `code_verifier` (`:740-747`), and a
one-call `authorize()` that drives the whole journey (`:799-860`).

It cannot serve this surface, for a reason that is structural rather than
stylistic:

* **Its callback is a loopback listener.** `authorize()` starts an in-process
  HTTP server and waits on it (`:812-819`; `src/oauth/callback.rs:110`,
  `:83`), dual-binding `127.0.0.1` and `[::1]`
  (`src/oauth/callback.rs:8-10`). That is a single-operator CLI shape. A
  multi-user gateway receives the provider's redirect on its own public
  origin, from someone else's browser.
* **It is single-identity.** Its storage keys on
  `storage_key(backend_name, issuer)` (`:114`) — no principal field at all. Two
  users of the same gateway would collide on one entry.
* **The same objection is already recorded in-tree.**
  `src/personal_accounts/provider.rs:25-28` states why
  `OAuthClient::refresh_token` was deliberately not reused: it writes the legacy
  `TokenStorage` and caches into its own `current_token`, "which would give the
  gateway a second grant store the custody service does not fence. Its HTTP and
  response-parsing SEMANTICS are reused; its persistence is not."

That sentence is the rule this design adopts for connect as well: **reuse the
protocol mechanics, never the persistence.** §1 and §2 say exactly which
functions that means.

### 0.4 Correction — no production code mints a new grant

The brief treats `commit_grant_if_unchanged` as the wiring target, which is
right, but the record it commits has no production author. The only production
construction of `GrantRecord` is `AccountService::apply`
(`src/personal_accounts/service.rs:413`), the **refresh** path, and it carries
the identity fields forward rather than minting them: `token_revision` is
`current.token_revision + 1` (`:414-417`), `authorization_epoch` is
`current.authorization_epoch` unless scopes narrowed (`:405-411`), and
`generation` is cloned from the current record (`:180`, `:190`).

So "what `generation`, `authorization_epoch`, `token_revision` and
`descriptor_revision` does a *first* grant get" is an unowned decision. §2.4
proposes the rule and marks it as a decision for review, because it is the value
the whole cache-binding fence is computed over
(`src/identity_propagation/account_strategies.rs:106-110`).

### 0.5 The structural fact that shapes §1, §2, §3 and §7

**The callback request carries no verified identity.** The provider redirects
the *user's browser* to the gateway's `redirect_uri`. That navigation has no
OIDC bearer token, so the `VerifiedIdentity` axum extension is absent and
`identity::account_key` (`src/personal_accounts/identity.rs:76-96`) cannot be
called there. The dashboard session cookie is not a substitute: it is an opaque
handle minted from a bootstrap link (`src/gateway/auth.rs:489`, `:503-526`) and
carries no principal.

Consequently the principal is bound **at initiation**, where the identity is
verified, and carried only in server-side pending state that the callback looks
up by an opaque `state` value. The callback reads no principal from the request,
because there is no principal in the request to read. §7 makes this the rule.

### 0.6 On STORE.1 migration — sharper than the brief asked

The brief asks whether the full-surface build changes the "nothing is migrated"
posture (`src/personal_accounts/mod.rs:779`,
`src/commands/upgrade.rs:243-247`). It does not, and the reason is stronger than
a scheduling preference:

The 3.x data is keyed by `storage_key(backend_name, issuer)`
(`src/oauth/client/mod.rs:114`). There is **no principal field in the key**. The
target `AccountKey` has two principal fields taken from a verified OIDC identity
(`src/personal_accounts/identity.rs:84-89`). A principal-keyed store therefore
cannot be populated from principal-free data without someone naming the
principal, and **there is no safe default** — any default silently hands one
user another user's live refresh token.

So STORE.1 splits:

* *Readable* — **already satisfied**. The 3.x files are intact at
  `~/.mcp-gateway/oauth/`, at mode 0600, and still hold usable refresh tokens
  (`src/commands/upgrade.rs:243-247`).
* *Migrated* — **blocked on an operator decision this design does not settle.**
  The decision is "which principal owns each 3.x credential", and it is an
  operator input, not an inference. Recommended answer: leave it unmigrated for
  4.0.0. Once connect exists (§1), re-consent costs one browser round trip per
  backend per user and produces correctly-keyed data, which is strictly better
  than a guessed mapping.

This is flagged explicitly rather than settled, per the brief.

---

## §1. Consent initiation

### 1.1 Which surface can carry a verified principal

`MIK-6745.JOURNEY.1` names the client: **Open WebUI on Spark**, reaching Google
Workspace through the gateway. Open WebUI speaks MCP and calls tools. It does
not POST to a dashboard namespace. So the question is not "where would a
disconnect button look best" — it is which surface can carry a verified
principal for the caller the criterion names.

* **`/ui/api/*`** (the prior doc's recommendation) is reachable with an OIDC
  credential, but the caller in JOURNEY.1 never makes such a request. Worse,
  `actor_from_client` in that namespace deliberately falls back to an
  `AuthenticatedClient` and then to a literal `"anonymous"` actor
  (`src/gateway/ui/control_plane.rs:476-478`, `:497-500`). Correct for a
  read-mostly dashboard, catastrophic for a grant mutation.
* **A meta-MCP tool** carries the identity uncollapsed:
  `MetaMcpCallerContext::verified_identity`
  (`src/gateway/meta_mcp/mod.rs:163`) exists precisely so the account boundary
  can see the real user.

**Recommendation: meta-MCP tools.** This reverses the prior doc's §1.2, and the
reversal is caused by scope, not by a new fact — self-revoke alone could sit
anywhere the user already is, but connect must be reachable by the MCP client
that performs the journey.

### 1.2 How many meta-tools, and the surface budget

CLAUDE.md fixes the Meta-MCP surface at 9–17 tools across gate configurations,
11 in the shipped default, and names surface bloat as the first anti-pattern.
Commit `37bd9121` has just compacted it, so the count must be re-read at
implementation time rather than quoted from here.

**Recommendation: two tools, not four.**

| Tool | Caller | Principal input |
|---|---|---|
| `gateway_account` | any authenticated caller | **none** |
| `gateway_account_admin` | admin only | a principal, and only here |

`gateway_account` takes an `action` enum — `connect`, `status`, `revoke` — which
is the repo's own convention for behaviour-selecting parameters (CLAUDE.md:
"Behavior-selecting parameters use enums, not booleans"). One tool covers
initiation, the caller's own view, and self-revoke at a cost of one surface
slot.

The split into two tool *names* is not cosmetic. Tool availability is already
gated by name: `CallerStanding::of_admin_flag(caller.is_admin).permits(tool_name)`
(`src/gateway/meta_mcp/mod.rs:1999`). A separate admin name is therefore
invisible to a non-admin through the existing mechanism, with no new gate
written — and it keeps the invariant that §7 rests on: **the self-service tool
has no field in which another user's principal could be named.**

Runner-up, recorded for review: three separate self-service tools
(`gateway_account_connect` / `_status` / `_revoke`). Cleaner schemas, three
surface slots, three sets of README / `benchmarks/public_claims.json` / badge
updates. Rejected on the compact-surface decision, not on taste.

**Obligation this creates.** Any meta-tool change must update README,
`benchmarks/public_claims.json` and the tool-count badges in one PR — CLAUDE.md
names this a known drift source, and there is a CI check on
`benchmarks/public_claims.json`. §11 makes that a stage item, not a footnote.

### 1.3 `action: "connect"` — what happens

Input: `descriptor_id`, the `accounts.descriptors` map key. Nothing else.

1. **Identity.** Read `caller.verified_identity`
   (`src/gateway/meta_mcp/mod.rs:163`). Absent → refuse with
   `IdentityBindingError::MissingVerifiedPrincipal`
   (`src/personal_accounts/identity.rs:58-59`). Never defaulted. §7.
2. **Descriptor resolution.** Look up `descriptor_id` in the configured
   descriptor map. Absent → `IdentityBindingError::UnknownDescriptor`
   (`identity.rs:60-66`), which removes that annotation (§9).
3. **The account key.** `identity::account_key(identity, descriptor)`
   (`identity.rs:76-96`). Built, never compared. §7.
4. **OAuth configuration.** Taken from the descriptor, which already carries
   every field the flow needs: `authorization_endpoint`, `token_endpoint`,
   `revocation_endpoint`, `client_id`, `client_secret_ref`, `redirect_uri`,
   `scopes`, `send_resource_parameter`
   (`src/personal_accounts/config.rs:265-283`).

   **The endpoints are already validated and pinned at startup.**
   `PersonalOAuthRefresh::bootstrap` (`src/personal_accounts/provider.rs:260`)
   is eager: it discovers, validates and pins issuer metadata for *every*
   managed descriptor before the gateway can reach Serving
   (`provider.rs:12-18`), and it refuses a descriptor whose configured
   `authorization_endpoint` disagrees with the discovered document
   (`provider.rs:461`) or whose endpoints fail the scheme checks
   (`provider.rs:474`). Connect therefore performs **no discovery of its own**
   and must not: it reads the snapshot bootstrap already accepted.
5. **PKCE and state.** `generate_pkce()` and `generate_state()` already exist
   (`src/oauth/client/mod.rs:1160`, `:1175`) but are private module functions.
   **Decision for review:** widen both to `pub(crate)`, or duplicate roughly
   four lines. Widening is recommended — one generator for the whole binary
   means one place to audit the entropy — and CLAUDE.md requires asking before
   any API visibility widening, so this is the ask.

   `generate_state()` currently draws 16 bytes (`:1176`). For the loopback flow
   that is a CSRF nonce. Here the state value is **the only thing authenticating
   the callback** (§2.1), so 16 bytes is too few. **Decision for review:** the
   pending-consent handle is a distinct 32-byte value, not `generate_state()`.
   Recommended, and it is why the reuse note above stops at PKCE.
6. **Capture the expectation.** `ConsentExpectation::captured(&lookup)`
   (`src/personal_accounts/service.rs:121-133`) over a `store.lookup` of this
   account key, taken **now**, at initiation.

   This is the point of the whole guarded-commit primitive.
   `src/personal_accounts/consent.rs:9-14` states it: `commit_grant` is
   unconditional and `lookup` releases the authority lock before it returns, so
   "a consent journey built from the pair compares a state it has already
   stopped holding. A grant or a revoke landing in that window is silently
   overwritten." The window that matters is the one the user spends in the
   browser — minutes, not microseconds. Capturing at the callback instead would
   shrink it to nothing and make the primitive pointless.
7. **Store the pending consent** (§1.4) under the handle.
8. **Return the authorization URL.** The tool returns a URL for the user to
   open, and does **not** open a browser. `OAuthClient::authorize` shells out to
   a local browser (`src/oauth/client/mod.rs:835-840`); a server answering a
   remote MCP client must not. The client presents the URL; the human opens it.

### 1.4 The pending-consent store — the one genuinely new component

Everything else in this design reuses something. This does not exist, and its
shape is a review decision.

```
handle (32 random bytes, URL-safe)  ->  PendingConsent {
    principal_authority,      // VerifiedIdentity::issuer,  captured at initiation
    principal_subject,        // VerifiedIdentity::subject, captured at initiation
    descriptor_id,
    code_verifier,            // PKCE; never leaves the process
    redirect_uri,             // as sent, so the exchange presents the same value
    scopes_requested,
    expectation,              // ConsentExpectation, captured at initiation
    created_at,
}
```

* **In memory, not durable.** Precedent and rationale are already written in
  this repo for the dashboard session store: an opaque handle in a
  `Mutex<HashSet<..>>`, "kept in memory: a dashboard session is not worth
  persisting" (`src/gateway/auth.rs:499`, `:503-510`). The same reasoning holds
  here and more strongly, because the entry holds a PKCE verifier. A gateway
  restart drops in-flight consents; the user retries. Stated, not hidden.
* **Single-use.** The lookup **removes** the entry. §3 depends on this: replay
  and double-return become the same "handle not found" case as expiry.
* **TTL-bounded.** Recommended 10 minutes, swept on access. **Decision for
  review:** the exact value, and whether it becomes a configurable limit
  alongside `AccountsLimits` (`src/personal_accounts/config.rs:306-312`). A
  fixed constant is recommended — CLAUDE.md's own rule is no config for a value
  that never changes.
* **Bounded in size.** An unauthenticated caller cannot reach initiation (§7),
  so this is not an open memory sink, but a bound is still cheap insurance.
  **Decision for review:** a cap, and whether exceeding it refuses or evicts
  oldest. Refusing is recommended; eviction would let a burst cancel a real
  user's in-flight consent.
* **Never logged, never rendered.** The entry holds a PKCE verifier; the
  existing account errors are secret-free by construction
  (`src/personal_accounts/mod.rs:83-100`) and `GrantRecord` redacts its own
  `Debug` (`mod.rs:151-155`). `PendingConsent` gets the same treatment.

---

### 1.6 Provider-specific authorize parameters — Google needs `access_type=offline`

Raised by external review and accepted. §4 says the surface exposes no refresh
action because the credential is refreshed when it is used
(`src/personal_accounts/worker.rs:210`). That is only true if a refresh token
exists, and with Google it does not by default: the authorization request must
carry `access_type=offline`, and a user who has already consented gets no new
refresh token on a re-consent unless the request also carries `prompt=consent`.

Without it the JOURNEY.1 run passes connect and first use, then fails an hour
later when the access token expires — the worst possible failure shape, because
it looks like a refresh bug rather than a consent bug.

Therefore:

* The authorize URL is built from the descriptor's configured parameters, not
  from a hardcoded set. `AccountDescriptor` (`src/personal_accounts/config.rs:255-292`)
  already carries `send_resource_parameter` as precedent for a per-provider
  authorize-time flag.
* **Decision for review:** whether `access_type` and `prompt` become named
  descriptor fields, or whether the descriptor gains a generic
  `extra_authorize_params` map. Named fields are recommended — a map invites a
  caller-shaped surface, and `send_resource_parameter` set the pattern.
* The callback (§2.2) must treat a token response **with no refresh token** as a
  refusal with an actionable reason, not as a successful connect. A grant with
  no refresh token is a grant that dies silently at first expiry, and
  `GrantRecord` (`src/personal_accounts/mod.rs:137-149`) has no state that means
  "connected but doomed".
* §10.3 gains `a_token_response_without_a_refresh_token_is_refused`.

---

## §2. The callback

### 2.1 It must be a public HTTP route, and the state handle is its only authenticator

The provider redirects a browser to the descriptor's `redirect_uri`
(`src/personal_accounts/config.rs:279`). That request arrives with no bearer
token, no OIDC identity and no gateway session (§0.5). So:

**`GET /accounts/callback` is a new served route, and it must be exempt from the
auth layer.** The default `public_paths` today are `/health` and `/metrics`, and
the bucket test asserts `/mcp` and `/` are *not* public
(`src/gateway/auth.rs:1163-1173`). Adding a third public path is a
security-relevant change and a reviewer should treat it as the second-hardest
thing in this document after §7.

**Two corrections from external review, both load-bearing, both detailed below.**
The `public_paths` entry exempts the route from *authentication* and from
nothing else: the origin guard is a separate global layer that still refuses
the provider's cross-site redirect (§2.6). And "a new served route" is not a
free choice of path — it must be the one every managed descriptor's
`redirect_uri` names, enforced at configuration load (§2.7).

What makes it safe is that the route is not anonymous in effect, only in
transport:

* The `state` handle is a 32-byte random value (§1.3 step 5) that the gateway
  itself minted, handed to exactly one verified caller, and stored server-side.
* The callback **looks it up**; it does not compare anything the caller supplied
  against anything else. An absent handle is simply not found. This is the same
  "make the bug inexpressible" doctrine §7 applies to the principal.
* The lookup **removes** the entry, so a handle works once.
* Everything the commit needs — principal, descriptor, verifier, expectation —
  comes out of that entry. Nothing is read from the query string except `state`,
  `code`, and the error parameters §3 handles.

Two things the route must NOT do, stated as review rejections:

* It must not accept a principal, subject, email or account id in the query
  string, however convenient. §7.
* It must not fall back to `actor_from_client`
  (`src/gateway/ui/control_plane.rs:476-478`) or any other identity guess. There
  is nothing to guess from.

### 2.2 The exchange

With the entry in hand:

1. **Resolve the client secret late.** `client_secret_ref` is an `env:VARIABLE`
   reference that "stays a reference so no client secret is materialised into a
   serialized or `Debug`-rendered configuration"
   (`src/personal_accounts/config.rs:273-277`), resolved through
   `EnvSecrets` (`src/personal_accounts/provider.rs:157-162`). The provider
   module already states the rule — "a client secret is read at refresh time
   only, and only against a snapshot bootstrap already accepted"
   (`provider.rs:20-23`) — and the callback adopts it verbatim: read the secret
   at exchange time, against the pinned metadata, never earlier.
2. **POST the token endpoint** over the provider module's transport, not a new
   client. `src/personal_accounts/provider.rs:30-32` describes it: "one
   `reqwest` client with certificate validation, redirect refusal, DNS pinning
   and the existing SSRF checks", behind the `ProviderHttp` trait
   (`provider.rs:108`). A second HTTP client here would bypass all four
   protections. Present `grant_type=authorization_code`, the `code`, the stored
   `redirect_uri` and the stored `code_verifier` — the same parameter set
   `token_exchange_params` already builds (`src/oauth/client/mod.rs:740-747`),
   whose *semantics* are reused per §0.3.
3. **Refuse a scope widening.** The refresh path already refuses a response that
   broadens what the user granted — "A refresh may narrow what the user granted.
   It may never widen it: that is a new consent, and the user has not given it"
   (`src/personal_accounts/service.rs:407-412`,
   `AccountServiceError::ScopeBroadeningRefused` at `:156`). Connect **is** that
   new consent, so the granted scopes are whatever the provider returns; the
   comparison here is against `scopes_requested` and a widening is a refusal,
   not a silent acceptance. **Decision for review:** whether a provider
   returning *more* scope than asked is a refusal or a recorded warning.
   Refusal is recommended.

### 2.3 The commit

One call: `CustodyHandle::commit_grant_if`
(`src/personal_accounts/worker.rs:254`) → `AccountService::commit_grant_if`
(`src/personal_accounts/service.rs:342`) →
`PersonalAccountStore::commit_grant_if_unchanged`
(`src/personal_accounts/consent.rs:75`), passing the account key rebuilt from
the stored principal, the expectation captured at initiation, and the new
record.

The guarded commit does the comparison and the publication under ONE acquisition
of the authority lock (`consent.rs:16-19`, implemented at `:91-103`). On a
mismatch it returns `GuardedCommit::Fenced` having written nothing (`:96-100`),
which `commit_grant_if` maps to `AccountServiceError::StaleConsentFenced`
(`service.rs:353`, variant at `:168`). §3.4 says what the user sees.

**The callback must not** look up first and commit second. That is the exact
two-call shape the primitive exists to replace (`consent.rs:9-14`), and
`witness` (`consent.rs:133`) logs every acquisition at the lock itself so a
double acquisition is visible "whatever the implementation claims about itself"
(`consent.rs:21-24`).

### 2.4 What a first grant's version fields are — decision for review

Per §0.4 this is unowned. The proposed rule:

| Field | First grant | Re-consent over a tombstone |
|---|---|---|
| `generation` | fresh 128-bit random, **32 lowercase hex** | same — **never** reused |
| `token_revision` | `1` | `1` |
| `authorization_epoch` | `1` | `1` |
| `descriptor_revision` | the descriptor's current revision, **64 lowercase hex** | same |
| `client_id` | the descriptor's resolved `client_id` | same |

Scopes are **sorted and deduplicated** before the record is built.

These are not stylistic choices; they are what the existing validator already
requires, and an earlier draft of this table started both counters at `0`, which
`validate_record` rejects outright (`src/personal_accounts/storage.rs:136-137`).
A first grant written that way could never commit, so connect as specified could
not have worked. The same function fixes the widths — `lower_hex(&record.
generation, 32)` and `lower_hex(&record.descriptor_revision, 64)` at `:134-135`
— and rejects unsorted *or* duplicated scopes with
`record.scopes.windows(2).any(|pair| pair[0] >= pair[1])` at `:138`, where the
`>=` is what makes a repeated scope fatal rather than merely untidy. Refresh
already satisfies this contract; connect must meet the same one, because it
writes through the same validator.

The reasoning, and why the epoch may restart:
`fence_tests.rs:139-140` records that "re-consent mints a new generation over the
tombstone, which is legitimate", and the cache binding is the five-field account
digest **widened with all four** of generation, authorization epoch, token
revision and descriptor revision
(`src/identity_propagation/account_strategies.rs:106-110`). A fresh generation
therefore already produces a different binding, so the epoch does not need to
carry across generations to keep the fence sound. It still increments within a
generation when a refresh narrows scope (`service.rs:405-411`), which is the
case it was built for.

A reviewer who disagrees should say so here rather than at implementation: this
table is the input to the fence, and getting it wrong is the one mistake in this
section that would not show up as a failing build.

### 2.5 What the browser sees

A plain HTML page — connected, or refused with a reason. It carries no token, no
account key, no principal and no state handle. The account errors are secret-free
by construction (`src/personal_accounts/mod.rs:83-100`); this page inherits that
rule. The page is the end of the browser's involvement; the MCP client observes
the result through `action: "status"` (§1.2) or simply by dispatching.

**The page is a closed set of gateway-owned strings, added after review.** The
refusal reason is chosen from the vocabulary of §2.6-§2.8 and §3; a provider's
`error` or `error_description` is **logged, never rendered**. This page is
unauthenticated and publicly reachable, so provider-controlled text rendered
into it is provider-controlled HTML. Two further rules for the same reason: the
response carries `Referrer-Policy: no-referrer`, so the authorization code in
the request URL cannot leak to a third party through `Referer`, and the page
loads no third-party subresource — no font, no script, no image.

### 2.6 BLOCKER — the origin guard refuses the provider's redirect

Found by external review and **confirmed at source**. It is the defect that
would have shipped a surface nobody can use.

`origin_guard_middleware` is a **global layer** applied to the whole router
outside authentication (`src/gateway/router/mod.rs:345-348`; the comment at
`:336-341` says so deliberately — "it is outside authentication, so a
cross-site request is refused before any identity, the anonymous one included,
is assigned"). Any request carrying `Sec-Fetch-Site` is refused unless the
value is `same-origin` or `none` (`origin_guard.rs:246-248`, enforced at
`:362-373`).

A provider redirect is neither. The browser's navigation to
`/accounts/callback` begins at the provider's origin, so the request arrives
with `Sec-Fetch-Site: cross-site` and is answered `403 Cross-site request not
allowed` **before the callback handler runs at all**. The `public_paths` auth
exemption §2.1 relies on does nothing here: it exempts the request from
authentication, and this gate sits outside authentication.

Why no existing code shows the problem: the shipped OAuth callback is not
served by the gateway router. `start_callback_server`
(`src/oauth/callback.rs:105-113`) binds its own loopback listener on an
ephemeral port and never passes through this middleware. This design is the
first thing to put a browser callback on the gateway itself.

**The fix, and the shape it must take.** Exempt the one callback path from the
`Sec-Fetch-Site` check only — not from the `Host` check, not from the `Origin`
check, and not for any other path:

* The `Host`/`:authority` comparison (`origin_guard.rs:377-382`) still runs, so
  the request must still be addressed to this gateway.
* The exemption is keyed on the exact served path, compared whole. Not a
  prefix, because a prefix match turns every path under it into an exemption.
* `/mcp` and every other route keep the gate unchanged. §10.3 gains two named
  tests: a `cross-site` navigation to the callback path with a minted handle is
  admitted, and a `cross-site` request to `/mcp` is still refused.

What makes the exemption safe is §1.4, not the guard: the handle is
single-use, TTL-bounded and unguessable, so a cross-site request to this path
with no valid handle achieves exactly the refusal of §3.

### 2.7 The callback path is not free — it must be the descriptor's `redirect_uri`

Also from external review, also confirmed. §2.1 names one served path. But a
managed descriptor already carries its own `redirect_uri`
(`src/personal_accounts/config.rs:279`), and it is **required**, not optional:
validation refuses a descriptor whose `redirect_uri` is absent or not an https
host (`config.rs:730-737`). The provider redirects to *that* URL. If it is not
the URL this gateway serves, consent leaves and never comes back.

The rule, then, stated as a validation rather than a hope: **a `managed`
descriptor's `redirect_uri` must equal this gateway's public URL plus the one
served callback path, and configuration validation refuses it otherwise.** One
served path stays true, and the descriptor's existing field becomes the thing
that proves it rather than a second source of truth.

The alternative — serving a route per descriptor at whatever path each
`redirect_uri` names — is rejected: it makes the origin-guard exemption of §2.6
a set that grows with configuration, which is precisely the prefix-shaped
exemption §2.6 refuses.

**Where the check lives, checked rather than assumed.**
`validate_descriptors` takes `Option<&AccountsConfig>` and nothing else
(`src/personal_accounts/config.rs:574-576`), so it cannot see the gateway's
public URL and this comparison cannot live there. It belongs one level up, in
`Config::validate` (`src/config/mod.rs:813`, which is the call site), where
`self.accounts` and `self.server.public_url` (`src/config/mod.rs:1365`) are both
in scope. Descriptor *structure* stays where it is; only the cross-field
comparison moves up.

**And `public_url` is optional.** It is `Option<String>` and unset by default;
the gateway already refuses to name itself honestly without it on a non-loopback
bind (`src/config/mod.rs:1357-1364`). The rule follows that precedent rather
than inventing one: **a `managed` descriptor requires `server.public_url` to be
set, and configuration validation refuses the combination otherwise.** Guessing
an origin from the bind address is exactly the dishonest naming that comment
refuses.

**One consequence for §10.3, stated because it bites at implementation time.**
`redirect_uri` must already be an https host (`config.rs:730-737`), so a plain
http test gateway cannot satisfy this rule through configuration. The
deterministic-provider journey test either terminates TLS or constructs its
descriptor below the validation boundary — and if it does the latter, it is no
longer evidence that the validation permits the real shape. Decide which at
implementation; do not discover it in CI.

`# ponytail: one path, one cross-field check at Config::validate.
Per-descriptor paths only if a provider ever refuses a shared redirect_uri.`

### 2.8 The token exchange must not reuse `token_exchange_params`

An earlier draft of §2.2 said to reuse `OAuthClient::token_exchange_params`.
External review caught it and the source agrees: that builder **unconditionally**
appends `resource` (`src/oauth/client/mod.rs:753-754`), while a personal-account
descriptor decides that per provider through `send_resource_parameter` — a
field that is mandatory on a managed descriptor and refuses the refresh when
absent (`src/personal_accounts/provider.rs:304-306`), and that the existing
refresh path applies conditionally (`provider.rs:333-335`).

So reusing the shared builder would send an RFC 8707 `resource` indicator to a
provider the operator configured *not* to send one to. Whether Google refuses
the exchange outright is not established here and the design does not claim it;
what is established is that the two paths would disagree about the same
descriptor field, and a connect that contradicts its own refresh is a bug
whichever way the provider answers.

**Build the exchange form the way `PersonalOAuthRefresh` builds the refresh
form** (`provider.rs:322-335`): `grant_type`, `code`, `redirect_uri`,
`client_id`, `code_verifier`, the resolved `client_secret` when
`client_secret_ref` is configured, and `resource` **only** when
`send_resource_parameter` is true.

**And read `iss` after all.** An earlier draft forbade it. `validate_issuer`
(`src/oauth/client/mod.rs:88-100`) already has exactly the semantics wanted: a
missing `iss` returns `Ok` and a present one must equal the recorded issuer, by
exact string comparison, with normalisation explicitly refused (`:91-94`). The
callback calls it with the pending entry's pinned issuer. Three lines, an
RFC 9207 mix-up defence the shipping client already performs, and §2.7's single
shared callback path makes it more relevant rather than less: every descriptor
returns to the same URL, so the response itself is the only thing that says
which authorization server answered.

---

## §3. Cancelled, expired and replayed consent

`MIK-6745.JOURNEY.1` requires browser cancellation and expired/replayed consent
state. The single-use, TTL-bounded lookup of §1.4 collapses four user-visible
cases into two code paths.

| Case | What arrives | Behaviour |
|---|---|---|
| User denies at the provider | `state` + `error=access_denied` | Consume the entry, commit nothing, show refused |
| User closes the browser | **nothing ever arrives** | Entry expires at TTL and is swept; store untouched |
| Return after the TTL | `state` + `code`, handle expired | Not found → refused; the code is never presented |
| Second return with the same handle (replay) | `state` + `code`, handle already consumed | Not found → refused, identically |
| A guessed or forged handle | `state` + `code` | Not found → refused, identically |

Three properties a reviewer should check are preserved:

* **Cancellation writes nothing.** The store is not touched at all on a denial.
  There is no "pending" or "failed" grant state to create — `AccountLookup` has
  four states (`service.rs:113-116`: `Absent`, `Connected`, `Revoked`,
  `ReconnectRequired`) and a cancelled consent leaves the account in whichever
  one it was already in.
* **Expiry and replay are indistinguishable from the outside.** Same refusal,
  same text. A caller must not be able to use the difference as an oracle for
  whether a given handle ever existed. This mirrors the existing rule at
  `src/gateway/ui/control_plane.rs:311` — "non-admin cannot use 403-vs-404 as an
  existence oracle."
* **A denial is not a revoke.** An existing connected grant survives a cancelled
  re-consent untouched, because §2.3 is the only path that writes and it is not
  reached.

### 3.4 The fenced case is a fifth, and it is not an error

A consent that completes but loses the race — another grant or a revoke landed
while the user was in the browser — returns `GuardedCommit::Fenced` and nothing
is written (`consent.rs:96-100`). The user-visible answer is "this consent is
stale, start again", not a failure. `consent.rs:29-30` names the intent: "a
fenced expectation is an ordinary refusal: the journey lost a race it was meant
to lose". The refusal text must not imply the account is broken.

---

## §4. Refresh — the surface exposes nothing

The single-flight refresh already exists, is already live, and is already
reached by dispatch rather than by any user action.

`CustodyHandle::refresh_if_expired` (`src/personal_accounts/worker.rs:210`)
carries **no** `expect(dead_code)`, unlike its neighbours (§9) — it is called in
production today through `VaultStrategy`. It drives the whole
`AccountService::refresh_if_expired` future on a blocking thread so "the store
work on BOTH sides of the provider call is off the event loop, the per-key
flight lock still serialises one account, and a slow provider stalls only its
own thread" (`worker.rs:202-209`). The per-account lock is
`AccountService::flight` (`service.rs:372`).

**The surface exposes no refresh action, and must not.** A caller-triggered
refresh would be a second entry into a single-flight the dispatch path already
drives correctly, and it buys the user nothing: the credential is refreshed when
it is used. The only refresh-adjacent thing the surface shows is
`action: "status"` reporting that an account is connected, revoked or needs
reconnecting — the states `AccountLookup` already distinguishes
(`service.rs:113-116`).

Two existing refusals stay exactly as they are: `ScopeBroadeningRefused`
(`service.rs:157`) and `ReconnectRequired` (`service.rs:155`), the latter
surfacing through `action: "status"` as a prompt to run `connect` again.

---

## §5. Self-revoke

A caller revokes their own grant. The prior doc's analysis holds and is
summarised here; the only change is the surface (§1.1).

`action: "revoke"` on `gateway_account`, input `descriptor_id` and nothing else.
Resolve the descriptor → build the key via `identity::account_key`
(`src/personal_accounts/identity.rs:76-96`) → call
`CustodyHandle::invalidate` (`src/personal_accounts/worker.rs:241`) → map the
error → return. No cache work, no lease bookkeeping, no store access of its own.

**The trait must not be widened.** `AccountCustody` is a two-method trait,
`refresh_if_expired` and `release` (`src/personal_accounts/vault.rs:46-56`), and
its own doc says it is "Type erasure only… Nothing here is a seam for a second
resolution path" (`:40-45`). `invalidate` is an inherent method on the concrete
handle. `VaultStrategy` holds `Arc<dyn AccountCustody>` (`vault.rs:82`), so the
strategy is a dead end for revoke; the concrete
`Option<Arc<GatewayCustody>>` lives on the `Gateway` struct
(`src/gateway/server/mod.rs:408`, downgraded for installation at `:1725-1732`)
and is what the meta-tool path must be given. An implementation that adds a
third trait method has not followed this design.

**Idempotency is already in the store, and the handler must not add a guard.**
`storage::commit::revoke` returns `Ok(())` with no IO both when nothing was ever
committed and when the entry is already `GrantState::Revoked`
(`src/personal_accounts/commit.rs:488-491`). A lookup-first check would
reintroduce the TOCTOU the single locked call removes, and would let the tool
disclose whether a grant exists for a descriptor the caller never connected.
Revoking a never-connected descriptor is a success, for the same reason.

**Revoke must also cancel pending consent, and the first draft missed this.**
`storage::commit::revoke` returns `Ok(())` **without writing** when the account
has no entry (`src/personal_accounts/commit.rs:488`) or is already tombstoned
(`:490`). So a consent captured as `ConsentExpectation::Absent`, followed by a
revoke that reports success, followed by the callback, finds the state still
`Absent`, the guarded commit does **not** fence, and a grant appears on an
account the user was just told was revoked. The same holds for a capture of
`Revoked`.

The fix is in the pending-consent store of §1.4, not in the durable store:
**revoke sweeps the pending-consent map for entries matching the account key and
drops them, before calling `invalidate`.** The map is in-process, short-lived and
small, so a linear scan is the whole implementation — no secondary index, no new
store primitive, no cancellation counter threaded through the guarded commit.

**The sweep alone is not enough, because it can only see entries still in the
map.** A callback that has already taken its entry and is blocked on the
provider's token endpoint is invisible to a linear scan: revoke sweeps nothing,
`invalidate` writes nothing (the account is `Absent` or already tombstoned), the
exchange returns, and the commit lands a grant on the account the user was just
told was revoked. The window is one provider round-trip wide — hundreds of
milliseconds, not microseconds — so it is reachable by an ordinary user who
clicks *revoke* while a consent tab is still finishing.

So the callback must stay visible for as long as it can still commit. **The
handler does not remove its entry on pickup; it transitions it in place to
`Exchanging` and removes it only after the guarded commit resolves.** Revoke's
sweep therefore finds in-flight journeys too, and marks them `Cancelled` rather
than dropping them. After the provider round-trip the handler re-reads its own
entry inside the same critical section as the guarded commit:

| Entry at commit time | Handler does |
|---|---|
| Still `Exchanging`, owned by this journey | Commit the grant, then remove the entry |
| `Cancelled` by a concurrent revoke | Discard the tokens, commit nothing, refuse the browser |
| Absent (TTL sweep won the race) | Same as `Cancelled` — refuse, indistinguishable per §3 |

A discarded exchange has already minted a live refresh token at the provider, so
the cancelled leg **must** present it to the pinned `revocation_endpoint` on the
way out, for the same reason revoke itself does (below). Dropping it silently
leaves exactly the live-credential-at-Google state this section exists to
prevent.

This keeps `ConsentExpectation` and the guarded-commit contract unchanged — the
fence is "my own pending entry is still mine and not cancelled", evaluated
beside the commit, not a new expectation variant threaded through it.

Why not the heavier fix: an account-level cancellation revision that pending
consent captures and the guarded commit checks would also work, and is what an
external reviewer proposed. It is rejected because it widens
`ConsentExpectation` and the guarded-commit contract — the one primitive §8.5
says must not be reshaped — to cover a race that a map scan closes at the edge.

`# ponytail: linear scan over the pending map; index by account key if the
map ever grows past a few hundred entries.`

**Ceiling, stated rather than hidden:** the pending map is per-process (§1.4).
In a multi-instance deployment a revoke on instance A does not cancel a pending
consent held by instance B. That is already true of the whole consent flow —
§1.4 binds a journey to one process — and it is why §1.4 is listed as a
constraint rather than an implementation detail. A deployment that load-balances
across instances needs shared pending state, which is out of scope here and
belongs with the same decision as session affinity.

**Revoke should also tell the provider, and an earlier draft only tombstoned
locally.** A managed descriptor may carry a pinned `revocation_endpoint`
(`src/personal_accounts/config.rs:270`, validated https when present at
`config.rs:741-742`). A tombstone that does not reach it leaves a live refresh
token at Google while the gateway reports the account revoked — true inside the
store, false in the world, and the user asked about the world.

The order is the load-bearing part: **tombstone first, then call the endpoint,
and never gate the tombstone on the call.** A provider that is slow or down must
not be able to keep a grant alive inside the gateway. A failed revocation call
is logged and reported in the result as "revoked here; the provider did not
confirm", which is the honest sentence and also the actionable one.

`# ponytail: best-effort, fire-after-commit. No retry queue until a provider
actually proves it needs one.`

**Non-unix builds refuse explicitly.** The non-unix `revoke` is a stub returning
`AccountError::InvalidConfiguration` (`commit.rs:613-619`) — a refusal, never a
silent success.

**Revoke leaves the account re-connectable.** It writes no terminal state and
does not blocklist the key; `fence_tests.rs:139-140` records that re-consent
minting a new generation over the tombstone is legitimate. With §1 in place this
is now testable end to end, which the prior doc could not claim.

---

## §6. Administrative revoke

This is the half the earlier ruling deferred. It is the only place in the design
where a caller-supplied principal is an input, and it is therefore the only
place where the §7 rule needs an explicit exception rather than an impossibility.

### 6.1 The tool and its gate

**Registration is the load-bearing step, and the first draft of this section
omitted it.** `CallerStanding::permits` is
`matches!(self, Self::Admin) || !is_admin_meta_tool(tool_name)`
(`src/gateway/router/authorization.rs:127-129`), and `is_admin_meta_tool` is a
`contains` over an explicit four-name allowlist (`:73-78`,
`gateway_kill_server`, `gateway_revive_server`, `gateway_reload_config`,
`gateway_reload_capabilities`). A name that is **not** in that list is permitted
to *everyone*. So `gateway_account_admin` must be added to `ADMIN_META_TOOLS`
at `authorization.rs:73-78`, and the design is not "no new gate is written" but
"no new gate **mechanism** is written — one new registry entry is." Omitting it
ships a tool that revokes other users' grants and is callable by any
authenticated caller. §10.4's `the_admin_tool_is_not_permitted_to_a_non_admin_caller`
must therefore exercise both `tools/list` and `tools/call`, since the two read
the same predicate (`authorization.rs:86-88`).

`gateway_account_admin`, gated by the existing per-name standing check:
`CallerStanding::of_admin_flag(caller.is_admin).permits(tool_name)`
(`src/gateway/meta_mcp/mod.rs:1999`), with `is_admin` at `:167`. No new gate is
written. A non-admin does not get "denied" — the name is not permitted to them
at all, which is the mechanism the repo already uses.

Actions:

| Action | Input | Effect |
|---|---|---|
| `revoke_principal` | `descriptor_id`, `principal_authority`, `principal_subject` | Revoke one named principal's grant on one backend |
| `revoke_backend` | `descriptor_id` | Revoke every principal's grant on that backend |

### 6.2 Why the principal is two fields, not one

The admin names `principal_authority` and `principal_subject` separately,
exactly the two fields `identity::account_key` takes from `VerifiedIdentity`
(`src/personal_accounts/identity.rs:84-89`). It must **not** accept an email, a
display name or a group.

The reason is recorded in-tree: `identity.rs:20-25` states that a mutable label
inside the isolation boundary would let one user's rename silently re-point
custody, which is why `email`, `name` and `groups` are excluded from the key by
construction. An admin tool that accepted an email would reintroduce exactly
that, one indirection further out. **Decision for review:** whether the admin
tool may accept `stable_actor_id` (`src/key_server/oidc.rs:132-140`) as an
alternative spelling of the same pair. Recommended yes, since it is the same
length-prefixed derivation and is what audit records already show — but it is a
second input shape and should be a deliberate choice.

The account key for the named principal is assembled by the **same** function as
every other path, with the two principal fields supplied rather than read from
the caller's own identity. That is the whole exception, and it is one function
argument wide.

### 6.3 Bulk revoke across a backend

`revoke_backend` needs to enumerate every account key under one
`descriptor_id`. **This is the one capability the store may not have.** The
lookup API is keyed by a complete `AccountKey` (`service.rs:362`,
`consent.rs:94`), and no enumeration-by-descriptor call was found. Marked as an
assumption rather than asserted: an implementer should confirm before the stage
that either the authority is enumerable or a listing primitive must be added.

If a primitive is needed, it belongs in the store beside
`lookup`/`revoke`/`commit_grant`, taking the authority lock once, and **must
not** be built by iterating a directory from the handler. §11 puts this at the
start of the admin stage so the answer is known before the tool is designed
against it.

If enumeration is unavailable and adding it is judged out of scope, the
defensible fallback is `revoke_principal` only, and `revoke_backend` moves to
its own ticket. That is a smaller surface and a reviewer may prefer it.

### 6.4 The audit record

Administrative revoke is the case where an audit record is not optional: one
person is acting on another person's credential. Each administrative revoke
records **actor** (the admin's own verified issuer+subject, never a
caller-supplied value), **subject** (the principal acted on), **backend**
(`descriptor_id`), **action**, **outcome** and **time**.

Reuse, do not invent: the control-plane audit path already exists and already
writes admin mutations with an actor — `commit_grant_audited`
(`src/control_plane/store.rs:292`) and the authorized-persisted-audited
behaviour asserted at `src/gateway/ui/control_plane.rs:1159-1161`. **Decision
for review:** whether the account audit record goes through that log or beside
the existing `AccountReleaseAudit` observer already baked into `GatewayCustody`
(`src/personal_accounts/mod.rs:646`). The control-plane log is recommended — it
is where an operator already looks for "who changed what" — but the two
subsystems are deliberately separate (§0.1) and merging them is a decision, not
a detail.

**Self-revoke writes no such record and must not.** Its actor and subject are
the same person by construction, so there is nothing an audit record would
disambiguate, and building a half-admin path into the self-service tool is the
review finding §5 exists to prevent. The existing `audit_refusal` on the
dispatch path (`src/identity_propagation/account_strategies.rs:636`) is
untouched either way.

### 6.5 BLOCKER — no caller can currently satisfy the admin contract

Found by external review and **confirmed at source**. §6 as designed requires a
caller who has *both* administrative standing *and* a verified identity. No such
caller exists today.

| Path | Admin standing | `VerifiedIdentity` |
|---|---|---|
| Key-server temporary token (`src/gateway/auth.rs:1040-1041`) | `admin: false`, hardcoded (`src/key_server/mod.rs:113`) | yes |
| Delegated OIDC bearer (`auth.rs:1046`) | `admin: false`, hardcoded (`src/key_server/mod.rs:172`) | yes |
| `admin.bearer_token` | yes | **none** |

`src/key_server/mod.rs:16` states the split plainly: "Admin endpoints are guarded
by a separate `admin.bearer_token`." Administrative standing reaches the
meta-tool surface as `AuthenticatedClient::admin`
(`src/gateway/router/handlers.rs:489-492`, and at `:1568`, `:1600`, `:1909`),
and the two paths that produce a `VerifiedIdentity` both set that field to
`false` unconditionally.

The consequence is not a refused call, it is worse in two directions:

1. An OIDC-verified operator **cannot** reach `gateway_account_admin` at all,
   whatever their role claims say.
2. An `admin.bearer_token` caller **can** reach it, but carries no verified
   issuer+subject — so §6.4's audit record has no actor to name, and the design's
   central promise ("actor is the admin's own verified identity, never a
   caller-supplied value") cannot be kept.

**This design does not resolve it, and stage 3 must not start until it is
resolved.** The resolution is an operator decision with real options:

| Option | Shape | Cost |
|---|---|---|
| Map OIDC principals to admin standing | A configured allowlist or role claim sets `AuthenticatedClient::admin` on the key-server paths | Touches `src/key_server/mod.rs:113`/`:172` and the auth config — a change to the inbound identity system, outside this surface |
| Reuse control-plane role mapping | `ControlPlaneRole` already resolves from a `VerifiedIdentity` (`src/control_plane/role_mapping.rs:153`) | Closest to existing machinery; needs a decision on whether a control-plane role grants meta-tool admin standing |
| Admin revoke moves to the control plane | Not a meta-tool at all; an authenticated control-plane mutation beside `commit_grant_audited` (`src/control_plane/store.rs:292`) | Loses meta-tool parity; gains an actor and an audit log that already exist |

**Recommendation: the third.** The control plane already has the actor, the
audit path and the admin-mutation test (`src/gateway/ui/control_plane.rs:1159-1161`);
the meta-tool surface has none of them and is also the surface CLAUDE.md says to
keep compact. A reviewer who prefers the meta-tool shape should pick option one
or two explicitly and fund the inbound change — but §6 must not be built on the
assumption that today's `is_admin` can coexist with today's `VerifiedIdentity`.

**If option one or two is chosen**, a second reviewer's point applies and is
accepted: admin revoke gets its **own constructor taking issuer and subject as
strings**, rather than stretching `account_key(Option<&VerifiedIdentity>, …)`
(`src/personal_accounts/identity.rs:76`) or forging an identity to satisfy it.
`VerifiedIdentity::email` is a mandatory `String` (`src/key_server/oidc.rs:111`),
so a forged one needs a fabricated email address — a fake principal built to get
past a type, which is exactly the shape §7 exists to forbid. Under option three
the point is moot: the control plane names its own actor.

This does not affect §5. Self-revoke needs a verified identity and **no** admin
standing, which both OIDC paths already provide.

### 6.6 What the admin still cannot do

* **Connect on another user's behalf.** Consent is the user's act; there is no
  `connect_principal`. An admin who needs a user connected asks the user.
* **Read another user's token.** Nothing in this surface returns credential
  material to anyone, admin included.
* **See another user's grant through the self-service tool.**
  `action: "status"` reports only the caller's own accounts.

---

## §7. The authorization model

This is the section to review hardest. A mis-identified caller here lets one
user hijack or destroy another's grant.

### 7.1 The rule

> A caller's `AccountKey` is **constructed** from the verified identity the
> transport attached, never compared against one the caller supplied. Two of the
> key's five fields come from `VerifiedIdentity`; the other three come from the
> configured descriptor. No field of a self-service request contributes a
> principal. A request with no verified identity is refused, never defaulted.
> Exactly one path takes a principal as input — the admin tool of §6 — and it is
> reached only through the existing per-name standing gate.

### 7.2 The existing identity mechanism, named

`VerifiedIdentity` is the struct at `src/key_server/oidc.rs:106-119` — `subject`,
`email`, `name`, `groups`, `issuer` — produced only by ID-token validation
(`oidc.rs:361` returns `Result<VerifiedIdentity, OidcError>`) and attached by the
auth layer as an axum extension, read at the transport edge with
`http_request.extensions().get::<VerifiedIdentity>().cloned()`
(`src/gateway/router/handlers.rs:588`; the openwebui adapter reads the same
extension at `src/gateway/openwebui_adapter.rs:302`).

**Which inbound mechanism this is, and which it is not, is §14.1.** `VerifiedIdentity`
is one of four identity shapes read side by side at `handlers.rs:583-588`, and the
only one naming a human by issuer+subject. It arrives through
`src/gateway/auth.rs:1040-1048` — a key-server temporary token, or a delegated OIDC
bearer gated on `delegated_bearer`, which defaults to `false`
(`src/config/features/key_server.rs:125`). Agent identity, mTLS identity and the
`X-Agent-ID` header are **not** account principals.

It reaches the meta-MCP layer uncollapsed as
`MetaMcpCallerContext::verified_identity`
(`src/gateway/meta_mcp/mod.rs:163`, propagated at `:249`), which is exactly why
the account surface belongs there (§1.1).

The key is built by one function, and every path in this design calls that one:

```rust
// src/personal_accounts/identity.rs:76-96
pub(crate) fn account_key(
    identity: Option<&VerifiedIdentity>,
    descriptor: &AccountDescriptor,
) -> Result<AccountKey, IdentityBindingError> {
    let identity = identity.ok_or(IdentityBindingError::MissingVerifiedPrincipal)?;
    let key = AccountKey {
        principal_authority: identity.issuer.clone(),
        principal_subject:   identity.subject.clone(),
        backend_id:          descriptor.descriptor_id.clone(),
        resource:            descriptor.resource.clone(),
        oauth_issuer:        descriptor.issuer.clone(),
    };
    key.digest()?;
    Ok(key)
}
```

* `principal_authority` ← `VerifiedIdentity::issuer`, `principal_subject` ←
  `VerifiedIdentity::subject` (`identity.rs:84-89`). Neither is caller-influenced.
* `backend_id`, `resource`, `oauth_issuer` ← the configured descriptor
  (`identity.rs:38-46`), immutable within a configuration revision.
* `email`, `name`, `groups` are excluded **by construction**: `identity.rs:20-25`
  records that a mutable label inside the isolation boundary would let a rename
  silently re-point custody, and the function does not mention those fields, so
  admitting one would appear in a diff.
* No verified principal → `MissingVerifiedPrincipal` (`identity.rs:58-59`). No
  anonymous, operator-token or API-key fallback exists for personal mode.

Today the only production caller is `VaultStrategy::prepare`
(`src/personal_accounts/vault.rs:133`). Connect, callback, status, self-revoke
and admin revoke all become callers of the same function. None re-derives a key
and none constructs `AccountKey` literally — the length-prefixed digest
(`src/personal_accounts/mod.rs:57-80`) is computed in one place.

### 7.3 Why there is no comparison step

The obvious design — accept a principal id, compare it to the caller, act on
match — is deliberately not used. A comparison can be got wrong: a normalisation
mismatch, a case fold, an early return on a parse error, and one user acts on
another. Constructing the key instead makes that bug **inexpressible**, because
the self-service request has no field in which another principal could be named.

`gateway_account` therefore takes `descriptor_id` and an `action` enum. That is
the whole input. A reviewer seeing a principal-shaped field added to it should
reject the change.

### 7.4 The callback is the hard case, and how it is closed

The callback has no verified identity to construct from (§0.5). The principal is
therefore **bound at initiation and transported in server-side state**, and the
callback authenticates by possession of an unguessable, single-use, TTL-bounded
handle that the gateway itself minted for one verified caller (§1.4, §2.1).

Three properties make this equivalent in strength, and a reviewer should check
each:

1. **The handle is never a principal.** It is a lookup key into memory. Finding
   it yields a principal that a verified identity supplied earlier; failing to
   find it yields nothing at all, and there is no path from a request to a
   principal that does not go through a successful lookup.
2. **The handle is single-use.** A leaked handle is useful once, within the TTL,
   and only to complete the consent the legitimate user started — the attacker
   would be donating their own provider authorization to the victim's account
   key, not taking anything.
3. **The handle is 32 bytes of randomness**, not the 16 of `generate_state()`
   (`src/oauth/client/mod.rs:1176`), precisely because here it is load-bearing
   rather than a CSRF nonce (§1.3 step 5).

**Mitigation, added after review.** An external reviewer rated the
forward-the-URL case CRITICAL rather than inherent, and the distinction is fair:
disclosing a hazard is not the same as bounding it. Three cheap bounds, none of
which requires a new mechanism:

1. **The authorize URL is never displayed to anyone but its initiator.** It is
   returned to the MCP caller that requested it (§1.3) and is not logged, not
   echoed in an audit record, and not retrievable by `action: "status"`.
2. **The TTL is short** (§1.4). A forwarded URL is useful for minutes, not days.
3. **`action: "status"` names what is connected**, so a user whose descriptor
   shows a grant they did not create can see it and revoke it (§5). Detection
   is the realistic defence here; prevention is not fully available.

**Decision for review (#9):** whether the callback additionally requires a
gateway session cookie (`SESSION_COOKIE`, `src/gateway/auth.rs:688`) belonging
to the initiating principal. That would close the case properly — the browser
would have to be the initiator's — at the cost of refusing every user who
consents from a browser with no gateway session, which includes every pure-MCP
client. Recommended **no** for 4.0.0, with the bounds above, and revisit if the
web UI becomes the primary consent entry point.

**What is deliberately not claimed:** this binds the *gateway principal* who
initiated consent to the grant. It does not prove the human who authorized at
the provider is the same human — a user who pastes their authorization URL to
someone else gets that person's provider account attached to their own gateway
principal. That is inherent to redirect-based OAuth, is true of the existing
loopback client too, and is noted so a reviewer is not left to discover it.

### 7.5 Admin standing, and what it does not grant

`is_admin` (`src/gateway/meta_mcp/mod.rs:167`) is **not consulted** anywhere in
`gateway_account`. An admin revoking their own grant goes through the identical
path as anyone else, and an admin cannot reach another principal's grant through
the self-service tool, because no field there names one.

Admin standing gates exactly one thing: whether `gateway_account_admin` is
permitted at all (`mod.rs:1999`). The blast radius of an `is_admin`
misdetermination is therefore bounded to that one tool name, which is the
property the two-tool split in §1.2 was chosen for.

### 7.6 The refusal vocabulary

| Condition | Outcome |
|---|---|
| No verified identity | `MissingVerifiedPrincipal` (`identity.rs:58-59`) — refuse |
| `descriptor_id` not configured | `UnknownDescriptor` (`identity.rs:60-66`) — refuse |
| Empty or oversized key field | `AccountError::InvalidAccountKey` via `digest()` (`mod.rs:59`, refused at `:77`) |
| Custody not configured | the `Option<Arc<GatewayCustody>>` is `None` — refuse, never a silent success |
| Non-unix build | `AccountError::InvalidConfiguration` (`commit.rs:613-619`) |
| Consent handle absent, expired or already used | refuse; indistinguishable across all three (§3) |
| Expectation no longer holds | `StaleConsentFenced` (`service.rs:168`) — an ordinary refusal (§3.4) |
| Non-admin reaching the admin tool | the name is not permitted (`mod.rs:1999`) |

No refusal carries token material; the account errors are secret-free by
construction (`src/personal_accounts/mod.rs:83-100`).

### 7.7 MIK-6746.CONTRACT.1 falls out here

CONTRACT.1 asks for wrong audience, issuer/backend swap, absent identity, mixed
credential strategies, direct/meta parity and expiry, and states that "a custom
header alone cannot pass the standard-interoperability cell."

The mechanism that answers it is `revalidate`
(`src/identity_propagation/account_strategies.rs:561`), which refuses on a
different verified caller (`:600`), an expired published lifetime (`:601-603`),
replaced custody (`:608-623`) and a durable custody refusal (`:624-630`) — and
"None of them falls back to the gateway-held credential, and none of them
degrades into a cache miss" (`:557-559`). This design adds no new credential
path around it: every credential this surface creates is consumed through the
same dispatch and the same recheck. That is the claim §10.4 tests.

The custom-header point is satisfied by §7.2: the identity is an OIDC ID token
validated at `src/key_server/oidc.rs:361`, not a header the caller asserts (`src/key_server/oidc.rs:361`).

---

## §8. What must NOT be reimplemented

The machinery below is built, unit-tested and correct. This section exists so a
reviewer can reject an implementation that rebuilds one of them.

### 8.1 Cache-entry invalidation happens by generation, not by eviction

The vault publishes the five-field account digest **widened with** the grant
generation, authorization epoch, token revision and descriptor revision, so a
re-authorized, rotated or revoked account "produces a DIFFERENT binding rather
than a silently reused one"
(`src/identity_propagation/account_strategies.rs:106-110`). The binding is
copied into every cache key and "never re-hashed and never parsed" (`:124-127`).

**Therefore:** no path in this design walks a cache, evicts a key, or bumps a
version. Connect, revoke and admin revoke all just write the store; the cache
follows because its keys changed.

### 8.2 `revalidate` refuses on epoch, audience, actor and custody change

`revalidate` (`account_strategies.rs:561`) runs before any cache entry may be
selected and before any egress. It refuses for a different verified caller
(`:600`), an exhausted published lifetime (`:601-603`), custody replaced after
the mint (`:608-623`), and — last and most important — a durable custody refusal,
"the only one that can see a revocation committed since the mint" (`:606-630`).
None of these degrades into a cache miss or falls back to the gateway-held
credential (`:557-559`).

**Therefore:** revoke does not notify the resolver, the registry or the executor.
It commits a tombstone and returns.

### 8.3 Fencing behaviour is already asserted

* `s08_a_stale_snapshot_cannot_land_after_a_durable_revoke`
  (`src/personal_accounts/fence_tests.rs:105`): a refresh that snapshotted before
  a durable revoke is `RefreshOutcome::Rejected`; the tombstone discloses the
  version it retired; a store reopen "resurrects neither the old token nor the
  rejected one".
* `s09_a_late_refresh_cannot_overwrite_a_newer_generation`
  (`fence_tests.rs:131`): re-consent mints a new generation over the tombstone,
  and a refresh snapshotted against the retired generation does not apply.

**Therefore:** revoke does not wait for, cancel, or coordinate with an in-flight
refresh. Any design that polls for quiescence, holds a lock across a provider
call, or retries the revoke is wrong. `CustodyHandle::invalidate`
(`worker.rs:241`) offloads onto the custody worker, the same serialization every
other custody operation uses.

### 8.4 Release-time recheck is unconditional

`AccountService::release` re-reads current state and compares the whole lease —
"a superseded generation, authorization or descriptor is just as retired"
(`service.rs:300-307`) — returning `LeaseRetired` (`service.rs:159`).

**Therefore:** no path here tries to cancel outstanding leases.

### 8.5 One authority-lock acquisition, proved at the lock

`commit_grant_if_unchanged` does the comparison and the publication under one
acquisition (`consent.rs:16-19`, `:91-103`), and `witness` (`consent.rs:133`)
logs attempt, acquire and release at the single acquisition point so a
double-acquiring caller is visible "whatever the implementation claims about
itself" (`consent.rs:21-24`).

**Therefore:** the callback never does lookup-then-commit (§2.3).

### 8.6 Transport, metadata and secrets

Metadata discovery is eager and complete at startup (`provider.rs:12-18`,
`:260`), endpoints are validated against the descriptor (`provider.rs:461`,
`:474`), the HTTP client already has certificate validation, redirect refusal,
DNS pinning and SSRF checks (`provider.rs:30-32`), and client secrets are
resolved late through `EnvSecrets` (`provider.rs:20-23`, `:157-162`).

**Therefore:** connect and callback discover nothing, build no second HTTP
client, and materialise no secret earlier than the exchange.

### 8.7 What may legitimately be reused from `src/oauth/`

For completeness, since §0.3 rejected the module as a whole: `generate_pkce`
(`src/oauth/client/mod.rs:1160`) and the token-exchange parameter shape
(`:740-747`). Not `authorize()`, not `callback.rs`, not `TokenStorage`, not
`storage_key`.

---

## §9. Every `expect(dead_code)` to remove

Twenty-five production sites, eight files, three cfg gates plus ungated sites.
The brief named four.

### 9.1 The inventory

| # | Symbol | Annotation | Item | Gate |
|---|---|---|---|---|
| 1 | `PersonalAccountStore::commit_grant` | `mod.rs:486-492` | `mod.rs:493` | `not(test)` |
| 2 | `PersonalAccountStore::revoke` | `mod.rs:518-524` | `mod.rs:525` | `all(not(test), not(kani))` |
| 3 | `PersonalAccountStore::mark_reconnect_required` | `mod.rs:547-553` | `mod.rs:554` | `not(test)` |
| 4 | `commit::revoke` (unix) | `commit.rs:472-478` | `commit.rs:479` | `all(not(test), not(kani))` |
| 5 | `commit::mark_reconnect_required` (unix) | `commit.rs:503-509` | `commit.rs:510` | `all(not(test), not(kani))` |
| 6 | `PersonalAccountStore::commit_grant_if_unchanged` | `consent.rs:71-74` | `consent.rs:75` | `all(not(test), not(kani))` |
| 7 | `GuardedCommitError::RuntimeNotImplemented` | `consent.rs:45-51` | `consent.rs:52` | `all(not(test), unix)` |
| 8 | `AccountServiceError::RuntimeNotImplemented` | `service.rs:142-148` | `service.rs:149` | `all(not(test), not(kani))` |
| 9 | `AccountServiceError::StaleConsentFenced` | `service.rs:161-167` | `service.rs:168` | `all(not(test), not(kani))` |
| 10 | `AccountService::store` | `service.rs:236-239` | `service.rs:240` | `all(not(test), not(kani))` |
| 11 | `AccountService::resolve` | `service.rs:248-251` | `service.rs:252` | `all(not(test), not(kani))` |
| 12 | `AccountService::invalidate` | `service.rs:322-325` | `service.rs:326` | `all(not(test), not(kani))` |
| 13 | `AccountService::commit_grant_if` | `service.rs:338-341` | `service.rs:342` | `all(not(test), not(kani))` |
| 14 | `CustodyHandle::capacity` | `worker.rs:133-136` | `worker.rs:137` | `not(test)` |
| 15 | `CustodyHandle::resolve` | `worker.rs:190-193` | `worker.rs:194` | `not(test)` |
| 16 | `CustodyHandle::invalidate` | `worker.rs:237-240` | `worker.rs:241` | `not(test)` |
| 17 | `CustodyHandle::commit_grant_if` | `worker.rs:250-253` | `worker.rs:254` | `not(test)` |
| 18 | `IdentityBindingError::UnknownDescriptor` | `identity.rs:62-65` | `identity.rs:66` | bare `expect` |
| 19 | `AccountsConfigError::UnknownField` | `config.rs:357-360` | `config.rs:361` | bare `expect` |

| 20 | `AccountsConfigError::RuntimeNotImplemented` | `config.rs:328-331` | `config.rs:332` | bare `expect` |
| 21 | `CustodyError::RuntimeNotImplemented` | `worker.rs:55-58` | `worker.rs:59` | bare `expect` |
| 22 | `CustodyStartError::RuntimeNotImplemented` | `worker.rs:75-78` | `worker.rs:79` | bare `expect` |
| 23 | `IdentityBindingError::RuntimeNotImplemented` | `identity.rs:52-55` | `identity.rs:56` | bare `expect` |
| 24 | `BoundAccountBackend::backend` | `src/config/account_bindings.rs:46-51` | `:52` | bare `expect` |
| 25 | `BoundAccountBackend::account` | `src/config/account_bindings.rs:61-66` | `:67` | bare `expect` |

Twenty-five rows, eight files. Enumerated by sweeping `dead_code` across `src/`
rather than by reading files one at a time, so the count is the sweep's, not a
tally kept by hand.

**Two things are deliberately not rows.** The module-level
`#![cfg_attr(not(unix), expect(dead_code, ...))]` at
`src/personal_accounts/mod.rs:16-22` is an umbrella over the whole module on
non-unix targets, not a per-item annotation; §9.3 explains why it still
constrains the removal set. And `src/fs_lock.rs:31` carries the attribute for an
unrelated reason.


### 9.2 Which come off, and which do not

**Come off as a direct consequence of this work:** 1, 2, 4, 6, 9, 10 (if the
handler uses it), 11 (if status uses it), 12, 13, 16, 17, 18.

**Stay, and must not be bulk-removed:**

* **3 and 5** — `mark_reconnect_required`. Nothing in this surface calls it. It
  is the path that marks an account needing re-consent after a non-recoverable
  provider refusal, and wiring it is its own decision.
* **7, 8, 19, 20, 21, 22, 23** — every `RuntimeNotImplemented`-shaped variant
  and the config field variant. `consent.rs:6-7` is explicit: "`RuntimeNotImplemented`
  is never a domain answer. It survives for the one target where the durable
  writers do not exist at all." These stay annotated on unix precisely because
  they must remain unreachable.
* **24, 25** — `BoundAccountBackend::backend` and `::account`. Their own reason
  strings say they are compile-time provenance that no consumer reads, to be
  deleted together if still unused — a different question from this surface, and
  not one this design answers.
* **14, 15** — `capacity` and `resolve` on the handle. Check at implementation
  whether the status action reaches `resolve`; `capacity` almost certainly stays.

An implementer who greps for the shared reason string and deletes every match
will light up the reconnect-required scaffolding, the not-implemented variants
and two unrelated provenance fields, none of which gains a caller. §10.5 pins this.

### 9.3 The three gates, and the non-unix trap

The gates are not uniform and the asymmetry is informative rather than
accidental:

* `not(test)` — the expectation applies under kani.
* `all(not(test), not(kani))` — it does not; those frames are already exercised
  by a kani harness today.
* `all(not(test), unix)` — row 7 only, and it is the trap.

`consent.rs:42-44` explains row 7: `unix` is in the predicate "not just
`not(test)`: on a non-unix target the module-level expectation in `super` already
covers every dead item here, and two expectations over one diagnostic leave the
inner one unfulfilled." That module-level expectation is
`src/personal_accounts/mod.rs:16-22` — a crate-module-level
`#![cfg_attr(not(unix), expect(dead_code, ...))]` whose own comment says the
unfulfilled expectation "is what tells the porter to delete this line"
(`mod.rs:14-15`).

**Consequence for the implementation stage:** the removal set is
cfg-dependent. A uniform removal produces a red non-unix build that nobody
predicted, and possibly a red `mod.rs:16` once enough inner items become live.
Each site is read individually.

### 9.4 Why removing them breaks nothing else

The attribute is `expect`, not `allow`. An `expect` whose lint does not fire is
itself an `unfulfilled_lint_expectations` warning, and the repo gates on
`clippy --all-targets -- -D warnings` (CLAUDE.md, Quality Gates). Annotation and
production caller are therefore mutually forcing: remove the annotation without
a caller and `dead_code` fires; add the caller without removing the annotation
and the expectation is unfulfilled. There is no green state in which one is
wrong. Two riders: the gates differ (§9.3), and every current call site outside
the module is a test file, where each gate already excludes `test`.

---

## §10. Test plan — names only

No test bodies here; this is DESIGN ONLY. Each name is mapped to the criterion
it moves and to the section that specifies its behaviour. Existing files are
named where a test belongs beside its neighbours.

### 10.1 MIK-6744.STORE.1 — keyed store, migration

Criterion (`docs/requirements/RELEASE-4.0.0-scope-update.md:42`): "keyed by
principal/backend/resource for load, save and refresh, protected at rest, with
**readable/migrated single-user data** and no silent loss."

In `src/personal_accounts/store_tests.rs`:

* `a_first_grant_lands_under_the_five_field_key_and_no_other`
* `two_principals_on_one_descriptor_do_not_share_a_stored_entry`
* `a_committed_grant_survives_a_store_reopen_with_identical_bytes`
* `a_connect_commit_writes_no_secret_into_any_diagnostic_rendering`

The migration conjunct is **not** settled by this design — see §10.6.

### 10.2 MIK-6744.STORE.2 — revoke and restart

Criterion (`:43`): revocation and restart "cannot leave an old refresh job or
cached credential usable under a new grant."

In `src/personal_accounts/fence_tests.rs` (beside `s08`/`s09`, which already
assert the store half):

* `s10_a_production_revoke_path_reaches_the_store` — the row's actual blocker:
  a caller outside `src/personal_accounts/` commits a revocation (§5).
* `s11_a_revoke_of_a_never_connected_descriptor_is_a_success` (§5)
* `s12_a_revoke_is_idempotent_across_a_restart`

In `src/gateway/meta_mcp/account_rest_tests.rs` (beside
`a_reconnected_grant_refuses_the_credential_prepared_under_the_old_one`, which
closed C4 at `:1295`):

* `a_self_revoke_through_the_meta_tool_refuses_the_next_dispatch`
* `a_reconnect_after_a_self_revoke_yields_a_usable_new_grant`

### 10.3 MIK-6745.JOURNEY.1 — the browser journey

Criterion (`:44`, discriminator at
`docs/requirements/RELEASE-4.0.0-scope-tests.md:43`): connect/use, browser
cancellation, expired/replayed consent state, refresh and revoke, with the
route recorded.

Deterministic-provider tests, in a new `tests/accounts_journey.rs` beside the
existing `tests/oauth_cancellation.rs`:

* `a_connect_action_returns_an_authorize_url_and_no_credential` (§1.3)
* `a_callback_with_the_minted_handle_commits_one_grant` (§2)
* `a_callback_handle_works_exactly_once` (§3, replay)
* `a_callback_after_the_ttl_is_refused_without_presenting_the_code` (§3)
* `a_replayed_and_an_expired_handle_are_indistinguishable` (§3 — the
  existence-oracle rule, `src/gateway/ui/control_plane.rs:311`)
* `a_provider_denial_writes_nothing_to_the_store` (§3)
* `a_cancelled_reconsent_leaves_an_existing_grant_connected` (§3)
* `a_consent_that_loses_the_race_is_refused_as_stale_not_as_broken` (§3.4)
* `a_revoke_during_the_token_exchange_commits_no_grant` (§3.4 — the handler is
  parked inside a deterministic provider's token endpoint while revoke runs;
  asserts the account stays revoked and the commit never fires)
* `a_cancelled_exchange_presents_its_minted_token_for_revocation` (§3.4 —
  asserts the discarded leg reaches `revocation_endpoint`, so the race fix does
  not trade a local grant for a live credential at the provider)
* `a_revoke_after_the_commit_resolves_removes_the_grant` (§3.4 — the other side
  of the interleaving, proving the fence is a fence and not a lock-out)
* `a_first_grant_record_passes_the_store_validator` (§2.4 — builds the first-
  grant record from the table and runs it through `validate_record`; this is the
  test whose absence let the table specify `0` counters that could never commit)
* `a_callback_route_rejects_a_principal_supplied_in_the_query_string` (§2.1)
* `the_callback_route_is_public_and_no_other_route_became_public` (§2.1 —
  guards the third `public_paths` entry; pairs with the existing bucket test at
  `src/gateway/auth.rs:1163-1173`)
* `a_cross_site_navigation_to_the_callback_is_admitted` (§2.6 — the origin-guard
  exemption; the request carries `Sec-Fetch-Site: cross-site`, as a provider
  redirect does)
* `a_cross_site_request_to_mcp_is_still_refused` (§2.6 — the exemption did not
  widen; pairs with the test above and fails if the path match became a prefix)
* `a_managed_descriptor_whose_redirect_uri_is_not_the_served_path_is_refused`
  (§2.7 — configuration validation, not a runtime surprise)
* `the_exchange_omits_resource_when_send_resource_parameter_is_false` (§2.8)
* `a_callback_whose_iss_is_not_the_pinned_issuer_does_not_redeem_the_code`
  (§2.8 — RFC 9207 mix-up)
* `a_provider_error_description_is_not_rendered_into_the_page` (§2.5)

Refresh needs no new name: it is already driven by dispatch (§4).

### 10.4 MIK-6746.CONTRACT.1 — no new credential path

Criterion (`:47`): audience rules, route parity, "a custom header alone cannot
pass the standard-interoperability cell."

In `src/gateway/meta_mcp/account_rest_tests.rs`:

* `a_grant_minted_by_connect_is_consumed_through_revalidate_like_any_other`
  (§7.7 — the claim that this surface adds no path around
  `src/identity_propagation/account_strategies.rs:561`)
* `a_connect_request_without_a_verified_identity_is_refused` (§7.2)
* `a_connect_request_carrying_only_a_custom_header_is_refused` (§7.2)
* `the_admin_tool_is_not_permitted_to_a_non_admin_caller` (§6.1)
* `an_admin_revoking_another_principal_writes_an_audit_row_naming_actor_and_subject`
  (§6.4)
* `an_admin_cannot_reach_another_principal_through_the_self_service_tool` (§7.5)

### 10.5 Guarding the annotation removal

One test does not map to a release criterion and exists only to stop §9.2 being
bulk-applied. In `src/personal_accounts/tests.rs`:

* `mark_reconnect_required_is_still_annotated_and_still_uncalled` — asserts by
  construction (a compile-time reference, not a string sweep) that rows 3 and 5
  of §9.1 keep their annotation.

**Revised after review: the checklist is now the primary, and the test is the
option.** An external reviewer's point stands — this asserts on compiler
scaffolding rather than on account behaviour, and a test whose subject is an
attribute will be deleted by the first person who reads it as noise. So §11
carries the removal subset per stage, and an implementer checks it there. Keep
the test only if a reviewer wants the guard to fail loudly rather than be
read carefully.

What must not happen either way: a sweep for the shared reason string that
removes all twenty-five.

### 10.6 STORE.1 migration — FLAGGED, not settled by this design

**This design does not settle the migration conjunct, and a reviewer should not
read it as doing so.**

What this design changes: STORE.1's *production-caller* gap closes, because
connect and revoke give the keyed store real callers outside the module
(§9.2 rows 1, 2, 4, 6, 12, 13).

What it does not change: 3.x single-user credentials are still not migrated.
`src/commands/upgrade.rs:243-247` states the 4.0.0 position plainly — 3.x tokens
are not migrated, the files are left at `~/.mcp-gateway/oauth/` mode 0600, and
the refresh tokens in them remain usable. `src/personal_accounts/mod.rs:770-790`
records the same: nothing is migrated.

Why this design cannot settle it: the 3.x storage key is
`storage_key(backend_name, issuer)` (`src/oauth/client/mod.rs:114`) and **has no
principal field**. The 4.0.0 key has five fields, two of which are the verified
principal (`src/personal_accounts/identity.rs:84-89`). A 3.x credential
therefore does not identify whose it is. Migrating it means *choosing* a
principal to attribute it to, and every candidate rule is an operator decision
with a different risk:

| Candidate rule | Risk |
|---|---|
| Attribute to the first principal who connects that backend | Hands one user another's credential if the deployment was ever shared |
| Attribute to a configured "legacy owner" principal | Correct, but needs new configuration and an operator who knows the answer |
| Migrate nothing; require re-consent | Safe, and is what 4.0.0 ships today |
| Migrate only when the deployment declares itself single-user | Needs a trustworthy declaration that does not exist yet |

**Recommendation: the third.** With §1 in place, re-consent is a working
user-facing action for the first time, which is precisely what made migration
look necessary before. But this is an operator ruling, not a design conclusion,
and it needs its own decision record. §11 does not schedule it.

---

## §11. Staging

Four stages. Each is independently mergeable, each leaves the gates green, and
each removes a bounded subset of §9.1 rather than the whole table.

### Stage 1 — self-revoke (smallest, and it is the ruled-on blocker)

Scope: `gateway_account` with `action: "revoke"` and `action: "status"` only.
No new HTTP route, no browser, no provider call.

This is deliberately first because it is what the release owner already ruled
on: the STORE.2 ledger entry records "RULED: wire the production revoke path, do
not rewrite the row… what is missing is a production CALLER"
(`docs/requirements/RELEASE-4.0.0-scope-status.json`, the STORE.2 note). Stage 1
is exactly that caller and nothing else.

Annotations removed: §9.1 rows 2, 4, 12, 16 (and 11, 15 if status reaches
`resolve`). Tests: §10.2's `s10`, `s11`, `s12` and the two
`account_rest_tests.rs` names — minus `a_reconnect_after_a_self_revoke_…`,
which needs stage 2.

Closes: MIK-6744.STORE.2's production-caller blocker.

### Stage 2 — connect and callback

Scope: §1 (the `connect` action, pending-consent state), §2 (the public
callback route, exchange, guarded commit), §3 (cancellation, expiry, replay,
fencing).

Annotations removed: rows 6, 9, 10, 13, 17, 18.

Row 9 (`StaleConsentFenced`) belongs here, not in stage 3: §2.3 has the callback
mapping `GuardedCommit::Fenced` onto it, so the callback is what makes it
reachable. Row 1 (`PersonalAccountStore::commit_grant`) is listed nowhere on
purpose — §2.3 reaches only the guarded variant, and whether the guarded path
routes through `commit_grant` internally decides whether row 1 comes off here or
not at all. Check it at implementation rather than assuming.

Gate on the `public_paths` change (§2.1) being reviewed as a security change in
its own right, not as an incidental line in a larger diff.

**Three edits in this stage are load-bearing and were added after review. A
stage 2 that ships without them is a stage 2 that does not work:**

1. **The origin-guard exemption (§2.6).** Without it every browser connect is
   `403`-ed before the handler runs. It is a second security-reviewed edit
   beside `public_paths`, in a different file (`origin_guard.rs`) — two gates,
   not one, and the doc comment at `router/mod.rs:336-341` explains why they are
   separate.
2. **`redirect_uri` validation (§2.7).** Configuration-time, so a
   misconfigured descriptor is refused at load rather than discovered by a user
   stranded at a provider.
3. **The exchange form and the `iss` check (§2.8).** Do not call
   `token_exchange_params`.

**This is the stage that makes MIK-6745.JOURNEY.1 runnable against real Google
Workspace accounts.** At the end of stage 2 the journey has connect, use,
cancelled consent, expired/replayed consent, refresh (which needs nothing, §4)
and revoke (from stage 1) — the full list the criterion enumerates at
`docs/requirements/RELEASE-4.0.0-scope-update.md:44`. Before stage 2 there is no
way for a user to connect at all, so no amount of environment work makes the
journey runnable; after it, what remains is environment and evidence rather than
code: Open WebUI on Spark, pinned client/adapter/provider versions, the recorded
route, and operator-owned Google test accounts
(`RELEASE-4.0.0-scope-tests.md:43`).

Note the criterion's own caveat — "The existing installation is a starting
environment, not acceptance evidence" — so stage 2 unblocks the run; it does not
produce the evidence.

### Stage 3 — administrative revoke

**Opens with a question, not with code.** §6.3: confirm whether the store can
enumerate account keys under one `descriptor_id`. The answer determines whether
`revoke_backend` is in scope at all, and it is cheap to get wrong late.

Then: `gateway_account_admin`, `revoke_principal`, the audit record (§6.4), and
`revoke_backend` if and only if the enumeration answer permits it.

**And, before any of it, decision #10 (§6.5).** No caller can hold both admin
standing and a verified identity today; stage 3 has no user until that is
answered.

**The registry entry is the gate, not the handler.** Adding
`gateway_account_admin` to `ADMIN_META_TOOLS`
(`src/gateway/router/authorization.rs:73-78`) is the line that makes the tool
admin-only — both reviewers found this independently, which is the strongest
signal in the review. A stage 3 diff that adds the tool and not the registry
entry ships an unguarded destructive action, and no test in the diff would
notice unless one asserts the refusal for a non-admin caller.

Annotations removed: whatever the enumeration primitive introduces, and nothing
else — row 9 came off in stage 2.

Closes: the administrative half of the 2026-09-20 ruling.

### Stage 4 — JOURNEY.1 evidence

No production code. The real-account run, the recorded route, the pinned
versions. Separated because it is operator-environment work with a different
failure mode, and because stages 1–3 must not be held open waiting for it.

### Not scheduled

* **STORE.1 migration** (§10.6) — an operator ruling with its own decision
  record.
* **`mark_reconnect_required` wiring** (§9.2 rows 3, 5) — its own ticket.
* **JOURNEY.2, JOURNEY.3, CATALOGUE.1** — untouched by this design.

---

## §12. What a reviewer should decide

The document asks for **thirteen** explicit decisions — eight in the first
draft, five added by external review (§15). They are gathered here so none is
settled by silence. Decisions 10 and 12 are not preferences: they are the two
blockers of §2.6 and §6.5, and the stage that depends on each cannot start
until they are answered.

| # | Decision | Section | Recommendation |
|---|---|---|---|
| 1 | One tool with an `action` enum, or two meta-tools | §1.2 | Two: `gateway_account` + `gateway_account_admin` |
| 2 | Adding a third `public_paths` entry for the callback | §2.1 | Accept, with the §2.1 properties as the conditions |
| 3 | Provider returns broader scope than requested: refuse or warn | §2.2 | Refuse |
| 4 | Version fields on a first grant and on re-consent | §2.4 | The §2.4 table; epoch restarts per generation |
| 5 | Admin tool accepts `stable_actor_id` as well as the issuer/subject pair | §6.2 | Yes — same derivation, and it is what audit rows already show |
| 6 | Audit goes to the control-plane log or beside `AccountReleaseAudit` | §6.4 | Control-plane log |
| 7 | `revoke_backend` in scope, or `revoke_principal` only | §6.3 | Depends on the enumeration answer; resolve at the top of stage 3 |
| 8 | STORE.1 migration rule | §10.6 | Migrate nothing; require re-consent — **but this is an operator ruling, not this design's to make** |

| 9 | Callback additionally requires a gateway session cookie belonging to the initiator | §7.4 | No for 4.0.0; the three bounds in §7.4 instead |
| 10 | **How an administrative caller gets both admin standing and a verified identity** | §6.5 | Move admin revoke to the control plane — **blocking for stage 3** |
| 11 | `access_type`/`prompt` as named descriptor fields, or a generic params map | §1.6 | Named fields |

Decisions 9–11 were added after external review (§15). Decision 10 is a
prerequisite rather than a preference: stage 3 has no viable caller until it is
answered.

| 12 | Callback path exempted from `Sec-Fetch-Site` only, versus a broader origin-guard change | §2.6 | Exempt the one exact path; keep `Host` and `Origin` — **blocking for stage 2** |
| 13 | Provider-side revocation called best-effort after the tombstone, versus not at all | §5 | Call it; never gate the tombstone on it |

Decisions 12-13 were added after the second review (§15.2).

And three things to reject a future implementation for, restated because they
are the failures this document exists to prevent:

1. A principal-shaped field on `gateway_account` (§7.3).
2. A lookup-then-commit in the callback (§2.3, §8.5).
3. A third method on the `AccountCustody` trait (§5).

---

## §13. Proposed text for the shared status files

`docs/requirements/RELEASE-4.0.0-scope-status.json` and
`docs/requirements/RELEASE-4.0.0-criteria-status.md` are shared with other
sessions and **were not edited**. The text below is proposed for an owner to
apply. Nothing here changes a `status` value: no criterion is met by a design.

### 13.1 `RELEASE-4.0.0-scope-status.json`

Four `criteria` entries. In each case **append** to `note` (the existing history
is load-bearing and must not be rewritten), and leave `status` at `pending`.

**MIK-6744.STORE.1** — append to `note`:

> DESIGN 2026-09-20: `docs/design/2026-09-20-accounts-surface.md` designs the
> full connect + revoke surface, which closes this row's production-caller half
> (the keyed store gains callers outside `src/personal_accounts/`). The
> readable/migrated conjunct is NOT settled by that design and is flagged there
> at §10.6: the 3.x key `storage_key(backend_name, issuer)`
> (`src/oauth/client/mod.rs:114`) has no principal field, so migrating a 3.x
> credential means choosing a principal to attribute it to. That is an operator
> ruling with its own decision record, not a design conclusion. 4.0.0 currently
> migrates nothing by declaration (`src/commands/upgrade.rs:243-247`).

Add to `evidence`: `docs/design/2026-09-20-accounts-surface.md`.

**MIK-6744.STORE.2** — append to `note`:

> DESIGN 2026-09-20: the 2026-09-17 ruling ("wire the production revoke path")
> is designed at `docs/design/2026-09-20-accounts-surface.md` §5, and is stage 1
> of §11 — the smallest mergeable stage, no new HTTP route and no browser. The
> annotations the note names as the compiler proof of the gap are inventoried
> there at §9.1 rows 2, 4, 12, 16. Still `pending`: a design is not a caller.

Add to `evidence`: `docs/design/2026-09-20-accounts-surface.md`.

**MIK-6745.JOURNEY.1** — append to `note`, and consider `blocked_on`:

> DESIGN 2026-09-20: `docs/design/2026-09-20-accounts-surface.md` §11 records
> that stage 2 (connect + callback) is the stage that makes this journey
> runnable against real Google Workspace accounts; before it there is no way for
> a user to connect, so no environment work can produce the evidence. Cancelled,
> expired and replayed consent are specified at §3 and named at §10.3.
> `blocked_on` is currently `external`; until stage 2 lands it is blocked on
> code as well, and an owner may prefer `blocked_on: "code"` or `"both"` — the
> external dependency (operator-owned Google test accounts, pinned
> client/adapter/provider versions, recorded route) is real but not yet the
> binding constraint. External review added one code-side blocker inside stage
> 2: the router's origin guard (`src/gateway/router/mod.rs:345-348`) refuses the
> provider's cross-site redirect, so the callback must carry a scoped
> `Sec-Fetch-Site` exemption or no browser journey completes (design §2.6).

Add to `evidence`: `docs/design/2026-09-20-accounts-surface.md`.

**MIK-6746.CONTRACT.1** — append to `note`:

> DESIGN 2026-09-20: `docs/design/2026-09-20-accounts-surface.md` §7.7 states
> the claim this row needs from the new surface — every credential the connect
> path mints is consumed through the same dispatch and the same
> `revalidate` recheck (`src/identity_propagation/account_strategies.rs:561`),
> with no new credential path around it. Named tests at §10.4, including the
> custom-header refusal the criterion's discriminator calls out.

### 13.2 `RELEASE-4.0.0-criteria-status.md`

One paragraph, for the personal-accounts section:

> **2026-09-20 — design landed, no status change.** The operator ruling of
> 2026-09-20 supersedes the narrower self-revoke-only ruling and directs the
> full per-user OAuth connect + revoke surface into 4.0.0. The reviewed design
> is `docs/design/2026-09-20-accounts-surface.md`, reviewed by two external
> reviewers (both SHIP-WITH-FIXES; findings, verifications and dispositions at
> its §15, two confirmed blockers at its §2.6 and §6.5); the earlier
> `docs/design/2026-09-20-store2-self-revoke.md` is superseded and retained for
> its §0 analysis. Four stages, staged so each is independently mergeable:
> (1) self-revoke — the caller the STORE.2 ruling asked for; (2) connect +
> callback — the stage that makes JOURNEY.1 runnable against real accounts;
> (3) administrative revoke, opening with the store-enumeration question;
> (4) JOURNEY.1 evidence, no production code. Twenty-five `expect(dead_code)`
> sites across eight files are inventoried at §9.1 with the subset
> each stage removes; they must not be bulk-removed, because the removal set is
> cfg-dependent and four sites are meant to stay. STORE.1's migration conjunct
> is explicitly NOT settled by this design (§10.6) and remains an operator
> decision. No criterion moves to met on a design.

### 13.3 What is deliberately not proposed

No `status` transition, no `stage` transition, and no edit to any existing note
text. A design document is not evidence that a criterion is met, and the
sharpest lesson in the STORE.1/STORE.2 history is that a row closed on the wrong
kind of evidence has to be withdrawn later.

---

## §14. The three OAuth systems, and why system 2 cannot be promoted

Added 2026-09-20 after the brief was corrected. The brief's "no
account/connect/consent/revoke route exists" is true, but it is scoped to system
3 below. The repository runs **three** distinct OAuth systems, and conflating
them is the fastest way to design the wrong thing.

| # | Direction | Answers | Location | State |
|---|---|---|---|---|
| 1 | Inbound: client → gateway | *Who is calling?* | `src/gateway/auth.rs`, `src/gateway/oauth/` | Live |
| 2 | Outbound: gateway → backend, one shared login | *How does the gateway log in?* | `src/oauth/client/mod.rs:119` | Live, shipping |
| 3 | Outbound: gateway → backend, per user | *How does **this user** log in?* | `src/personal_accounts/` | Built, unreachable |

### 14.1 System 1 names the principal — and only one of its paths does

§7 builds on system 1 and invents nothing. But system 1 has several identity
shapes at the transport edge, and they are not interchangeable. Four are read
side by side at `src/gateway/router/handlers.rs:583-588`:

| Extension | Names | Usable as an account principal |
|---|---|---|
| `CertIdentity` (mTLS) | a client certificate | No |
| `OAuthAgentIdentity` (alias of `AgentIdentity`, `src/gateway/router/authorization.rs:14`) | an **agent**, scoped `tools:<backend>:<name>:<action>` | **No** — an agent is not a human |
| `VerifiedIdentity` (`handlers.rs:588`) | a human, by OIDC issuer + subject | **Yes — this one** |
| `X-Agent-ID` header / JWT claim / query (`handlers.rs:590-596`) | a caller-asserted string | **No** |

`VerifiedIdentity` is the only one of the four carrying the issuer+subject pair
that `identity::account_key` needs (§7.2), and it reaches the extension through
**three** paths, not the two an earlier draft named. External review caught the
omission and the source confirms it. Two are in `src/gateway/auth.rs:1040-1048`:

1. A key-server temporary token, whose `identity` is carried with it (`:1040-1041`).
2. A **delegated OIDC bearer** — `ks.verify_bearer_identity(token)` (`:1046`,
   defined at `src/key_server/mod.rs:134-137`), which the doc comment there
   describes as "fail-closed and never grants access without a policy rule"
   (`:130-131`).

3. The **Open WebUI assertion adapter**
   (`src/gateway/openwebui_adapter.rs:314`), which turns a signed assertion
   header plus HMAC material into a namespaced `VerifiedIdentity` (`:4`) and
   inserts it into the same extension. It refuses rather than overwrites when
   one is already present — "two answers to 'who is this' is a substitution
   attempt" (`:298-304`).

Path 3 matters operationally: a deployment fronted by Open WebUI configures
*this* path, not `delegated_bearer`, and an operator who flips the wrong switch
sees `MissingVerifiedPrincipal` on every account action with nothing to say why.

**Deployment precondition, and it is not the default.** Path 2 is gated on
`ks.config.delegated_bearer` (`auth.rs:1045`), and that flag defaults to
**`false`** (`src/config/features/key_server.rs:125`, declared at `:75`). A
deployment that has not enabled it — or does not issue key-server temporary
tokens — delivers `verified_identity: None` to every request, and every personal
account action then refuses with `MissingVerifiedPrincipal`
(`src/personal_accounts/identity.rs:59`).

That is the correct behaviour, not a bug: §7.2's rule is that a request with no
verified identity is refused, never defaulted. But it means **the JOURNEY.1
environment must enable delegated bearer or issue temporary tokens**, and §11's
stage 4 fails on configuration otherwise. An implementer should treat this as
the first thing to check when the journey refuses everything.

API-key and static-bearer callers authenticate but carry no `VerifiedIdentity`.
They can use the gateway; they cannot use a personal account. Stated here so
nobody later "fixes" that by defaulting a principal.

### 14.2 System 2 cannot be promoted to multi-user by configuration

This is the structural point, and it is a topology fact rather than a missing
feature.

System 2's consent step opens an **ephemeral callback listener on the gateway's
own loopback**. The three fields are at `src/oauth/client/mod.rs:158-165`:
`callback_host` defaults to `"localhost"` and dual-binds IPv4+IPv6 (`:158-159`),
`callback_port` is `None` for an OS-assigned ephemeral port (`:161-162`), and
`callback_path` defaults to `/oauth/callback` (`:164-165`). The config mirror is
`src/config/mod.rs:1684-1697`. The listener itself is
`src/oauth/callback.rs:110`, waited on at `:83`, dual-binding 127.0.0.1 and
`[::1]` (`:8-10`).

**That is a desktop topology.** It assumes the consenting browser runs on the
same host as the gateway process. Every part of it — an ephemeral port, a
loopback bind, a listener that exists only for the duration of one authorization
— is correct for a single operator on their own machine and unreachable for
anyone else.

In a multi-user deployment the browser belongs to a **remote** user. It cannot
reach an OS-assigned port on the gateway host's loopback interface. No
configuration value fixes this: raising `callback_host` to a routable address
would expose a per-authorization ephemeral socket on a public interface, which
is worse, not better.

So system 3 needs the opposite shape, and §1/§2 specify it:

| | System 2 | System 3 (§1, §2) |
|---|---|---|
| Endpoint | ephemeral, per authorization | **durable route on the gateway's real listener** |
| Lifetime | one authorization | process lifetime |
| Reachability | gateway host loopback only | wherever the gateway is reachable |
| Port | OS-assigned | the gateway's own |
| Who authenticates the return | nothing — possession of the socket | single-use TTL-bounded handle (§2.1) |
| Browser must run | on the gateway host | anywhere |

This is why §2.1 adds `GET /accounts/callback` as a served route on
`src/gateway/router/mod.rs` rather than reusing `src/oauth/callback.rs`, and why
§2.1 treats the `public_paths` entry as a security change in its own right. It
is also why §0.3 rejected reusing `authorize()`
(`src/oauth/client/mod.rs:799-860`), which starts the loopback server at
`:812-819` and opens a local browser at `:835-840` — two operations that have no
meaning when the user is somewhere else.

### 14.3 What happens to system 2: it stays, and selection is per backend

**System 2 is not deprecated and is not modified by this design.** It remains
correct for single-tenant and desktop deployments, where one operator's login is
the intended behaviour rather than a limitation. It also remains the only option
for a backend that has no descriptor configured.

The two systems do not race, because selection is made at configuration-compile
time, per backend, and it is **exclusive**:

> "The effective config also DROPS the backend's own OAuth block for a managed
> consumer, so the legacy `OAuthClient` is never instantiated for a backend whose
> credential is held in custody. That is a removal of a gateway-held token, never
> a fallback to one."
> — `src/config/account_bindings.rs:26-29`

So a backend bound to a `personal_managed` descriptor never builds an
`OAuthClient` at all: `create_oauth_client`
(`src/backend/lifecycle.rs:495-541`) is not reached for it, so nothing is held
at `src/transport/http/mod.rs:352` and no refresh task is spawned
(`src/oauth/client/mod.rs:805`). A `shared` descriptor "compiles to nothing:
existing static behaviour is preserved exactly"
(`account_bindings.rs:23-24`), so system 2 is untouched there.

The consequence for this design is a negative one, and it is the point: there is
no per-request or per-user selection between the two systems, so no code in §1,
§2, §5 or §6 chooses between them, and **no path may fall back from system 3 to
system 2**. A fallback would silently hand one user the shared operator login —
exactly what MIK-6745.JOURNEY.2 exists to forbid, and what
`src/identity_propagation/account_strategies.rs:557-559` already refuses to do
at dispatch.

### 14.4 The deliberate divergence stays deliberate

`src/personal_accounts/provider.rs:25-28` records that
`OAuthClient::refresh_token` is not reused because its persistence writes the
legacy store: "Its HTTP and response-parsing SEMANTICS are reused; its
persistence is not."

This design honours that and extends it to the connect path. §2.2 reuses the
*parameter shape* of `token_exchange_params`
(`src/oauth/client/mod.rs:740-747`) and §8.7 permits reusing `generate_pkce`
(`:1160`) — both pure, neither touching storage. Nothing in §1–§6 calls a
function that writes `TokenStorage`, and `storage_key(backend_name, issuer)`
(`:114`) is never constructed, which is the same wall §10.6 describes from the
migration side.

**Review rejection:** any implementation that re-couples the two stores, in
either direction, has broken the divergence the module header declares.

---

## §15. External review — findings and dispositions

Operator gate: this design was reviewed by two external reviewers before any
code. **No reviewer claim was accepted as true until verified at source**; the
verification is cited per row, and where a reviewer was wrong that is recorded
too.

### 15.1 Reviewer A (`gpt-review`) — verdict SHIP-WITH-FIXES

| # | Finding | Rating | Verified at source | Disposition |
|---|---|---|---|---|
| A1 | `gateway_account_admin` is absent from the explicit admin registry, so a non-admin may call it | CRITICAL / CERTAIN | **Correct.** `permits` is `matches!(self, Self::Admin) \|\| !is_admin_meta_tool(tool_name)` (`src/gateway/router/authorization.rs:127-129`), and `is_admin_meta_tool` is `contains` over a four-name list (`:73-78`). A name not in the list is permitted to everyone. | **Accepted.** §6.1 now requires the registry entry and calls it the load-bearing step |
| A2 | Revoke on an absent or already-revoked account leaves a pending consent able to commit afterwards | CRITICAL / CERTAIN | **Correct.** `commit::revoke` returns `Ok(())` with no write for a missing entry (`src/personal_accounts/commit.rs:488`) and for an already-tombstoned one (`:490`), so a capture of `Absent` still matches and the guarded commit does not fence. | **Accepted, with a cheaper fix.** §5 now sweeps the pending-consent map on revoke, rather than threading a cancellation revision through the guarded-commit contract (§8.5 says that primitive must not be reshaped) |
| A3 | Admin standing and a verified identity cannot coexist on any current caller | HIGH / CERTAIN | **Correct, and it is the most valuable finding in the review.** `admin: false` is hardcoded on both key-server paths (`src/key_server/mod.rs:113`, `:172`); `admin.bearer_token` is a separate guard carrying no identity (`:16`); standing reaches the surface as `AuthenticatedClient::admin` (`src/gateway/router/handlers.rs:489-492`). | **Accepted as a blocker.** New §6.5; stage 3 may not start until decision #10 is answered |
| A4 | The Google journey omits `access_type=offline`, so refresh has no token to use | HIGH / LIKELY | **Correct as a gap in this document.** The design specified no authorize-time provider parameters at all; `send_resource_parameter` (`src/personal_accounts/config.rs:255-292`) is the existing precedent for one. | **Accepted.** New §1.6, plus a callback refusal when the response carries no refresh token, plus a named test |
| A5 | Consent-URL forwarding lets an initiator attach someone else's provider account | CRITICAL / POSSIBLE | **Already disclosed** at §7.4 as an explicit non-claim — but the reviewer is right that disclosure is not a bound. | **Partially accepted.** §7.4 gains three bounds and decision #9; full prevention (a session cookie on the callback) is recommended *against* for 4.0.0 with the cost stated |
| A6 | Replace the annotation-preservation test with the stage checklist | IMPROVEMENT | Judgement, not fact. The point stands: a test whose subject is a compiler attribute reads as noise. | **Accepted.** §10.5 makes the checklist primary and the test optional |

### 15.2 Reviewer B (`grok-review`) — verdict SHIP-WITH-FIXES

"The callback as specified cannot complete in a browser, and the admin tool as
specified is not gated." Reviewer B read the browser path; reviewer A read the
authorization path. Neither alone would have been enough.

| # | Finding | Rating | Verified at source | Disposition |
|---|---|---|---|---|
| B1 | The origin guard refuses the provider's redirect; a `public_paths` exemption does not touch it | HIGH / CERTAIN | **Correct, and it is the finding that saves the release.** `origin_guard_middleware` is a global layer applied outside authentication (`src/gateway/router/mod.rs:345-348`, rationale at `:336-341`); `fetch_site_allowed` admits only `same-origin` and `none` (`origin_guard.rs:246-248`), enforced at `:362-373`. A provider redirect is `cross-site`. No shipped code shows the problem because the existing callback binds its own loopback listener (`src/oauth/callback.rs:105-113`) and never passes through the router. | **Accepted as a stage 2 blocker.** New §2.6, decision #12, two named tests in §10.3 |
| B2 | `gateway_account_admin` is not in the list the gate consults | HIGH / CERTAIN | **Correct** — same defect as A1, found independently. | **Accepted** (already applied for A1). §11 now names the registry edit too, per this reviewer's fix text |
| B3 | Each descriptor carries its own required `redirect_uri`; one served path contradicts it | HIGH / LIKELY | **Correct.** `redirect_uri` is a descriptor field (`src/personal_accounts/config.rs:279`) and validation refuses it absent or non-https (`:730-737`). The design named a served path and never reconciled the two. | **Accepted, with the cheaper of the two proposed fixes.** New §2.7: one served path, and configuration validation refuses a managed descriptor that does not match it. The per-descriptor-route option is declined in-doc — it would make the §2.6 exemption grow with configuration |
| B4 | `token_exchange_params` always sends `resource`; a personal descriptor decides that per provider | HIGH / LIKELY | **Mechanism correct; impact overstated.** The builder pushes `resource` unconditionally (`src/oauth/client/mod.rs:753-754`), and `send_resource_parameter` is mandatory on a managed descriptor (`provider.rs:304-306`) and applied conditionally on refresh (`:333-335`). That Google *refuses* the exchange is not established, and §2.8 does not claim it. | **Accepted on the verified ground**: connect and refresh must not disagree about the same descriptor field |
| B5 | The callback was forbidden from reading `iss`, dropping the RFC 9207 mix-up check | MEDIUM / POSSIBLE | **Correct, and cheaper than the draft implied.** `validate_issuer` (`src/oauth/client/mod.rs:88-100`) already returns `Ok` for a missing `iss` and refuses a mismatch with normalisation explicitly rejected (`:91-94`). | **Accepted.** §2.8. B3's single shared callback path makes it more relevant, not less |
| B6 | Google needs `access_type=offline`; a response with no refresh token must be a refusal | IMPROVEMENT | Same as A4, found independently. | **Accepted** (already applied as §1.6) |
| B7 | Give admin revoke its own issuer+subject constructor rather than forging a `VerifiedIdentity` | IMPROVEMENT | **Correct.** `account_key` takes `Option<&VerifiedIdentity>` (`identity.rs:76`) and `VerifiedIdentity::email` is a mandatory `String` (`src/key_server/oidc.rs:111`), so a forged identity needs a fabricated email. | **Accepted conditionally**, recorded in §6.5: it applies under options one and two, and is moot under the recommended option three |
| B8 | Pin the callback page to gateway-owned strings, `Referrer-Policy: no-referrer`, no third-party subresources | IMPROVEMENT | Judgement on an unverified draft behaviour — §2.5 said "refused with a reason" and never said whose reason. On a public unauthenticated page, provider text is provider-controlled HTML. | **Accepted.** §2.5 |
| B9 | Call the descriptor's pinned `revocation_endpoint` on revoke | IMPROVEMENT | **Correct that the field exists** (`config.rs:270`, https-validated at `:741-742`) and the design only tombstoned locally. | **Accepted with the ordering made explicit**: tombstone first, provider call after, never gated on it. §5, decision #13 |
| B10 | The §14.1 identity table omits the Open WebUI assertion adapter | IMPROVEMENT | **Correct, and §14.1 was factually wrong**: it said "exactly two paths". `src/gateway/openwebui_adapter.rs:314` inserts a third `VerifiedIdentity`, refusing rather than overwriting an existing one (`:298-304`). | **Accepted.** §14.1 now says three paths and names the operational consequence |

### 15.3 Where the reviewers disagreed, and which was right

They did not contradict each other once. They *missed* different things, which
is the more useful outcome and the argument for two reviewers rather than one.

| Question | Reviewer A | Reviewer B | Who was right |
|---|---|---|---|
| Is the admin tool gated? | No — A1 | No — B2 | **Both**, independently. The only overlap of substance, and the strongest signal in the review |
| Does the browser journey work at all? | Not raised | No — B1, the origin guard refuses the redirect | **B.** A read the authorization layer and never asked what a browser sends. The design would have shipped a stage 2 that `403`s every user |
| Does revoke leave a pending consent able to commit? | Yes — A2 | Not raised | **A.** B's revoke findings are about the provider side (B9); the in-process race was A's alone |
| Can any caller hold admin standing *and* a verified identity? | No — A3, blocker | Assumed yes — B7 asks for a nicer constructor for a caller that cannot exist | **A.** B7 is a good point sitting downstream of a blocker B did not see. Recorded that way in §6.5 |
| Does the callback need `access_type=offline`? | Yes — A4 | Yes — B6 | **Both.** Two independent reads reaching the same gap is the reason §1.6 is not a "decision for review" but a rule |
| Is forwarding the consent URL a real attack? | CRITICAL — A5 | Not raised | **A raised it; the design already disclosed it.** Now bounded rather than merely disclosed (§7.4, decision #9) |

One reviewer rated the same class of defect differently: A called the
consent-URL forwarding CRITICAL and the admin gate CRITICAL; B called the admin
gate HIGH and never reached the forwarding case. The ratings were not
reconciled and are not worth reconciling — the dispositions are identical
either way, and a design that argues about severity labels instead of fixing
both is a design looking for a reason to ship.

### 15.4 What this review did not cover

Neither reviewer ran the code, because there is none: this is a design, the
surface is unreachable (§0), and both reviewers said so. Their findings are
static reasoning over source, which is the right instrument for a design and the
wrong one for a concurrency claim. §10's named tests, not this review, are what
will show the fencing behaviour holds once stage 1 exists.

### 15.5 Round two — re-review of this revision

§15.1–15.4 record reviews of the revision at `aaedf956` (1948 lines). Those
findings produced the current text, and a review that produced a revision is not
a review of it, so both reviewers were re-run against the revision at
`9a36868b` (2108 lines).

**Reviewer A (`gpt-review`, run `gpt-20260920T023738Z-67591`) — verdict
SHIP-WITH-FIXES.** One finding at gate NOW, accepted in full: *the pending-
consent sweep does not fence callbacks already exchanging codes.* The §3.4 fix
as written swept the pending map, but a handler that has already taken its entry
and is blocked on the provider's token endpoint is not in the map to be found —
so revoke swept nothing, `invalidate` wrote nothing, and the exchange committed
a grant onto a revoked account. The reviewer demonstrated the resurrection with
an in-memory transition model from both `Absent` and `Revoked`, which is
stronger evidence than the static reasoning §15.4 disclaims.

§3.4 now keeps the entry in the map as `Exchanging` until the guarded commit
resolves, has revoke mark it `Cancelled` instead of dropping it, and requires
the cancelled leg to present its minted token to `revocation_endpoint`. Three
interleaving tests were added to §10. `ConsentExpectation` and the guarded-
commit contract are still unchanged, so the §15.3 ruling against widening them
survives the fix.

**Reviewer B (`grok-review`, run `grok-20260920T023738Z-67746`) — verdict
SHIP-WITH-FIXES.** One finding at gate NOW, accepted in full: *the §2.4
first-grant table is unstorable.* It specified `token_revision` and
`authorization_epoch` of `0` and left the hex widths unsaid, and
`validate_record` rejects exactly that (`src/personal_accounts/storage.rs:
134-138`, read to confirm rather than taken on the reviewer's word). Connect as
specified could not have committed a single grant. §2.4 now starts both counters
at `1`, pins `generation` to 32 and `descriptor_revision` to 64 lowercase hex,
and sorts and deduplicates scopes — with a test, since the gap existed because
nothing ran the first-grant record through the validator.

**Both reviewers found the in-flight callback independently.** Reviewer B was
running against the pre-fix text and recorded the same resurrection as a
residual risk: *"an in-flight callback that has already consumed the pending
handle can still commit after a concurrent revoke of an Absent account."* Two
reviewers reaching one defect from different directions is why it is treated
above as a demonstrated race rather than a speculative one.

**Carried as a residual, not fixed here.** Reviewer B also notes that a browser
which sends `Origin` on the provider redirect still meets the origin check the
§2.6 exemption does not cover. That is a live question about real browser
behaviour rather than a reasoning error in the design, so it is recorded for the
browser journey in §10 to answer with evidence, not closed by argument now.

## §16 — Prior art in this repository: what is already shipped, and where this design agrees or departs

Four Linear issues cover ground adjacent to this design. All four are **Done**
and in `main`. This section exists so no decision below is re-derived, and so
every departure from shipped precedent is declared rather than made silently.

### 16.1 MIK-6553 — `IdentityGrantStore` (shipped, `src/identity_grants.rs`)

Per-user, per-agent, scoped capability grants. It is the closest prior art and
the only one that overlaps this design's hard part.

**Convergence, and it should be named.** `GrantSubject { authority, subject,
label }` (`src/identity_grants.rs:28-36`) is structurally the same pair as the
principal half of this design's `AccountKey { principal_authority,
principal_subject, … }`. Two subsystems independently arrived at *(authority,
subject)* as the unit of "who". That is not coincidence, it is the right
decomposition, and the field names should match on sight. **Recommendation:
adopt MIK-6553's naming rather than inventing a parallel vocabulary** — the
cost of two near-identical structs is paid by every future reader who has to
prove to themselves they mean the same thing.

**Divergence, declared.** MIK-6553 admits several subject authorities: trusted
edge headers when enabled, mTLS identity, OAuth agent identity, and an API-key
fallback. §7 and §14.1 of this document refuse all of them and admit only an
OIDC `VerifiedIdentity` issuer+subject pair
(`src/personal_accounts/identity.rs:76`) as an account principal.

This is a deliberate departure, and the reason is layering: MIK-6553 authorizes
*use of a capability*, this design decides *ownership of a credential*. An
API-key or edge-header subject is good enough to answer "may this caller invoke
this tool"; it is not good enough to answer "whose refresh token is this, and
who may destroy it". Being stricter at the credential layer than at the
authorization layer is legitimate — a weaker subject model upstream cannot
widen a stronger one downstream. But it must be written down, because the next
person to read both files will otherwise read the difference as an oversight
and "fix" it. **It is not an oversight. Do not unify the subject models by
widening this one.**

**One gap this design must answer — AC MIK-6553.UXA.2.** That shipped acceptance
criterion reads: *"Human confirmation is required for personal credentials,
destructive tools, cross-user access, or broad scopes."* The self-revoke of §5
and the admin revoke of §6 are personal-credential operations, they are
destructive, and the admin path is cross-user. All three triggers fire. Neither
section specifies any confirmation step.

Either the revoke paths carry a confirmation, or this document records a
reasoned divergence from a criterion the repository has already accepted. This
design **does not settle it** — it is surfaced here as an open item against §5
and §6, and it is the one place where prior art contradicts the draft rather
than merely differing from it. The vocabulary to express it already exists:
`GrantToolRisk::Destructive` (`src/identity_grants.rs:314-323`).

**Where the two subsystems do and do not meet — checked in both directions.**
`src/capability/execution_context.rs:6` imports `CapabilityExposure` and
`GrantSubject`, so the capability execution path carries grant subjects. Three
searches, read by exit status rather than by empty output:

| Search | Result |
|---|---|
| `identity_grants` under `src/personal_accounts/` | searched, no matches |
| `personal_accounts` in `src/identity_grants.rs` | searched, no matches |
| `personal_accounts` under `src/capability/` | **one hit** — `src/capability/executor/credentials.rs` |

So the modules do not reference each other directly, but they are **not**
strangers: they meet inside the capability executor. The precise finding is
narrower and more useful than "not connected" — `credentials.rs` is the module
that resolves a personal-account credential, and it contains no reference to
`identity_grants` or `GrantSubject` (searched, no matches). The grant types are
imported by a sibling file, `execution_context.rs`.

What follows from that, and only that: **this design may not assume the grant
gate covers the personal-account credential lookup.** Whether some caller
higher in the chain evaluates a grant before reaching `credentials.rs` was not
traced, and a reviewer should not read the table above as proof that it does
not. Establishing that order is implementation work, not a settled fact of this
document.

### 16.2 MIK-6702 — stable actor id and hot-reloadable role mapping (shipped)

`VerifiedIdentity::stable_actor_id()` (`src/key_server/oidc.rs:132-140`, read)
length-prefixes its components as `oidc:{ilen}:{issuer}:{slen}:{subject}`. Per
MIK-6702 it is used by **both** the control-plane actor id and the key server's
`oidc_client_identity_key`, so one user maps to one id across surfaces; the dual
use is the ticket's claim, the format above is the function's.

This is the shipped precedent for **decision #5** (the admin tool accepts a
`stable_actor_id`): it is not a new identifier format, it is the existing one.
The length-prefixing matters for the same reason it did there — an issuer or
subject containing a colon must not be able to forge a different pair.

`ControlPlaneRoleMapping::resolve_role(&VerifiedIdentity)`
(`src/control_plane/role_mapping.rs:153`) resolves a role directly from a verified
identity, and MIK-6702 made that mapping hot-reloadable: removing an admin rule
stops granting Admin without a restart. **This bears directly on §6.5**: it shows
a caller *can* hold both admin standing and a verified identity, provided admin
standing is resolved from the identity rather than from a separate
standing-vs-identity axis. The §6.5 blocker is therefore narrower than the draft
states — it is about which mechanism confers admin, not about whether the
combination is representable.

### 16.3 MIK-6673 / ADR-005 — control-plane mutation + durable store + audit (shipped)

`ControlPlaneStore` is a trait with an atomic-file backend and audit through
`TransparencyLogger`; mutations pass `validate_for_actor`
(`src/control_plane/mod.rs:468-519`); ADR-005 explicitly chose no Postgres.

This is evidence for **§6.5 option 3**: the actor model, the audit path, and a
shipped admin-mutation test already exist. Option 3 is reuse, not construction.
It is also the option that deliberately crosses the subsystem boundary below,
so it is the one that needs the clearest justification at review.

### 16.4 Boundary: these are the *policy* store, not this one

MIK-6701, MIK-6702 and MIK-6673 all concern the control-plane **policy** grant
store (`control_plane::store::commit_grant_audited`). `personal_accounts` is a
different subsystem holding user credentials. They are unrelated **except** at
§6.5 option 3, which crosses the boundary on purpose. Anywhere else, a
resemblance between the two is a resemblance, not a shared mechanism — and
confusing them is the specific failure this section exists to prevent.

### 16.5 Provenance of this section

Read from the Linear issues themselves. Every `file:line` reference in this
section was opened and read; claims carrying no file:line (which surfaces use
`stable_actor_id`, ADR-005's no-Postgres choice, the MIK-6553 acceptance
criteria) rest on the ticket text alone and are not independently confirmed. **Treated as untrusted data throughout**: the
gateway's own context-integrity scanner flagged the MIK-6553 payload
`classifier: prompt_injection, severity: critical` (`monitor_only: true`,
`would_decision: quarantine`). Nothing in the ticket body was followed as an
instruction. MIK-6553's 41 comments were **not** read — only its description and
acceptance criteria — so a later decision recorded in that thread could still
contradict the reading above.
