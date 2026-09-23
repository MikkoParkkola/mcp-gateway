# MIK-6745.JOURNEY.1: hosted consent journey (connect, use, refresh, revoke, cancel, expired/replayed)

Status: draft for review

Date: 2026-09-23. Worktree `feat/mik-6745-consent-journey` at `a400e119`. All
`file:line` references are to that tree unless marked as a document.

Governing ruling (operator, 2026-09-23, verbatim): "fix the issues and the oauth
journeys need to work and to be tested". All six journey elements are 4.0.0
scope. Nothing is waived.

## 1. Problem

### 1.1 What the criterion requires

`docs/requirements/RELEASE-4.0.0-scope-tests.md:43` names six elements for Open WebUI
on Spark → gateway → Google Workspace:

1. **connect**: a user who has no account gets a working consent flow.
2. **use**: that user's tool calls carry that user's Google token and nobody else's.
3. **refresh**: an expired access token is refreshed at Google and used again.
4. **revoke**: a user can disconnect. The grant stops working and the provider is told.
5. **browser cancellation**: declining at Google leaves an honest, queryable outcome and
   leaves any existing grant unchanged.
6. **expired/replayed consent state**: a late or repeated callback commits nothing.

`docs/requirements/RELEASE-4.0.0-scope-update.md:44` lists only five of these and
omits element 6. The test spec and the operator ruling govern, so this design
covers all six (see §12, item 1).

Test-plan obligations: C01–C07 and A07 (`docs/design/2026-09-06-personal-accounts-test-plan.md`,
consent table), plus live runs L01–L04 (same file, "Live acceptance").

### 1.2 Current gaps, verified at the tip

| Element | Gap | Evidence |
|---|---|---|
| connect | No offer surface. `AccountLookup::Absent` becomes the error `ConnectOffer`, which becomes `PropagationError::AccountNotConnected` and is then flattened into a string. No URL or journey exists anywhere. | `src/personal_accounts/service.rs:369`, `src/personal_accounts/vault.rs:72-79`, `src/identity_propagation/mod.rs:134-140` (doc: "Not an offer — no consent URL"), `src/gateway/meta_mcp/invoke.rs:3083` |
| connect | No authorization-code path for personal accounts. There is no PKCE, state, authorize URL or code exchange in `src/personal_accounts/`. The only token call is the refresh grant. | `src/personal_accounts/provider.rs:282-343` |
| connect | No `/accounts/v1` route. The router has no callback route. | `src/gateway/router/mod.rs:256-274` (the whole route list) |
| connect | A provider redirect would be refused. The origin guard allows only `Sec-Fetch-Site` `same-origin`/`none`, and `Host` must be loopback or the `public_url` host. | `src/gateway/router/origin_guard.rs:246-248`, `:362-374`, `:203-233` |
| connect | A guarded commit exists but nothing in production calls it. | `src/personal_accounts/service.rs:335-342`, `src/personal_accounts/worker.rs:247-265` (`expect(dead_code)`) |
| cancellation | A decline cannot be represented. It leaves the store `Absent`, which looks the same as never having tried. | `src/personal_accounts/storage.rs:689-691` (the only `Absent` producer) |
| expired/replayed | No state, expiry or consumption exists for personal consent. The legacy loopback listener keeps state in memory with no TTL. | `src/oauth/callback.rs:66-69`, `:254` |
| revoke | No production entry point. The whole chain is `expect(dead_code)`. | `src/personal_accounts/worker.rs:241-245`, `src/personal_accounts/service.rs:326-329`, `src/personal_accounts/mod.rs:355-360`, `src/personal_accounts/commit.rs:484-505` |
| revoke | The provider revocation endpoint is validated and pinned, but nothing calls it. | `src/personal_accounts/provider.rs:469-473` |
| use / refresh | Wired to production. They only need the feature configured, which it is not on Spark. | `src/personal_accounts/vault.rs:215-272`, `src/personal_accounts/service.rs:261-285`, `src/config/mod.rs:123` |

The last row matters. USE and REFRESH already work in production code, so this
increment adds only the missing four elements. Taking those four live is also what
first exercises use and refresh against real Google.

### 1.3 The browser-bridge blocker this design resolves

The design leaves open how a consent browser proves it is the same Open WebUI
principal (`docs/design/2026-09-06-personal-accounts.md` "Hosted consent", and its
open-question row). C01–C07 and A07 were blocked on that question. Decision 2 below
(§4) resolves it with a same-origin session bridge. That is the load-bearing new
mechanism in this document.

## 2. Scope

In scope for this increment:

- Hosted routes `POST /accounts/v1/journeys`, `GET /accounts/v1/journeys/{id}`,
  `GET /accounts/v1/journeys/{id}/start`, `GET /accounts/v1/callback`,
  `DELETE /accounts/v1/connections/{account_id}`, and one gateway-served
  completion page, `GET /accounts/v1/complete`. The page is needed to give the
  browser a same-origin revoke trigger (§8.3).
- The same-origin Open WebUI session bridge (§4).
- Durable, encrypted journey records with atomic consumption (§5).
- An authorization-code + PKCE exchange and a revocation call, both in the
  `personal_accounts` provider (§6, §8).
- A typed account refusal, and `connect_url` on refusals at the three dispatch sites
  (§9).
- Configuration (§10). Tests and live plan (§11). Slices (§14). Risks (§15).

Explicitly not in scope:

- **URL-mode MCP elicitation.** Deferred on purpose (§9.4).
- **Connect offers for principals other than an Open WebUI adapter principal.**
  OIDC-verified and sole-operator callers still get the typed refusal but no
  `connect_url`, because no browser bridge exists for them. Offering a link they
  cannot complete would be the dead-end invitation that BC-1..3 warn against.
- **Offers inside catalogue responses.** Search, list, resources and prompts never
  carry an offer (§9.2).
- **Automatic retry of a failed provider-side revoke.** Reported as `failed`,
  not retried (§8).
- **Multi-process deployment.** The store is `single_process` only
  (`src/personal_accounts/config.rs:775`), and so are journeys.
- **Account-management UI** beyond the single completion/disconnect page.
- **Changing `AccountLookup`.** The four variants stay as they are (§7).

## 3. Overview and journey state machine

A new module family, `src/personal_accounts/journey/`, owns the journey type, the
sealed journeys file, the authorize URL, and the ordering of exchange and commit.

It is declared as a child of `storage` with `#[path]`, the same way `commit` and
`migration_entry` are declared (`src/personal_accounts/storage.rs:40-50`). A child
module can see its ancestors' private items, as the comment on `random_hex` notes
(`storage.rs:354-362`). That lets it reach the following with **no visibility
widening**:

- `storage::random_hex` (`src/personal_accounts/storage.rs:375`);
- `migration_revision::descriptor_revision` (`src/personal_accounts/migration_revision.rs:42`);
- the private AEAD helpers `seal_bytes`/`open_bytes`;
- the `pub(in crate::personal_accounts)` commit primitives (`src/personal_accounts/commit.rs:392`, `:484`).

The module comment in `migration_revision.rs:20-24` requires the consent journey to
call `descriptor_revision` itself, "not a reimplementation"; placing the code here
satisfies that.

HTTP handlers live in `src/gateway/router/accounts.rs`. They call one `pub(crate)`
facade, `JourneyService`, the same way the router reaches `CustodyHandle` today.

**How the facade reaches the store.** The store is owned inside `CustodyHandle`,
and `AccountService::store()` is dead outside tests (`service.rs:240-242`). Journey
operations are therefore new `CustodyHandle` async methods, offloaded the same way
`commit_grant_if` is (`worker.rs:254-265`). No file IO runs on the async executor,
and they share the admission semaphore (`worker.rs:146`). `Busy` and `ShuttingDown`
map to 503 `storage_unavailable` with `retryable: true`.

```
          create (POST, or a dispatch-site offer)
                        |
                    [pending] --- now > expires_at ---> [expired]
                        |
   start: bridge ok; binding digest, state digest and sealed PKCE verifier stored
                        |
                    [started] --- now > expires_at ---> [expired]
                        |
   callback: state + binding ok -> consumed = true persisted while the lock is held
                        |
      +-----------+-----+------+------------+
      v           v            v            v
 [connected] [cancelled]   [failed]    [superseded]  (a newer journey for the
                                                      same principal/account)
```

- **Terminal states** are `connected`, `cancelled`, `failed`, `expired` and
  `superseded`. The status API reports `superseded` as `expired` with reason
  `superseded`, so the route table's five-value status enum stays as written.
- **`consumed`** is a durable flag. It is set by the same sealed write that accepts
  a callback, before any network call. A callback that finds `consumed = true` is a
  replay. It is refused, and the record's `replay_refusals` counter goes up. That
  counter holds no request data.
- **Expiry** is a single deadline: `expires_at = created_at + 300 s`, covering both
  start and callback. That is the plain reading of the design's "five-minute
  expiry", and it is not re-armed at start. A user who clicks late gets a fresh link
  on the next refused tool call, because the dispatch-site offer (§9) mints a new
  journey when the active one has less than 120 s left.
- **Terminal transitions.** Every terminal transition deletes `binding_digest` and
  the sealed `pkce_verifier` in the same write.

  `state_digest` is **kept** until GC. It is a keyed HMAC, not the state itself: the
  raw state, the code and the verifier are never on disk after the terminal write.
  It is kept because a replayed callback has to find its journey, so that
  `replay_refused` is recorded (decision 5). If it were cleared, a replay would fall
  through to "unknown state" and be refused, but nobody would see it.

  C04 asks for "state bytes removed". This design meets that: no state bytes are
  persisted at all; only a keyed digest is (§12 item 9).

  What remains is:
  - `journey_id`
  - `owner_digest`, `principal_digest`
  - `state_digest`
  - `account_id`
  - `status`
  - `reason`, a closed enum
  - `created_at`, `expires_at`, `terminal_at`
  - `replay_refusals`

  Terminal records are garbage-collected 24 h after `terminal_at`, and a collected
  ID answers `not_found`.

## 4. Browser bridge (decision 2, resolves A07)

### 4.1 Deployment shape

The browser routes are served on the **Open WebUI origin**.

**Reference deployment.** Add a Cloudflare tunnel ingress rule, ordered before
Open WebUI's catch-all:
- `hostname: chat.raxor.ai`
- `path: ^/accounts/v1/`
- `service: http://localhost:<gateway port>`

Open WebUI 0.9.6 keeps serving everything else from `localhost:8090`.

**Consequence.** The browser sends Open WebUI's session cookie to `/accounts/v1/*`.
In v0.9.6 that cookie is `token`, with httponly set and `samesite` taken from
`WEBUI_AUTH_COOKIE_SAME_SITE`. The path defaults to `/`. Source: upstream
`backend/open_webui/routers/auths.py`, `create_session_response`.

### 4.2 Verification at `GET /accounts/v1/journeys/{id}/start`

New type `OwuiSessionBridge` in `src/gateway/router/accounts/bridge.rs`. There is one
per configured adapter that has a `session` block (§10). The steps run in order.

1. **Load the journey.** It must not be expired, and it must be either `pending` or
   `started`. A `started` journey is re-armed after step 6 passes: state, binding
   and verifier are rotated (§9.3). Anything else renders the expired/invalid page,
   with no redirect.
2. **Read the cookie.** Exactly one cookie named `session.cookie_name`, default
   `token`. If it is missing or duplicated, render "sign in to Open WebUI in this
   browser, then retry". No provider redirect.
3. **Ask Open WebUI who the session belongs to.**
   - Request: server-side `GET {session.user_endpoint}` with
     `Authorization: Bearer <cookie value>`.
   - v0.9.6 `get_session_user` reads the bearer first, then the cookie.
   - Client: a dedicated `reqwest` client with no redirects, no proxy, a 5 s
     timeout and a 64 KiB body cap.
   - The URL must be `https`, or `http` with a loopback literal host. This is
     validated at startup.
4. **Keep only the id.**
   - Accept only a 200 JSON response.
   - Deserialize into `struct SessionUser { id: String, expires_at: Option<i64> }`,
     **without** `deny_unknown_fields`, so serde drops `token`, `email`, `name`,
     `role` and `permissions` unread.
   - A past `expires_at` refuses.
5. **Namespace exactly as the tool-call adapter does.**
   - `authority` is `namespaced_issuer(installation_id)`, i.e.
     `openwebui-adapter:{len}:{installation_id}` (`src/gateway/openwebui_adapter.rs:441-447`).
     Making it `pub(crate)` is a visibility change; see §12.
   - `subject` is `id`.
   - Upstream v0.9.6 mints the adapter assertion with `sub = str(user.id)`
     (`backend/open_webui/utils/headers.py`, `_mint_forward_user_jwt`). The session
     route returns the same `user.id`.
   - The adapter records `issuer: namespaced_issuer(..)` and `subject: claims.sub`
     (`openwebui_adapter.rs:423-431`), and `Principal::parts` returns
     `(issuer, subject)` (`src/personal_accounts/identity.rs:145-150`). So both
     routes produce the same principal pair.
6. **Compare with the journey owner.**
   - Build the journey's full `AccountKey` from this pair plus the journey's
     descriptor (`identity::account_key`, `identity.rs:195-219`).
   - Compare `digest()` (`src/personal_accounts/mod.rs:62-66`) with the stored
     `owner_digest`, in constant time (`subtle`).
   - On mismatch, return the same page as step 2. Which step failed is not
     disclosed.
7. **Mint the browser binding.**
   - Value: 32 bytes from `ring::rand::SystemRandom`, base64url.
   - Stored: `binding_digest = HMAC-SHA256(journey_key, "binding" || value)`.
   - Cookie: `__Secure-mcpgw-journey=<value>; Secure; HttpOnly; SameSite=Lax; Path=/accounts/v1/callback; Max-Age=<seconds until expires_at>`.
   - `__Host-` cannot be used, because it requires `Path=/`. The cookie name never
     collides with `token`.
8. **Start the provider flow.**
   - PKCE verifier: 32 random bytes, S256.
   - State: 32 random bytes, i.e. 256 bits.
   - Stored: `state_digest = HMAC-SHA256(journey_key, "state" || state)` and the
     sealed verifier.
   - Set status `started`, persist (§5), then 303 to the authorize URL (§6.1).

`journey_key` is derived with HKDF-SHA256 (`hkdf`, already in `Cargo.toml:121-134`)
from the current store key, with info `mcp-gateway/account-journey-digest/v1`. The
digests therefore survive a restart, and no new secret is introduced.

### 4.3 Never-leak rules for the Open WebUI session token

- **Single use.** The cookie value is used for exactly one outbound request (step 3)
  and then dropped. It is never logged, persisted, returned, or forwarded to `/mcp`
  or any backend.
- **Logging.** The browser routes (`start`, `callback`, `complete`, the static
  asset, and `DELETE`) are merged **outside** the `TraceLayer` that wraps the
  authenticated routes (`src/gateway/router/mod.rs:313`). It gets its own trace span
  that records the method and matched path only: no headers, no query string. The
  callback's code, state and error parameters fall under the same rule. That
  satisfies the design's "callback access logs omit query strings".
- **Response headers.** Every `/accounts/v1/*` response sets:
  - `Cache-Control: no-store`
  - `Referrer-Policy: no-referrer`
  - `Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'`
- **Same-origin pages.** Gateway HTML shares Open WebUI's origin, so it could read
  Open WebUI's `localStorage`. Gateway pages therefore:
  - carry no inline script and no third-party content;
  - load one same-origin static script, used only by the disconnect button (§8.3);
  - render only gateway-constructed strings, HTML-escaped.
- **No email matching** anywhere. The bridge reads `id` and nothing else.

## 5. Journey persistence and atomic consumption (decision 8)

### 5.1 Where records live

Journeys are stored in **one sealed file, `authority_dir/journeys.json`**. It sits beside
`authority.json` (`src/personal_accounts/storage.rs:58`) and uses the same private
directory rules (`storage.rs:295-305`). That directory's lifetime lock already covers
it (`claim_store`, `storage.rs:336-351`).

**Format**
- The envelope is the existing `TokenEnvelope` (`storage.rs:65-73`).
- It is sealed with the existing AES-256-GCM `seal_bytes` and the current store key.
- Schema is `personal_accounts.journeys.v1`.
- AAD is `encode_fields(b"mcp-gateway/account-journeys-aad/v1", [schema, key_id, instance_id, store_epoch])`, which mirrors `authority_aad` (`storage.rs:398-403`).
  - Binding `store_epoch` means a journeys file copied from another store, or from a re-initialised one, fails authentication.

**Why not inside `authority.json`**
- `Authority` is an existing versioned schema with `deny_unknown_fields` semantics.
- Adding journeys to it would force a migration of every store.
- It would also make every grant commit rewrite unrelated journey bytes.

**Missing file**
- A missing file means an empty table.
- This fails closed: an empty table knows no state digest, so every callback is refused as unknown.
- It also keeps existing stores working with no `init-store` change.
- An unreadable, unauthenticated or oversized file refuses every journey operation with `storage_unavailable`. It is never treated as empty.

**Size bound**
- `journeys_total * 1 KiB`, plus the measured envelope framing (the `record_file_limit` pattern, `storage.rs:572-599`).

```rust
// src/personal_accounts/journey/record.rs  (sealed plaintext, never logged: redacted Debug)
struct JourneyTable { journeys: BTreeMap<JourneyId, JourneyRecord> }   // JourneyId = 32 lowercase hex (random_hex)
struct JourneyRecord {
    owner_digest: String,            // AccountKey::digest() of the full account key
    account_id: String,              // descriptor id == AccountKey.backend_id
    descriptor_revision: String,     // migration_revision::descriptor_revision at creation
    issuer: String,                  // descriptor issuer, recorded for the RFC 9207 check
    expected: ConsentExpectation,    // captured from store lookup at creation (serde added)
    return_path: String,             // one of the configured allowlisted paths
    status: JourneyStatus,           // Pending | Started | Connected | Cancelled | Failed | Expired | Superseded
    reason: Option<JourneyReason>,   // closed enum, §7
    consumed: bool,
    state_digest: Option<String>,    // HMAC, set at start, kept until GC (replay detection)
    binding_digest: Option<String>,  // HMAC, only while Started
    principal_digest: String,        // per-principal limit key, §5.3
    pkce_verifier: Option<String>,   // plaintext only inside this sealed file; removed at terminal
    created_at: u64, expires_at: u64, terminal_at: Option<u64>,
    replay_refusals: u32,
}
```

The owner's raw subject is **not** stored. Owner equality always goes through the
digest (§4.2 step 6). `ConsentExpectation` (`src/personal_accounts/service.rs:112-117`)
gains `Serialize`/`Deserialize`. It only holds non-secret `GrantVersion` fields
(`src/personal_accounts/mod.rs:162-167`).

### 5.2 Locking and compare-and-swap

The journey table is kept in memory as `Option<JourneyTable>` inside the **same
`parking_lot::Mutex` as the authority**. `PersonalAccountStore.authority`
(`mod.rs:179-189`) becomes a struct `{ authority, journeys }`, still acquired only
through `lock_authority()` (`mod.rs:279-302`). That gives journeys the same poisoning
rule: a failed write after rename sets the slot to `None`, as `write_manifest` does
(`commit.rs:196-236`).

Journeys are written with the same scratch-file → `sync_all` → `rename` → directory
sync sequence as `write_manifest`. That sequence is factored into one private helper
parameterised by file name, not copied.

Every journey mutation is a single function running under one lock acquisition:

```rust
// src/personal_accounts/journey/store.rs  (methods on PersonalAccountStore)
fn journey_transition<T>(&self, now: u64,
    f: impl FnOnce(&mut JourneyTable, &Authority) -> Result<T, JourneyRefusal>)
    -> Result<T, JourneyError>
// 1. lock_authority()   2. expire every record with expires_at <= now (clears secrets)
// 3. f(table)           4. seal + write journeys.json   5. publish in-memory table
// 6. release.  f never performs IO; no network call ever runs under this lock.
```

**Atomic consumption** is one `journey_transition`. Under the lock it:
- finds the record whose `state_digest` equals `HMAC(state)`;
- checks the binding, status `Started`, `!consumed` and `now < expires_at`;
- sets `consumed = true`;
- takes the verifier out of the record, returning it to the caller;
- persists all of the above.

Only after that write has returned does the handler release the lock and POST the
code to the token endpoint.

**Consequences**
- Two racing callbacks serialise on the mutex. Exactly one sees `consumed == false`; the other is a replay.
- A crash after persist and before exchange leaves `consumed = true` with no verifier on disk. A replay after restart is therefore refused. This is C03's restart clause.
- A crash before persist leaves the journey `Started`. A later replay of the same URL can consume it once, which is still at most one exchange.

**Why commit re-locks.** The grant is committed through `commit_grant_if_unchanged`
(`src/personal_accounts/consent.rs:66-104`), which takes the lock again. The token POST
cannot run under a sync mutex. The generation fence (§6.3) is what makes the second
acquisition safe.

### 5.3 Limits (C06)

These are enforced inside `journey_transition` at creation. The limit names are the
ones already specified in the design's configuration table (`accounts.limits`):

| Limit | Default | Rule | Refusal |
|---|---|---|---|
| `journeys_total` | 1024 | Count of non-terminal records | 503 `capacity_exceeded`, `Retry-After` = seconds to the earliest `expires_at` |
| `journeys_per_user` | 8 | Non-terminal records with this `owner_digest` prefix set (see below) | 429 `rate_limited`, `Retry-After` as above |
| `starts_per_minute_per_user` | 10 | Creations in a sliding 60 s window, kept in memory only | 429 `rate_limited`, `Retry-After` = window remainder |
| one active per principal/account | — | A new creation marks the previous non-terminal record with the same `owner_digest` as `Superseded` and clears its secrets | none; this is not a refusal |

**Per-user counting.** `journeys_per_user` needs a per-principal key that does not
depend on the account. Records therefore also store
`principal_digest = SHA-256(len-prefixed authority, subject)`, using the
`mcp-gateway/journey-principal/v1` domain and the same length-prefix encoding as
`AccountKey::digest`.

**Capacity release.** Expiry releases capacity because step 2 of `journey_transition`
expires stale records before counting.

**Rate window.** The creation-rate window is in memory. A restart forgets it. That is
acceptable because it throttles and does not protect state.

## 6. Start, callback, exchange and commit (decisions 1, 3)

### 6.1 Authorize URL

This is a new pure function, `journey::authorize_url(descriptor, pinned, state, challenge) -> Url`.
It exists because `OAuthClient::build_authorize_url` (`src/oauth/client/mod.rs:697-728`)
cannot be reused, for three reasons:

- it is a private method on the legacy client;
- it always appends `resource`, ignoring the descriptor's required
  `send_resource_parameter` (`src/personal_accounts/config.rs:255-292`);
- its companion `generate_state` is 16 bytes (`client/mod.rs:1175-1178`), below the
  design's 256-bit floor.

**Parameters**

- `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge`,
  `code_challenge_method=S256`.
- `scope`: the descriptor scopes, space-joined.
- `resource`: only when `send_resource_parameter == Some(true)`.
- Values from a new descriptor field, `authorize_extra`. This is a **closed enum
  map**, not free-form text. The allowed keys are:
  - `access_type` = `offline` | `online`
  - `prompt` = `consent` | `select_account` | `none`
  - `include_granted_scopes` = `true` | `false`

**Why `authorize_extra` exists.** Without `access_type=offline`, Google issues no
refresh token, and element 3 (refresh) cannot pass live. Without `prompt=consent`,
a re-consent from `ReconnectRequired` or `Revoked` also omits the refresh token.
The Google descriptor in §10 therefore sets both.

**Endpoint.** The base URL is the **pinned** `authorization_endpoint` from
bootstrap. `accept_metadata` (`src/personal_accounts/provider.rs:453-483`) has
already checked it for equality with the configured value. It is never taken
from the request.

### 6.2 Callback

`GET /accounts/v1/callback?code|error&state[&iss]` runs these steps in order.
Every refusal renders one generic, sanitized page, reports status via the journey,
and exchanges nothing.

1. **Locate the journey.** Hash `state` and look up the record under
   `journey_transition`. A missing or unknown state gets `invalid_request`, and no
   record is touched.
2. **Check expiry.** If `now >= expires_at`, set `Expired`, reason `expired`, clear
   the secrets, and refuse (decision 5).
3. **Check for replay.** If `consumed` or status is terminal, increment
   `replay_refusals` and refuse. The status keeps its original terminal value, and
   the API adds `replay_refused: true`.
4. **Check the browser binding.** `HMAC(cookie)` must equal `binding_digest`. On a
   mismatch or a missing cookie, set `Failed`, reason `browser_mismatch`, clear the
   secrets, and refuse. This is terminal, so an attacker who holds the state cannot
   keep retrying.
5. **Handle a provider error** (§7). If `error` is present, set `Cancelled` or
   `Failed`, persist, and render the outcome page (step 12).
6. **Check the issuer.** Call `validate_issuer(iss, recorded_issuer)`
   (`src/oauth/client/mod.rs:88-100`, `pub`). A mismatch gives `Failed`, reason
   `issuer_mismatch`. The helper allows an absent `iss`, as RFC 9207 permits. The
   mix-up defence therefore does not depend on `iss`: the state is bound to one
   descriptor, and the code is only ever redeemed at that descriptor's **pinned**
   token endpoint. An attacker's code is sent to the endpoint that did not issue it,
   so it fails there.

   The same step also compares the journey's `descriptor_revision` with the
   current descriptor's. A mismatch (the config was replaced by a reload) ends the
   journey `Failed` with reason `config_changed`, and the code is never exchanged.
7. **Consume.** Set `consumed = true` and take the verifier out, in the same write
   (§5.2). Release the lock.
8. **Exchange** the code with
   `PersonalOAuthRefresh::exchange_code(account_id, code, verifier, redirect_uri)`,
   described below.
9. **Validate the grant.** Each of these is terminal `Failed` with the given reason,
   and nothing is committed:
   - The granted `scope` must be a superset of the descriptor scopes. If the
     response omits `scope`, the requested scopes are assumed (RFC 6749 §5.1).
     Otherwise: `scope_missing`.
   - `token_type` must be `Bearer`, compared case-insensitively. Otherwise:
     `unexpected_token_form`.
   - `access_token` must be non-empty. Otherwise: `unexpected_token_form`.
   - When `access_type=offline` is configured, a `refresh_token` is required.
     Otherwise: `no_refresh_token`.
10. **Audit.** Write `account_grant_attempt` through `audit_identity_propagation`
    (`src/identity_propagation/mod.rs:606-613`). After step 11, write
    `account_grant` or `account_grant_fenced`. That second write is best effort and
    only logged on failure, the same pattern the refusal audit uses
    (`invoke.rs:2964-2984`). If the pre-commit write
    fails, the journey is `Failed` with reason `audit_unavailable`, the gateway
    makes a best-effort provider revoke of the fresh token, and nothing is
    committed (C07).
11. **Commit** through `CustodyHandle::commit_grant_if(account, &journey.expected, record)`
    (`src/personal_accounts/worker.rs:254-265`). This gives it a production caller,
    so its `expect(dead_code)` and the one on `service.rs:335-342` are removed. The
    record carries:
    - `generation = random_hex()`;
    - `token_revision = 1`;
    - `authorization_epoch = 1`;
    - `descriptor_revision` from the journey;
    - sorted, deduplicated scopes.

    A `StaleConsentFenced` result gives `Failed`, reason `superseded_grant` (§6.3).
12. **Finish.** Set `Connected` and clear the secrets. The callback then **renders
    the sanitized outcome page itself** (200) and does not redirect again.

    The reason is Fetch Metadata: `Sec-Fetch-Site` describes the whole redirect
    chain. A second hop, Google → `/callback` → `/complete`, would arrive as
    `cross-site`. The origin guard would refuse it, and a `SameSite=Strict`
    Open WebUI cookie would be withheld.

    The page links to the journey's allowlisted `return_path` and to
    `/accounts/v1/complete`. The user clicks that link, which is a new same-origin
    navigation. No token appears in any URL, page or log.

    The same page renders every terminal outcome from steps 2–11, which
    satisfies C04's "display sanitized reason". This amends decision 3's
    "303 to completion page"; see §12 item 10.

**Exchange and revoke methods.** Both are new methods on `PersonalOAuthRefresh`
(`src/personal_accounts/provider.rs:232-258`). They reuse:

- the pinned metadata;
- `SecretSource`, for the client secret;
- the `ProviderHttp::post_token` seam (`provider.rs:108-121`).

That seam's doc changes to "form POST to a pinned credential endpoint (token or
revocation)". It remains the only credential-bearing call, so the existing
invariant that credentials go only through `post_token` still holds.

The exchange form is `grant_type=authorization_code`, `code`, `redirect_uri`,
`client_id`, `code_verifier`, the optional `client_secret`, and `resource` only if
`send_resource_parameter` is set. That is the same shape as
`token_exchange_params` (`client/mod.rs:735-757`), minus the unconditional
`resource`.

**Sharing the provider.** The provider is shared with custody as
`Arc<GatewayRefreshProvider>`. `start_custody_with_http`
(`src/personal_accounts/mod.rs:530-559`) keeps one `Arc` and passes a clone to
`CustodyHandle::start`, through `impl<T: RefreshProvider> RefreshProvider for Arc<T>`.
The journey therefore uses exactly the metadata snapshot that refresh uses.

### 6.3 Generation fence (C05)

`journey.expected` is `ConsentExpectation::captured(lookup)` at **creation time**.
The captured value is `Absent`, `Connected(v)`, `Revoked(v)` or
`ReconnectRequired(v)`; `captured` is at `service.rs:121-133`, and the lookup is
`PersonalAccountStore::lookup`, `mod.rs:306-313`.

`commit_grant_if_unchanged` compares that value with the live state under the
lock (`consent.rs:84-100`). It returns `Fenced` if any of these happened after the
journey was created:

- a revoke;
- another journey's commit;
- a refresh (which bumps `token_revision`);
- an `invalid_grant` fence.

Revoke deliberately does **not** cancel pending journeys. The fence is the only
mechanism that stops a stale callback. That keeps C05's mutation test honest
(§11.2, T-C05a).

**Trade-off.** A refresh between creation and callback fences a re-consent that
started from `Connected`. The user sees "account changed while you were
connecting; retry". That is the conservative outcome, and the one the design
requires: the newest generation wins.

### 6.4 Router mounting and origin guard

**Mounting in `create_router_with`** (`src/gateway/router/mod.rs:212`):

- **Owner API routes.** `POST /accounts/v1/journeys` and
  `GET /accounts/v1/journeys/{id}` join the authenticated `routes` chain
  (`mod.rs:256-274`). They sit behind `auth_middleware` and the Open WebUI adapter
  layer (`mod.rs:301-314`).
  - The principal comes only from the `VerifiedIdentity` extension set by the
    adapter (`src/gateway/openwebui_adapter.rs:313-314`).
  - Request bodies use `deny_unknown_fields`. A `principal` field is therefore
    rejected as an unknown field.
- **Browser routes.** `start`, `callback` and `complete` form one `Router` merged
  after the auth layer, alongside the other unauthenticated merges
  (`mod.rs:317-341`). Their authentication is the §4 bridge plus the §6.2
  state/binding checks.
- **`DELETE /accounts/v1/connections/{account_id}`** is mounted **once**, in the
  browser-route router, outside `auth_middleware`. Mounting it twice would be an
  overlapping path and method, which axum's `Router::merge` rejects.

  The handler authenticates explicitly, in this order:
  1. It runs the existing API-key-plus-adapter verification, invoking the same
     functions the middleware uses.
  2. Otherwise it runs the §4 bridge.
  3. If both credentials are present, it refuses.

  See §8.3.
- **Feature flag.** With `accounts.hosted` absent, none of these routes are mounted.
  They return the router's normal 404.

**Two scoped changes in `origin_guard_middleware`**
(`src/gateway/router/origin_guard.rs:317-405`):

1. **Hosted Host.** `host_allowed` (`:203-233`) additionally accepts the host of
   `accounts.hosted.public_origin`, **only when** the path starts with
   `/accounts/v1/`.
   - Without the path condition, `/mcp` would become reachable on the Open WebUI
     origin.
   - `origin_allowed` gets the same path-scoped addition. Same-origin `DELETE`
     from the completion page then carries `Origin: https://chat.raxor.ai` and is
     accepted.
2. **Callback navigation exemption.** The `Sec-Fetch-Site` refusal (`:362-374`)
   is skipped only when **all** of these hold:
   - method is `GET`;
   - path equals exactly `/accounts/v1/callback`;
   - `Sec-Fetch-Mode: navigate`;
   - `Sec-Fetch-Dest: document`.

   The `Origin` check still runs, and so does the Host check (under rule 1). The
   existing `Origin: null` refusal test (`src/gateway/router/tests.rs:2437-2446`)
   and the cross-site `no-cors` refusal (`:2421-2434`) must stay green, and
   T-GUARD below extends them.

## 7. Cancellation, provider errors, expiry, replay (decisions 4, 5; BC-2)

**Error mapping at callback step 5.** Every row produces a terminal journey,
clears its secrets in the same write, and renders the outcome page (§6.2 step 12). The page
shows only the sanitized reason and "retry the tool call to reconnect".

| Provider `error` | Journey status | `reason` (closed enum `JourneyReason`) |
|---|---|---|
| `access_denied` | `cancelled` | `user_denied` |
| `consent_required`, `interaction_required`, `login_required`, `account_selection_required` | `cancelled` | `consent_not_completed` |
| `temporarily_unavailable`, `server_error` | `failed` | `provider_unavailable` |
| anything else | `failed` | `provider_error` |

What is **not** carried:

- `error_description` and `error_uri`, in any status, page or log;
- the raw `error` string. It is only matched against the table.

Nothing is committed, so an existing grant is unchanged by construction.

**BC-2 decision.** Declined consent becomes distinguishable through the **journey
record**, and `AccountLookup::Absent` keeps its meaning. The alternative, a
`Declined` store state, is rejected for three reasons:

- `Absent` is the only state that expects a first grant.
  `ConsentExpectation::Absent` is what a first grant is committed against
  (`src/personal_accounts/service.rs:121-133`, `consent.rs:88`). A declined state
  would need a new expectation arm, and a manifest schema change in
  `personal_accounts.authority.v1`, for information that is about an attempt and
  not about a grant.
- Declining must not change a *connected* account. A store-level state would have
  to coexist with `Connected`, which the one-state-per-entry manifest
  (`AuthorityEntry.state`, `mod.rs:202-219`) cannot express.
- The design already assigns the attempt outcome to the journey status: its
  status values include "cancelled".

The observable answer to "was consent declined?" is therefore
`GET /accounts/v1/journeys/{id}` returning `status: "cancelled"`, and the completion
page. Both stay queryable for 24 h after the terminal transition (§3).

**Expired and replayed callbacks** (decision 5) are §6.2 steps 2–3:

- Either one is refused before any exchange.
- A replay increments `replay_refusals`. The status API reports
  `{status: <original terminal status>, replay_refused: true}`, and
  `{status: "expired"}` for a late callback.
- A replay after restart is refused, because `consumed` is durable (§5.2).

## 8. Revoke (decision 7)

### 8.1 Local tombstone with token capture

`commit::revoke` deletes the record file after it writes the tombstone
(`src/personal_accounts/commit.rs:484-505`). After it returns, the refresh token is
gone, so the provider can no longer be told.

The fix is a new store method, `PersonalAccountStore::revoke_capturing(account) -> Result<Option<RevocationMaterial>, AccountError>`.
Under **one** `lock_authority()` acquisition it:

1. calls `storage::lookup`;
2. if the result is `Connected(record)`, copies `refresh_token` (or `access_token`
   when there is no refresh token) into
   `RevocationMaterial { token: Zeroizing<String>, hint }`, with a redacted `Debug`;
3. calls the existing `commit::revoke`.

`Revoked` and `Absent` stay idempotent no-ops (`commit.rs:490-495`) and return
`None`. `ReconnectRequired` is tombstoned. A record that still exists is captured,
and one that does not returns `None`.

The chain `CustodyHandle::invalidate` → `AccountService::invalidate` →
`PersonalAccountStore::revoke` (`src/personal_accounts/worker.rs:241-245`,
`service.rs:326-329`, `mod.rs:355-360`) is re-pointed at `revoke_capturing` and
returns the material. Its three `expect(dead_code)` attributes are deleted, because
the DELETE route is now a production caller.

### 8.2 Sequence for `DELETE /accounts/v1/connections/{account_id}`

1. **Resolve the caller.** The principal comes from verified auth (§8.3). The
   account key is `identity::account_key(Some(principal), descriptor)`
   (`src/personal_accounts/identity.rs:195-219`). An unknown `account_id`, or a
   descriptor that is not managed, returns `not_found`. Because the key is built
   from the caller's own principal, A's DELETE can only ever name A's key. B's
   entry has a different digest and cannot be addressed.
2. **Tombstone.** Call `custody.invalidate(&key)`. On a store failure return
   `storage_unavailable` (503). Nothing else is attempted.
3. **Invalidate connections.** For every backend bound to `account_id`, call
   `Backend::evict_identity_slots(&format!("acct:v1:{digest}:"))`
   (`src/backend/pool.rs:384`). The prefix is the stable head of `cache_binding`
   (`src/personal_accounts/vault.rs:311-327`), and the loop is the same one
   `config_reload` uses (`src/config_reload/mod.rs:1852`).
   - Response and idempotency cache entries need no sweep. They are keyed on a
     `cache_binding` that includes the generation. After the tombstone, no lease
     can be issued for that generation (`AccountLookup::Revoked`), so those
     entries can never be read again and age out on TTL.
   - Leases already prepared fail recheck (`vault.rs:293-300`). That is the tested
     revocation-after-prepare path (`account_rest_tests.rs:587`).
4. **Audit.** Write `account_revoke`. If the write fails, the response is 503
   `audit_unavailable` with `local_status: "revoked"`, as the design's error
   envelope specifies. The tombstone stays.
5. **Provider revocation.** If `revocation_endpoint` is pinned and material was
   captured, call
   `PersonalOAuthRefresh::revoke_token(account_id, token, hint)`. It POSTs
   `token`, `token_type_hint` and client authentication to the pinned endpoint
   (RFC 7009), through `post_token`. The result maps to `provider_revocation`:

   | Outcome | `provider_revocation` |
   |---|---|
   | HTTP 200 | `confirmed` |
   | Any other status or transport error | `failed` |
   | No endpoint configured | `unsupported` |
   | Nothing to revoke (already revoked, or absent) | `not_applicable` |

   A provider failure never un-tombstones.
6. **Respond.** 200
   `{schema_version, account_id, status: "revoked", provider_revocation}`.

**Route-table amendment (explicit).** The design's enum is
`confirmed/pending/unsupported`. `pending` promises a retry that this increment
does not build. It is replaced by `failed`, and `not_applicable` is added.

### 8.3 Who can call DELETE, and how an Open WebUI user reaches it

**API credential.** A caller holding the API key plus a verified adapter assertion
is authenticated by the handler. It calls the same verification functions as the
auth and adapter middleware, because the route is mounted once, outside that
chain (§6.4).

**Browser credential.** An Open WebUI user has no gateway API key, and only Open WebUI
can mint the adapter assertion. L03 needs a user-reachable revoke, so DELETE also
accepts a bridge-verified browser session. It runs the §4.2 steps 2–5 and derives
the principal from the Open WebUI session, under these rules:

- `Origin` is required and must equal `accounts.hosted.public_origin`.
- `Sec-Fetch-Site` must be `same-origin`.
- There is no CORS allowance, so a cross-origin `DELETE` fails its preflight.
- A request carrying both credentials is refused, following the same
  no-conflicting-identity rule as `src/gateway/openwebui_adapter.rs:296-301`.

**The trigger** is the completion page `GET /accounts/v1/complete`, which is
bridge-authenticated. For each managed descriptor it shows the caller's own
connection status and a "Disconnect" button. The button is wired by the single
same-origin static script `GET /accounts/v1/assets/complete.js`, which issues
`fetch(url, {method: "DELETE", credentials: "same-origin"})`. A plain HTML form
cannot send DELETE, which is why the script exists. The page is linked from
every connect result and reachable directly at
`https://chat.raxor.ai/accounts/v1/complete`.

## 9. Connect offer on refusals (decisions 6, 10; BC-1)

### 9.1 Typed refusal

`refusal()` in `src/personal_accounts/vault.rs:72-79` currently lifts only
`ConnectOffer` into a typed error. It will also lift `Revoked` and
`ReconnectRequired`:

```rust
// src/identity_propagation/mod.rs (PropagationError is already #[non_exhaustive], :130)
AccountNotConnected(String),                    // existing; doc drops "Not an offer"
AccountReconnectRequired { revoked: bool, message: String },   // new
```

The comment at `vault.rs:55-71` says Revoked and ReconnectRequired stay `Refuse`
because "none of them is remedied by connecting an account". That is no longer
true: a journey is exactly that remedy. The comment is rewritten, and the
store-failure invariant it protects is kept, since store errors still map to
`Refuse`.

At the three **dispatch** refusal sites, each typed variant becomes
`Error::JsonRpc { code, message, data }` (`src/error.rs:208-215`). The sites are:

- **MCP meta invoke.** The `refuse` closure in
  `src/gateway/meta_mcp/invoke.rs:2964-2990` / `:3083`, as reached from
  `invoke_tool_traced` at `:1630`.
- **Direct route.** `src/gateway/router/backend_handlers.rs:719-729`. The refusal
  is emitted at `:814-819` with `-32003`.
- **REST capability.** `src/identity_propagation/account_strategies.rs:438-452`,
  reached through `resolve_capability_account_credential`
  (`invoke.rs:3161`).

`data` is:

```json
{"schema_version":"accounts.v1",
 "error":{"code":"account_not_connected|reconnect_required","message":"…","retryable":false,
          "correlation_id":"…"},
 "account_id":"google-workspace",
 "connect_url":"https://chat.raxor.ai/accounts/v1/journeys/<id>/start"}
```

**JSON-RPC codes.**
- The MCP meta route and the capability route use `-32001`, per the design.
- The direct route keeps its existing `-32003`/HTTP 403 (`backend_handlers.rs:814-819`), so its current clients are not broken. `build_http_error_response` gains a `data` argument.
- This per-route split is stated explicitly; see §12.

**Refusal text.** The existing refusal message text is kept, and the URL is
appended: `… connect your account: <connect_url>`. Open WebUI's native MCP client
may pass only the message to the model and drop `error.data`. A link alone never
authenticates, because of the §4 bridge, so putting it in the text is safe. L02
records whether the user actually saw a clickable link.

**Catalogue path.** The same typed error also reaches the shared
`resolve_propagation_credential` (`invoke.rs:2891-2908`). That function serves
both the direct route and the catalogue (`src/gateway/meta_mcp/discovery_fetch.rs:49`).
The offer is therefore **not** minted inside it. See §9.2.

### 9.2 Where an offer may be minted: the BC-1 rule

**Definition.** `offer_for(caller, backend, refusal) -> Option<Url>` lives on
`JourneyService`. It is the only function that creates a journey on a caller's
behalf. It is called from exactly three places: the three dispatch sites in §9.1,
after they have decided to refuse.

A `connect_url` is disclosed **iff all** of the following hold:

1. **D, dispatch-site predicate.** The request is a dispatch that names backend `X`
   explicitly, and every existing gate that runs before credential resolution has
   already passed for this caller. The call site guarantees this: the offer is
   computed at the exact point where the refusal is raised today. Whatever gates
   run before credential resolution (the capability kill switch at
   `invoke.rs:1593-1607`, and `refuse_unbound_account_backend` at `:1633`) pre-empt
   it.
2. **R, refusal-type predicate.** The refusal is the typed account state for the
   caller's **own** `AccountKey`: `AccountNotConnected` or
   `AccountReconnectRequired`. These never apply:
   - `Refuse` (store failure, busy, shutdown, missing principal);
   - `Misconfigured`;
   - `AuditFailed`;
   - the INV-2 isolation refusal (`invoke.rs:1635-1660`).
3. **B, bridge predicate.** The principal is `Principal::Verified`, its authority
   is `namespaced_issuer(installation_id)` for an adapter with a configured
   `session` block, and `accounts.hosted` is configured.
4. **C, catalogue-intersection predicate.** No catalogue site mints or carries an
   offer. A backend's *presence* in any listing is governed by the intersection of
   the two existing predicates:
   - the caller-aware `!meta_route_isolation_refused_for_caller(b, binding)`
     (`src/gateway/meta_mcp/mod.rs:1267-1275`);
   - the caller-blind `!meta_route_isolation_refused(b)` (`mod.rs:1211-1212`).

   Both go through `enforce_oauth_isolation_for` (`mod.rs:1125`). On a multi-user
   gateway the caller-blind predicate is false for every personal-account backend
   (the `account_descriptor_id` arm, `mod.rs:1151-1164`). So the intersection is empty
   for such backends, and a catalogue offer would disclose presence that eleven
   sites deliberately withhold.

**The sites that must never mint or carry an offer.** At the tip there are 5
caller-aware sites and 11 caller-blind sites.

- **Caller-aware (5).**
  - `search.rs:183`, `:279`, `:639`, `:713`.
  - `discovery_fetch.rs:75`, via `catalogue_credential_for`, which is used at
    `protocol.rs:165` and `resources.rs:301`, `:413`.
- **Caller-blind (11).**
  - `protocol.rs:263`, `:319`.
  - `resources.rs:381`, `:457`, `:503`, `:540`.
  - `spec_preview.rs:92`, `:185`, `:240`.
  - `surfaced.rs:142`.
  - `mod.rs:1478`.

Why D ∧ R ∧ B adds no presence disclosure: the refusal already names the backend
the caller asked for. The message is `identity propagation required for backend
'{server}' but …` (`invoke.rs:2985-2987`). A caller who names an unknown backend
already gets a different error. The offer adds exactly two things:

- the descriptor id `account_id`;
- a URL to a journey bound to the caller's own principal.

Neither reveals anything about any other principal.

The single-predicate implementation that BC-1 warns against is gating on the
caller-aware predicate at a catalogue site. It is excluded structurally, because
`offer_for` has no catalogue caller. It is also excluded by test (T-BC1).

### 9.3 Offer reuse and creation cost

`offer_for` reuses the caller's journey for that account only when it is still
`pending` and has at least 120 s left. Otherwise it creates a new journey, which
supersedes the predecessor.

A `started` journey is never reused. Otherwise a double-click, or a Back after
reaching Google, would hand the user a link that `start` refuses. The owner can
also re-run `start` on their own `started` journey. That rotates the state, binding
and verifier, and invalidates the earlier authorize URL.

Reuse avoids a durable write on every refused call.

Limit refusals from §5.3 degrade the result. The typed refusal is still returned,
with no `connect_url`, and `data.error.retryable = true` plus `retry_after`.

### 9.4 URL-mode elicitation: not in this increment

The capability plumbing exists. `ElicitationCreateParams` carries `mode`/`url`
(`src/protocol/messages.rs:513-529`), and `Declared` tracks URL mode
(`src/protocol/meta.rs:438-443`). The gateway also has a session-scoped sender
(`src/gateway/proxy.rs:274-330`).

It is still deferred, for three reasons:

1. The refusal carries the same URL, and it is the baseline every client receives.
2. Elicitation adds a server-initiated request with its own 120 s-timeout path
   (`src/gateway/destructive_confirmation.rs:65`). That is a second delivery channel
   to test, and it needs a live check of whether Open WebUI 0.9.6 even declares URL
   mode.
3. Nothing in C01–C07, A07 or L01–L04 requires it.

It can be added later without changing any contract here.

### 9.5 Security argument per threat

| Threat | Defence | Where |
|---|---|---|
| Stolen `connect_url` | A link is not authentication. `start` requires an Open WebUI session whose namespaced id matches the owner digest. | §4.2 steps 2–6 |
| Wrong browser (A starts, B's browser finishes) | Binding cookie digest checked at callback. A mismatch is terminal `failed`. | §4.2 step 7, §6.2 step 4 |
| Login CSRF / forced consent into an attacker's account | Callback requires the victim's binding cookie, which only `start` in the victim's own session sets. A flow started by the attacker binds to the attacker's browser. | §6.2 step 4 |
| CSRF on DELETE | Non-simple method, `Origin` required and equal to the hosted origin, `Sec-Fetch-Site: same-origin`, no CORS | §8.3 |
| Open redirect | Redirect targets are the pinned authorize endpoint and the fixed `/accounts/v1/complete`. `return_path` is matched against the configured allowlist exactly, never a URL. | §6.1, §6.2 step 12, §10 |
| Replay | Durable `consumed` flag, set before exchange | §5.2, §6.2 step 3 |
| Race (two callbacks) | Consumption runs under the authority mutex, so exactly one wins | §5.2 |
| Restart | `consumed` and verifier removal are persisted before the network call | §5.2 |
| Issuer mix-up | `validate_issuer` on a present `iss`. State is bound to one descriptor, and the code is redeemed only at the pinned token endpoint. | §6.2 step 6 |
| Scope downgrade | Granted scopes must be a superset of the descriptor's, or the grant is not committed | §6.2 step 9 |
| Stale generation | `commit_grant_if` against the expectation captured at creation | §6.3 |
| Token leakage (URLs, logs, pages) | No token in any response. Query strings are not traced. `GrantRecord`/`RevocationMaterial` have redacted `Debug`. Provider `error_description` is dropped. | §4.3, §6.2, §7 |
| Open WebUI token leakage | One outbound use only. Never stored, logged or forwarded. Serde drops profile fields. Gateway pages carry a CSP with no inline script. | §4.2 steps 3–4, §4.3 |
| Disclosure via `connect_url` | Predicate D ∧ R ∧ B, never minted at the 16 catalogue sites | §9.2 |
| Principal forgery in request body | `deny_unknown_fields`. The principal comes only from verified auth or the bridge. | §6.4 |
| Host confusion (`/mcp` on the Open WebUI origin) | The hosted Host is accepted only under `/accounts/v1/` | §6.4 |
| Resource exhaustion | `journeys_total`, `journeys_per_user`, `starts_per_minute_per_user`, and the sealed file size bound | §5.3 |

## 10. Configuration (decision 9)

New optional block `accounts.hosted`, plus two additions to existing types. All new
structs use `deny_unknown_fields`, so an unknown field rejects startup, as
`AccountsConfig` already does (`src/personal_accounts/config.rs:190-225`).

**Omission is a no-op.** If `accounts.hosted` is omitted, no route is mounted, the
origin guard is unchanged, no offer is minted, and refusal text is byte-identical
to today's.

```yaml
accounts:
  # ...existing fields unchanged...
  hosted:                                   # new, optional
    public_origin: "https://chat.raxor.ai"  # https, origin only (no path/query/userinfo)
    return_paths: ["/"]                     # nonempty, absolute paths, exact match
  limits:                                   # AccountsLimits gains the three names the
    journeys_total: 1024                    # design's table already fixes (config.rs:306-312
    journeys_per_user: 8                    # currently carries only store_entries and
    starts_per_minute_per_user: 10          # authority_bytes)
  adapters:
    - kind: openwebui_signed_header         # existing fields unchanged
      installation_id: spark-owui
      # ...
      session:                              # new, optional: enables the browser bridge
        user_endpoint: "http://127.0.0.1:8090/api/v1/auths/"   # https, or http on loopback literal
        cookie_name: "token"
  descriptors:
    google-workspace:
      mode: personal_managed
      provider: google
      issuer: "https://accounts.google.com"
      resource: "https://www.googleapis.com/"
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth"
      token_endpoint: "https://oauth2.googleapis.com/token"
      revocation_endpoint: "https://oauth2.googleapis.com/revoke"
      client_id: "<web client id>"
      client_secret_ref: "env:GOOGLE_OAUTH_CLIENT_SECRET"
      redirect_uri: "https://chat.raxor.ai/accounts/v1/callback"
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"]
      send_resource_parameter: false
      authorize_extra: { access_type: offline, prompt: consent }   # new, closed enum map
```

**Validation, run in `resolve`** (`config.rs:443-551`) from
`Config::validate_with_env` (`src/config/mod.rs:813-838`):

- **Callback path.** For every `personal_managed` descriptor,
  `redirect_uri == public_origin + "/accounts/v1/callback"`. This needs no separate
  callback-path field, because the descriptor's `redirect_uri` is already the
  "exact HTTPS callback" in the design's configuration table. It closes the gap
  noted in the accounts map: `redirect_uri` is currently validated but read by no
  runtime code.
- **Adapter session.** `hosted` requires at least one adapter with a `session`
  block.
- **Limits.** The three limit fields reject zero and overflow, matching the rule
  that `AccountsLimits` applies today (`config.rs:306-321`).
- **Secrets.** The client secret stays an `env:` reference, resolved late through
  `SecretSource` (`src/personal_accounts/provider.rs:147-170`).

## 11. Test plan

### 11.1 Fixtures (in-process, no new crates)

There are no mock crates (`Cargo.toml:170-176`). Every fake below is an in-process
axum server on `127.0.0.1:0`.

**Fake authorization server (HTTPS).**
- It extends the rustls loopback fixture in
  `src/personal_accounts/provider/wire_tests/fixture.rs:106-296`.
  - That fixture is `pub(super)` today. It moves to a `#[cfg(test)]` module at
    `src/personal_accounts/provider/test_support.rs`, visible as
    `pub(in crate::personal_accounts)`.
  - This is a test-only visibility change. It is listed in §12.
- The client is `GatewayProviderHttp::for_test` (`http.rs:88-93`) with the
  fixture CA added. That is the existing pattern in
  `wire_tests/gateway.rs:153` and `:265`.
- Endpoints:
  - `/.well-known/openid-configuration`
  - `/token`: scripted responses for `authorization_code`, with a recorded
    request log
  - `/revoke`: scripted as 200, 400 or 503
- The authorize step is not served. A test reads the 303 `Location` from `start`,
  asserts its query, and builds the callback URL itself, which is what a browser
  would do after consent.

**Fake Open WebUI session endpoint (plain HTTP, loopback).**
- `GET /api/v1/auths/` maps `Bearer <t>` to a scripted
  `{id, expires_at, token, email, name, role}`.
  - The extra fields are present deliberately, to prove they are dropped.
- It can also answer 401, 500, slow (beyond the 5 s timeout) or oversize.
- It records every `Authorization` value it receives.

**Gateway harness.**
- The real `create_router_with` from `test_router_app_state*`
  (`src/gateway/router/tests.rs:86-571`).
- A real store in a `TempDir`, as in `account_resolver_fixture.rs:289-300`.
- A signed-assertion helper for the adapter header, as in the existing
  `openwebui_adapter` tests.
- Browser headers are set explicitly (`router/tests.rs:2426-2458`).

**Store probes.**
- The existing lock witness (`consent.rs:132-`) and `store_probe`, which count
  real acquisitions.

### 11.2 Automated cases

Each row gives:
- why it fails against today's tree ("today");
- the decisive assertion;
- the named mutation the test must catch.

"Exchange count" means the number of requests at the fake AS `/token` for the
`authorization_code` grant type.

| ID | Case (test-plan ref) | Today | Decisive assertion | Mutation caught |
|---|---|---|---|---|
| T-C01 | A creates a journey (POST with adapter assertion), `start` with A's Open WebUI cookie, then callback with code and state (C01, connect) | 404 on `/accounts/v1/journeys` | 303 to the pinned authorize URL with S256, a 43-char state and no `resource`. Then the callback returns 200 with the outcome page (no 3xx). Exchange count 1. Store `lookup(A)` is `Connected`, `lookup(B)` is `Absent`. Status JSON has no `access_token`/`refresh_token` key and no token substring. | Commit keyed on the adapter principal instead of the journey owner. `resource` sent despite `false`. |
| T-C01b | The committed grant is used: `gateway_invoke` as A reaches the capture backend with A's token (use) | No grant can be created | Captured `Authorization` equals the exchanged access token. B gets a refusal with zero dispatches. | Cache binding not per principal |
| T-REF | The exchanged grant expires (fixed clock), then invoke as A (refresh) | No grant from a code | One refresh POST to the fake `/token`, and the rotated token reaches the backend | `access_type=offline` dropped (fake AS issues no refresh token). The journey must then be `failed/no_refresh_token`, asserted in T-C05c. |
| T-C02a | A's link, `start` with B's Open WebUI cookie (C02) | 404 | Refusal page. No `Set-Cookie`. Journey still `pending`. Zero `/token` requests. | Owner comparison removed, or compares only `installation_id` |
| T-C02b | `start` with no cookie. `start` with two `token` cookies. | 404 | Refused. Fake Open WebUI receives zero calls on the missing-cookie path. | Absence treated as "no check" |
| T-C02c | A's journey, correct state, B's binding cookie or no cookie (swapped cookie) | 404 | `failed/browser_mismatch`. Exchange count 0. A second attempt with the right cookie is also refused (terminal). | Binding check skipped when the cookie is absent |
| T-C02d | Cross-origin `start`/DELETE (`Sec-Fetch-Site: cross-site`, or `Origin: https://evil`). POST body with a `principal` field. | 404 | 403 from the origin guard for start/DELETE. 400 `invalid_request` for the body. | Exemption widened to all `/accounts/v1/*` |
| T-A07 | Email-only match: the fake Open WebUI returns A's email with a different `id`. A link opened with no Open WebUI session. | 404 | Both refused before any provider redirect | Principal derived from `email` |
| T-C03a | Callback after `expires_at` (fixed clock +301 s) (C03, expired) | 404 | Status `expired`. Exchange count 0. `lookup` unchanged. | Expiry compared with `>` against the wrong field, or checked after consume |
| T-C03b | Same callback URL twice (replayed) | 404 | Second: exchange count stays 1, `replay_refused: true` | `consumed` set after exchange instead of before |
| T-C03c | Two concurrent callbacks, one held at the fake `/token` by the fixture `Pause` | 404 | Exactly one exchange. The other is refused as a replay. | Consume split into read-then-write across two lock acquisitions |
| T-C03d | Consume, then crash before exchange (`faults` boundary); custody `shutdown` (`worker.rs:273-292`) releases the file locks; reopen, replay | 404 | Refused. Exchange count 0. The journeys file on disk has no verifier. | `consumed` kept in memory only |
| T-C03e | `iss` mismatch. `redirect_uri` changed by a config reload between start and callback (replaced config). | 404 | `failed/issuer_mismatch`, exchange 0. Replaced config: `descriptor_revision` differs, so `failed/config_changed`, exchange 0. | `validate_issuer` call removed |
| T-C04a | A already connected at gen1. A new journey is created. Callback returns `error=access_denied&error_description=<marker>` (C04, cancellation) | 404 | Status `cancelled`, reason `user_denied`. `lookup(A)` is still `Connected(gen1)`, with a byte-identical record file. `<marker>` appears in no response, page or captured log. | Cancel path commits or fences the existing grant |
| T-C04b | `error=server_error`; unknown error code | 404 | `failed/provider_unavailable`, `failed/provider_error`. The grant is unchanged. | Raw `error` string echoed |
| T-C04c | Persistence after connect, cancel, error and expiry: decrypt `journeys.json` with the test key | No file exists | For every terminal record, `binding_digest` and `pkce_verifier` are `None`, and no raw state, code or token byte appears in the plaintext. Status is still queryable. | Secrets cleared only on success |
| T-BC2 | Never-attempted vs declined: B with no journey vs B after `access_denied` | Indistinguishable (`Absent` either way) | `lookup` is `Absent` in both. The status API distinguishes them: `404 not_found` vs `cancelled`. | — (pins the BC-2 decision) |
| T-C05a | Connected at gen1. A journey is created (expects `Connected(gen1)`). DELETE revokes. The journey is NOT cancelled. Callback. (C05, stale generation) | 404 | `failed/superseded_grant`. `lookup(A)` is `Revoked`. Exchange count 1 (the fence acts after the exchange). | Commit via unconditional `commit_grant` |
| T-C05b | Two journeys for different accounts of A. Re-consent on one. Callback of the older stale journey for the same account. | 404 | Fenced. The newer generation survives. | Expectation captured at callback time instead of creation |
| T-C05c | Fake `/token` returns fewer scopes; `token_type=mac`; no `refresh_token` with `access_type=offline` | 404 | `failed/scope_missing`, `failed/unexpected_token_form`, `failed/no_refresh_token`. Nothing committed. | Scope check uses intersection instead of superset |
| T-C06a | Nine creations for one principal (`journeys_per_user`=8), with a fixed clock | 404 | The 9th gets 429 `rate_limited` with `Retry-After`. After expiry (+301 s), creation succeeds. | Expiry sweep not run before counting |
| T-C06b | `journeys_total` = 2, three principals | 404 | Third gets 503 `capacity_exceeded` with `Retry-After` | Global bound unchecked |
| T-C06c | A has a pending journey for account X, and B has one for X. A creates a new one for X. | 404 | A's old journey is `superseded`, A's journey for account Y is untouched, and B's journey is untouched. | Supersede keyed on `account_id` only |
| T-C07a | Anonymous status and DELETE; B asks for A's journey status; B calls DELETE with A's `account_id` | 404 | 401 for anonymous. `not_found` for B's status request, with no `account_id` in the body. B's DELETE revokes only B's own key (a no-op), and A stays `Connected`. | Status lookup without an owner check |
| T-C07b | Transparency logger fails on write (grant) | 404 | `failed/audit_unavailable`. Nothing committed. Fake `/revoke` receives the fresh token once. | Audit after commit |
| T-C07c | Logger fails on revoke | Unreachable (no route) | 503 `audit_unavailable`, `local_status: "revoked"`, and `lookup` is `Revoked` | Tombstone rolled back on audit error |
| T-REV | A and B connected. A calls DELETE through the browser credential (bridge cookie plus `Origin`) (revoke) | No route | 200 `provider_revocation: confirmed`. Fake `/revoke` got A's refresh token. `lookup(A)` is `Revoked`, `lookup(B)` is `Connected`. A's invoke gives `reconnect_required` with a `connect_url`, and B's invoke dispatches. The `evict_identity_slots` count for A's prefix is ≥ 1 after a prior A call. | Capture after the tombstone (the token is gone, so `not_applicable`) |
| T-REV2 | Fake `/revoke` returns 503 | No route | 200, `provider_revocation: failed`, and still `Revoked` locally | Provider failure un-tombstones |
| T-OFFER | Unconnected A calls `gateway_invoke`, the direct `/mcp/{backend}`, and a capability tool | Refusal with no `data` | Each error carries `data.error.code == "account_not_connected"`, `connect_url` starting with `public_origin`, and the URL in `message`. At most one journey is created (reused). | Offer minted in `resolve_propagation_credential` (T-BC1 then fails) |
| T-OFFER2 | Same, but with an OIDC-verified principal, and with `accounts.hosted` absent | Refusal, no data | No `connect_url`. With hosted absent, the message is byte-identical to today's text. | Predicate B dropped |
| T-BC1 | Unconnected A calls every catalogue method: `gateway_search_tools`, `gateway_list_tools` (single and all), `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`, `resources/read`, `prompts/get`, `logging/setLevel`, the spec preview, surfaced tools | n/a | Zero journeys created (store probe). No response contains `accounts/v1`. | Offer attached at any of the 16 sites |
| T-GUARD | Callback with `Sec-Fetch-Site: cross-site, Mode: navigate, Dest: document`; the same with `Mode: cors`; the same path with POST; `/mcp` with `Host: chat.raxor.ai` | Callback 403; `/mcp` 403 | Only the first passes the guard. `/mcp` is still 403 on the hosted host. The existing `Origin: null` test stays green. | Exemption by prefix, or Host allowed globally |
| T-GUARD2 | The callback outcome page is the landing step. Send a `cross-site` navigate callback. Separately, send a direct `cross-site` request to `/accounts/v1/complete`. | n/a | The callback returns 200 with the outcome HTML and **no** 3xx. The direct `/accounts/v1/complete` request is still 403. | Callback 303s to `/complete` (the guard refuses the second hop) |
| T-LEAK | `tracing` capture layer across T-C01 and T-REV | n/a | No captured event contains the Open WebUI token, code, state, verifier, access or refresh token, or `email` | Default `TraceLayer` applied to `/accounts/v1` |
| T-CFG | Unknown field under `hosted`/`session`; `redirect_uri` ≠ origin + callback path; `http` non-loopback `user_endpoint`; omitted `hosted` | n/a | The first three reject startup. Omitted `hosted`: route 404, and the refusal text is unchanged. | `deny_unknown_fields` missing |

Element coverage:
- connect: T-C01, T-OFFER
- use: T-C01b
- refresh: T-REF
- revoke: T-REV, T-REV2, T-C07c
- browser cancellation: T-C04a, T-BC2
- expired/replayed: T-C03a–d

### 11.3 Verifying the tests can fail

Each slice lands its tests red first, recorded in the PR against the parent commit.

For the mutations in the table, delete the named branch, confirm the test goes red,
and restore it. `cargo mutants` is not assumed to be installed.

The C05a design is deliberate. Revoke does not cancel journeys, so the fence is the
only barrier that can make the test pass. Swapping `commit_grant_if` for
`commit_grant` must turn it red.

### 11.4 Live run on Spark (L01–L04)

**Operator prerequisites.** Only the operator can supply these.

1. **Google Cloud OAuth client.**
   - Type: "Web application".
   - Authorized redirect URI: exactly `https://chat.raxor.ai/accounts/v1/callback`.
   - Consent screen: in "Testing" status, listing the two test accounts as test
     users.
   - Record the project ID and the client revision.
2. **Two designated Google test accounts, A and B.** Each gets one seeded
   discriminator message, for example the subject `JOURNEY-A-<nonce>` in A's
   mailbox. These accounts must not be anyone's personal mailbox.
3. **Open WebUI users.** One Open WebUI user each for A and B, plus an unconnected
   user, Carla. None of them may be an Open WebUI admin.
4. **Least-privilege scopes.** Default:
   `https://www.googleapis.com/auth/gmail.readonly`.
   - Any additional scope must be named by the operator.
   - The chosen list goes verbatim into `descriptors.*.scopes`.
5. **Secrets, as environment references only.**
   - `GOOGLE_OAUTH_CLIENT_SECRET`
   - the store key variable named in `accounts.keys`
   - the adapter HMAC variable, which must match Open WebUI's
     `FORWARD_USER_INFO_HEADER_JWT_SECRET`
6. **Store directories.** Run `mcp-gateway accounts init-store` once on Spark
   (`src/commands/accounts.rs:184`).
7. **Google caveats.** These are inferred, not verified; the operator should check
   them against current Google documentation before recording.
   - Refresh tokens issued to an external app in "Testing" status are believed to
     expire after about 7 days. Run the whole L02/L03 set inside one 7-day window.
     If you re-run later, expect `invalid_grant` and a `reconnect_required` offer,
     which is itself valid evidence for reconnect.
   - `gmail.readonly` is a restricted scope. An unverified app shows Google's
     "unverified app" interstitial, which the driver must click through and record.

**Cloudflare change.** In `cloudflared` `config.yml`, insert this ingress rule
before the `chat.raxor.ai` catch-all:

```yaml
- hostname: chat.raxor.ai
  path: ^/accounts/v1/
  service: http://localhost:<gateway port>
```

Leave `httpHostHeader` unset, so the gateway sees `Host: chat.raxor.ai`.

Before you record anything, check the route:

```sh
curl -sI https://chat.raxor.ai/accounts/v1/complete
```

It must answer from the gateway, identified by its `Content-Security-Policy`
header. Open WebUI's SPA must not answer it.

**Gateway config.** Use the §10 block with:

- `installation_id` set to the value already used by the deployed adapter;
- `session.user_endpoint: http://127.0.0.1:8090/api/v1/auths/`.

Also, **L01 must confirm** that the Google Workspace backend is reachable from Open
WebUI through one of the three covered dispatch routes. Record which route
(`gateway_invoke`, the direct `/mcp/{name}`, or a capability).

**Pinned evidence (L01).** Record:

- the gateway commit and artifact SHA-256 (binaries carry no embedded commit, so the
  directory digest serves as provenance);
- the Open WebUI 0.9.6 image digest;
- the `cloudflared` rule text;
- the Google client revision;
- the redacted gateway config (secrets remain `env:` references);
- the actual MCP route.

**Runs.** The driver is independent (L02 requires this) and acts as a real user in
a real browser.

| Step | Action | Evidence to capture |
|---|---|---|
| L02-1 | Carla asks the model to read mail | Screenshot of the refusal showing a clickable link. The status of the created journey. Carla sees no operator data. |
| L02-2 | A: refusal, click link, Google consent, completion page | Screenshots of each page (URL bar visible, no token in it). A reads `JOURNEY-A-<nonce>`. |
| L02-3 | B repeats, then A and B interleave calls and discovery | Each sees only their own discriminator |
| A07-live | A's `connect_url` opened in Carla's browser session | Refusal page, no Google redirect |
| L03-cancel | A new journey for B, where B clicks "Cancel" at Google | Completion page reads "cancelled". Status JSON `cancelled/user_denied`. B's existing grant still works. |
| L03-expired | Open a `connect_url` 6 minutes after the refusal; re-submit a captured callback URL from browser history | "expired" page. Status shows `replay_refused`. No new grant. |
| L03-refresh | Natural expiry: wait for the Google access token to lapse (about 60 min, `expires_in`), then A calls a tool. No clock-skew mechanism is built. | Sanitized log line `refresh committed` (no token). The tool result arrives through Open WebUI. |
| L03-revoke | A presses "Disconnect" on `/accounts/v1/complete` | Response JSON with `provider_revocation: confirmed`. A's next call is refused with a reconnect link. B still works. A's Google account permissions page no longer lists the app. |
| L03-restart | Restart the gateway, repeat an A call and a B call | Grants survive. The replay is still refused. |
| L04 | Restore the backed-up test store onto a copy, run the documented rollback (remove `hosted`, restart), confirm only the designated users are exposed | Transcript of the rollback. The residual provider-side revoke outcome is recorded. |

Evidence never includes environment dumps, database or store files, tokens,
cookies or mailbox contents beyond the discriminator subject line. Screenshots
crop the browser's cookie and devtools panes.

Fault injection is integration evidence (T-C03c, T-REV2, T-C07b/c) and is labelled
that way, not as live Google results.

## 12. Contradictions found, amendments, and visibility changes

These are contradictions between the recorded constraints and the source, and the
amendments this design makes to the earlier design.

1. **The criterion wording differs between documents.**
   - `RELEASE-4.0.0-scope-update.md:44` lists five elements.
   - `RELEASE-4.0.0-scope-tests.md:43` and test-plan C03 add expired/replayed state.
   - This design follows the six-element text and the 2026-09-23 ruling.
   - The scope-update row needs a doc correction. This is not a code question.
2. **The BC-1 site counts are stale.**
   - The note says 4 caller-aware and 12 caller-blind sites. At the tip there are 5
     caller-aware sites (4 in `search.rs` plus `discovery_fetch.rs:75`) and 11
     caller-blind sites (§9.2).
   - The in-code doc comment (`src/gateway/meta_mcp/mod.rs:1235-1242`) says "the
     seven that must keep failing closed". That counts only `meta_route_isolation_refused`
     sites and misses the 4 direct `enforce_oauth_isolation_for(…, false)` calls.
   - The §9.2 rule does not depend on the count. T-BC1 enumerates the methods, not
     the sites.
3. **`vault.rs:55-71` and `identity_propagation/mod.rs:134-140` state premises
   this design reverses.**
   - The first says revoked and reconnect-required states are "not remedied by
     connecting".
   - The second says `AccountNotConnected` is "not an offer".
   - Both comments are rewritten in slice 5, the slice that makes them false.
4. **The direct route and the design table use different JSON-RPC codes.**
   - The direct route refuses with `-32003`/403 (`backend_handlers.rs:814-819`).
   - The design table says `-32001` for the MCP account refusal.
   - Decision: `-32001` on the meta and capability routes; the direct route keeps
     `-32003`; `error.data` is identical on all three. A reviewer may prefer
     unifying on `-32001`, which is a client-visible change on the direct route.
5. **`validate_issuer` accepts an absent `iss`** (`src/oauth/client/mod.rs:88-100`).
   The mix-up defence rests on state being bound to a single descriptor plus the
   pinned token endpoint (§6.2 step 6), not on `iss`.
6. **Amendments to the route table.** Each of these is an explicit change to
   `docs/design/2026-09-06-personal-accounts.md`:
   - `provider_revocation` becomes `confirmed | failed | unsupported | not_applicable`
     (§8.2).
   - `superseded` is reported as `expired` with a reason (§3).
   - New routes: `GET /accounts/v1/complete` and `/accounts/v1/assets/complete.js`.
   - DELETE accepts bridge-cookie authentication (§8.3).
7. **The BC-2 premise ("no test closes C2 until the store can represent a declined
   state")** is met by the journey record, not by the store (§7). Treat this as a
   reviewed interpretation, not a silent reinterpretation.
8. **`wire_tests.rs:9-13` and `wire_tests/gateway.rs:7` carry stale comments.**
   They say "PROPOSAL ONLY … does NOT compile", but the module is wired in at
   `provider.rs:53`. Fix them when the fixture moves (slice 2).
9. **C04 "terminal journey code/state/verifier bytes are removed" (reviewed
   interpretation).** After the terminal write, no raw state, code or verifier is
   persisted. The keyed `state_digest` is kept until GC (§3). Without it, decision
   5's "status shows replay attempt refused" is unimplementable, because a replay
   would look the same as a random string. T-C04c asserts exactly this.
10. **Decision 3 said "303 to an allowlisted completion page". This design renders
    the outcome on the callback response itself.** Fetch Metadata's
    `Sec-Fetch-Site` describes the whole redirect chain, so a second hop to
    `/complete` would arrive as `cross-site`. The origin guard would refuse it, and
    a `SameSite=Strict` Open WebUI cookie would be withheld (§6.2 step 12,
    T-GUARD2). The completion page is still reachable with a same-origin click from
    the outcome page.

**Visibility widenings.** Operator policy requires asking before each one, so
each is listed here for operator approval.

| Item | From → to | Why |
|---|---|---|
| `namespaced_issuer` (`src/gateway/openwebui_adapter.rs:441`) | private → `pub(crate)` | The bridge must derive the identical authority. A copy would be the drift the length-prefix comment warns about. |
| `validate_issuer` | already `pub` | none |
| wire fixture (`provider/wire_tests/fixture.rs`) | `pub(super)` → `pub(in crate::personal_accounts)`, `cfg(test)` only | Reused by the router-level journey tests |
| `PersonalAccountStore::revoke_capturing`, `JourneyService` | new `pub(crate)` | Router facade, the same level as `CustodyHandle` |

## 13. Open questions (not decidable from source)

1. **Does Open WebUI 0.9.6's native MCP client show JSON-RPC `error.message` to the
   user or the model?**
   - It is unknown whether the client does either, and whether the model reproduces
     the link.
   - This is decided only by L02-1. If the link is not visible, add URL-mode
     elicitation, which reopens the §9.4 deferral.
2. **Is Open WebUI's `WEBUI_AUTH_COOKIE_SAME_SITE` set to `strict` on Spark?**
   - If it is, the cookie is not sent when the user follows a link from a chat
     message rendered in a new tab. Same-site navigation from chat.raxor.ai keeps
     `strict` cookies, so this is likely fine, but it must be observed in L02-2.
3. **Which route does Spark's Google Workspace backend use?** It could be an MCP
   backend or a REST capability. This decides which of the three dispatch sites
   carries L02. All three are built.
4. **Is `gmail.readonly` enough scope?** The Google scope set is an operator choice.

## 14. Delivery slices

Each slice merges independently with its own tests. Each slice that adds a
production caller also deletes the matching `expect(dead_code)`, because otherwise
the build fails. The `connect_url` surface comes **last**. BC-1..3 forbid inviting
users into a flow that cannot yet be completed.

| # | Slice | Tests | Removes `expect(dead_code)` at |
|---|---|---|---|
| 1 | Config types: `hosted`, `session`, three limits, `authorize_extra`, plus validation. Nothing is mounted. | T-CFG | — |
| 2 | Journey table: sealed file, `journey_transition`, limits, GC. Fixture moved to test support. | T-C06a/b/c, T-C04c (store level), restart unit of T-C03d | — |
| 3 | Provider: `authorize_url`, `exchange_code`, `revoke_token`; `Arc` sharing | Unit tests against the fake AS: form shapes, pinned endpoints, `send_resource_parameter` | — |
| 4 | Revoke: `revoke_capturing`, DELETE (API credential), slot eviction, audit | T-REV (API variant), T-REV2, T-C07c, T-C07a (DELETE part) | `worker.rs:241-245`, `service.rs:326-329`, `mod.rs:355-360`, `commit.rs` revoke |
| 5 | Hosted routes: POST/status/start/callback/complete, bridge, origin-guard changes, trace isolation, browser DELETE | T-C01, T-C02a–d, T-A07, T-C03a–e, T-C04a/b, T-BC2, T-C05a–c, T-C07a/b, T-GUARD, T-LEAK, T-REF, T-C01b | `service.rs:335-342`, `worker.rs:247-253` (`commit_grant_if`), `service.rs` `StaleConsentFenced` |
| 6 | Typed refusal plus `offer_for` at the three dispatch sites; comment rewrites (§12 item 3) | T-OFFER, T-OFFER2, T-BC1 | — |
| 7 | Live run (§11.4) and evidence | L01–L04 | — |

Slices 1 to 4 ship no user-visible change while `hosted` is absent. Slice 4's
DELETE accepts only the API credential until slice 5 adds the bridge.

## 15. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Open WebUI drops `error.message`/`data`, so the user never sees the link | Medium | Connect unusable live | URL also in the message text. L02-1 observes it. Fallback: elicitation (§13 item 1). |
| Open WebUI changes the session route shape or cookie name after 0.9.6 | Low (image is pinned) | Bridge refuses everyone (fails closed) | Version pinned in L01. `cookie_name` and `user_endpoint` are configurable. |
| Gateway HTML on the Open WebUI origin becomes an XSS pivot into Open WebUI | Low | High | Strict CSP, no inline script, escaped fixed strings, one static script (§4.3) |
| Google omits `refresh_token` on re-consent | Medium | Refresh fails later | `prompt=consent`. Journey `failed/no_refresh_token` instead of a half-working grant (§6.2 step 9). |
| A refresh between creation and callback fences a legitimate re-consent | Low | User retries once | Documented trade-off (§6.3). The retry creates a new journey. |
| Journeys write contention on the authority mutex | Low | Latency on refusals | Offer reuse (§9.3). Rate limits. No IO in the closure beyond one small file write. |
| Missing `journeys.json` treated as empty after tampering | Low | None beyond refusing callbacks | Fails closed. Stale-copy rollback is additionally fenced by `commit_grant_if` (§5.2). |
| Provider revoke fails silently to the user | Medium | Grant still live at Google | `provider_revocation: failed` is shown on the page, with a link to the Google permissions page. The local tombstone blocks gateway use regardless. |
| Test fixture visibility change needs approval (§12) | — | Slice 2 blocked | Asked up front in this document |
